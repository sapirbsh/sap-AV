using System.Buffers;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;
using SapAV.Core.Mitre;
using SapAV.Core.Signatures;

namespace SapAV.Core.Heuristics;

/// <summary>Scores a file with heuristics. Implemented by <see cref="FileHeuristics"/>; fake it in tests (A7).</summary>
public interface IFileHeuristics
{
    /// <summary>
    /// Runs the heuristics on the file at <paramref name="path"/>. Name and path rules always run; content rules
    /// run if the file can be opened (see <see cref="HeuristicResult.ContentInspected"/>). Never throws for I/O.
    /// </summary>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    HeuristicResult Analyze(string path, HeuristicContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Same as <see cref="Analyze(string, HeuristicContext, CancellationToken)"/> for an already open handle (the
    /// single-handle scan pipeline): content rules read the handle; <paramref name="path"/> is only used for the
    /// name and folder rules. The handle is validated first and is not closed.
    /// </summary>
    HeuristicResult Analyze(SafeFileHandle handle, string path, HeuristicContext context, CancellationToken cancellationToken = default);
}

/// <summary>
/// The file heuristics (ROADMAP feature 2, step 4). Each rule adds points; at <see cref="Threshold"/> or more the
/// file is Suspicious, never Malicious. Thread-safe and stateless. Synchronous like the other content readers.
/// </summary>
/// <remarks>
/// <para>Rules and points (one strong signal is enough; weak signals need company):</para>
/// <list type="table">
/// <item><term>Double extension (<c>.pdf.exe</c>)</term><description><see cref="DoubleExtensionScore"/>, T1036.007</description></item>
/// <item><term>Right-to-left override in the name</term><description><see cref="RightToLeftOverrideScore"/>, T1036.002</description></item>
/// <item><term>Oversized PE padded past the size limit</term><description><see cref="PaddingScore"/>, T1027.001</description></item>
/// <item><term>High-entropy PE sections (packed)</term><description><see cref="HighEntropyScore"/>, T1027.002</description></item>
/// <item><term>Broken Authenticode signature</term><description><see cref="BrokenSignatureScore"/>, T1204.002</description></item>
/// <item><term>Unsigned PE</term><description><see cref="UnsignedScore"/>, T1204.002</description></item>
/// <item><term>Executable/script in Temp, Downloads or AppData</term><description><see cref="RiskyFolderScore"/>, T1204.002</description></item>
/// <item><term>Executable/script with an Internet/Restricted-zone Mark-of-the-Web</term><description><see cref="InternetOriginScore"/>, T1204.002</description></item>
/// </list>
/// <para>
/// To keep false positives low, a file with a <b>trusted</b> signature (Microsoft or OtherTrusted) gets no
/// points for the weak signals (entropy, folder, internet origin); only the masquerading and padding rules count for it.
/// Entropy is measured over the PE <b>section data only</b>, not the overlay, so ordinary installers whose
/// compressed payload sits in the overlay aren't flagged. Non-PE files get no entropy rule (archives,
/// media and Office files are high-entropy by nature).
/// </para>
/// <para>
/// Padding rule (carried over from the A2 review): a PE file over <see cref="MaxSizeBytes"/> (the hasher's limit,
/// so it would otherwise be skipped unscanned) whose overlay is at least half the file and whose sampled
/// overlay blocks (the tail plus evenly spaced samples) are all near-constant. Only the headers and those
/// samples are read, never the whole file.
/// </para>
/// <para>Files are opened like the hasher (<see cref="SecureFile"/>): devices, pipes, directories, offline files are not read.</para>
/// </remarks>
public sealed class FileHeuristics : IFileHeuristics
{
    public const int DefaultThreshold = 60;
    public const int DoubleExtensionScore = 60;
    public const int RightToLeftOverrideScore = 60;
    public const int PaddingScore = 60;
    public const int HighEntropyScore = 35;
    public const int BrokenSignatureScore = 30;
    public const int UnsignedScore = 15;
    public const int RiskyFolderScore = 15;
    public const int InternetOriginScore = 15;

    /// <summary>Section-data entropy (bits/byte) at or above which a PE counts as packed or encrypted.</summary>
    public const double HighEntropyBitsPerByte = 7.2;

    /// <summary>Less section data than this is too little for a meaningful entropy value.</summary>
    public const int MinEntropySampleBytes = 4096;

    private const int ReadBufferSize = 128 * 1024;
    private const int PaddingSampleSize = 4096;
    private const int PaddingSampleCount = 16;
    private const double PaddingMaxEntropy = 1.0;

    /// <param name="maxSizeBytes">The hasher's size limit; larger PE files are checked for padding instead of read.</param>
    /// <param name="threshold">Score at which a file is Suspicious.</param>
    public FileHeuristics(long maxSizeBytes = Sha256Hasher.DefaultMaxSizeBytes, int threshold = DefaultThreshold)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maxSizeBytes);
        ArgumentOutOfRangeException.ThrowIfLessThan(threshold, 1);
        MaxSizeBytes = maxSizeBytes;
        Threshold = threshold;
    }

    public long MaxSizeBytes { get; }

    public int Threshold { get; }

    /// <inheritdoc/>
    public HeuristicResult Analyze(string path, HeuristicContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        using var handle = SecureFile.OpenRegularFile(path, out var failure, out _);
        if (handle is null)
        {
            return new HeuristicResult(NameFindings(path).AsReadOnly(), Threshold, contentInspected: false, failure.Message, failure.Reason);
        }

        return AnalyzeValidated(new HandleContent(handle), path, context, cancellationToken);
    }

    /// <inheritdoc/>
    public HeuristicResult Analyze(SafeFileHandle handle, string path, HeuristicContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handle);
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        if (!SecureFile.Validate(handle, out var failure, out _))
        {
            return new HeuristicResult(NameFindings(path).AsReadOnly(), Threshold, contentInspected: false, failure.Message, failure.Reason);
        }

        return AnalyzeValidated(new HandleContent(handle), path, context, cancellationToken);
    }

    /// <summary>
    /// The same rules on content already in memory: exactly the PE parsing, entropy, padding and overlay code
    /// the handle path runs, reading <paramref name="content"/> instead of a file. <paramref name="path"/> is only
    /// used for the name and folder rules and is never opened, so nothing touches the disk (the unit tests use
    /// this, so a real antivirus can't block their synthetic PE files; the scan pipeline reads by handle).
    /// The result always has <see cref="HeuristicResult.ContentInspected"/> set.
    /// </summary>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    internal HeuristicResult Analyze(ReadOnlyMemory<byte> content, string path, HeuristicContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        return AnalyzeValidated(new MemoryContent(content), path, context, cancellationToken);
    }

    private HeuristicResult AnalyzeValidated(Content content, string path, HeuristicContext context, CancellationToken cancellationToken)
    {
        var findings = NameFindings(path);
        try
        {
            InspectContent(content, path, context, findings, cancellationToken);
            return new HeuristicResult(findings.AsReadOnly(), Threshold, contentInspected: true, null);
        }
        catch (Exception ex) when (Sha256Hasher.TryClassify(ex, out var reason))
        {
            return new HeuristicResult(findings.AsReadOnly(), Threshold, contentInspected: false, ex.Message, reason);
        }
    }

    private static List<HeuristicFinding> NameFindings(string path)
    {
        var findings = new List<HeuristicFinding>();
        string name = Path.GetFileName(path);

        if (FileNameRules.DoubleExtension(name) is { } doubleExtension)
        {
            findings.Add(new(HeuristicKind.DoubleExtension, DoubleExtensionScore,
                $"double file extension {doubleExtension}", MitreTechniqueIds.DoubleFileExtension));
        }

        if (FileNameRules.HasRightToLeftOverride(name))
        {
            findings.Add(new(HeuristicKind.RightToLeftOverride, RightToLeftOverrideScore,
                "file name contains a right-to-left override character", MitreTechniqueIds.RightToLeftOverride));
        }

        return findings;
    }

    private void InspectContent(
        Content content, string path, HeuristicContext context, List<HeuristicFinding> findings, CancellationToken cancellationToken)
    {
        long length = content.Length;
        var head = new byte[(int)Math.Min(PeHeaders.HeaderReadSize, length)];
        int headLength = ReadFully(content, head, 0);
        var pe = PeHeaders.TryParse(head.AsSpan(0, headLength), length);

        bool isExecutable = pe is not null || FileNameRules.ScriptExtensions.Contains(Path.GetExtension(path));
        bool trusted = context.IsTrustedSigned;

        if (pe is not null && length > MaxSizeBytes)
        {
            if (IsPadded(content, pe, length, cancellationToken) is { } overlayPercent)
            {
                findings.Add(new(HeuristicKind.PaddedOversizedExecutable, PaddingScore,
                    $"executable is {length} bytes, over the {MaxSizeBytes}-byte scan limit, and {overlayPercent}% of it is padding",
                    MitreTechniqueIds.BinaryPadding));
            }
        }
        else if (pe is not null && !trusted)
        {
            var entropy = SectionEntropy(content, pe, cancellationToken);
            if (entropy is { } bits && bits >= HighEntropyBitsPerByte)
            {
                findings.Add(new(HeuristicKind.HighEntropyExecutable, HighEntropyScore,
                    $"executable sections have high entropy ({bits:F2} bits/byte): packed or encrypted",
                    MitreTechniqueIds.SoftwarePacking));
            }
        }

        if (pe is not null && context.Signature is { IsChecked: true } signature && !signature.IsTrusted)
        {
            findings.Add(signature.HasBrokenSignature
                ? new(HeuristicKind.BrokenSignature, BrokenSignatureScore,
                    $"signature does not verify ({signature.FailureReason})", MitreTechniqueIds.MaliciousFile)
                : new(HeuristicKind.UnsignedExecutable, UnsignedScore, "executable is not signed", MitreTechniqueIds.MaliciousFile));
        }

        if (isExecutable && !trusted && FileNameRules.ClassifyFolder(path) is var folder and not RiskyFolder.None)
        {
            findings.Add(new(HeuristicKind.RiskyFolderExecutable, RiskyFolderScore,
                $"executable in a {folder} folder", MitreTechniqueIds.MaliciousFile));
        }

        if (isExecutable && !trusted && context.MarkOfTheWeb is { IsFromInternet: true } mark)
        {
            findings.Add(new(HeuristicKind.InternetOrigin, InternetOriginScore,
                mark.HostUrl is { } url ? $"executable downloaded from the internet ({url})" : "executable downloaded from the internet",
                MitreTechniqueIds.MaliciousFile));
        }
    }

    /// <summary>Entropy of the PE section data (not headers or overlay), or null if there is too little.</summary>
    private static double? SectionEntropy(Content content, PeHeaders pe, CancellationToken cancellationToken)
    {
        var entropy = new ShannonEntropy();
        var buffer = ArrayPool<byte>.Shared.Rent(ReadBufferSize);
        try
        {
            foreach (var (offset, size) in pe.SectionData)
            {
                for (long done = 0; done < size;)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    int want = (int)Math.Min(ReadBufferSize, size - done);
                    int read = content.Read(buffer.AsSpan(0, want), offset + done);
                    if (read == 0)
                    {
                        break;
                    }

                    entropy.Add(buffer.AsSpan(0, read));
                    done += read;
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }

        return entropy.Total >= MinEntropySampleBytes ? entropy.Value : null;
    }

    /// <summary>The overlay's share of the file in percent if it is padding; otherwise null.</summary>
    private static int? IsPadded(Content content, PeHeaders pe, long length, CancellationToken cancellationToken)
    {
        long overlay = length - pe.ImageEnd;
        if (overlay < length / 2 || overlay < PaddingSampleSize)
        {
            return null;
        }

        var sample = new byte[PaddingSampleSize];
        for (int i = 0; i <= PaddingSampleCount; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Evenly spaced through the overlay; i == PaddingSampleCount is the very end of the file.
            long offset = pe.ImageEnd + ((overlay - PaddingSampleSize) * i / PaddingSampleCount);
            int read = ReadFully(content, sample, offset);
            if (read < PaddingSampleSize || ShannonEntropy.Of(sample) > PaddingMaxEntropy)
            {
                return null;
            }
        }

        return (int)(overlay * 100 / length);
    }

    private static int ReadFully(Content content, byte[] buffer, long offset)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = content.Read(buffer.AsSpan(total), offset + total);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total;
    }

    /// <summary>
    /// Random-access, read-only content for the rules: an open file handle or bytes in memory. Both run the same
    /// rule code; only the reads differ.
    /// </summary>
    private abstract class Content
    {
        public abstract long Length { get; }

        /// <summary>Reads up to <c>buffer.Length</c> bytes at <paramref name="offset"/>; 0 at or past the end.</summary>
        public abstract int Read(Span<byte> buffer, long offset);
    }

    private sealed class HandleContent(SafeFileHandle handle) : Content
    {
        public override long Length => RandomAccess.GetLength(handle);

        public override int Read(Span<byte> buffer, long offset) => RandomAccess.Read(handle, buffer, offset);
    }

    private sealed class MemoryContent(ReadOnlyMemory<byte> bytes) : Content
    {
        public override long Length => bytes.Length;

        public override int Read(Span<byte> buffer, long offset)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(offset); // same contract as RandomAccess.Read
            if (offset >= bytes.Length)
            {
                return 0;
            }

            var source = bytes.Span[(int)offset..];
            int count = Math.Min(buffer.Length, source.Length);
            source[..count].CopyTo(buffer);
            return count;
        }
    }
}
