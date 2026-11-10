using System.Buffers;
using System.Collections.Frozen;
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
/// <item><term>E3: unsigned PE in AppData with a machine-generated name</term><description><see cref="RandomNameScore"/>, T1204.002, Infostealer</description></item>
/// <item><term>E3: untrusted executable named like a known miner</term><description><see cref="MinerNameScore"/>, T1496.001, Miner</description></item>
/// <item><term>E3: script whose text starts a miner</term><description><see cref="MinerScriptScore"/>, T1496.001, Miner</description></item>
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

    /// <summary>Plain Offline on an executable (<c>attrib +O</c>): weak. Hidden from naive scanners, but also set by old HSM software.</summary>
    public const int PlainOfflineScore = 10;

    /// <summary>
    /// E3: a machine-generated name on an unsigned PE in AppData. Fires only together with the unsigned (15) and AppData (15)
    /// findings, so all three make exactly the threshold (60); signed programs never get it.
    /// </summary>
    public const int RandomNameScore = 30;

    /// <summary>E3: an untrusted executable named like a known miner; with "unsigned" (15) it reaches the threshold.</summary>
    public const int MinerNameScore = 45;

    /// <summary>E3: a script that starts a miner (<see cref="MinerRules.AnalyzeCommandLine"/> says miner): strong on its own.</summary>
    public const int MinerScriptScore = 60;

    /// <summary>E3: scripts up to this size are read for miner command lines (only the first bytes of larger ones).</summary>
    public const int MaxScriptBytes = 64 * 1024;

    /// <summary>Script extensions whose text is checked for miner command lines.</summary>
    private static readonly FrozenSet<string> MinerScriptExtensions =
        new[] { ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".wsf" }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

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

        using var handle = SecureFile.OpenRegularFile(path, out var failure, out var attributes);
        if (handle is null)
        {
            return new HeuristicResult(NameFindings(path).AsReadOnly(), Threshold, contentInspected: false, failure.Message, failure.Reason);
        }

        return AnalyzeValidated(new HandleContent(handle), path, context, cancellationToken, FilePlaceholder.IsPlainOffline(attributes, NativeFile.ReparseTagOf(handle, attributes)));
    }

    /// <inheritdoc/>
    public HeuristicResult Analyze(SafeFileHandle handle, string path, HeuristicContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handle);
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        if (!SecureFile.Validate(handle, out var failure, out var attributes))
        {
            return new HeuristicResult(NameFindings(path).AsReadOnly(), Threshold, contentInspected: false, failure.Message, failure.Reason);
        }

        return AnalyzeValidated(new HandleContent(handle), path, context, cancellationToken, FilePlaceholder.IsPlainOffline(attributes, NativeFile.ReparseTagOf(handle, attributes)));
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

    private HeuristicResult AnalyzeValidated(Content content, string path, HeuristicContext context, CancellationToken cancellationToken, bool plainOffline = false)
    {
        var findings = NameFindings(path);
        try
        {
            InspectContent(content, path, context, findings, cancellationToken, plainOffline);
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
        Content content, string path, HeuristicContext context, List<HeuristicFinding> findings, CancellationToken cancellationToken, bool plainOffline)
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

        // E3: random-named unsigned program in AppData (infostealer / dropper copies). Only with a checked, untrusted signature:
        // legitimate per-user installs (Discord, Teams, VS Code) are signed and never get it.
        if (pe is not null && context.Signature is { IsChecked: true, IsTrusted: false }
            && FileNameRules.ClassifyFolder(path) == RiskyFolder.AppData && FileNameRules.RandomNameReason(path) is { } random)
        {
            findings.Add(new(HeuristicKind.RandomNameAppDataExecutable, RandomNameScore,
                $"unsigned program in AppData whose name looks machine-generated ({random})", MitreTechniqueIds.MaliciousFile));
        }

        // E3: known miner programs, and scripts that start one.
        if (isExecutable && !trusted && MinerRules.IsMinerName(path))
        {
            findings.Add(new(HeuristicKind.MinerProgramName, MinerNameScore, "executable named like a known cryptominer", MitreTechniqueIds.ComputeHijacking));
        }

        if (!trusted && MinerScriptExtensions.Contains(Path.GetExtension(path)) && MinerScript(content, length) is { IsMiner: true } miner)
        {
            findings.Add(new(HeuristicKind.MinerScript, MinerScriptScore,
                $"script starts a cryptominer ({string.Join(", ", miner.Reasons)})", MitreTechniqueIds.ComputeHijacking));
        }

        if (isExecutable && !trusted && plainOffline)
        {
            findings.Add(new(HeuristicKind.PlainOfflineAttribute, PlainOfflineScore, "executable with the Offline attribute set by hand (no cloud or HSM provider behind it)",
                MitreTechniqueIds.HideArtifacts));
        }

        if (isExecutable && !trusted && context.MarkOfTheWeb is { IsFromInternet: true } mark)
        {
            findings.Add(new(HeuristicKind.InternetOrigin, InternetOriginScore,
                mark.HostUrl is { } url ? $"executable downloaded from the internet ({url})" : "executable downloaded from the internet",
                MitreTechniqueIds.MaliciousFile));
        }
    }

    /// <summary>
    /// E3: the miner analysis of a script's first <see cref="MaxScriptBytes"/> bytes (UTF-16 with a BOM, else UTF-8 / ANSI). Only
    /// the text is looked at; nothing is run.
    /// </summary>
    private static MinerAnalysis MinerScript(Content content, long length)
    {
        var bytes = new byte[(int)Math.Min(length, MaxScriptBytes)];
        int read = ReadFully(content, bytes, 0);
        var span = bytes.AsSpan(0, read);
        string text = span.StartsWith((ReadOnlySpan<byte>)[0xFF, 0xFE]) ? System.Text.Encoding.Unicode.GetString(span[2..])
            : span.StartsWith((ReadOnlySpan<byte>)[0xFE, 0xFF]) ? System.Text.Encoding.BigEndianUnicode.GetString(span[2..])
            : System.Text.Encoding.UTF8.GetString(span);
        return MinerRules.AnalyzeCommandLine(text);
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
