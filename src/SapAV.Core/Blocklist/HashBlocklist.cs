using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using SapAV.Core.Hashing;
using SapAV.Core.Mitre;
using SapAV.Core.Models;

namespace SapAV.Core.Blocklist;

/// <summary>
/// Immutable set of blocked SHA-256 hashes with O(1) lookup.
/// </summary>
/// <remarks>
/// <para>
/// Format (<c>data/hashes/blocklist.txt</c>): one hash per line; lines whose first non-blank character is
/// <c>#</c> are comments; blank lines are ignored; surrounding whitespace is trimmed; hashes are
/// case-insensitive and stored lowercase. A leading byte-order mark is ignored. Line endings may be
/// LF, CRLF or CR.
/// </para>
/// <para>
/// Any other line (wrong length, non-hex, trailing text, longer than <see cref="MaxLineLength"/>) is
/// skipped and counted; the first <see cref="MaxReportedErrors"/> are kept in <see cref="Errors"/> with
/// line numbers and <see cref="TotalErrorCount"/> has the full count. Loading never throws because of a
/// line's content and always continues with the next line. Over-long lines are cut off while reading,
/// so a huge line never becomes a huge string. Input larger than the size limit (default
/// <see cref="DefaultMaxSizeBytes"/>) is rejected with <see cref="InvalidDataException"/>.
/// </para>
/// <para>
/// Instances never change after loading, so they are safe to read from any number of threads. To reload,
/// load a new instance and swap the reference (e.g. a <c>volatile</c> field or <c>Interlocked.Exchange</c>);
/// readers holding the old instance keep a consistent view. <see cref="Fingerprint"/> tells whether two
/// instances hold the same set of hashes.
/// </para>
/// </remarks>
public sealed class HashBlocklist
{
    /// <summary>Default maximum input size: 64 MiB (about a million hashes).</summary>
    public const long DefaultMaxSizeBytes = 64L * 1024 * 1024;

    /// <summary>Lines longer than this many characters are reported as malformed.</summary>
    public const int MaxLineLength = 1024;

    /// <summary>At most this many malformed lines are kept in <see cref="Errors"/>.</summary>
    public const int MaxReportedErrors = 100;

    private const char ByteOrderMark = (char)0xFEFF;
    private const int ReadChunkChars = 4096;

    private readonly FrozenSet<string> _hashes;

    private HashBlocklist(
        FrozenSet<string> hashes,
        IReadOnlyList<BlocklistLineError> errors,
        int totalErrorCount,
        int duplicateCount)
    {
        _hashes = hashes;
        Errors = errors;
        TotalErrorCount = totalErrorCount;
        DuplicateCount = duplicateCount;
        Fingerprint = ComputeFingerprint(hashes);
    }

    /// <summary>A blocklist with no entries.</summary>
    public static HashBlocklist Empty { get; } =
        new(FrozenSet<string>.Empty, Array.Empty<BlocklistLineError>(), 0, 0);

    /// <summary>Number of distinct hashes.</summary>
    public int Count => _hashes.Count;

    /// <summary>The first <see cref="MaxReportedErrors"/> skipped malformed lines, in line order.</summary>
    public IReadOnlyList<BlocklistLineError> Errors { get; }

    /// <summary>Total number of skipped malformed lines (may be more than <see cref="Errors"/> holds).</summary>
    public int TotalErrorCount { get; }

    /// <summary>Number of valid lines that repeated a hash already loaded (case-insensitively).</summary>
    public int DuplicateCount { get; }

    /// <summary>
    /// Lowercase hex SHA-256 over the sorted set of hashes (each followed by <c>'\n'</c>). It depends only on
    /// which hashes are listed, not on order, case, comments or duplicates, so the scan cache (C5) can
    /// tell whether the blocklist really changed.
    /// </summary>
    public string Fingerprint { get; }

    /// <summary>
    /// True if <paramref name="sha256"/> (64 hex characters, any case) is in the blocklist.
    /// Malformed or null input returns false. Never throws.
    /// </summary>
    public bool Contains(string? sha256) =>
        Sha256Hex.TryNormalize(sha256, out var normalized) && _hashes.Contains(normalized);

    /// <summary>
    /// If <paramref name="sha256"/> is blocklisted, returns a Malicious detection (source Blocklist,
    /// MITRE <see cref="MitreTechniqueIds.MaliciousFile"/>). Never throws.
    /// </summary>
    public bool TryMatch(string? sha256, [NotNullWhen(true)] out Detection? detection)
    {
        if (Sha256Hex.TryNormalize(sha256, out var normalized) && _hashes.Contains(normalized))
        {
            detection = new Detection(
                Verdict.Malicious,
                $"SHA-256 {normalized} is in the local blocklist",
                MitreTechniqueIds.MaliciousFile,
                DetectionSource.Blocklist);
            return true;
        }

        detection = null;
        return false;
    }

    /// <summary>Loads a blocklist file (UTF-8, BOM optional).</summary>
    /// <remarks>
    /// The file is opened with <c>FileShare.ReadWrite | FileShare.Delete</c> so an updater can replace it.
    /// A missing, unreadable or oversized file throws (the caller decides whether to keep the previous
    /// instance).
    /// </remarks>
    /// <exception cref="InvalidDataException">The file is larger than <paramref name="maxSizeBytes"/>.</exception>
    /// <exception cref="IOException">The file can't be opened or read.</exception>
    /// <exception cref="UnauthorizedAccessException">Access to the file is denied.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    public static async Task<HashBlocklist> LoadAsync(
        string path, CancellationToken cancellationToken = default, long maxSizeBytes = DefaultMaxSizeBytes)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentOutOfRangeException.ThrowIfNegative(maxSizeBytes);

        var options = new FileStreamOptions
        {
            Mode = FileMode.Open,
            Access = FileAccess.Read,
            Share = FileShare.ReadWrite | FileShare.Delete,
            Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
        };

        var stream = new FileStream(path, options);
        await using (stream.ConfigureAwait(false))
        {
            return await LoadAsync(stream, cancellationToken, maxSizeBytes).ConfigureAwait(false);
        }
    }

    /// <summary>Loads from a stream (UTF-8 unless a BOM says otherwise). The stream is not disposed.</summary>
    /// <exception cref="InvalidDataException">More than <paramref name="maxSizeBytes"/> bytes remain in the stream.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    public static async Task<HashBlocklist> LoadAsync(
        Stream stream, CancellationToken cancellationToken = default, long maxSizeBytes = DefaultMaxSizeBytes)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfNegative(maxSizeBytes);

        if (stream.CanSeek && stream.Length - stream.Position > maxSizeBytes)
        {
            throw TooLarge(maxSizeBytes);
        }

        // Also counts bytes as they are read, for non-seekable streams and files that grow.
        var limited = new SizeLimitedReadStream(stream, maxSizeBytes);
        using var reader = new StreamReader(limited, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
        return await ParseAsync(reader, maxChars: long.MaxValue, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Loads from a text reader. The reader is not disposed.</summary>
    /// <param name="maxSizeBytes">Limit on the number of characters read (a UTF-8 blocklist is ASCII, so
    /// characters and bytes match).</param>
    /// <exception cref="InvalidDataException">More than <paramref name="maxSizeBytes"/> characters were read.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    public static Task<HashBlocklist> LoadAsync(
        TextReader reader, CancellationToken cancellationToken = default, long maxSizeBytes = DefaultMaxSizeBytes)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentOutOfRangeException.ThrowIfNegative(maxSizeBytes);
        return ParseAsync(reader, maxSizeBytes, cancellationToken);
    }

    private static async Task<HashBlocklist> ParseAsync(TextReader reader, long maxChars, CancellationToken cancellationToken)
    {
        var state = new ParseState();
        var chunk = new char[ReadChunkChars];
        var line = new char[MaxLineLength];
        int lineLength = 0;
        bool lineTooLong = false;
        bool lineStarted = false;
        bool afterCarriageReturn = false;
        long totalChars = 0;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int read = await reader.ReadAsync(chunk.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            totalChars += read;
            if (totalChars > maxChars)
            {
                throw TooLarge(maxChars);
            }

            for (int i = 0; i < read; i++)
            {
                char c = chunk[i];
                if (afterCarriageReturn)
                {
                    afterCarriageReturn = false;
                    if (c == '\n')
                    {
                        continue; // second half of CRLF (possibly split across chunks)
                    }
                }

                if (c is '\r' or '\n')
                {
                    state.ProcessLine(line.AsSpan(0, lineLength), lineTooLong);
                    lineLength = 0;
                    lineTooLong = false;
                    lineStarted = false;
                    afterCarriageReturn = c == '\r';
                    continue;
                }

                lineStarted = true;
                if (lineLength < MaxLineLength)
                {
                    line[lineLength++] = c;
                }
                else
                {
                    lineTooLong = true; // drop the rest of the line; never build a huge string
                }
            }
        }

        if (lineStarted)
        {
            state.ProcessLine(line.AsSpan(0, lineLength), lineTooLong); // last line without a newline
        }

        return new HashBlocklist(
            state.Hashes.ToFrozenSet(StringComparer.Ordinal),
            state.Errors.AsReadOnly(),
            state.TotalErrors,
            state.Duplicates);
    }

    private sealed class ParseState
    {
        public HashSet<string> Hashes { get; } = new(StringComparer.Ordinal);
        public List<BlocklistLineError> Errors { get; } = [];
        public int TotalErrors { get; private set; }
        public int Duplicates { get; private set; }
        private int _lineNumber;

        public void ProcessLine(ReadOnlySpan<char> text, bool tooLong)
        {
            _lineNumber++;

            if (_lineNumber == 1 && text.StartsWith(ByteOrderMark))
            {
                text = text[1..]; // BOM left in place by a non-detecting TextReader
            }

            text = text.Trim();
            if (text.IsEmpty && !tooLong)
            {
                return;
            }

            if (!text.IsEmpty && text[0] == '#')
            {
                return; // comment, however long
            }

            if (tooLong)
            {
                AddError($"Line is longer than {MaxLineLength} characters.");
                return;
            }

            if (!Sha256Hex.TryNormalize(text, out var normalized))
            {
                AddError(text.Length != Sha256Hex.Length
                    ? $"Expected {Sha256Hex.Length} hex characters, found {text.Length} characters."
                    : "Contains characters that are not hexadecimal.");
                return;
            }

            if (!Hashes.Add(normalized))
            {
                Duplicates++;
            }
        }

        private void AddError(string reason)
        {
            TotalErrors++;
            if (Errors.Count < MaxReportedErrors)
            {
                Errors.Add(new BlocklistLineError(_lineNumber, reason));
            }
        }
    }

    private static string ComputeFingerprint(FrozenSet<string> hashes)
    {
        var sorted = hashes.ToArray();
        Array.Sort(sorted, StringComparer.Ordinal);

        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> line = stackalloc byte[Sha256Hex.Length + 1];
        line[^1] = (byte)'\n';
        foreach (var hash in sorted)
        {
            Encoding.ASCII.GetBytes(hash, line);
            sha.AppendData(line);
        }

        return Convert.ToHexStringLower(sha.GetHashAndReset());
    }

    private static InvalidDataException TooLarge(long max) =>
        new($"Blocklist is larger than the maximum of {max} bytes.");

    /// <summary>Read-only pass-through stream that throws once more than the limit has been read.</summary>
    private sealed class SizeLimitedReadStream(Stream inner, long maxBytes) : Stream
    {
        private long _total;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => Count(inner.Read(buffer, offset, count));

        public override int Read(Span<byte> buffer) => Count(inner.Read(buffer));

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            Count(await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false));

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        private int Count(int read)
        {
            _total += read;
            return _total > maxBytes ? throw TooLarge(maxBytes) : read;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
