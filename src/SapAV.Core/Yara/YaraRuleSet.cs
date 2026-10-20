using System.Collections.Frozen;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using SapAV.Core.Mitre;
using SapAV.Core.Models;

namespace SapAV.Core.Yara;

/// <summary>
/// A compiled, immutable set of YARA rules. Thread-safe: any number of threads can scan with one instance
/// at the same time. Owns native memory, so dispose it when it is no longer used.
/// </summary>
/// <remarks>
/// <para>
/// <b>Loading.</b> <see cref="LoadDirectory"/> reads every <c>*.yar</c> file under the directory, recursively
/// (so E2's <c>third-party/</c> subfolder is included), in ordinal path order, skipping hidden/system files
/// and reparse points (a junction can't pull in rules from elsewhere). Each file is first compiled on its own;
/// a file that can't be read or doesn't compile is skipped and listed in <see cref="FileErrors"/>, and never
/// breaks the rest. The files that compiled are then compiled together into one rule set, each in its own
/// YARA namespace (its relative path), so rule names may repeat across files. <c>include</c> is disabled.
/// </para>
/// <para>
/// <b>Meta.</b> Each rule's <c>verdict</c> / <c>mitre</c> / <c>description</c> meta is read once at load
/// (see <see cref="YaraRuleInfo"/>). When the lenient MITRE parser changes a <c>mitre</c> value (drops a
/// token, or falls back to T1204.002 because nothing is valid), a <see cref="YaraWarningKind.Mitre"/> warning
/// names the rule and the raw value. Trim/upper-case only, or no <c>mitre</c> meta at all (the documented
/// default T1204.002, ROADMAP X1), give no warning. Core has no logger: the engine logs <see cref="Warnings"/>.
/// </para>
/// <para>
/// <b>Reloading.</b> Load a new instance, swap the reference (e.g. <see cref="YaraScanner.SwapRules"/>), then
/// dispose the old one. Disposing while scans are running is safe: the native rules are freed only after
/// the last running scan finishes; scans that start after disposal return
/// <see cref="YaraFailureReason.RulesDisposed"/>.
/// </para>
/// </remarks>
public sealed unsafe class YaraRuleSet : IDisposable
{
    /// <summary>The rules folder, relative to the application's data root.</summary>
    public const string DefaultRelativeDirectory = @"data\rules";

    /// <summary>Rule files must have this extension (case-insensitive).</summary>
    public const string RuleFileExtension = ".yar";

    /// <summary>Default maximum size of one rule file: 16 MiB.</summary>
    public const long DefaultMaxRuleFileBytes = 16L * 1024 * 1024;

    private const string FingerprintVersion = "sapav-yara-rules-v1\n";

    private readonly RulesHandle _handle;
    private readonly FrozenDictionary<IntPtr, YaraRuleInfo> _rulesByPointer;
    private int _disposed;

    private YaraRuleSet(
        RulesHandle handle,
        FrozenDictionary<IntPtr, YaraRuleInfo> rulesByPointer,
        IReadOnlyList<YaraRuleInfo> rules,
        IReadOnlyList<string> loadedFiles,
        IReadOnlyList<YaraRuleFileError> fileErrors,
        IReadOnlyList<YaraRuleWarning> warnings,
        string fingerprint)
    {
        _handle = handle;
        _rulesByPointer = rulesByPointer;
        Rules = rules;
        LoadedFiles = loadedFiles;
        FileErrors = fileErrors;
        Warnings = warnings;
        Fingerprint = fingerprint;
    }

    /// <summary>All non-private rules, in compile order.</summary>
    public IReadOnlyList<YaraRuleInfo> Rules { get; }

    /// <summary>Rule files (relative paths / source names) that compiled and are part of this set.</summary>
    public IReadOnlyList<string> LoadedFiles { get; }

    /// <summary>Rule files that were skipped, with the reason.</summary>
    public IReadOnlyList<YaraRuleFileError> FileErrors { get; }

    /// <summary>Meta and compiler warnings for loaded rules (see <see cref="YaraWarningKind"/>).</summary>
    public IReadOnlyList<YaraRuleWarning> Warnings { get; }

    /// <summary>
    /// Lowercase hex SHA-256 over the sorted list of loaded files (relative path + SHA-256 of the content).
    /// It changes exactly when the compiled rules can change (a file added, removed, edited, or starting or
    /// stopping to compile), so the scan cache (C5) can tell whether a re-scan is needed.
    /// </summary>
    public string Fingerprint { get; }

    public bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    /// <summary>Test seam: runs inside a scan, after the rules are referenced and right before libyara runs.</summary>
    internal Action? BeforeNativeScanHook { get; set; }

    /// <summary>True once the native rules have actually been freed (after disposal and the last running scan).</summary>
    internal bool IsNativeReleased => _handle.Released;

    /// <summary>Loads and compiles every <c>*.yar</c> file under <paramref name="directory"/> (recursive).</summary>
    /// <exception cref="DirectoryNotFoundException">The directory doesn't exist.</exception>
    /// <exception cref="DllNotFoundException">libyara.dll is missing.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    public static YaraRuleSet LoadDirectory(
        string directory, CancellationToken cancellationToken = default, long maxRuleFileBytes = DefaultMaxRuleFileBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentOutOfRangeException.ThrowIfNegative(maxRuleFileBytes);

        var root = Path.GetFullPath(directory);
        if (!Directory.Exists(root))
        {
            throw new DirectoryNotFoundException($"YARA rules directory not found: {root}");
        }

        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            AttributesToSkip = FileAttributes.Hidden | FileAttributes.System | FileAttributes.ReparsePoint,
            IgnoreInaccessible = true,
            MatchType = MatchType.Simple,
        };

        var files = Directory.EnumerateFiles(root, "*" + RuleFileExtension, options)
            .Where(f => Path.GetExtension(f).Equals(RuleFileExtension, StringComparison.OrdinalIgnoreCase))
            .Select(f => (Full: f, Name: Path.GetRelativePath(root, f).Replace('\\', '/')))
            .OrderBy(f => f.Name, StringComparer.Ordinal)
            .ToArray();

        var sources = new List<PreparedSource>();
        var errors = new List<YaraRuleFileError>();
        foreach (var (full, name) in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                byte[] bytes = ReadRuleFile(full, maxRuleFileBytes);
                if (PreparedSource.TryCreate(name, bytes, out var prepared, out var why))
                {
                    sources.Add(prepared);
                }
                else
                {
                    errors.Add(new YaraRuleFileError(name, [why]));
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                errors.Add(new YaraRuleFileError(name, [$"Could not read the file: {ex.Message}"]));
            }
        }

        return Build(sources, errors, cancellationToken);
    }

    /// <summary>Compiles rule text from memory (tests, generated rules). Same rules as <see cref="LoadDirectory"/>.</summary>
    /// <exception cref="ArgumentException">A name is blank or used twice (case-insensitive).</exception>
    public static YaraRuleSet FromSources(IEnumerable<YaraRuleSource> sources, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(sources);
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var prepared = new List<PreparedSource>();
        var errors = new List<YaraRuleFileError>();
        foreach (var source in sources)
        {
            ArgumentNullException.ThrowIfNull(source);
            ArgumentException.ThrowIfNullOrWhiteSpace(source.Name, nameof(sources));
            ArgumentNullException.ThrowIfNull(source.Text, nameof(sources));
            if (!names.Add(source.Name))
            {
                throw new ArgumentException($"Duplicate rule source name '{source.Name}'.", nameof(sources));
            }

            if (PreparedSource.TryCreate(source.Name, Encoding.UTF8.GetBytes(source.Text), out var p, out var why))
            {
                prepared.Add(p);
            }
            else
            {
                errors.Add(new YaraRuleFileError(source.Name, [why]));
            }
        }

        return Build(prepared, errors, cancellationToken);
    }

    /// <summary>Compiles a single rule text (convenience for tests).</summary>
    public static YaraRuleSet FromSource(string name, string text) => FromSources([new YaraRuleSource(name, text)]);

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _handle.Dispose(); // frees the native rules now, or when the last running scan releases its reference
        }
    }

    /// <summary>
    /// Scans <paramref name="length"/> bytes at <paramref name="data"/>. Never throws for libyara errors;
    /// returns <see cref="YaraFailureReason.RulesDisposed"/> if this set was disposed before the scan started.
    /// </summary>
    internal YaraScanResult ScanMemory(byte* data, long length, int timeoutSeconds)
    {
        bool added = false;
        try
        {
            if (IsDisposed)
            {
                return YaraScanResult.NotScanned(YaraFailureReason.RulesDisposed, "The rule set was disposed.", length);
            }

            _handle.DangerousAddRef(ref added);
        }
        catch (ObjectDisposedException)
        {
            return YaraScanResult.NotScanned(YaraFailureReason.RulesDisposed, "The rule set was disposed.", length);
        }

        try
        {
            BeforeNativeScanHook?.Invoke();

            byte empty = 0;
            var state = new ScanState(_rulesByPointer);
            var stateHandle = GCHandle.Alloc(state);
            int error;
            try
            {
                error = LibYara.yr_rules_scan_mem(
                    _handle.DangerousGetHandle(),
                    data is null || length == 0 ? &empty : data,
                    (nuint)length,
                    LibYara.ScanFlagsFastMode | LibYara.ScanFlagsReportRulesMatching,
                    &OnScanCallback,
                    GCHandle.ToIntPtr(stateHandle),
                    timeoutSeconds);
            }
            finally
            {
                stateHandle.Free();
            }

            if (state.CallbackFailure is { } failure)
            {
                return YaraScanResult.NotScanned(YaraFailureReason.EngineError,
                    $"Scan callback failed: {failure.GetType().Name}: {failure.Message}", length, Fingerprint);
            }

            return error switch
            {
                LibYara.ErrorSuccess => YaraScanResult.Scanned(state.Matches.AsReadOnly(), length, Fingerprint),
                LibYara.ErrorScanTimeout => YaraScanResult.NotScanned(YaraFailureReason.Timeout,
                    $"YARA scan timed out after {timeoutSeconds} s.", length, Fingerprint),
                LibYara.ErrorCouldNotMapFile => YaraScanResult.NotScanned(YaraFailureReason.IoError,
                    "Memory could not be read during the YARA scan (e.g. a page of the mapped file failed to load).",
                    length, Fingerprint),
                _ => YaraScanResult.NotScanned(YaraFailureReason.EngineError,
                    $"yr_rules_scan_mem failed (YARA error {error}).", length, Fingerprint),
            };
        }
        finally
        {
            if (added)
            {
                _handle.DangerousRelease();
            }
        }
    }

    // --- Compilation ---

    private static YaraRuleSet Build(List<PreparedSource> sources, List<YaraRuleFileError> errors, CancellationToken cancellationToken)
    {
        LibYara.EnsureInitialized();

        // Pass 1: each source on its own, so one broken file can't take the others down.
        var valid = new List<PreparedSource>();
        foreach (var source in sources)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var log = new CompilerLog();
            IntPtr rules = Compile([source], log, out _);
            if (rules == IntPtr.Zero)
            {
                errors.Add(new YaraRuleFileError(source.Name, log.ErrorsOr("The YARA compiler rejected the file.")));
                continue;
            }

            LibYara.yr_rules_destroy(rules);
            valid.Add(source);
        }

        // Pass 2: everything that compiled, together (one scan per file instead of one per rule file).
        // Namespaces keep the files independent, so this should always succeed; if it doesn't, the
        // offending file is dropped and the rest compiled again.
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var log = new CompilerLog { RecordWarnings = true, Sources = valid };
            IntPtr rules = Compile(valid, log, out int failedIndex);
            if (rules != IntPtr.Zero)
            {
                return Create(new RulesHandle(rules), valid, errors, log.Warnings);
            }

            if (failedIndex < 0)
            {
                throw new InvalidOperationException(
                    "The YARA compiler failed to produce rules: " + string.Join("; ", log.ErrorsOr("unknown error")));
            }

            errors.Add(new YaraRuleFileError(valid[failedIndex].Name,
                log.ErrorsOr("The file did not compile together with the other rule files.")));
            valid.RemoveAt(failedIndex);
        }
    }

    /// <summary>Compiles <paramref name="sources"/> into one YR_RULES; returns zero (and the failing index) on error.</summary>
    private static IntPtr Compile(IReadOnlyList<PreparedSource> sources, CompilerLog log, out int failedIndex)
    {
        failedIndex = -1;
        int error = LibYara.yr_compiler_create(out IntPtr compiler);
        if (error != LibYara.ErrorSuccess)
        {
            log.Errors.Add($"yr_compiler_create failed (YARA error {error}).");
            return IntPtr.Zero;
        }

        var logHandle = GCHandle.Alloc(log);
        try
        {
            LibYara.yr_compiler_set_callback(compiler, &OnCompilerMessage, GCHandle.ToIntPtr(logHandle));
            LibYara.yr_compiler_set_include_callback(compiler, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

            for (int i = 0; i < sources.Count; i++)
            {
                log.CurrentIndex = i;
                fixed (byte* text = sources[i].Utf8Text)
                fixed (byte* ns = sources[i].Utf8Namespace)
                {
                    if (LibYara.yr_compiler_add_string(compiler, text, ns) > 0)
                    {
                        failedIndex = i; // the compiler can't be used after an error
                        return IntPtr.Zero;
                    }
                }
            }

            error = LibYara.yr_compiler_get_rules(compiler, out IntPtr rules);
            if (error != LibYara.ErrorSuccess || rules == IntPtr.Zero)
            {
                log.Errors.Add($"yr_compiler_get_rules failed (YARA error {error}).");
                return IntPtr.Zero;
            }

            return rules;
        }
        finally
        {
            LibYara.yr_compiler_destroy(compiler);
            logHandle.Free();
        }
    }

    private static YaraRuleSet Create(
        RulesHandle handle, List<PreparedSource> loaded, List<YaraRuleFileError> errors, List<YaraRuleWarning> warnings)
    {
        var byPointer = new Dictionary<IntPtr, YaraRuleInfo>();
        var rules = new List<YaraRuleInfo>();
        try
        {
            var yrRules = (LibYara.YrRules*)handle.DangerousGetHandle();
            for (var rule = yrRules->RulesTable; (rule->Flags & LibYara.RuleFlagsNull) == 0; rule++)
            {
                if ((rule->Flags & LibYara.RuleFlagsPrivate) != 0)
                {
                    continue; // private rules are never reported
                }

                var info = ReadRule(rule, warnings);
                byPointer[(IntPtr)rule] = info;
                rules.Add(info);
            }
        }
        catch
        {
            handle.Dispose();
            throw;
        }

        return new YaraRuleSet(
            handle,
            byPointer.ToFrozenDictionary(),
            rules.AsReadOnly(),
            loaded.Select(s => s.Name).ToArray(),
            errors.OrderBy(e => e.File, StringComparer.Ordinal).ToArray(),
            warnings.AsReadOnly(),
            ComputeFingerprint(loaded));
    }

    private static YaraRuleInfo ReadRule(LibYara.YrRule* rule, List<YaraRuleWarning> warnings)
    {
        string identifier = LibYara.Utf8(rule->Identifier) ?? "(unnamed)";
        string file = rule->Namespace is null ? "" : LibYara.Utf8(rule->Namespace->Name) ?? "";

        var tags = new List<string>();
        // Tags: consecutive NUL-terminated strings, ended by an empty one.
        for (byte* tag = rule->Tags; tag is not null && *tag != 0;)
        {
            var bytes = MemoryMarshal.CreateReadOnlySpanFromNullTerminated(tag);
            tags.Add(Encoding.UTF8.GetString(bytes));
            tag += bytes.Length + 1;
        }

        MetaValue? mitre = null, verdict = null, description = null;
        if (rule->Metas is not null)
        {
            for (var meta = rule->Metas; ; meta++)
            {
                var name = LibYara.Utf8(meta->Identifier);
                var value = new MetaValue(meta->Type, meta->Type == LibYara.MetaTypeString ? LibYara.Utf8(meta->String) : null, meta->Integer);
                if (string.Equals(name, "mitre", StringComparison.OrdinalIgnoreCase))
                {
                    mitre ??= value;
                }
                else if (string.Equals(name, "verdict", StringComparison.OrdinalIgnoreCase))
                {
                    verdict ??= value;
                }
                else if (string.Equals(name, "description", StringComparison.OrdinalIgnoreCase))
                {
                    description ??= value;
                }

                if ((meta->Flags & LibYara.MetaFlagsLastInRule) != 0)
                {
                    break;
                }
            }
        }

        return new YaraRuleInfo(
            file,
            identifier,
            tags.AsReadOnly(),
            InterpretVerdict(file, identifier, verdict, warnings),
            InterpretMitre(file, identifier, mitre, warnings),
            description?.Text);
    }

    internal static MitreTechniqueSelection InterpretMitre(string file, string rule, MetaValue? meta, List<YaraRuleWarning> warnings)
    {
        const string Fallback = MitreTechniqueIds.MaliciousFile;
        if (meta is null)
        {
            return MitreTechniqueIdFormat.SelectOrDefault(null, Fallback); // documented default, no warning
        }

        string raw = meta.Value.Display;
        if (meta.Value.Text is not { } text)
        {
            warnings.Add(new YaraRuleWarning(file, rule, YaraWarningKind.Mitre, raw,
                $"YARA rule {rule} ({file}): mitre meta {raw} is not a string; using fallback {Fallback}."));
            return MitreTechniqueIdFormat.SelectOrDefault(null, Fallback);
        }

        var selection = MitreTechniqueIdFormat.SelectOrDefault(text, Fallback);
        if (!MitreTechniqueIdFormat.TryNormalize(text, out _))
        {
            warnings.Add(new YaraRuleWarning(file, rule, YaraWarningKind.Mitre, text,
                $"YARA rule {rule} ({file}): mitre meta \"{text}\" has no valid technique ID; using fallback {Fallback}."));
        }
        else if (MitreTechniqueIdFormat.InvalidTokens(text) is { Count: > 0 } dropped)
        {
            var used = string.Join(", ", new[] { selection.PrimaryId }.Concat(selection.SecondaryIds));
            warnings.Add(new YaraRuleWarning(file, rule, YaraWarningKind.Mitre, text,
                $"YARA rule {rule} ({file}): mitre meta \"{text}\" contains invalid token(s) " +
                $"{string.Join(", ", dropped.Select(t => $"\"{t}\""))}, which were dropped; using {used}."));
        }

        return selection;
    }

    internal static Verdict InterpretVerdict(string file, string rule, MetaValue? meta, List<YaraRuleWarning> warnings)
    {
        if (meta is null)
        {
            return Verdict.Malicious;
        }

        switch (meta.Value.Text?.Trim().ToLowerInvariant())
        {
            case "malicious":
                return Verdict.Malicious;
            case "suspicious" or "pup" or "hacktool":
                return Verdict.Suspicious;
            default:
                string raw = meta.Value.Display;
                warnings.Add(new YaraRuleWarning(file, rule, YaraWarningKind.Verdict, raw,
                    $"YARA rule {rule} ({file}): unknown verdict meta {raw}; using Suspicious."));
                return Verdict.Suspicious;
        }
    }

    private static string ComputeFingerprint(IEnumerable<PreparedSource> loaded)
    {
        var sb = new StringBuilder(FingerprintVersion);
        foreach (var source in loaded.OrderBy(s => s.Name, StringComparer.Ordinal))
        {
            sb.Append(source.Name).Append('\n').Append(source.ContentSha256).Append('\n');
        }

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString())));
    }

    private static byte[] ReadRuleFile(string path, long maxBytes)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        if (stream.Length > maxBytes)
        {
            throw new IOException($"The file is {stream.Length} bytes, over the {maxBytes}-byte limit for a rule file.");
        }

        var buffer = new byte[stream.Length];
        stream.ReadExactly(buffer);
        return buffer;
    }

    // --- Native callbacks ---

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int OnScanCallback(IntPtr context, int message, IntPtr messageData, IntPtr userData)
    {
        ScanState? state = null;
        try
        {
            state = (ScanState)GCHandle.FromIntPtr(userData).Target!;
            if (message == LibYara.CallbackMsgRuleMatching && state.RulesByPointer.TryGetValue(messageData, out var info))
            {
                state.Matches.Add(info);
            }

            return LibYara.CallbackContinue;
        }
        catch (Exception ex)
        {
            // Never let an exception cross into native code.
            if (state is not null)
            {
                state.CallbackFailure = ex;
            }

            return LibYara.CallbackError;
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnCompilerMessage(int errorLevel, byte* fileName, int lineNumber, LibYara.YrRule* rule, byte* message, IntPtr userData)
    {
        try
        {
            var log = (CompilerLog)GCHandle.FromIntPtr(userData).Target!;
            string text = $"line {lineNumber}: {LibYara.Utf8(message)}";
            if (errorLevel == LibYara.CompilerErrorLevelError)
            {
                log.Errors.Add(text);
            }
            else if (log.RecordWarnings && log.Sources is { } sources && log.CurrentIndex >= 0 && log.CurrentIndex < sources.Count)
            {
                string? ruleName = rule is null ? null : LibYara.Utf8(rule->Identifier);
                string file = sources[log.CurrentIndex].Name;
                log.Warnings.Add(new YaraRuleWarning(file, ruleName, YaraWarningKind.Compiler, null,
                    $"YARA compiler warning in {file}{(ruleName is null ? "" : $", rule {ruleName}")}: {text}"));
            }
        }
        catch
        {
            // Never let an exception cross into native code; a lost message is better than a crash.
        }
    }

    // --- Helper types ---

    internal readonly record struct MetaValue(int Type, string? Text, long Integer)
    {
        public string Display => Type switch
        {
            LibYara.MetaTypeString => $"\"{Text}\"",
            LibYara.MetaTypeBoolean => Integer != 0 ? "true" : "false",
            _ => Integer.ToString(System.Globalization.CultureInfo.InvariantCulture),
        };
    }

    private sealed class ScanState(FrozenDictionary<IntPtr, YaraRuleInfo> rulesByPointer)
    {
        public FrozenDictionary<IntPtr, YaraRuleInfo> RulesByPointer { get; } = rulesByPointer;
        public List<YaraRuleInfo> Matches { get; } = [];
        public Exception? CallbackFailure { get; set; }
    }

    private sealed class CompilerLog
    {
        public List<string> Errors { get; } = [];
        public List<YaraRuleWarning> Warnings { get; } = [];
        public bool RecordWarnings { get; init; }
        public IReadOnlyList<PreparedSource>? Sources { get; init; }
        public int CurrentIndex { get; set; } = -1;

        public IReadOnlyList<string> ErrorsOr(string fallback) => Errors.Count > 0 ? Errors.ToArray() : [fallback];
    }

    private sealed class PreparedSource
    {
        private PreparedSource(string name, byte[] utf8Text, string contentSha256)
        {
            Name = name;
            Utf8Text = utf8Text;
            Utf8Namespace = NulTerminated(Encoding.UTF8.GetBytes(name));
            ContentSha256 = contentSha256;
        }

        public string Name { get; }
        public byte[] Utf8Text { get; }      // NUL-terminated
        public byte[] Utf8Namespace { get; } // NUL-terminated
        public string ContentSha256 { get; }

        public static bool TryCreate(string name, byte[] content, out PreparedSource source, out string error)
        {
            ReadOnlySpan<byte> text = content;
            if (text.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]))
            {
                text = text[3..]; // UTF-8 BOM: libyara's lexer would see it as a syntax error
            }

            if (text.Contains((byte)0))
            {
                source = null!;
                error = "The file contains a NUL byte (not a text rule file).";
                return false;
            }

            source = new PreparedSource(name, NulTerminated(text), Convert.ToHexStringLower(SHA256.HashData(text)));
            error = string.Empty;
            return true;
        }

        private static byte[] NulTerminated(ReadOnlySpan<byte> bytes)
        {
            var result = new byte[bytes.Length + 1];
            bytes.CopyTo(result);
            return result;
        }
    }

    /// <summary>Owns the native YR_RULES; reference counting keeps it alive while scans run.</summary>
    private sealed class RulesHandle : SafeHandle
    {
        public RulesHandle(IntPtr rules)
            : base(IntPtr.Zero, ownsHandle: true) => SetHandle(rules);

        public bool Released { get; private set; }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            Released = true;
            return LibYara.yr_rules_destroy(handle) == LibYara.ErrorSuccess;
        }
    }
}
