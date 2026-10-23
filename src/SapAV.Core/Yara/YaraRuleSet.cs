using System.Collections.Frozen;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SapAV.Core.Mitre;
using SapAV.Core.Models;

namespace SapAV.Core.Yara;

/// <summary>
/// A compiled, immutable set of YARA rules (YARA-X engine). Thread-safe: any number of threads can scan with
/// one instance at the same time (each scan gets its own YARA-X scanner). Owns native memory: dispose it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Loading.</b> <see cref="LoadDirectory"/> reads every <c>*.yar</c> file under the directory, recursively
/// (so E2's <c>third-party/</c> subfolder is included), in ordinal path order, skipping hidden/system files
/// and reparse points (a junction can't pull in rules from elsewhere). Each file is first compiled on its own;
/// a file that can't be read, doesn't compile, or imports a module outside <see cref="AllowedModules"/> is
/// skipped and listed in <see cref="FileErrors"/>, and never breaks the rest. The files that passed are then
/// compiled together, each in its own namespace (its relative path), so rule names may repeat across files.
/// <c>include</c> is disabled (<c>YRX_DISABLE_INCLUDES</c>); rules have no other file access.
/// </para>
/// <para>
/// <b>Module allowlist.</b> The imports are taken from the <i>compiled</i> rules (<c>yrx_rules_iter_imports</c>),
/// never from the text, so an <c>import</c> inside a comment or string can't fool it, and every real import is
/// seen. A file importing any other module (e.g. <c>console</c>, <c>cuckoo</c>, <c>magic</c>, <c>dotnet</c>) is rejected.
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
/// the last running scan finishes (and its scanner is destroyed); scans that start after disposal return
/// <see cref="YaraFailureReason.RulesDisposed"/>.
/// </para>
/// </remarks>
public sealed unsafe partial class YaraRuleSet : IDisposable
{
    /// <summary>The rules folder, relative to the application's data root.</summary>
    public const string DefaultRelativeDirectory = @"data\rules";

    /// <summary>Rule files must have this extension (case-insensitive).</summary>
    public const string RuleFileExtension = ".yar";

    /// <summary>Default maximum size of one rule file: 16 MiB.</summary>
    public const long DefaultMaxRuleFileBytes = 16L * 1024 * 1024;

    /// <summary>
    /// Modules rules may import. <c>pe</c> (PE structure), <c>math</c> (entropy etc.) and <c>hash</c> are pure
    /// functions of the scanned bytes. Everything else is refused: <c>console</c> writes output, and parsers we
    /// don't need (dotnet, elf, macho, lnk, ...) only add attack surface.
    /// </summary>
    public static readonly FrozenSet<string> AllowedModules = new[] { "pe", "math", "hash" }.ToFrozenSet(StringComparer.Ordinal);

    private const string FingerprintVersion = "sapav-yarax-rules-v1\n";

    private readonly RulesHandle _handle;
    private readonly FrozenDictionary<(string Namespace, string Identifier), (int Index, YaraRuleInfo Info)> _rulesByName;
    private int _disposed;

    private YaraRuleSet(
        RulesHandle handle,
        FrozenDictionary<(string, string), (int, YaraRuleInfo)> rulesByName,
        IReadOnlyList<YaraRuleInfo> rules,
        IReadOnlyList<string> loadedFiles,
        IReadOnlyList<YaraRuleFileError> fileErrors,
        IReadOnlyList<YaraRuleWarning> warnings,
        string fingerprint)
    {
        _handle = handle;
        _rulesByName = rulesByName;
        Rules = rules;
        LoadedFiles = loadedFiles;
        FileErrors = fileErrors;
        Warnings = warnings;
        Fingerprint = fingerprint;
    }

    /// <summary>All rules the engine reports, in compile order.</summary>
    public IReadOnlyList<YaraRuleInfo> Rules { get; }

    /// <summary>Rule files (relative paths / source names) that compiled and are part of this set.</summary>
    public IReadOnlyList<string> LoadedFiles { get; }

    /// <summary>Rule files that were skipped, with the reason.</summary>
    public IReadOnlyList<YaraRuleFileError> FileErrors { get; }

    /// <summary>Meta and compiler warnings for loaded rules (see <see cref="YaraWarningKind"/>).</summary>
    public IReadOnlyList<YaraRuleWarning> Warnings { get; }

    /// <summary>
    /// Lowercase hex SHA-256 over the engine generation and the sorted list of loaded files (relative path +
    /// SHA-256 of the content). It changes exactly when the compiled rules can change (a file added, removed,
    /// edited, starting or stopping to compile, or a different engine), so the scan cache (C5) can tell whether
    /// a re-scan is needed.
    /// </summary>
    public string Fingerprint { get; }

    public bool IsDisposed => Volatile.Read(ref _disposed) != 0;

    /// <summary>Test seam: runs inside a scan, after the rules are referenced and right before YARA-X runs.</summary>
    internal Action? BeforeNativeScanHook { get; set; }

    /// <summary>True once the native rules have actually been freed (after disposal and the last running scan).</summary>
    internal bool IsNativeReleased => _handle.Released;

    /// <summary>Loads and compiles every <c>*.yar</c> file under <paramref name="directory"/> (recursive).</summary>
    /// <remarks>Rule problems never throw; they are reported in <see cref="FileErrors"/>.</remarks>
    /// <exception cref="DirectoryNotFoundException">The directory doesn't exist.</exception>
    /// <exception cref="DllNotFoundException">yara_x_capi.dll is missing.</exception>
    /// <exception cref="InvalidOperationException">The YARA-X engine itself failed (it could not create a
    /// compiler or scanner-independent object, e.g. out of memory). Not caused by rule content.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    public static YaraRuleSet LoadDirectory(
        string directory, CancellationToken cancellationToken = default, long maxRuleFileBytes = DefaultMaxRuleFileBytes)
    {
        var files = ReadDirectoryFiles(directory, out var readErrors, cancellationToken, maxRuleFileBytes);
        return FromFiles(files, readErrors, cancellationToken);
    }

    /// <summary>
    /// Reads (never compiles) every <c>*.yar</c> file under <paramref name="directory"/>, the same files and names
    /// <see cref="LoadDirectory"/> uses, sorted by name. Files that can't be read, or are over
    /// <paramref name="maxRuleFileBytes"/>, are reported in <paramref name="readErrors"/>. Used by the engine (B5),
    /// which reads the rule files and sends their bytes to the sandboxed worker that compiles them.
    /// </summary>
    /// <exception cref="DirectoryNotFoundException">The directory doesn't exist.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    public static IReadOnlyList<YaraRuleFile> ReadDirectoryFiles(
        string directory, out IReadOnlyList<YaraRuleFileError> readErrors, CancellationToken cancellationToken = default,
        long maxRuleFileBytes = DefaultMaxRuleFileBytes)
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

        var read = new List<YaraRuleFile>();
        var errors = new List<YaraRuleFileError>();
        foreach (var (full, name) in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                read.Add(new YaraRuleFile(name, ReadRuleFile(full, maxRuleFileBytes)));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                errors.Add(new YaraRuleFileError(name, [$"Could not read the file: {ex.Message}"]));
            }
        }

        readErrors = errors.AsReadOnly();
        return read.AsReadOnly();
    }

    /// <summary>
    /// Compiles rule files that were already read (<see cref="ReadDirectoryFiles"/>, or bytes the engine sent to the
    /// sandboxed worker). Content checks (UTF-8, no NUL), compilation and the module allowlist are exactly those of
    /// <see cref="LoadDirectory"/>; <paramref name="readErrors"/> are carried into <see cref="FileErrors"/>.
    /// </summary>
    /// <exception cref="ArgumentException">A name is blank or used twice (case-insensitive).</exception>
    /// <exception cref="InvalidOperationException">The YARA-X engine itself failed (see <see cref="LoadDirectory"/>).</exception>
    public static YaraRuleSet FromFiles(
        IEnumerable<YaraRuleFile> files, IEnumerable<YaraRuleFileError>? readErrors = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(files);
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var sources = new List<PreparedSource>();
        var errors = new List<YaraRuleFileError>(readErrors ?? []);
        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(file);
            ArgumentException.ThrowIfNullOrWhiteSpace(file.Name, nameof(files));
            ArgumentNullException.ThrowIfNull(file.Content, nameof(files));
            if (!names.Add(file.Name))
            {
                throw new ArgumentException($"Duplicate rule file name '{file.Name}'.", nameof(files));
            }

            if (PreparedSource.TryCreate(file.Name, file.Content, out var prepared, out var why))
            {
                sources.Add(prepared);
            }
            else
            {
                errors.Add(new YaraRuleFileError(file.Name, [why]));
            }
        }

        return Build(sources, errors, cancellationToken);
    }

    /// <summary>Compiles rule text from memory (tests, generated rules). Same rules as <see cref="LoadDirectory"/>.</summary>
    /// <exception cref="ArgumentException">A name is blank or used twice (case-insensitive).</exception>
    /// <exception cref="InvalidOperationException">The YARA-X engine itself failed (see <see cref="LoadDirectory"/>).</exception>
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
    /// Scans <paramref name="length"/> bytes at <paramref name="data"/> with a scanner of its own. Never throws
    /// for engine errors; returns <see cref="YaraFailureReason.RulesDisposed"/> if this set was disposed first.
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

        IntPtr scanner = IntPtr.Zero;
        try
        {
            BeforeNativeScanHook?.Invoke();

            if (YaraXNative.yrx_scanner_create(_handle.DangerousGetHandle(), out scanner) != YaraXNative.Success)
            {
                return YaraScanResult.NotScanned(YaraFailureReason.EngineError,
                    $"yrx_scanner_create failed: {YaraXNative.LastError()}", length, Fingerprint);
            }

            YaraXNative.yrx_scanner_fast_scan(scanner, true);
            if (timeoutSeconds > 0)
            {
                YaraXNative.yrx_scanner_set_timeout(scanner, (ulong)timeoutSeconds);
            }

            var state = new ScanState(_rulesByName);
            var stateHandle = GCHandle.Alloc(state);
            int result;
            try
            {
                YaraXNative.yrx_scanner_on_matching_rule(scanner, &OnMatchingRule, GCHandle.ToIntPtr(stateHandle));
                result = YaraXNative.yrx_scanner_scan(scanner, length == 0 ? null : data, (nuint)length);
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

            return result switch
            {
                YaraXNative.Success => YaraScanResult.Scanned(
                    state.Matches.OrderBy(m => m.Index).Select(m => m.Info).ToArray(), length, Fingerprint),
                YaraXNative.ScanTimeout => YaraScanResult.NotScanned(YaraFailureReason.Timeout,
                    $"YARA scan timed out after {timeoutSeconds} s.", length, Fingerprint),
                _ => YaraScanResult.NotScanned(YaraFailureReason.EngineError,
                    $"yrx_scanner_scan failed ({result}): {YaraXNative.LastError()}", length, Fingerprint),
            };
        }
        finally
        {
            if (scanner != IntPtr.Zero)
            {
                YaraXNative.yrx_scanner_destroy(scanner); // always before the rules can be released
            }

            if (added)
            {
                _handle.DangerousRelease();
            }
        }
    }

    // --- Compilation ---

    private static YaraRuleSet Build(List<PreparedSource> sources, List<YaraRuleFileError> errors, CancellationToken cancellationToken)
    {
        YaraXNative.EnsureAvailable();

        // Pass 1: each source on its own (syntax, semantics, module allowlist), so one bad file can't take the others down.
        var valid = new List<PreparedSource>();
        foreach (var source in sources)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var problems = CompileAlone(source);
            if (problems.Count > 0)
            {
                errors.Add(new YaraRuleFileError(source.Name, problems));
            }
            else
            {
                valid.Add(source);
            }
        }

        // Pass 2: everything that passed, together, one namespace per file. A source that still fails here is
        // dropped and reported; YARA-X keeps compiling the others, and build always produces a rule set.
        cancellationToken.ThrowIfCancellationRequested();
        var warnings = new List<YaraRuleWarning>();
        var loaded = new List<PreparedSource>();
        IntPtr compiler = CreateCompiler();
        IntPtr rules;
        try
        {
            foreach (var source in valid)
            {
                if (AddSource(compiler, source) is { Count: > 0 } late)
                {
                    errors.Add(new YaraRuleFileError(source.Name, late));
                }
                else
                {
                    loaded.Add(source);
                }
            }

            CollectCompilerWarnings(compiler, loaded, warnings);
            rules = YaraXNative.yrx_compiler_build(compiler);
        }
        finally
        {
            YaraXNative.yrx_compiler_destroy(compiler);
        }

        if (rules == IntPtr.Zero)
        {
            throw new InvalidOperationException($"yrx_compiler_build failed: {YaraXNative.LastError()}");
        }

        var handle = new RulesHandle(rules);
        try
        {
            // Defence in depth: the combined set must import nothing outside the allowlist either.
            if (DisallowedImports(rules) is { Count: > 0 } bad)
            {
                throw new InvalidOperationException($"Combined rules import disallowed modules: {string.Join(", ", bad)}");
            }

            return Create(handle, loaded, errors, warnings);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    /// <summary>Compiles one source alone; returns its problems (empty if it is fine).</summary>
    private static IReadOnlyList<string> CompileAlone(PreparedSource source)
    {
        IntPtr compiler = CreateCompiler();
        IntPtr rules = IntPtr.Zero;
        try
        {
            if (AddSource(compiler, source) is { Count: > 0 } problems)
            {
                return problems;
            }

            rules = YaraXNative.yrx_compiler_build(compiler);
            if (rules == IntPtr.Zero)
            {
                return [$"yrx_compiler_build failed: {YaraXNative.LastError()}"];
            }

            var bad = DisallowedImports(rules);
            return bad.Count == 0
                ? []
                : bad.Select(m => $"imports module \"{m}\", which is not allowed (allowed: {string.Join(", ", AllowedModules.Order())})").ToArray();
        }
        finally
        {
            if (rules != IntPtr.Zero)
            {
                YaraXNative.yrx_rules_destroy(rules);
            }

            YaraXNative.yrx_compiler_destroy(compiler);
        }
    }

    private static IntPtr CreateCompiler()
    {
        if (YaraXNative.yrx_compiler_create(YaraXNative.DisableIncludes, out IntPtr compiler) != YaraXNative.Success || compiler == IntPtr.Zero)
        {
            throw new InvalidOperationException($"yrx_compiler_create failed: {YaraXNative.LastError()}");
        }

        return compiler;
    }

    /// <summary>Adds <paramref name="source"/> in its own namespace; returns the errors it caused (empty on success).</summary>
    private static IReadOnlyList<string> AddSource(IntPtr compiler, PreparedSource source)
    {
        int result;
        fixed (byte* ns = source.Utf8Namespace)
        fixed (byte* text = source.Utf8Text)
        {
            if (YaraXNative.yrx_compiler_new_namespace(compiler, ns) != YaraXNative.Success)
            {
                return [$"Could not create namespace: {YaraXNative.LastError()}"];
            }

            result = YaraXNative.yrx_compiler_add_source_with_origin(compiler, text, ns);
        }

        if (result == YaraXNative.Success)
        {
            return [];
        }

        string fallback = YaraXNative.LastError();
        if (YaraXNative.yrx_compiler_errors_json(compiler, out var buffer) != YaraXNative.Success)
        {
            return [fallback];
        }

        var messages = ParseReports(YaraXNative.TakeBuffer(buffer))
            .Where(r => r.Origin is null || r.Origin == source.Name)
            .Select(r => r.Line is { } line ? $"line {line}: {r.Title}" : r.Title)
            .ToArray();
        return messages.Length > 0 ? messages : [fallback];
    }

    private static void CollectCompilerWarnings(IntPtr compiler, List<PreparedSource> loaded, List<YaraRuleWarning> warnings)
    {
        if (YaraXNative.yrx_compiler_warnings_json(compiler, out var buffer) != YaraXNative.Success)
        {
            return;
        }

        var names = loaded.Select(s => s.Name).ToHashSet(StringComparer.Ordinal);
        foreach (var report in ParseReports(YaraXNative.TakeBuffer(buffer)))
        {
            string file = report.Origin is { } o && names.Contains(o) ? o : "";
            string where = report.Line is { } line ? $"line {line}: " : "";
            warnings.Add(new YaraRuleWarning(file, null, YaraWarningKind.Compiler, null,
                $"YARA compiler warning in {(file.Length > 0 ? file : "rules")}: {where}{report.Title} ({report.Code})"));
        }
    }

    private static List<string> DisallowedImports(IntPtr rules)
    {
        var imports = new List<string>();
        var handle = GCHandle.Alloc(imports);
        try
        {
            YaraXNative.yrx_rules_iter_imports(rules, &OnImport, GCHandle.ToIntPtr(handle));
        }
        finally
        {
            handle.Free();
        }

        return imports.Where(m => !AllowedModules.Contains(m)).Distinct(StringComparer.Ordinal).ToList();
    }

    private static YaraRuleSet Create(
        RulesHandle handle, List<PreparedSource> loaded, List<YaraRuleFileError> errors, List<YaraRuleWarning> warnings)
    {
        var collected = new RuleCollector(warnings);
        var gch = GCHandle.Alloc(collected);
        try
        {
            YaraXNative.yrx_rules_iter(handle.DangerousGetHandle(), &OnRule, GCHandle.ToIntPtr(gch));
        }
        finally
        {
            gch.Free();
        }

        if (collected.Failure is { } failure)
        {
            throw new InvalidOperationException("Reading the compiled rules failed.", failure);
        }

        var byName = new Dictionary<(string, string), (int, YaraRuleInfo)>();
        for (int i = 0; i < collected.Rules.Count; i++)
        {
            var info = collected.Rules[i];
            byName[(info.File, info.Identifier)] = (i, info);
        }

        return new YaraRuleSet(
            handle,
            byName.ToFrozenDictionary(),
            collected.Rules.AsReadOnly(),
            loaded.Select(s => s.Name).ToArray(),
            errors.OrderBy(e => e.File, StringComparer.Ordinal).ToArray(),
            warnings.AsReadOnly(),
            ComputeFingerprint(loaded));
    }

    private static YaraRuleInfo ReadRule(IntPtr rule, List<YaraRuleWarning> warnings)
    {
        YaraXNative.yrx_rule_identifier(rule, out byte* id, out nuint idLength);
        YaraXNative.yrx_rule_namespace(rule, out byte* ns, out nuint nsLength);
        string identifier = YaraXNative.Utf8(id, idLength);
        string file = YaraXNative.Utf8(ns, nsLength);

        var tags = new List<string>();
        var tagsHandle = GCHandle.Alloc(tags);
        var meta = new Dictionary<string, MetaValue>(StringComparer.OrdinalIgnoreCase);
        var metaHandle = GCHandle.Alloc(meta);
        try
        {
            YaraXNative.yrx_rule_iter_tags(rule, &OnTag, GCHandle.ToIntPtr(tagsHandle));
            YaraXNative.yrx_rule_iter_metadata(rule, &OnMetadata, GCHandle.ToIntPtr(metaHandle));
        }
        finally
        {
            tagsHandle.Free();
            metaHandle.Free();
        }

        return new YaraRuleInfo(
            file,
            identifier,
            tags.AsReadOnly(),
            InterpretVerdict(file, identifier, meta.TryGetValue("verdict", out var v) ? v : null, warnings),
            InterpretMitre(file, identifier, meta.TryGetValue("mitre", out var m) ? m : null, warnings),
            meta.TryGetValue("description", out var d) ? d.Text : null);
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

    // --- Compiler reports (JSON) ---

    internal readonly record struct CompilerReport(string Code, string Title, string? Origin, int? Line);

    // "--> origin:line:column" in the report text; the origin is greedy because it may contain ':' only before line:col.
    [GeneratedRegex(@"-->\s*(?<origin>.+?):(?<line>\d+):(?<col>\d+)\s*$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex LocationRegex();

    internal static List<CompilerReport> ParseReports(string json)
    {
        var reports = new List<CompilerReport>();
        if (string.IsNullOrWhiteSpace(json))
        {
            return reports;
        }

        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
            {
                return reports;
            }

            foreach (var item in doc.RootElement.EnumerateArray())
            {
                string code = item.TryGetProperty("code", out var c) ? c.GetString() ?? "" : "";
                string title = item.TryGetProperty("title", out var t) ? t.GetString() ?? "" : "";
                string text = item.TryGetProperty("text", out var x) ? x.GetString() ?? "" : "";
                string? origin = null;
                int? line = null;
                if (LocationRegex().Match(text) is { Success: true } match)
                {
                    origin = match.Groups["origin"].Value;
                    line = int.Parse(match.Groups["line"].Value, CultureInfo.InvariantCulture);
                }

                reports.Add(new CompilerReport(code, title.Length > 0 ? title : text, origin, line));
            }
        }
        catch (JsonException)
        {
            reports.Add(new CompilerReport("", json.Length > 500 ? json[..500] : json, null, null));
        }

        return reports;
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

    // --- Native callbacks: never let an exception cross into native code ---

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnMatchingRule(IntPtr rule, IntPtr userData)
    {
        ScanState? state = null;
        try
        {
            state = (ScanState)GCHandle.FromIntPtr(userData).Target!;
            YaraXNative.yrx_rule_identifier(rule, out byte* id, out nuint idLength);
            YaraXNative.yrx_rule_namespace(rule, out byte* ns, out nuint nsLength);
            var key = (YaraXNative.Utf8(ns, nsLength), YaraXNative.Utf8(id, idLength));
            if (state.RulesByName.TryGetValue(key, out var entry))
            {
                state.Matches.Add(entry);
            }
        }
        catch (Exception ex)
        {
            if (state is not null)
            {
                state.CallbackFailure = ex;
            }
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnRule(IntPtr rule, IntPtr userData)
    {
        RuleCollector? collector = null;
        try
        {
            collector = (RuleCollector)GCHandle.FromIntPtr(userData).Target!;
            collector.Rules.Add(ReadRule(rule, collector.Warnings));
        }
        catch (Exception ex)
        {
            if (collector is not null)
            {
                collector.Failure ??= ex;
            }
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnImport(byte* moduleName, IntPtr userData)
    {
        try
        {
            ((List<string>)GCHandle.FromIntPtr(userData).Target!).Add(YaraXNative.Utf8(moduleName) ?? "");
        }
        catch
        {
            // A lost name would make the check unsafe, but an exception can't cross into native code; the
            // list then simply lacks it. (Only OutOfMemory could get here.)
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnTag(byte* tag, IntPtr userData)
    {
        try
        {
            ((List<string>)GCHandle.FromIntPtr(userData).Target!).Add(YaraXNative.Utf8(tag) ?? "");
        }
        catch
        {
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnMetadata(YaraXNative.YrxMetadata* metadata, IntPtr userData)
    {
        try
        {
            var meta = (Dictionary<string, MetaValue>)GCHandle.FromIntPtr(userData).Target!;
            string name = YaraXNative.Utf8(metadata->Identifier) ?? "";
            var value = metadata->ValueType switch
            {
                YaraXNative.MetaString => new MetaValue(MetaKind.String, YaraXNative.Utf8(metadata->String), 0),
                YaraXNative.MetaI64 => new MetaValue(MetaKind.Integer, null, metadata->I64),
                YaraXNative.MetaBoolean => new MetaValue(MetaKind.Boolean, null, metadata->Boolean != 0 ? 1 : 0),
                YaraXNative.MetaF64 => new MetaValue(MetaKind.Float, null, 0, metadata->F64),
                _ => new MetaValue(MetaKind.Bytes, null, (long)metadata->BytesLength),
            };
            meta.TryAdd(name, value); // first one wins, like before
        }
        catch
        {
        }
    }

    // --- Helper types ---

    internal enum MetaKind
    {
        String,
        Integer,
        Boolean,
        Float,
        Bytes,
    }

    internal readonly record struct MetaValue(MetaKind Kind, string? Text, long Integer, double Float = 0)
    {
        public string Display => Kind switch
        {
            MetaKind.String => $"\"{Text}\"",
            MetaKind.Boolean => Integer != 0 ? "true" : "false",
            MetaKind.Float => Float.ToString(CultureInfo.InvariantCulture),
            MetaKind.Bytes => $"({Integer} bytes)",
            _ => Integer.ToString(CultureInfo.InvariantCulture),
        };
    }

    private sealed class ScanState(FrozenDictionary<(string, string), (int, YaraRuleInfo)> rulesByName)
    {
        public FrozenDictionary<(string, string), (int Index, YaraRuleInfo Info)> RulesByName { get; } = rulesByName;
        public List<(int Index, YaraRuleInfo Info)> Matches { get; } = [];
        public Exception? CallbackFailure { get; set; }
    }

    private sealed class RuleCollector(List<YaraRuleWarning> warnings)
    {
        public List<YaraRuleInfo> Rules { get; } = [];
        public List<YaraRuleWarning> Warnings { get; } = warnings;
        public Exception? Failure { get; set; }
    }

    private sealed class PreparedSource
    {
        private PreparedSource(string name, byte[] utf8Text, string contentSha256)
        {
            Name = name;
            Utf8Text = utf8Text;
            Utf8Namespace = YaraXNative.ToUtf8z(name);
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
                text = text[3..]; // UTF-8 BOM
            }

            if (text.Contains((byte)0))
            {
                source = null!;
                error = "The file contains a NUL byte (not a text rule file).";
                return false;
            }

            if (!System.Text.Unicode.Utf8.IsValid(text))
            {
                source = null!;
                error = "The file is not valid UTF-8.";
                return false;
            }

            var z = new byte[text.Length + 1];
            text.CopyTo(z);
            source = new PreparedSource(name, z, Convert.ToHexStringLower(SHA256.HashData(text)));
            error = string.Empty;
            return true;
        }
    }

    /// <summary>Owns the native YRX_RULES; reference counting keeps it alive while scans run.</summary>
    private sealed class RulesHandle : SafeHandle
    {
        public RulesHandle(IntPtr rules)
            : base(IntPtr.Zero, ownsHandle: true) => SetHandle(rules);

        public bool Released { get; private set; }

        public override bool IsInvalid => handle == IntPtr.Zero;

        protected override bool ReleaseHandle()
        {
            Released = true;
            YaraXNative.yrx_rules_destroy(handle);
            return true;
        }
    }
}
