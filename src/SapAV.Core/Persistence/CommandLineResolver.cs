namespace SapAV.Core.Persistence;

/// <summary>
/// Turns a persistence command line into the file it runs (ROADMAP C2). Security-sensitive: the command line is
/// attacker-chosen, and the result decides what C3 / C4 scan. Pure string work plus <see cref="IPathProbe"/> existence
/// checks; nothing is executed, and no target is opened.
/// </summary>
/// <remarks>
/// <para><b>Rules.</b></para>
/// <list type="number">
/// <item><c>%NAME%</c> is expanded with the given <see cref="EnvironmentBlock"/> (machine or the entry's user; never the
/// engine's own). An undefined name stays as written and sets <see cref="ResolutionFlag.UnknownEnvironmentVariable"/>.</item>
/// <item>The program is found as CreateProcess does with no application name: a quoted first token is the path; an unquoted
/// one is tried at each space in turn ("C:\Program.exe", "C:\Program Files\My.exe", ...), <c>.exe</c> appended to a name
/// without an extension. Candidates are probed (first one that exists wins); a first token with an extension is taken
/// unless it is confirmed missing, and then the longer candidates are probed as CreateProcess does. When the program's own
/// path has a space, <see cref="ResolutionFlag.UnquotedPathWithSpaces"/>; when more than one candidate exists,
/// <see cref="ResolutionFlag.UnquotedPathAmbiguous"/>; when a picked program or library had candidates after it,
/// <see cref="ResolutionFlag.LaterCandidates"/> (a scan that finds it missing is then no proof that nothing runs).</item>
/// <item>A bare name is searched in <see cref="EnvironmentBlock.SearchDirectories"/> (System32, Windows, PATH; the
/// application and current folders of the launching process are not known and not searched). A relative path with a
/// folder, a drive-relative or rooted path is <see cref="TargetUnresolvedReason.NotFullyQualified"/>; UNC is
/// <see cref="TargetUnresolvedReason.NetworkPath"/>; <c>\\.\</c>, <c>\??\</c>, <c>\\?\GLOBALROOT</c> are device paths.</item>
/// <item>System hosts in System32 / SysWOW64 (or PowerShell 7 under Program Files) are unwrapped to their payload:
/// <c>rundll32 &lt;dll&gt;,&lt;entry&gt;</c>, <c>regsvr32 [/s /u /n /i:x] &lt;dll&gt;</c> (a URL in <c>/i:</c> is
/// <see cref="ResolutionFlag.RemotePayload"/>), <c>cmd /c|/k|/r &lt;command&gt;</c> (switches read as cmd reads them, attached
/// forms like <c>/d/c</c> and <c>/cX</c> included, see <see cref="CmdSwitches"/>; anything else before the command is
/// <see cref="TargetUnresolvedReason.HostArgumentsNotUnderstood"/>; the command is resolved again with cmd's <c>^</c> escapes removed; <c>start</c> and
/// <c>call</c> skipped; other built-ins are <see cref="ResolutionFlag.InlineCommand"/>; every command of a <c>&amp;</c> / <c>|</c> chain is resolved),
/// <c>powershell|pwsh -File &lt;script&gt;</c> (<c>-Command</c>, <c>-EncodedCommand</c> and their prefixes are inline),
/// <c>wscript|cscript &lt;script&gt;</c>, <c>mshta &lt;hta|url|javascript:&gt;</c>. E4 (review C follow-up M4, review C M9):
/// payloads Microsoft binaries start from their arguments are extracted and flagged <see cref="ResolutionFlag.LauncherPayload"/>:
/// <c>rundll32 url.dll,FileProtocolHandler|OpenURL</c>, <c>shell32.dll,ShellExec_RunDLL</c>, <c>zipfldr.dll,RouteTheCall</c>,
/// <c>pcwutl.dll,LaunchApplication</c>, <c>advpack / setupapi</c> INF installs; <c>shell32.dll,Control_RunDLL &lt;cpl&gt;</c> adds the
/// <c>.cpl</c> as another command; <c>regsvr32</c> judges every DLL and a local <c>/i:</c> scriptlet; <c>conhost [--headless] &lt;command&gt;</c>,
/// <c>forfiles /c &lt;command&gt;</c>, <c>pcalua -a &lt;program&gt;</c>, <c>explorer &lt;program&gt;</c> (explorer.exe in the Windows folder),
/// <c>msiexec /i|/package &lt;msi&gt;</c> and <c>/y|/z &lt;dll&gt;</c>. What can't be extracted is unresolved (so Unverified), never the
/// launcher itself. A host elsewhere (a copied "rundll32.exe" in Temp) is not a host: it is the target itself. Nesting is followed
/// <see cref="MaxDepth"/> levels.</item>
/// <item>The result is normalized with ExactPath (exact names, trailing dots/spaces kept).</item>
/// </list>
/// Bounded: input over <see cref="EnvironmentBlock.MaxExpandedLength"/> is <see cref="TargetUnresolvedReason.TooLong"/>,
/// at most <see cref="MaxCandidates"/> candidates and <see cref="MaxProbes"/> probes per command line. Never throws for any input.
/// Recursion happens only through <c>ResolveCommandLine → Unwrap → Cmd → ResolveNested</c>, and that path counts
/// <see cref="MaxDepth"/>; nothing else here recurses, so no input can overflow the stack.
/// </remarks>
public sealed class CommandLineResolver(IPathProbe probe)
{
    public const int MaxDepth = 3;
    public const int MaxCandidates = 16;
    public const int MaxProbes = 256;

    /// <summary>Most <c>call</c> prefixes followed in one <c>cmd</c> command; more is <see cref="TargetUnresolvedReason.NestingTooDeep"/>.</summary>
    public const int MaxCallPrefixes = 8;

    /// <summary>Most commands of one <c>cmd</c> chain resolved; the rest count as unknown.</summary>
    public const int MaxChainCommands = 8;

    private static readonly HashSet<string> CmdBuiltins = new(StringComparer.OrdinalIgnoreCase)
    {
        "assoc", "break", "cd", "chdir", "cls", "color", "copy", "date", "del", "dir", "echo", "endlocal", "erase", "exit", "for",
        "ftype", "goto", "if", "md", "mkdir", "mklink", "move", "path", "pause", "popd", "prompt", "pushd", "rd", "rem", "ren",
        "rename", "rmdir", "set", "setlocal", "shift", "time", "title", "type", "ver", "verify", "vol",
    };

    private readonly IPathProbe _probe = probe ?? throw new ArgumentNullException(nameof(probe));

    private enum FileRole
    {
        /// <summary>CreateProcess: <c>.exe</c> appended without an extension; bare names searched.</summary>
        Program,

        /// <summary>LoadLibrary: <c>.dll</c> appended without an extension; bare names searched.</summary>
        Library,

        /// <summary>A script argument: relative to the (unknown) current folder, so a bare name isn't resolved.</summary>
        Script,
    }

    /// <summary>Resolves a whole command line (Run value, service ImagePath, IFEO Debugger, ...).</summary>
    public ResolvedCommand Resolve(string? commandLine, EnvironmentBlock environment)
    {
        ArgumentNullException.ThrowIfNull(environment);
        var state = new State(environment);
        if (Prepare(commandLine, state, out var expanded) is { } failed)
        {
            return failed;
        }

        return Guard(() => ResolveCommandLine(expanded!, state, 0));
    }

    /// <summary>
    /// Resolves a program given apart from its arguments (a task's Exec Command + Arguments, a shortcut's target +
    /// arguments). The program may be quoted or not; spaces in it are part of the path.
    /// </summary>
    /// <param name="workingDirectory">
    /// The entry's working directory (a task's or shortcut's), as stored: a relative program or script is relative to it, and a
    /// bare program name is looked for there first, as CreateProcess does. Null or unusable: not searched.
    /// </param>
    public ResolvedCommand ResolveProgram(string? program, string? arguments, EnvironmentBlock environment, string? workingDirectory = null)
    {
        ArgumentNullException.ThrowIfNull(environment);
        var state = new State(environment);
        if (Prepare(program, state, out var path) is { } failed)
        {
            return failed;
        }

        state.SetWorkingDirectory(workingDirectory);
        var args = state.ExpandOrNull(arguments ?? string.Empty) ?? string.Empty;
        return Guard(() =>
        {
            var file = ResolveFile(Unquote(path!.Trim()), FileRole.Program, state);
            return file.Path is { } resolved
                ? Unwrap(resolved, args, state, 0)
                : state.Unresolved(file.Reason!.Value, null, args);
        });
    }

    /// <summary>Resolves a DLL path (a ServiceDll, a COM InprocServer32): bare names are searched like LoadLibrary.</summary>
    public ResolvedCommand ResolveLibrary(string? path, EnvironmentBlock environment, string? hostPath = null, string arguments = "")
    {
        ArgumentNullException.ThrowIfNull(environment);
        var state = new State(environment);
        if (Prepare(path, state, out var expanded) is { } failed)
        {
            return failed;
        }

        return Guard(() =>
        {
            if (hostPath is not null)
            {
                state.Flags.Add(ResolutionFlag.InterpreterHost);
            }

            var file = ResolveFile(Unquote(expanded!.Trim()), FileRole.Library, state);
            return file.Path is { } resolved
                ? state.Resolved(resolved, arguments, hostPath)
                : state.Unresolved(file.Reason!.Value, hostPath, arguments);
        });
    }

    private ResolvedCommand? Prepare(string? text, State state, out string? expanded)
    {
        expanded = null;
        if (string.IsNullOrWhiteSpace(text))
        {
            return ResolvedCommand.Unresolved(TargetUnresolvedReason.EmptyCommand);
        }

        if (text.Length > EnvironmentBlock.MaxExpandedLength)
        {
            return ResolvedCommand.Unresolved(TargetUnresolvedReason.TooLong);
        }

        if (text.Contains('\0'))
        {
            return ResolvedCommand.Unresolved(TargetUnresolvedReason.Malformed);
        }

        expanded = state.ExpandOrNull(text);
        return expanded is null ? ResolvedCommand.Unresolved(TargetUnresolvedReason.TooLong, flags: state.Flags) : null;
    }

    private static ResolvedCommand Guard(Func<ResolvedCommand> resolve)
    {
        try
        {
            return resolve();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Attacker-chosen input: a path the model refuses (or any surprise) is reported, never thrown.
            return ResolvedCommand.Unresolved(TargetUnresolvedReason.Malformed);
        }
    }

    private ResolvedCommand ResolveCommandLine(string text, State state, int depth)
    {
        text = text.TrimStart(' ', '\t');
        if (text.Length == 0)
        {
            return state.Unresolved(TargetUnresolvedReason.EmptyCommand);
        }

        if (text[0] == '"')
        {
            int end = text.IndexOf('"', 1);
            if (end < 0)
            {
                return state.Unresolved(TargetUnresolvedReason.Malformed);
            }

            var file = ResolveFile(text[1..end], FileRole.Program, state);
            string args = text[(end + 1)..].Trim();
            return file.Path is { } quoted ? Unwrap(quoted, args, state, depth) : state.Unresolved(file.Reason!.Value, null, args);
        }

        var candidates = Candidates(text);
        if (candidates.Count == 1)
        {
            var only = candidates[0];
            var file = ResolveFile(only.Text, FileRole.Program, state);
            string args = text[only.End..].Trim();
            return file.Path is { } plain ? Unwrap(plain, args, state, depth) : state.Unresolved(file.Reason!.Value, null, args);
        }

        if (IsDecisive(candidates[0].Text) && ResolveDecisive(text, candidates[0], state, depth) is { } decided)
        {
            return decided;
        }

        return ResolveUnquoted(text, candidates, state, depth);
    }

    /// <summary>
    /// A first token with an extension, with more text after it: it runs if it exists, or can't be ruled out. Follow-up review H-B:
    /// when it is confirmed missing, CreateProcess goes on to the longer candidates (<c>C:\a\app.data dir\evil.exe</c>), so null
    /// sends the caller to <see cref="ResolveUnquoted"/>.
    /// </summary>
    private ResolvedCommand? ResolveDecisive(string text, (string Text, int End) first, State state, int depth)
    {
        // Only a drive path goes on: a longer candidate of a bare name has a separator in it, so it is relative and unknown
        // either way, and a UNC path is never probed.
        bool drive = IsDriveQualified(first.Text);
        var file = ResolveFile(first.Text, FileRole.Program, state, probeQualified: drive, quiet: drive);
        string args = text[first.End..].Trim();
        if (file.Path is { } path)
        {
            state.Further = true;
            return Unwrap(path, args, state, depth);
        }

        return drive && file.Reason is TargetUnresolvedReason.NotFoundOnSearchPath ? null : state.Unresolved(file.Reason!.Value, null, args);
    }

    /// <summary>An unquoted command line with spaces and no decisive first token: probe candidates as CreateProcess would.</summary>
    private ResolvedCommand ResolveUnquoted(string text, List<(string Text, int End)> candidates, State state, int depth)
    {
        int intended = candidates.FindIndex(c => HasExtension(c.Text));
        var found = new List<(string Path, int Index)>();
        TargetUnresolvedReason? firstFailure = null;
        for (int i = 0; i < candidates.Count && found.Count < 2; i++)
        {
            if (state.ProbesLeft <= 0)
            {
                firstFailure ??= TargetUnresolvedReason.SearchLimitReached;
                break;
            }

            var file = ResolveFile(candidates[i].Text, FileRole.Program, state, probeQualified: true, quiet: true);
            if (file.Path is { } path)
            {
                found.Add((path, i));
            }
            else if (file.Reason is not TargetUnresolvedReason.NotFoundOnSearchPath)
            {
                firstFailure ??= file.Reason;
            }
        }

        if (found.Count > 1)
        {
            state.Flags.Add(ResolutionFlag.UnquotedPathAmbiguous);
        }

        int chosen = found.Count > 0 ? found[0].Index : intended >= 0 ? intended : -1;
        if (chosen > 0 || intended > 0)
        {
            state.Flags.Add(ResolutionFlag.UnquotedPathWithSpaces);
        }

        if (found.Count > 0)
        {
            state.Further |= chosen < candidates.Count - 1;
            return Unwrap(found[0].Path, text[candidates[chosen].End..].Trim(), state, depth);
        }

        // A path longer than the candidate cap isn't known to be missing: the real program may lie past the last candidate.
        if (candidates.Count >= MaxCandidates)
        {
            firstFailure ??= TargetUnresolvedReason.SearchLimitReached;
        }

        // Some candidate couldn't even be probed (drive-relative, a limit): that is unknown, not "confirmed missing".
        if (firstFailure is { } unknown)
        {
            return state.Unresolved(unknown, null, text);
        }

        // Nothing exists: report what was most likely meant (the first candidate with an extension), as not found.
        state.Flags.Add(ResolutionFlag.TargetNotFound);
        if (chosen >= 0 && PersistenceText.NormalizeLocalPath(WithDefaultExtension(candidates[chosen].Text, FileRole.Program)) is { } guess)
        {
            return state.Resolved(guess, text[candidates[chosen].End..].Trim());
        }

        return state.Unresolved(TargetUnresolvedReason.NotFoundOnSearchPath, null, text);
    }

    /// <summary>The prefixes CreateProcess tries for an unquoted command line: up to each run of whitespace, then the whole.</summary>
    private static List<(string Text, int End)> Candidates(string text)
    {
        var result = new List<(string, int)>();
        for (int i = 0; i < text.Length && result.Count < MaxCandidates - 1; i++)
        {
            if (text[i] is ' ' or '\t' && i > 0 && text[i - 1] is not (' ' or '\t'))
            {
                result.Add((text[..i], i));
            }
        }

        var whole = text.TrimEnd(' ', '\t');
        if (result.Count == 0 || result[^1].Item1 != whole)
        {
            result.Add((whole, text.Length));
        }

        return result;
    }

    /// <summary>A first token that settles the program without probing: fully qualified (or bare) with an extension.</summary>
    private static bool IsDecisive(string token) => HasExtension(token) && (IsDriveQualified(token) || IsBareName(token) || token.StartsWith(@"\\", StringComparison.Ordinal));

    private (string? Path, TargetUnresolvedReason? Reason) ResolveFile(
        string token, FileRole role, State state, bool probeQualified = false, bool quiet = false)
    {
        token = token.Trim();
        if (token.Length == 0)
        {
            return (null, TargetUnresolvedReason.EmptyCommand);
        }

        if (token.Contains('%'))
        {
            return (null, state.Flags.Contains(ResolutionFlag.UnknownEnvironmentVariable)
                ? TargetUnresolvedReason.UnknownEnvironmentVariable
                : TargetUnresolvedReason.NotFullyQualified);
        }

        if (IsDevicePath(token))
        {
            return (null, TargetUnresolvedReason.DevicePath); // before the character check: \??\ has '?' in it
        }

        if (token.IndexOfAny(['"', '<', '>', '|', '*', '?']) >= 0 && !token.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            return (null, TargetUnresolvedReason.Malformed);
        }

        if (IsDriveQualified(token) || IsExtendedDrive(token))
        {
            var path = PersistenceText.NormalizeLocalPath(WithDefaultExtension(token, role));
            if (path is null)
            {
                return (null, TargetUnresolvedReason.DevicePath);
            }

            if (probeQualified && !state.Probe(_probe, path))
            {
                return (null, TargetUnresolvedReason.NotFoundOnSearchPath);
            }

            return (path, null);
        }

        if (token.StartsWith(@"\\", StringComparison.Ordinal) || token.StartsWith("//", StringComparison.Ordinal))
        {
            return (null, TargetUnresolvedReason.NetworkPath);
        }

        if (FromWorkingDirectory(token, role, state, out var relativeResult))
        {
            return relativeResult;
        }

        if (!IsBareName(token) || role == FileRole.Script)
        {
            return (null, TargetUnresolvedReason.NotFullyQualified);
        }

        var name = WithDefaultExtension(token, role);
        var folders = state.Environment.SearchDirectories;
        for (int i = 0; i < folders.Count; i++)
        {
            if (state.ProbesLeft <= 0)
            {
                return (null, TargetUnresolvedReason.SearchLimitReached);
            }

            if (PersistenceText.NormalizeLocalPath(Path.Join(folders[i], name)) is { } candidate && state.Probe(_probe, candidate))
            {
                state.Flags.Add(ResolutionFlag.ResolvedFromSearchPath);
                state.Further |= i < folders.Count - 1;
                return (candidate, null);
            }
        }

        if (!quiet)
        {
            state.Flags.Add(ResolutionFlag.TargetNotFound);
        }

        return (null, TargetUnresolvedReason.NotFoundOnSearchPath);
    }

    /// <summary>
    /// A name relative to the entry's working directory (rooted-without-a-drive and drive-relative names don't qualify). True
    /// with the result when that settles it: a relative path or script is there, or nowhere; a bare program found there wins
    /// over the search path. False: not applicable, or a bare name to look for on the search path.
    /// </summary>
    private bool FromWorkingDirectory(string token, FileRole role, State state, out (string? Path, TargetUnresolvedReason? Reason) result)
    {
        result = default;
        if (state.WorkingDirectory is not { } folder || token.Contains(':') || token[0] is '\\' or '/')
        {
            return false;
        }

        bool bareProgram = IsBareName(token) && role != FileRole.Script;
        if (folder.StartsWith(@"\\", StringComparison.Ordinal))
        {
            if (bareProgram)
            {
                return false; // the engine doesn't look at the share; the search path is what it can check
            }

            result = (null, TargetUnresolvedReason.NetworkPath);
            return true;
        }

        if (PersistenceText.NormalizeLocalPath(Path.Join(folder, WithDefaultExtension(token, role))) is not { } candidate)
        {
            return false;
        }

        if (!bareProgram)
        {
            result = (candidate, null); // the scan's open says whether it exists
            return true;
        }

        if (!state.Probe(_probe, candidate))
        {
            return false;
        }

        state.Flags.Add(ResolutionFlag.ResolvedFromWorkingDirectory);
        state.Further = true; // the search path comes after the working directory
        result = (candidate, null);
        return true;
    }

    /// <summary>Unwraps a system host to its payload; anything else is the target itself.</summary>
    private ResolvedCommand Unwrap(string program, string args, State state, int depth)
    {
        var host = HostKind(program, state.Environment);
        if (host is null)
        {
            return state.Resolved(program, args);
        }

        state.Further = false; // how the host was found says nothing about how its payload is found

        if (depth >= MaxDepth)
        {
            return state.Unresolved(TargetUnresolvedReason.NestingTooDeep, program, args);
        }

        return host switch
        {
            "rundll32.exe" => Rundll32(program, args, state, depth),
            "regsvr32.exe" => Regsvr32(program, args, state),
            "cmd.exe" => Cmd(program, args, state, depth),
            "powershell.exe" => PowerShell(program, args, state, positionalIsFile: false),
            "pwsh.exe" => PowerShell(program, args, state, positionalIsFile: true),
            "wscript.exe" or "cscript.exe" => ScriptHost(program, args, state),
            "mshta.exe" => Mshta(program, args, state),
            "conhost.exe" => Conhost(program, args, state, depth),
            "forfiles.exe" => Forfiles(program, args, state, depth),
            "pcalua.exe" => Pcalua(program, args, state, depth),
            "explorer.exe" => Explorer(program, args, state),
            "msiexec.exe" => Msiexec(program, args, state),
            _ => state.Resolved(program, args),
        };
    }

    private static string? HostKind(string program, EnvironmentBlock environment)
    {
        string name = Path.GetFileName(program).ToLowerInvariant();
        if (name is not ("rundll32.exe" or "regsvr32.exe" or "cmd.exe" or "powershell.exe" or "pwsh.exe" or "wscript.exe"
            or "cscript.exe" or "mshta.exe" or "conhost.exe" or "forfiles.exe" or "pcalua.exe" or "explorer.exe" or "msiexec.exe"))
        {
            return null;
        }

        string folder = Path.GetDirectoryName(program) ?? string.Empty;
        if (environment.SystemRoot is { } root && PersistenceText.NormalizeLocalPath(root) is { } systemRoot)
        {
            string[] systemFolders =
            [
                Path.Join(systemRoot, "System32"), Path.Join(systemRoot, "SysWOW64"),
                Path.Join(systemRoot, "System32", "WindowsPowerShell", "v1.0"), Path.Join(systemRoot, "SysWOW64", "WindowsPowerShell", "v1.0"),
            ];
            if (systemFolders.Any(f => string.Equals(f, folder, StringComparison.OrdinalIgnoreCase))
                || (name == "explorer.exe" && string.Equals(systemRoot.TrimEnd('\\'), folder.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)))
            {
                return name;
            }
        }

        if (name == "pwsh.exe" && environment.Get("ProgramFiles") is { } programFiles
            && PersistenceText.NormalizeLocalPath(programFiles) is { } pf
            && string.Equals(Path.GetDirectoryName(folder), Path.Join(pf, "PowerShell"), StringComparison.OrdinalIgnoreCase))
        {
            return name;
        }

        return null;
    }

    private ResolvedCommand Rundll32(string host, string args, State state, int depth)
    {
        state.Flags.Add(ResolutionFlag.InterpreterHost);
        string rest = args.TrimStart();
        if (rest.Length == 0)
        {
            return state.Unresolved(TargetUnresolvedReason.MissingHostArgument, host);
        }

        if (IsInlineScheme(rest) || IsInlineScheme(rest.TrimStart('"')))
        {
            state.Flags.Add(ResolutionFlag.InlineCommand);
            return state.Unresolved(TargetUnresolvedReason.InlineCommand, host, rest);
        }

        string dll;
        string after;
        if (rest[0] == '"')
        {
            int end = rest.IndexOf('"', 1);
            if (end < 0)
            {
                return state.Unresolved(TargetUnresolvedReason.Malformed, host, rest);
            }

            dll = rest[1..end];
            after = rest[(end + 1)..];
        }
        else
        {
            int stop = rest.IndexOfAny([',', ' ', '\t']);
            dll = stop < 0 ? rest : rest[..stop];
            after = stop < 0 ? string.Empty : rest[stop..];
        }

        string entryAndArgs = after.TrimStart(',', ' ', '\t').Trim();
        var library = LibraryPayload(host, dll, entryAndArgs, state);
        return LauncherDll(library, state.Environment) is { } launcher
            ? Rundll32Launcher(host, library, launcher, entryAndArgs, state, depth)
            : library;
    }

    /// <summary>What a Microsoft DLL's rundll32 entry point does with the rest of the command line (E4, review C follow-up M4).</summary>
    private enum LauncherEntry
    {
        /// <summary>Runs the rest as a program or opens it like a double-click (ShellExecute).</summary>
        CommandLine,

        /// <summary>Loads the first argument as a Control Panel library (<c>.cpl</c>).</summary>
        ControlPanel,

        /// <summary>Installs an INF file named in the arguments.</summary>
        Inf,

        /// <summary>Registers the first argument as a library.</summary>
        Library,
    }

    /// <summary>The launcher DLL's file name (lower case) when <paramref name="library"/> is one in System32 / SysWOW64; otherwise null.</summary>
    private static string? LauncherDll(ResolvedCommand library, EnvironmentBlock environment)
    {
        if (library.TargetPath is not { } path || environment.SystemRoot is not { } root || PersistenceText.NormalizeLocalPath(root) is not { } systemRoot)
        {
            return null;
        }

        string folder = Path.GetDirectoryName(path) ?? string.Empty;
        bool system = string.Equals(folder, Path.Join(systemRoot, "System32"), StringComparison.OrdinalIgnoreCase)
            || string.Equals(folder, Path.Join(systemRoot, "SysWOW64"), StringComparison.OrdinalIgnoreCase);
        string name = Path.GetFileName(path).ToLowerInvariant();
        return system && name is "url.dll" or "shell32.dll" or "zipfldr.dll" or "ieframe.dll" or "shdocvw.dll" or "pcwutl.dll" or "advpack.dll"
            or "ieadvpack.dll" or "setupapi.dll" or "syssetup.dll"
            ? name
            : null;
    }

    private static LauncherEntry? EntryKind(string dll, string entry)
    {
        string e = entry.ToLowerInvariant();
        return (dll, e) switch
        {
            ("url.dll", "fileprotocolhandler" or "fileprotocolhandlera" or "openurl" or "openurla") => LauncherEntry.CommandLine,
            ("shell32.dll", "shellexec_rundll" or "shellexec_rundlla" or "shellexec_rundllw") => LauncherEntry.CommandLine,
            ("shell32.dll", "control_rundll" or "control_rundlla" or "control_rundllw" or "control_rundllasuser" or "control_rundllasuserw"
                or "control_rundllnofallback") => LauncherEntry.ControlPanel,
            ("zipfldr.dll", "routethecall") => LauncherEntry.CommandLine,
            ("ieframe.dll" or "shdocvw.dll", "openurl") => LauncherEntry.CommandLine,
            ("pcwutl.dll", "launchapplication") => LauncherEntry.CommandLine,
            ("advpack.dll" or "ieadvpack.dll", "launchinfsection" or "launchinfsectionex") => LauncherEntry.Inf,
            ("advpack.dll" or "ieadvpack.dll", "registerocx") => LauncherEntry.Library,
            ("setupapi.dll", "installhinfsection" or "installhinfsectiona" or "installhinfsectionw") => LauncherEntry.Inf,
            ("syssetup.dll", "setupinfobjectinstallaction") => LauncherEntry.Inf,
            _ => null,
        };
    }

    /// <summary>
    /// E4 (review C follow-up M4): a Microsoft DLL whose rundll32 entry point starts something named in its arguments
    /// (<c>url.dll,FileProtocolHandler &lt;exe&gt;</c>, <c>shell32.dll,ShellExec_RunDLL &lt;exe&gt;</c>, <c>advpack.dll,LaunchINFSection
    /// &lt;inf&gt;</c>, ...). The payload is extracted and becomes the target (flagged <see cref="ResolutionFlag.LauncherPayload"/>), or
    /// the entry is Unverified when it can't be (a relative path, an <c>@</c> variable, ...). Control Panel libraries are loaded, not
    /// launched: the DLL stays the target and a <c>.cpl</c> with a path (or one found on the search path) is judged as well.
    /// </summary>
    private ResolvedCommand Rundll32Launcher(string host, ResolvedCommand library, string dll, string entryAndArgs, State state, int depth)
    {
        state.Further = false; // how the launcher DLL was found says nothing about how its payload is found
        int split = entryAndArgs.IndexOfAny([' ', '\t']);
        string entry = (split < 0 ? entryAndArgs : entryAndArgs[..split]).TrimEnd(',');
        string rest = split < 0 ? string.Empty : entryAndArgs[split..].Trim();
        switch (EntryKind(dll, entry))
        {
            case LauncherEntry.CommandLine:
                if (rest.StartsWith('?') && rest.IndexOf('?', 1) is var close and > 0)
                {
                    rest = rest[(close + 1)..].TrimStart(); // ShellExec_RunDLL's optional "?flags?" prefix
                }

                if (rest.Length == 0)
                {
                    // E4 review H1: a launcher entry without a payload is not "the Microsoft DLL itself": what runs is unknown.
                    return state.Unresolved(TargetUnresolvedReason.MissingHostArgument, host, entryAndArgs);
                }

                if (IsRemote(rest.Trim('"')))
                {
                    state.Flags.Add(ResolutionFlag.RemotePayload);
                    return state.Unresolved(TargetUnresolvedReason.RemotePayload, host, rest).WithFlags(ResolutionFlag.LauncherPayload);
                }

                return Launched(host, rest, state, depth);

            case LauncherEntry.ControlPanel:
                var tokens = Tokenize(rest.Replace(',', ' '));
                if (tokens.Count == 0)
                {
                    return library;
                }

                string cpl = tokens[0].Value;
                var applet = LibraryPayload(host, cpl, rest, state.ForChainCommand());
                bool qualified = !IsBareName(cpl);
                return qualified || (applet.TargetPath is not null && !applet.HasFlag(ResolutionFlag.TargetNotFound))
                    ? library.WithAdditional([applet])
                    : library;

            case LauncherEntry.Inf:
                var inf = Tokenize(rest.Replace(',', ' ')).Select(t => t.Value).FirstOrDefault(t => t.EndsWith(".inf", StringComparison.OrdinalIgnoreCase));
                return inf is null
                    ? state.Unresolved(TargetUnresolvedReason.HostArgumentsNotUnderstood, host, rest)
                    : ScriptPayload(host, inf, rest, state).WithFlags(ResolutionFlag.LauncherPayload);

            case LauncherEntry.Library:
                var first = Tokenize(rest).FirstOrDefault().Value;
                return string.IsNullOrEmpty(first)
                    ? state.Unresolved(TargetUnresolvedReason.MissingHostArgument, host, entryAndArgs)
                    : LibraryPayload(host, first, rest, state).WithFlags(ResolutionFlag.LauncherPayload);

            default:
                // E4 review H1: an entry by ordinal (shell32.dll,#61) may be any export, a launcher one included, so with arguments it
                // can't be judged. Named entries that launch nothing (SHCreateLocalServerRunDll, ...) and a bare ordinal stay the DLL.
                return entry.StartsWith('#') && rest.Length > 0
                    ? state.Unresolved(TargetUnresolvedReason.HostArgumentsNotUnderstood, host, entryAndArgs)
                    : library;
        }
    }

    /// <summary>
    /// A program a launcher starts from its arguments: resolved as a command line one level deeper (so nesting stays bounded),
    /// with the launcher as host unless the payload has its own, and flagged <see cref="ResolutionFlag.LauncherPayload"/>.
    /// </summary>
    private ResolvedCommand Launched(string host, string commandLine, State state, int depth)
    {
        state.Flags.Add(ResolutionFlag.InterpreterHost);
        state.Flags.Add(ResolutionFlag.LauncherPayload);
        return ResolveNested(host, commandLine, state, depth).WithFlags(ResolutionFlag.LauncherPayload);
    }

    /// <summary>
    /// <c>regsvr32 [/s /u /n /i:x] dll [dll ...]</c>: every DLL is registered, so each is judged (E4, review C follow-up M4: the
    /// last one alone was kept, so <c>regsvr32 /s evil.dll scrobj.dll</c> hid evil.dll). A local <c>/i:</c> scriptlet that
    /// scrobj.dll (or any DllInstall) is handed, when it looks like a file, becomes the target; a URL there is a remote payload.
    /// </summary>
    private ResolvedCommand Regsvr32(string host, string args, State state)
    {
        state.Flags.Add(ResolutionFlag.InterpreterHost);
        var tokens = Tokenize(args, out bool truncated);
        if (truncated)
        {
            return state.Unresolved(TargetUnresolvedReason.SearchLimitReached, host, args); // the DLL is the last name: past the cap it's unknown
        }

        var dlls = new List<int>();
        string? install = null;
        for (int i = 0; i < tokens.Count; i++)
        {
            string value = tokens[i].Value;
            if (value.Length > 1 && value[0] is '/' or '-')
            {
                if (value.Length > 2 && char.ToLowerInvariant(value[1]) == 'i' && value[2] == ':')
                {
                    string argument = value[3..].Trim('"').Trim();
                    if (IsRemote(argument))
                    {
                        state.Flags.Add(ResolutionFlag.RemotePayload);
                    }
                    else if (argument.Length > 0)
                    {
                        install = argument;
                    }
                }

                continue;
            }

            dlls.Add(i);
        }

        if (dlls.Count == 0)
        {
            return state.Unresolved(TargetUnresolvedReason.MissingHostArgument, host, args);
        }

        string remaining = string.Join(' ', tokens.Where((_, i) => !dlls.Contains(i)).Select(t => t.Raw));
        var libraries = dlls.Select((index, n) => LibraryPayload(host, tokens[index].Value, remaining, n == 0 ? state : state.ForChainCommand())).ToList();
        bool scrobj = dlls.Any(i => Path.GetFileName(tokens[i].Value).Equals("scrobj.dll", StringComparison.OrdinalIgnoreCase)
            || Path.GetFileName(tokens[i].Value).Equals("scrobj", StringComparison.OrdinalIgnoreCase));
        if (install is not null && (scrobj || !IsBareName(install) || Path.GetExtension(install).ToLowerInvariant() is ".sct" or ".xml" or ".txt"))
        {
            var scriptlet = ScriptPayload(host, install, remaining, state.ForChainCommand()).WithFlags(ResolutionFlag.LauncherPayload);
            return scriptlet.WithAdditional(libraries);
        }

        return libraries[0].WithAdditional(libraries.Skip(1));
    }

    /// <summary>
    /// <c>conhost.exe [--headless] [--width n] ... [--] &lt;command&gt;</c> (E4, M4): the command is what runs. Only conhost's own
    /// options are skipped; anything else before the command is not understood (never "conhost itself").
    /// </summary>
    private ResolvedCommand Conhost(string host, string args, State state, int depth)
    {
        var tokens = Tokenize(args);
        int i = 0;
        while (i < tokens.Count)
        {
            string value = tokens[i].Value;
            string lower = value.ToLowerInvariant();
            if (lower == "--")
            {
                i++;
                break;
            }

            if (lower.StartsWith("--", StringComparison.Ordinal))
            {
                string name = lower[2..];
                if (name is "width" or "height" or "signal" or "server" or "feature" or "vtmode")
                {
                    i += 2;
                }
                else if (name is "headless" or "inheritcursor" or "textmode")
                {
                    i++;
                }
                else
                {
                    state.Flags.Add(ResolutionFlag.InterpreterHost);
                    return state.Unresolved(TargetUnresolvedReason.HostArgumentsNotUnderstood, host, args);
                }

                continue;
            }

            if ((i == 0 && lower.StartsWith("0x", StringComparison.Ordinal)) || lower == "-forcev1")
            {
                i++;
                continue;
            }

            break;
        }

        return i >= tokens.Count ? state.Resolved(host, args) : Launched(host, args[tokens[i].Start..], state, depth);
    }

    /// <summary>
    /// <c>forfiles [/p dir] [/m mask] [/s] [/d date] /c "command"</c> (E4, M4): the <c>/c</c> command runs once per file (its
    /// <c>0xHH</c> escapes decoded). Without <c>/c</c> it only echoes names. A command whose program is an <c>@</c> variable can't be known.
    /// </summary>
    private ResolvedCommand Forfiles(string host, string args, State state, int depth)
    {
        state.Flags.Add(ResolutionFlag.InterpreterHost);
        var tokens = Tokenize(args);
        string? command = null;
        for (int i = 0; i < tokens.Count; i++)
        {
            string value = tokens[i].Value;
            if (value.Length < 2 || value[0] is not ('/' or '-'))
            {
                return state.Unresolved(TargetUnresolvedReason.HostArgumentsNotUnderstood, host, args);
            }

            switch (value[1..].ToLowerInvariant())
            {
                case "c":
                    command = i + 1 < tokens.Count ? tokens[++i].Value : string.Empty;
                    break;
                case "p" or "m" or "d":
                    i++;
                    break;
                case "s":
                    break;
                default:
                    return state.Unresolved(TargetUnresolvedReason.HostArgumentsNotUnderstood, host, args);
            }
        }

        if (command is null)
        {
            state.Flags.Add(ResolutionFlag.InlineCommand);
            return state.Unresolved(TargetUnresolvedReason.InlineCommand, host, args); // the default: cmd /c echo @file
        }

        if (HexUnescape(command) is not { } unescaped)
        {
            return state.Unresolved(TargetUnresolvedReason.Malformed, host, args); // review L1: a control character (NUL, ...) escaped in
        }

        command = unescaped.Trim();
        if (command.Length == 0)
        {
            return state.Unresolved(TargetUnresolvedReason.MissingHostArgument, host, args);
        }

        return command.TrimStart('"').StartsWith('@')
            ? state.Unresolved(TargetUnresolvedReason.HostArgumentsNotUnderstood, host, args)
            : Launched(host, command, state, depth);
    }

    /// <summary>forfiles' <c>0xHH</c> escapes (<c>0x22</c> is a quote); null when one decodes to a control character (below 0x20, review L1).</summary>
    private static string? HexUnescape(string text)
    {
        if (!text.Contains("0x", StringComparison.OrdinalIgnoreCase))
        {
            return text;
        }

        var result = new System.Text.StringBuilder(text.Length);
        for (int i = 0; i < text.Length; i++)
        {
            if (i + 3 < text.Length && text[i] == '0' && text[i + 1] is 'x' or 'X' && char.IsAsciiHexDigit(text[i + 2]) && char.IsAsciiHexDigit(text[i + 3]))
            {
                char decoded = (char)Convert.ToInt32(text.Substring(i + 2, 2), 16);
                if (decoded < ' ')
                {
                    return null;
                }

                result.Append(decoded);
                i += 3;
            }
            else
            {
                result.Append(text[i]);
            }
        }

        return result.ToString();
    }

    /// <summary><c>pcalua.exe -a &lt;program&gt; [-c &lt;arguments&gt;] [-d &lt;folder&gt;]</c> (E4, review C M9): the program is what runs.</summary>
    private ResolvedCommand Pcalua(string host, string args, State state, int depth)
    {
        state.Flags.Add(ResolutionFlag.InterpreterHost);
        var tokens = Tokenize(args);
        string? program = null, arguments = null;
        for (int i = 0; i + 1 < tokens.Count; i++)
        {
            string name = tokens[i].Value.ToLowerInvariant();
            if (name is "-a" or "/a")
            {
                program = tokens[++i].Value;
            }
            else if (name is "-c" or "/c")
            {
                arguments = tokens[++i].Value;
            }
        }

        if (program is null)
        {
            return state.Unresolved(TargetUnresolvedReason.MissingHostArgument, host, args);
        }

        state.Flags.Add(ResolutionFlag.LauncherPayload);
        var file = ResolveFile(program, FileRole.Program, state);
        var nested = file.Path is { } path ? Unwrap(path, arguments ?? string.Empty, state, depth + 1) : state.Unresolved(file.Reason!.Value, host, arguments ?? string.Empty);
        return (nested.HostPath is not null ? nested : new ResolvedCommand(nested.TargetPath, nested.UnresolvedReason, host, nested.Arguments, nested.Flags, nested.Additional))
            .WithFlags(ResolutionFlag.LauncherPayload);
    }

    /// <summary>explorer.exe's own switches (<c>/select,</c> and <c>/root,</c> name an object after the comma).</summary>
    private static readonly HashSet<string> ExplorerSwitches = new(StringComparer.OrdinalIgnoreCase) { "/n", "/e", "/separate", "/select", "/root" };

    /// <summary>
    /// <c>explorer.exe [/n] [/e] [/root,|/select,]&lt;object&gt;</c> opens the object like a double-click (E4, review C M9; E4 review
    /// H1): a file given to it (program, script or document) is the payload and the target, never explorer. Explorer itself is the
    /// target only with no object, its window switches alone, or a local folder (a drive path whose last part has no extension
    /// once trailing dots and spaces are trimmed, as Windows does). An unknown switch, a <c>shell:</c> / <c>::{CLSID}</c> location or a
    /// relative name can't be judged: Unverified.
    /// </summary>
    private ResolvedCommand Explorer(string host, string args, State state)
    {
        var tokens = Tokenize(args, out bool truncated);
        if (truncated)
        {
            state.Flags.Add(ResolutionFlag.InterpreterHost);
            return state.Unresolved(TargetUnresolvedReason.SearchLimitReached, host, args);
        }

        string? target = null;
        int end = 0;
        foreach (var token in tokens)
        {
            // Switches are comma-separated and may share a token with the object ("/e,/select,C:\x\a.exe").
            string part = token.Value;
            while (part.StartsWith('/'))
            {
                int comma = part.IndexOf(',');
                string name = comma < 0 ? part : part[..comma];
                if (!ExplorerSwitches.Contains(name))
                {
                    state.Flags.Add(ResolutionFlag.InterpreterHost);
                    return state.Unresolved(TargetUnresolvedReason.HostArgumentsNotUnderstood, host, args);
                }

                part = comma < 0 ? string.Empty : part[(comma + 1)..].TrimStart();
            }

            part = part.Trim(',', ' ');
            if (part.Length > 0)
            {
                target = part;
                end = token.End;
                break;
            }
        }

        if (target is null)
        {
            return state.Resolved(host, args); // no object: a window
        }

        string rest = args[end..].Trim();
        if (IsRemote(target))
        {
            state.Flags.Add(ResolutionFlag.InterpreterHost);
            state.Flags.Add(ResolutionFlag.RemotePayload);
            return state.Unresolved(TargetUnresolvedReason.RemotePayload, host, rest).WithFlags(ResolutionFlag.LauncherPayload);
        }

        string trimmed = target.TrimEnd('.', ' ', '\\', '/');
        if (IsDriveQualified(target) && trimmed.Length > 2 && trimmed.IndexOf(':', 2) < 0 && !HasExtension(trimmed))
        {
            return state.Resolved(host, args); // a local folder: explorer shows it, nothing else runs
        }

        state.Flags.Add(ResolutionFlag.InterpreterHost);
        state.Flags.Add(ResolutionFlag.LauncherPayload);
        var file = ResolveFile(target, FileRole.Script, state);
        return file.Path is { } path ? state.Resolved(path, rest, host) : state.Unresolved(file.Reason!.Value, host, rest);
    }

    /// <summary>
    /// <c>msiexec</c> (E4, review C M9; E4 review H1): the package a command installs, repairs, uninstalls, advertises or patches
    /// (<c>/i /package /a /j /x /uninstall /f /p /update</c>) is the target, and so is the library of <c>/y</c> / <c>/z</c>; a URL there is a
    /// remote payload. msiexec itself is the target only when every argument is a known switch that runs no package (<c>/q</c>,
    /// <c>/norestart</c>, <c>/l*v log</c>, ...) or a <c>PROPERTY=value</c>. A product code (the cached package of an installed product), a
    /// missing package or an unknown switch can't be judged: Unverified, never msiexec.
    /// </summary>
    private ResolvedCommand Msiexec(string host, string args, State state)
    {
        var tokens = Tokenize(args, out bool truncated);
        if (truncated)
        {
            state.Flags.Add(ResolutionFlag.InterpreterHost);
            return state.Unresolved(TargetUnresolvedReason.SearchLimitReached, host, args);
        }

        for (int i = 0; i < tokens.Count; i++)
        {
            string value = tokens[i].Value;
            if (value.Length < 2 || value[0] is not ('/' or '-'))
            {
                if (value.IndexOf('=') > 0)
                {
                    continue; // PROPERTY=value
                }

                state.Flags.Add(ResolutionFlag.InterpreterHost);
                return state.Unresolved(TargetUnresolvedReason.HostArgumentsNotUnderstood, host, args);
            }

            var kind = MsiexecSwitch(value[1..].ToLowerInvariant());
            switch (kind)
            {
                case MsiSwitch.Plain:
                    continue;
                case MsiSwitch.TakesValue:
                    i++;
                    continue;
                case MsiSwitch.Package or MsiSwitch.Library:
                    return MsiexecPayload(host, args, tokens, i, kind == MsiSwitch.Library, state);
                default:
                    state.Flags.Add(ResolutionFlag.InterpreterHost);
                    return state.Unresolved(TargetUnresolvedReason.HostArgumentsNotUnderstood, host, args);
            }
        }

        return state.Resolved(host, args);
    }

    private enum MsiSwitch
    {
        Unknown,

        /// <summary>Runs no package and takes no value (<c>/qn</c>, <c>/norestart</c>).</summary>
        Plain,

        /// <summary>Takes a value that is not a package (<c>/l*v log.txt</c>, <c>/t</c>, <c>/g</c>).</summary>
        TakesValue,

        /// <summary>The next argument is a package (or a product code).</summary>
        Package,

        /// <summary>The next argument is a library to register (<c>/y</c>) or unregister (<c>/z</c>).</summary>
        Library,
    }

    private static MsiSwitch MsiexecSwitch(string name)
    {
        static bool Letters(string s, string allowed) => s.Skip(1).All(allowed.Contains);
        return name switch
        {
            "i" or "package" or "a" or "x" or "uninstall" or "p" or "update" or "j" or "ju" or "jm" => MsiSwitch.Package,
            _ when name[0] == 'f' && Letters(name, "pecdaumsvo") => MsiSwitch.Package, // repair: /f, /fvomus
            "y" or "z" => MsiSwitch.Library,
            "quiet" or "passive" or "norestart" or "forcerestart" or "promptrestart" or "?" or "h" or "help" or "unregister" or "regserver" => MsiSwitch.Plain,
            _ when name[0] == 'q' && Letters(name, "nbrfh+-!") => MsiSwitch.Plain,
            _ when name[0] == 'l' && Letters(name, "iwearucmopvx+!*") => MsiSwitch.TakesValue, // /l*v logfile
            "log" or "t" or "g" => MsiSwitch.TakesValue,
            _ => MsiSwitch.Unknown,
        };
    }

    /// <summary>The package (or library) after msiexec switch <paramref name="index"/>; <c>/update</c> may list several, each judged.</summary>
    private ResolvedCommand MsiexecPayload(
        string host, string args, List<(string Value, string Raw, int Start, int End)> tokens, int index, bool library, State state)
    {
        state.Flags.Add(ResolutionFlag.InterpreterHost);
        string value = index + 1 < tokens.Count ? tokens[index + 1].Value.Trim() : string.Empty;
        if (value.Length == 0 || value[0] is '/' or '-')
        {
            return state.Unresolved(TargetUnresolvedReason.MissingHostArgument, host, args);
        }

        if (value.StartsWith('{'))
        {
            return state.Unresolved(TargetUnresolvedReason.HostArgumentsNotUnderstood, host, args); // a product code: no package named
        }

        state.Flags.Add(ResolutionFlag.LauncherPayload);
        string rest = args[tokens[index + 1].End..].Trim();
        var packages = value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (packages.Length == 0)
        {
            return state.Unresolved(TargetUnresolvedReason.MissingHostArgument, host, args);
        }

        var results = packages.Take(MaxChainCommands)
            .Select((package, n) => library
                ? LibraryPayload(host, package, rest, n == 0 ? state : state.ForChainCommand())
                : ScriptPayload(host, package, rest, n == 0 ? state : state.ForChainCommand()))
            .ToList();
        if (packages.Length > MaxChainCommands)
        {
            results.Add(state.ForChainCommand().Unresolved(TargetUnresolvedReason.SearchLimitReached, host, rest));
        }

        return results[0].WithAdditional(results.Skip(1));
    }

    private ResolvedCommand LibraryPayload(string host, string dll, string remaining, State state)
    {
        if (IsRemote(dll))
        {
            state.Flags.Add(ResolutionFlag.RemotePayload);
            return state.Unresolved(TargetUnresolvedReason.RemotePayload, host, remaining);
        }

        var file = ResolveFile(dll, FileRole.Library, state);
        if (file.Reason == TargetUnresolvedReason.NetworkPath)
        {
            state.Flags.Add(ResolutionFlag.RemotePayload);
        }

        return file.Path is { } path ? state.Resolved(path, remaining, host) : state.Unresolved(file.Reason!.Value, host, remaining);
    }

    private ResolvedCommand Cmd(string host, string args, State state, int depth)
    {
        var switches = CmdSwitches.Parse(args);
        if (switches.Outcome == CmdSwitches.Kind.InteractiveShell)
        {
            return state.Resolved(host, args); // only known switches and no /c /k /r: cmd itself is the target
        }

        state.Flags.Add(ResolutionFlag.InterpreterHost);
        if (switches.Outcome != CmdSwitches.Kind.Command)
        {
            // Follow-up review H-A: text cmd may read differently from us (an unknown switch, a word, too many switches) is
            // never "cmd itself": what it runs is unknown.
            return state.Unresolved(switches.Outcome == CmdSwitches.Kind.TooMany
                ? TargetUnresolvedReason.SearchLimitReached
                : TargetUnresolvedReason.HostArgumentsNotUnderstood, host, args);
        }

        string inner = args[switches.CommandStart..].Trim();
        if (inner.Length >= 2 && inner[0] == '"' && inner[^1] == '"' && inner.Count(c => c == '"') > 2)
        {
            inner = inner[1..^1].Trim(); // cmd strips the outer quotes in this case (see cmd /?)
        }

        var commands = SplitChain(inner);
        if (commands.Count == 1)
        {
            return CmdInner(host, inner, state, depth);
        }

        return ResolveChain(host, commands, state, depth);
    }

    /// <summary>
    /// A <c>&amp;</c> / <c>&amp;&amp;</c> / <c>||</c> / <c>|</c> chain (section C review H4): every command runs, so every one is resolved,
    /// each with its own flags (one missing command says nothing about the next). The first with a file is the target, the others
    /// are <see cref="ResolvedCommand.Additional"/>; a chain is also flagged InlineCommand. Past
    /// <see cref="MaxChainCommands"/>, the rest counts as unknown.
    /// </summary>
    private ResolvedCommand ResolveChain(string host, List<string> commands, State state, int depth)
    {
        var results = new List<ResolvedCommand>(commands.Count);
        foreach (var command in commands.Take(MaxChainCommands))
        {
            results.Add(CmdInner(host, command.Trim(), state.ForChainCommand(), depth));
        }

        if (commands.Count > MaxChainCommands)
        {
            results.Add(state.Unresolved(TargetUnresolvedReason.SearchLimitReached, host));
        }

        int primary = results.FindIndex(r => r.TargetPath is not null && !r.HasFlag(ResolutionFlag.TargetNotFound));
        primary = primary < 0 ? 0 : primary;
        var others = results.Where((_, i) => i != primary).ToArray();
        return results[primary].WithFlags(ResolutionFlag.InlineCommand).WithAdditional(others);
    }

    /// <summary>The commands of a cmd chain, split at unquoted, unescaped <c>&amp;</c> and <c>|</c> (doubled or not); empty ones dropped.</summary>
    private static List<string> SplitChain(string text)
    {
        var parts = new List<string>();
        int start = 0;
        while (start <= text.Length)
        {
            int stop = FirstUnquoted(text[start..], '&', '|');
            if (stop < 0)
            {
                Add(text[start..]);
                break;
            }

            Add(text.Substring(start, stop));
            start += stop + 1;
            if (start < text.Length && text[start] is '&' or '|')
            {
                start++;
            }
        }

        if (parts.Count == 0)
        {
            parts.Add(string.Empty);
        }

        return parts;

        void Add(string part)
        {
            if (!string.IsNullOrWhiteSpace(part))
            {
                parts.Add(part);
            }
        }
    }

    private ResolvedCommand CmdInner(string host, string inner, State state, int depth)
    {
        // Follow-up review H-B: cmd drops its ^ escapes before it runs anything ("ev^il.exe" runs evil.exe).
        inner = CmdUnescape(inner);

        // "call" prefixes are stripped in a capped loop, never by recursion: a Run value is attacker-chosen, and an
        // uncatchable stack overflow here would take the SYSTEM engine down (section C review H1).
        var tokens = Tokenize(inner);
        for (int calls = 0; tokens.Count > 0 && tokens[0].Value.Equals("call", StringComparison.OrdinalIgnoreCase); calls++)
        {
            if (calls >= MaxCallPrefixes)
            {
                return state.Unresolved(TargetUnresolvedReason.NestingTooDeep, host, inner);
            }

            inner = inner[tokens[0].End..].Trim();
            tokens = Tokenize(inner);
        }

        if (tokens.Count == 0)
        {
            return state.Unresolved(TargetUnresolvedReason.MissingHostArgument, host);
        }

        string verb = tokens[0].Value;
        if (verb.Equals("start", StringComparison.OrdinalIgnoreCase))
        {
            int i = 1;
            if (i < tokens.Count - 1 && tokens[i].Raw.StartsWith('"'))
            {
                i++; // the window title
            }

            while (i < tokens.Count && tokens[i].Value.StartsWith('/'))
            {
                bool takesValue = tokens[i].Value.ToLowerInvariant() is "/d" or "/node" or "/affinity";
                i += takesValue ? 2 : 1;
            }

            if (i >= tokens.Count)
            {
                return state.Unresolved(TargetUnresolvedReason.MissingHostArgument, host, inner);
            }

            return ResolveNested(host, inner[tokens[i].Start..], state, depth);
        }

        if (CmdBuiltins.Contains(verb) || verb.StartsWith('@') || verb.StartsWith('(') || verb.Contains('>') || verb.Contains('<'))
        {
            state.Flags.Add(ResolutionFlag.InlineCommand);
            return state.Unresolved(TargetUnresolvedReason.InlineCommand, host, inner);
        }

        return ResolveNested(host, inner, state, depth);
    }

    private ResolvedCommand ResolveNested(string host, string command, State state, int depth)
    {
        var nested = ResolveCommandLine(command, state, depth + 1);
        // The innermost host is the one that runs the target; keep the outer one only when nothing nested was a host.
        return nested.HostPath is not null ? nested : new ResolvedCommand(nested.TargetPath, nested.UnresolvedReason, host, nested.Arguments, nested.Flags, nested.Additional);
    }

    private ResolvedCommand PowerShell(string host, string args, State state, bool positionalIsFile)
    {
        var tokens = Tokenize(args, out bool truncated);
        if (tokens.Count == 0)
        {
            return state.Resolved(host, args); // an interactive shell
        }

        state.Flags.Add(ResolutionFlag.InterpreterHost);
        NotePowerShellStealth(tokens, state);
        bool stopped = false; // an inline command, stdin or a positional command came before the tokens ran out
        for (int i = 0; i < tokens.Count && !stopped; i++)
        {
            string value = tokens[i].Value;
            if (value.Length > 1 && IsDash(value[0]))
            {
                string name = value[1..].ToLowerInvariant();
                if ("file".StartsWith(name, StringComparison.Ordinal))
                {
                    return i + 1 < tokens.Count
                        ? ScriptPayload(host, tokens[i + 1].Value, args[tokens[i + 1].End..].Trim(), state)
                        : state.Unresolved(TargetUnresolvedReason.MissingHostArgument, host, args);
                }

                if (IsInlinePowerShellParameter(name))
                {
                    stopped = true;
                    continue;
                }

                if (TakesPowerShellValue(name))
                {
                    i++; // skip the value
                }

                continue;
            }

            if (value == "-")
            {
                stopped = true; // commands from standard input
                continue;
            }

            if (positionalIsFile)
            {
                return ScriptPayload(host, value, args[tokens[i].End..].Trim(), state);
            }

            stopped = true; // Windows PowerShell: a positional argument is a command
        }

        if (truncated && !stopped)
        {
            return state.Unresolved(TargetUnresolvedReason.SearchLimitReached, host, args); // a -File may lie past the cap
        }

        state.Flags.Add(ResolutionFlag.InlineCommand);
        return state.Unresolved(TargetUnresolvedReason.InlineCommand, host, args);
    }

    /// <summary>A hidden window and an encoded command, in any order (the full PowerShell rules are E4's).</summary>
    private static void NotePowerShellStealth(List<(string Value, string Raw, int Start, int End)> tokens, State state)
    {
        for (int i = 0; i < tokens.Count; i++)
        {
            string value = tokens[i].Value;
            if (value.Length < 2 || !IsDash(value[0]))
            {
                continue;
            }

            string name = value[1..].ToLowerInvariant();
            if (name is "e" or "ec" || (name.Length >= 2 && "encodedcommand".StartsWith(name, StringComparison.Ordinal)))
            {
                state.Flags.Add(ResolutionFlag.EncodedCommand);
            }
            else if ("windowstyle".StartsWith(name, StringComparison.Ordinal) && i + 1 < tokens.Count)
            {
                string style = tokens[i + 1].Value.ToLowerInvariant();
                if (style == "1" || (style.Length > 0 && "hidden".StartsWith(style, StringComparison.Ordinal)))
                {
                    state.Flags.Add(ResolutionFlag.HiddenWindow);
                }
            }
        }
    }

    private static bool IsInlinePowerShellParameter(string name) =>
        (name.Length >= 1 && "command".StartsWith(name, StringComparison.Ordinal))
        || name is "e" or "ec" or "cwa" or "commandwithargs"
        || (name.Length >= 2 && "encodedcommand".StartsWith(name, StringComparison.Ordinal));

    /// <summary>Parameters that take a value (skipped with it), by unambiguous prefix as powershell.exe / pwsh accept them.</summary>
    private static bool TakesPowerShellValue(string name)
    {
        static bool Prefix(string full, string n, int min) => n.Length >= min && full.StartsWith(n, StringComparison.Ordinal);
        return name is "ep" or "if" or "of" or "wd" or "sf" or "ea"
            || Prefix("executionpolicy", name, 2) || Prefix("windowstyle", name, 1) || Prefix("version", name, 1)
            || Prefix("psconsolefile", name, 2) || Prefix("inputformat", name, 2) || Prefix("outputformat", name, 1)
            || Prefix("configurationname", name, 3) || Prefix("workingdirectory", name, 2) || Prefix("settingsfile", name, 2)
            || Prefix("custompipename", name, 2) || Prefix("encodedarguments", name, 8);
    }

    private static bool IsDash(char c) => c is '-' or '/' or '\u2013' or '\u2014' or '\u2015';

    private ResolvedCommand ScriptHost(string host, string args, State state)
    {
        state.Flags.Add(ResolutionFlag.InterpreterHost);
        var tokens = Tokenize(args, out bool truncated);
        int index = tokens.FindIndex(t => !t.Value.StartsWith("//", StringComparison.Ordinal));
        return index < 0
            ? state.Unresolved(truncated ? TargetUnresolvedReason.SearchLimitReached : TargetUnresolvedReason.MissingHostArgument, host, args)
            : ScriptPayload(host, tokens[index].Value, args[tokens[index].End..].Trim(), state);
    }

    private ResolvedCommand Mshta(string host, string args, State state)
    {
        state.Flags.Add(ResolutionFlag.InterpreterHost);
        var tokens = Tokenize(args);
        if (tokens.Count == 0)
        {
            return state.Unresolved(TargetUnresolvedReason.MissingHostArgument, host);
        }

        string first = tokens[0].Value;
        if (IsInlineScheme(first) || first.StartsWith("about:", StringComparison.OrdinalIgnoreCase))
        {
            state.Flags.Add(ResolutionFlag.InlineCommand);
            return state.Unresolved(TargetUnresolvedReason.InlineCommand, host, args);
        }

        return ScriptPayload(host, first, args[tokens[0].End..].Trim(), state);
    }

    private ResolvedCommand ScriptPayload(string host, string script, string remaining, State state)
    {
        if (IsRemote(script))
        {
            state.Flags.Add(ResolutionFlag.RemotePayload);
            return state.Unresolved(TargetUnresolvedReason.RemotePayload, host, remaining);
        }

        var file = ResolveFile(script, FileRole.Script, state);
        if (file.Reason == TargetUnresolvedReason.NetworkPath)
        {
            state.Flags.Add(ResolutionFlag.RemotePayload);
        }

        return file.Path is { } path ? state.Resolved(path, remaining, host) : state.Unresolved(file.Reason!.Value, host, remaining);
    }

    /// <summary>Most tokens <see cref="Tokenize(string)"/> returns.</summary>
    public const int MaxTokens = 64;

    /// <summary>Splits arguments by the MSVC rules (quotes group, <c>\"</c> is a literal quote); at most <see cref="MaxTokens"/> tokens.</summary>
    internal static List<(string Value, string Raw, int Start, int End)> Tokenize(string text) => Tokenize(text, out _);

    /// <param name="truncated">True when text is left after <see cref="MaxTokens"/> tokens (what a host does with it is unknown).</param>
    internal static List<(string Value, string Raw, int Start, int End)> Tokenize(string text, out bool truncated)
    {
        var tokens = new List<(string, string, int, int)>();
        int i = 0;
        truncated = false;
        while (i < text.Length)
        {
            while (i < text.Length && text[i] is ' ' or '\t')
            {
                i++;
            }

            if (i >= text.Length)
            {
                break;
            }

            if (tokens.Count >= MaxTokens)
            {
                truncated = true;
                break;
            }

            int start = i;
            var value = new System.Text.StringBuilder();
            bool quoted = false;
            while (i < text.Length && (quoted || text[i] is not (' ' or '\t')))
            {
                char c = text[i];
                if (c == '\\')
                {
                    int slashes = 0;
                    while (i < text.Length && text[i] == '\\')
                    {
                        slashes++;
                        i++;
                    }

                    if (i < text.Length && text[i] == '"')
                    {
                        value.Append('\\', slashes / 2);
                        if (slashes % 2 == 1)
                        {
                            value.Append('"');
                            i++;
                        }
                    }
                    else
                    {
                        value.Append('\\', slashes);
                    }

                    continue;
                }

                if (c == '"')
                {
                    quoted = !quoted;
                }
                else
                {
                    value.Append(c);
                }

                i++;
            }

            tokens.Add((value.ToString(), text[start..i], start, i));
        }

        return tokens;
    }

    /// <summary>cmd's escape removal: outside quotes, <c>^x</c> is <c>x</c> and a trailing <c>^</c> is dropped; inside quotes <c>^</c> is literal.</summary>
    internal static string CmdUnescape(string text)
    {
        if (!text.Contains('^'))
        {
            return text;
        }

        var result = new System.Text.StringBuilder(text.Length);
        bool quoted = false;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (c == '"')
            {
                quoted = !quoted;
            }
            else if (c == '^' && !quoted)
            {
                if (++i >= text.Length)
                {
                    break;
                }

                c = text[i];
            }

            result.Append(c);
        }

        return result.ToString();
    }

    private static int FirstUnquoted(string text, params char[] stops)
    {
        bool quoted = false;
        for (int i = 0; i < text.Length; i++)
        {
            if (text[i] == '"')
            {
                quoted = !quoted;
            }
            else if (!quoted && text[i] == '^')
            {
                i++; // an escaped character is literal
            }
            else if (!quoted && stops.Contains(text[i]))
            {
                return i;
            }
        }

        return -1;
    }

    private static string Unquote(string text) =>
        text.Length >= 2 && text[0] == '"' && text[^1] == '"' ? text[1..^1] : text.Trim('"');

    private static string WithDefaultExtension(string path, FileRole role)
    {
        if (role == FileRole.Script || HasExtension(path) || path.EndsWith('.') || path.EndsWith('\\'))
        {
            return path;
        }

        return path + (role == FileRole.Library ? ".dll" : ".exe");
    }

    private static bool HasExtension(string path)
    {
        string name = path[(path.LastIndexOfAny(['\\', '/']) + 1)..];
        int dot = name.LastIndexOf('.');
        return dot > 0 && dot < name.Length - 1;
    }

    private static bool IsDriveQualified(string token) =>
        token.Length >= 3 && char.IsAsciiLetter(token[0]) && token[1] == ':' && token[2] is '\\' or '/';

    private static bool IsBareName(string token) => token.IndexOfAny(['\\', '/', ':']) < 0;

    private static bool IsDevicePath(string token) =>
        token.StartsWith(@"\\.\", StringComparison.Ordinal) || token.StartsWith(@"\??\", StringComparison.Ordinal)
        || token.StartsWith(@"\\?\GLOBALROOT", StringComparison.OrdinalIgnoreCase) || token.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase)
        || token.StartsWith("//./", StringComparison.Ordinal) || token.StartsWith("//?/", StringComparison.Ordinal)
        || (token.StartsWith(@"\\?\", StringComparison.Ordinal) && !IsExtendedDrive(token)
            && !token.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase));

    private static bool IsExtendedDrive(string token) =>
        token.Length >= 7 && token.StartsWith(@"\\?\", StringComparison.Ordinal) && char.IsAsciiLetter(token[4]) && token[5] == ':' && token[6] == '\\';

    private static bool IsRemote(string text) =>
        text.StartsWith("http:", StringComparison.OrdinalIgnoreCase) || text.StartsWith("https:", StringComparison.OrdinalIgnoreCase)
        || text.StartsWith("ftp:", StringComparison.OrdinalIgnoreCase) || text.StartsWith(@"\\", StringComparison.Ordinal)
        || text.StartsWith("//", StringComparison.Ordinal);

    private static bool IsInlineScheme(string text) =>
        text.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase) || text.StartsWith("vbscript:", StringComparison.OrdinalIgnoreCase);

    /// <summary>Per-resolution state: the environment, the flags so far and the probe budget.</summary>
    private sealed class State(EnvironmentBlock environment)
    {
        // Shared by the commands of a chain: the budget is per command line.
        private int[] _probesLeft = [MaxProbes];

        public EnvironmentBlock Environment { get; } = environment;

        public HashSet<ResolutionFlag> Flags { get; private init; } = [];

        public int ProbesLeft => _probesLeft[0];

        /// <summary>The expanded working directory, when it is usable: a normalized local path or a UNC path.</summary>
        public string? WorkingDirectory { get; private set; }

        /// <summary>For one command of a chain: the flags so far and the working directory, but its own flags from here on.</summary>
        public State ForChainCommand() => new(Environment)
        {
            Flags = [.. Flags],
            _probesLeft = _probesLeft,
            WorkingDirectory = WorkingDirectory,
        };

        public void SetWorkingDirectory(string? folder)
        {
            if (string.IsNullOrWhiteSpace(folder) || ExpandOrNull(folder) is not { } expanded)
            {
                return;
            }

            string trimmed = expanded.Trim().Trim('"');
            WorkingDirectory = trimmed.StartsWith(@"\\", StringComparison.Ordinal) && !trimmed.StartsWith(@"\\?\", StringComparison.Ordinal)
                ? trimmed
                : PersistenceText.NormalizeLocalPath(trimmed);
        }

        /// <summary>True unless the file is confirmed missing: an Unknown answer may be the program, so it stops the search.</summary>
        public bool Probe(IPathProbe probe, string path)
        {
            if (_probesLeft[0] <= 0)
            {
                return false;
            }

            _probesLeft[0]--;
            try
            {
                return probe.Probe(path) != PathProbeResult.Missing;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                return true;
            }
        }

        public string? ExpandOrNull(string text)
        {
            var expanded = Environment.Expand(text, out bool unknown);
            if (unknown)
            {
                Flags.Add(ResolutionFlag.UnknownEnvironmentVariable);
            }

            if (Environment.IsUser && text.Contains('%'))
            {
                Flags.Add(ResolutionFlag.UserEnvironment);
            }

            return expanded;
        }

        /// <summary>The program / library just picked had later candidates (<see cref="ResolutionFlag.LaterCandidates"/> on the result).</summary>
        public bool Further { get; set; }

        public ResolvedCommand Resolved(string path, string args, string? host = null)
        {
            if (Further)
            {
                Flags.Add(ResolutionFlag.LaterCandidates);
            }

            return ResolvedCommand.Resolved(path, args, host, Flags);
        }

        public ResolvedCommand Unresolved(TargetUnresolvedReason reason, string? host = null, string args = "")
        {
            // Section C review H4: a payload outside the file system is the same finding whichever host (if any) runs it.
            if (reason is TargetUnresolvedReason.NetworkPath or TargetUnresolvedReason.DevicePath)
            {
                Flags.Add(ResolutionFlag.RemotePayload);
            }

            return ResolvedCommand.Unresolved(reason, host, args, Flags);
        }
    }
}
