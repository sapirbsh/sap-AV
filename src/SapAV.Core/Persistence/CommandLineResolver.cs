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
/// without an extension. Candidates are probed (first one that exists wins) unless the first token is already a fully
/// qualified path with an extension. When the program's own path has a space, <see cref="ResolutionFlag.UnquotedPathWithSpaces"/>;
/// when more than one candidate exists, <see cref="ResolutionFlag.UnquotedPathAmbiguous"/>.</item>
/// <item>A bare name is searched in <see cref="EnvironmentBlock.SearchDirectories"/> (System32, Windows, PATH; the
/// application and current folders of the launching process are not known and not searched). A relative path with a
/// folder, a drive-relative or rooted path is <see cref="TargetUnresolvedReason.NotFullyQualified"/>; UNC is
/// <see cref="TargetUnresolvedReason.NetworkPath"/>; <c>\\.\</c>, <c>\??\</c>, <c>\\?\GLOBALROOT</c> are device paths.</item>
/// <item>System hosts in System32 / SysWOW64 (or PowerShell 7 under Program Files) are unwrapped to their payload:
/// <c>rundll32 &lt;dll&gt;,&lt;entry&gt;</c>, <c>regsvr32 [/s /u /n /i:x] &lt;dll&gt;</c> (a URL in <c>/i:</c> is
/// <see cref="ResolutionFlag.RemotePayload"/>), <c>cmd /c|/k &lt;command&gt;</c> (resolved again; <c>start</c> and
/// <c>call</c> skipped; other built-ins and <c>&amp;</c> / <c>|</c> chains are <see cref="ResolutionFlag.InlineCommand"/>),
/// <c>powershell|pwsh -File &lt;script&gt;</c> (<c>-Command</c>, <c>-EncodedCommand</c> and their prefixes are inline),
/// <c>wscript|cscript &lt;script&gt;</c>, <c>mshta &lt;hta|url|javascript:&gt;</c>. A host elsewhere (a copied
/// "rundll32.exe" in Temp) is not a host: it is the target itself. Nesting is followed <see cref="MaxDepth"/> levels.</item>
/// <item>The result is normalized with ExactPath (exact names, trailing dots/spaces kept).</item>
/// </list>
/// Bounded: input over <see cref="EnvironmentBlock.MaxExpandedLength"/> is <see cref="TargetUnresolvedReason.TooLong"/>,
/// at most <see cref="MaxCandidates"/> candidates and <see cref="MaxProbes"/> probes per command line. Never throws for any input.
/// </remarks>
public sealed class CommandLineResolver(IPathProbe probe)
{
    public const int MaxDepth = 3;
    public const int MaxCandidates = 16;
    public const int MaxProbes = 256;

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
    public ResolvedCommand ResolveProgram(string? program, string? arguments, EnvironmentBlock environment)
    {
        ArgumentNullException.ThrowIfNull(environment);
        var state = new State(environment);
        if (Prepare(program, state, out var path) is { } failed)
        {
            return failed;
        }

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
        if (candidates.Count == 1 || IsDecisive(candidates[0].Text))
        {
            var first = candidates[0];
            var file = ResolveFile(first.Text, FileRole.Program, state);
            string args = text[first.End..].Trim();
            return file.Path is { } plain ? Unwrap(plain, args, state, depth) : state.Unresolved(file.Reason!.Value, null, args);
        }

        return ResolveUnquoted(text, candidates, state, depth);
    }

    /// <summary>An unquoted command line with spaces and no decisive first token: probe candidates as CreateProcess would.</summary>
    private ResolvedCommand ResolveUnquoted(string text, List<(string Text, int End)> candidates, State state, int depth)
    {
        int intended = candidates.FindIndex(c => HasExtension(c.Text));
        var found = new List<(string Path, int Index)>();
        TargetUnresolvedReason? firstFailure = null;
        for (int i = 0; i < candidates.Count && found.Count < 2 && state.ProbesLeft > 0; i++)
        {
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
            return Unwrap(found[0].Path, text[candidates[chosen].End..].Trim(), state, depth);
        }

        // Nothing exists: report what was most likely meant (the first candidate with an extension), as not found.
        state.Flags.Add(ResolutionFlag.TargetNotFound);
        if (chosen >= 0 && PersistenceText.NormalizeLocalPath(WithDefaultExtension(candidates[chosen].Text, FileRole.Program)) is { } guess)
        {
            return state.Resolved(guess, text[candidates[chosen].End..].Trim());
        }

        return state.Unresolved(firstFailure ?? TargetUnresolvedReason.NotFoundOnSearchPath, null, text);
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

        if (token.IndexOfAny(['"', '<', '>', '|', '*', '?']) >= 0 && !token.StartsWith(@"\\?\", StringComparison.Ordinal))
        {
            return (null, TargetUnresolvedReason.Malformed);
        }

        if (IsDevicePath(token))
        {
            return (null, TargetUnresolvedReason.DevicePath);
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

        if (!IsBareName(token) || role == FileRole.Script)
        {
            return (null, TargetUnresolvedReason.NotFullyQualified);
        }

        var name = WithDefaultExtension(token, role);
        foreach (var folder in state.Environment.SearchDirectories)
        {
            if (state.ProbesLeft <= 0)
            {
                break;
            }

            if (PersistenceText.NormalizeLocalPath(Path.Join(folder, name)) is { } candidate && state.Probe(_probe, candidate))
            {
                state.Flags.Add(ResolutionFlag.ResolvedFromSearchPath);
                return (candidate, null);
            }
        }

        if (!quiet)
        {
            state.Flags.Add(ResolutionFlag.TargetNotFound);
        }

        return (null, TargetUnresolvedReason.NotFoundOnSearchPath);
    }

    /// <summary>Unwraps a system host to its payload; anything else is the target itself.</summary>
    private ResolvedCommand Unwrap(string program, string args, State state, int depth)
    {
        var host = HostKind(program, state.Environment);
        if (host is null)
        {
            return state.Resolved(program, args);
        }

        if (depth >= MaxDepth)
        {
            return state.Unresolved(TargetUnresolvedReason.NestingTooDeep, program, args);
        }

        return host switch
        {
            "rundll32.exe" => Rundll32(program, args, state),
            "regsvr32.exe" => Regsvr32(program, args, state),
            "cmd.exe" => Cmd(program, args, state, depth),
            "powershell.exe" => PowerShell(program, args, state, positionalIsFile: false),
            "pwsh.exe" => PowerShell(program, args, state, positionalIsFile: true),
            "wscript.exe" or "cscript.exe" => ScriptHost(program, args, state),
            "mshta.exe" => Mshta(program, args, state),
            _ => state.Resolved(program, args),
        };
    }

    private static string? HostKind(string program, EnvironmentBlock environment)
    {
        string name = Path.GetFileName(program).ToLowerInvariant();
        if (name is not ("rundll32.exe" or "regsvr32.exe" or "cmd.exe" or "powershell.exe" or "pwsh.exe" or "wscript.exe"
            or "cscript.exe" or "mshta.exe"))
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
            if (systemFolders.Any(f => string.Equals(f, folder, StringComparison.OrdinalIgnoreCase)))
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

    private ResolvedCommand Rundll32(string host, string args, State state)
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

        return LibraryPayload(host, dll, after.TrimStart(',', ' ', '\t').Trim(), state);
    }

    private ResolvedCommand Regsvr32(string host, string args, State state)
    {
        state.Flags.Add(ResolutionFlag.InterpreterHost);
        var tokens = Tokenize(args);
        int dllIndex = -1;
        for (int i = 0; i < tokens.Count; i++)
        {
            string value = tokens[i].Value;
            if (value.Length > 1 && value[0] is '/' or '-')
            {
                if (value.Length > 2 && char.ToLowerInvariant(value[1]) == 'i' && value[2] == ':' && IsRemote(value[3..].Trim('"')))
                {
                    state.Flags.Add(ResolutionFlag.RemotePayload);
                }

                continue;
            }

            dllIndex = i;
        }

        if (dllIndex < 0)
        {
            return state.Unresolved(TargetUnresolvedReason.MissingHostArgument, host, args);
        }

        string remaining = string.Join(' ', tokens.Where((_, i) => i != dllIndex).Select(t => t.Raw));
        return LibraryPayload(host, tokens[dllIndex].Value, remaining, state);
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
        var tokens = Tokenize(args);
        int index = tokens.FindIndex(t => t.Value.Equals("/c", StringComparison.OrdinalIgnoreCase)
            || t.Value.Equals("/k", StringComparison.OrdinalIgnoreCase) || t.Value.Equals("/r", StringComparison.OrdinalIgnoreCase));
        if (index < 0)
        {
            return state.Resolved(host, args); // an interactive shell: cmd itself is the target
        }

        state.Flags.Add(ResolutionFlag.InterpreterHost);
        string inner = args[tokens[index].End..].Trim();
        if (inner.Length >= 2 && inner[0] == '"' && inner[^1] == '"' && inner.Count(c => c == '"') > 2)
        {
            inner = inner[1..^1].Trim(); // cmd strips the outer quotes in this case (see cmd /?)
        }

        if (FirstUnquoted(inner, '&', '|') is int chain and >= 0)
        {
            state.Flags.Add(ResolutionFlag.InlineCommand); // a chain: the first command is resolved, the rest is inline
            inner = inner[..chain].Trim();
        }

        return CmdInner(host, inner, state, depth);
    }

    private ResolvedCommand CmdInner(string host, string inner, State state, int depth)
    {
        var tokens = Tokenize(inner);
        if (tokens.Count == 0)
        {
            return state.Unresolved(TargetUnresolvedReason.MissingHostArgument, host);
        }

        string verb = tokens[0].Value;
        if (verb.Equals("call", StringComparison.OrdinalIgnoreCase))
        {
            return CmdInner(host, inner[tokens[0].End..].Trim(), state, depth);
        }

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

        if (CmdBuiltins.Contains(verb) || verb.StartsWith('@') || verb.Contains('>') || verb.Contains('<'))
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
        return nested.HostPath is not null ? nested : new ResolvedCommand(nested.TargetPath, nested.UnresolvedReason, host, nested.Arguments, nested.Flags);
    }

    private ResolvedCommand PowerShell(string host, string args, State state, bool positionalIsFile)
    {
        var tokens = Tokenize(args);
        if (tokens.Count == 0)
        {
            return state.Resolved(host, args); // an interactive shell
        }

        state.Flags.Add(ResolutionFlag.InterpreterHost);
        for (int i = 0; i < tokens.Count; i++)
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
                    break;
                }

                if (TakesPowerShellValue(name))
                {
                    i++; // skip the value
                }

                continue;
            }

            if (value == "-")
            {
                break; // commands from standard input
            }

            if (positionalIsFile)
            {
                return ScriptPayload(host, value, args[tokens[i].End..].Trim(), state);
            }

            break; // Windows PowerShell: a positional argument is a command
        }

        state.Flags.Add(ResolutionFlag.InlineCommand);
        return state.Unresolved(TargetUnresolvedReason.InlineCommand, host, args);
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
        var tokens = Tokenize(args);
        int index = tokens.FindIndex(t => !t.Value.StartsWith("//", StringComparison.Ordinal));
        return index < 0
            ? state.Unresolved(TargetUnresolvedReason.MissingHostArgument, host, args)
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

    /// <summary>Splits arguments by the MSVC rules (quotes group, <c>\"</c> is a literal quote); at most 64 tokens.</summary>
    internal static List<(string Value, string Raw, int Start, int End)> Tokenize(string text)
    {
        var tokens = new List<(string, string, int, int)>();
        int i = 0;
        while (i < text.Length && tokens.Count < 64)
        {
            while (i < text.Length && text[i] is ' ' or '\t')
            {
                i++;
            }

            if (i >= text.Length)
            {
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
        public EnvironmentBlock Environment { get; } = environment;

        public HashSet<ResolutionFlag> Flags { get; } = [];

        public int ProbesLeft { get; private set; } = MaxProbes;

        public bool Probe(IPathProbe probe, string path)
        {
            if (ProbesLeft <= 0)
            {
                return false;
            }

            ProbesLeft--;
            try
            {
                return probe.FileExists(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                return false;
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

        public ResolvedCommand Resolved(string path, string args, string? host = null) =>
            ResolvedCommand.Resolved(path, args, host, Flags);

        public ResolvedCommand Unresolved(TargetUnresolvedReason reason, string? host = null, string args = "") =>
            ResolvedCommand.Unresolved(reason, host, args, Flags);
    }
}
