using System.Text.Json.Serialization;
using SapAV.Core.Serialization;

namespace SapAV.Core.Persistence;

/// <summary>
/// Something worth knowing about how a command line was resolved (ROADMAP C2). These are facts for the judgement (C3),
/// not verdicts. Serialized to JSON by name.
/// </summary>
[JsonConverter(typeof(StrictEnumConverter<ResolutionFlag>))]
public enum ResolutionFlag
{
    /// <summary>
    /// The program path isn't quoted and the program that runs has a space in its path, so CreateProcess first tried a
    /// shorter path ("unquoted service path", T1574.009): anyone who can create that shorter file hijacks the entry.
    /// </summary>
    UnquotedPathWithSpaces,

    /// <summary>More than one candidate of an unquoted command line exists; the first one (what runs) was picked.</summary>
    UnquotedPathAmbiguous,

    /// <summary>A bare program / DLL name was found through the search order (System32, Windows, PATH).</summary>
    ResolvedFromSearchPath,

    /// <summary>A searched name, or every candidate of an unquoted path, wasn't found.</summary>
    TargetNotFound,

    /// <summary>
    /// The program is a system host (rundll32, cmd, powershell, wscript/cscript, mshta, regsvr32, svchost): the target is
    /// the DLL or script it runs, and <see cref="ResolvedCommand.HostPath"/> is the host.
    /// </summary>
    InterpreterHost,

    /// <summary>The host runs inline code (<c>powershell -Command/-EncodedCommand</c>, <c>cmd /c echo</c>, <c>javascript:</c>).</summary>
    InlineCommand,

    /// <summary>
    /// The payload is outside this machine's file system: the host fetches it from the network (<c>mshta http://</c>,
    /// <c>regsvr32 /i:http://</c>), or any target is a UNC or device path, or a shortcut
    /// points at a network path.
    /// </summary>
    RemotePayload,

    /// <summary>Environment variables were expanded with the entry's user's environment (from their hive).</summary>
    UserEnvironment,

    /// <summary>A <c>%NAME%</c> wasn't defined in the environment used; it was left as written.</summary>
    UnknownEnvironmentVariable,

    /// <summary>The stored command line was cut at <see cref="PersistenceEntry.MaxCommandLineLength"/>.</summary>
    CommandLineTruncated,

    /// <summary>A shortcut's target differs between its sources (ID list, LinkInfo, environment block): the shell's choice was used.</summary>
    ShortcutTargetMismatch,

    /// <summary>A COM handler's class was taken from the user's own <c>Software\Classes</c>, which overrides the machine registration (T1546.015).</summary>
    UserComOverride,

    /// <summary>A bare name was found in the entry's working directory (a task's or shortcut's), which CreateProcess searches before the system.</summary>
    ResolvedFromWorkingDirectory,

    /// <summary>PowerShell is started with a hidden window (<c>-WindowStyle Hidden</c> and its prefixes).</summary>
    HiddenWindow,

    /// <summary>PowerShell runs a Base64-encoded command (<c>-EncodedCommand</c> and its prefixes).</summary>
    EncodedCommand,

    /// <summary>
    /// The target was picked from a search that had more candidates after it (a longer unquoted path, a later search folder):
    /// if it turns out missing when scanned, CreateProcess / LoadLibrary would go on to those, so "not found" then isn't
    /// confirmed missing (section C follow-up review H-B).
    /// </summary>
    LaterCandidates,

    /// <summary>
    /// E4 (review C follow-up M4 / M9): the target was taken from the arguments of a Microsoft binary that starts it indirectly:
    /// <c>rundll32 url.dll,FileProtocolHandler &lt;exe&gt;</c>, <c>rundll32 shell32.dll,ShellExec_RunDLL &lt;exe&gt;</c>, <c>regsvr32
    /// /i:&lt;scriptlet&gt; scrobj.dll</c>, <c>conhost --headless &lt;exe&gt;</c>, <c>forfiles /c</c>, <c>pcalua -a</c>, <c>explorer
    /// &lt;exe&gt;</c>, <c>msiexec /i|/y</c>.
    /// </summary>
    LauncherPayload,
}
