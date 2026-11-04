using System.Security.AccessControl;
using System.Text;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Sandbox;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Sandbox;

/// <summary>
/// D3 (A2 review M5): as SYSTEM / elevated the blocklist and rules load only from the protected data folders (or a configured
/// admin-only folder). The shipped files are only a seed, copied from a trusted install folder. Temp roots stand in for
/// <c>%ProgramData%\sap-AV</c> and the install folder; the folder trust is faked.
/// </summary>
public sealed class ProtectedRulesSourceTests : IDisposable
{
    private const string ShippedHash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    private const string PlantedHash = "1111111111111111111111111111111111111111111111111111111111111111";

    private readonly TempDir _temp = new();
    private readonly FakeTrust _trust = new();

    public ProtectedRulesSourceTests()
    {
        Directory.CreateDirectory(ShippedRules);
        File.WriteAllText(Path.Combine(ShippedRules, "shipped.yar"), "rule shipped { condition: false }");
        Directory.CreateDirectory(Path.GetDirectoryName(ShippedBlocklist)!);
        File.WriteAllText(ShippedBlocklist, ShippedHash + "\n");
        File.SetLastWriteTimeUtc(ShippedBlocklist, DateTime.UtcNow.AddDays(-1));
    }

    public void Dispose() => _temp.Dispose();

    private string Root => Path.Combine(_temp.Path, "sap-AV");

    private string ManagedRules => Path.Combine(Root, "Rules");

    private string ManagedBlocklist => Path.Combine(Root, "Blocklist", "blocklist.txt");

    private string ShippedRules => Path.Combine(_temp.Path, "install", "data", "rules");

    private string ShippedBlocklist => Path.Combine(_temp.Path, "install", "data", "hashes", "blocklist.txt");

    private ProtectedRulesSource Source(SandboxOptions? options = null) => new(
        options ?? new SandboxOptions { RulesDirectory = ManagedRules, BlocklistPath = ManagedBlocklist },
        new QuarantineAccessPolicy([QuarantineTestContext.CurrentUser]), _trust, ShippedRules, ShippedBlocklist, ManagedRules, ManagedBlocklist,
        parentIsDataRoot: true);

    [Fact]
    public void Apply_ProtectedMode_UsesTheProgramDataFolders_DebugKeepsTheShippedFiles_AndAConfiguredPathWins()
    {
        var service = new SandboxOptions();
        ProtectedRulesSource.Apply(service, protectedMode: true);
        Assert.Equal(EngineDataFolders.Rules, service.ResolvedRulesDirectory);
        Assert.Equal(Path.Combine(EngineDataFolders.Blocklist, "blocklist.txt"), service.ResolvedBlocklistPath);

        var debug = new SandboxOptions();
        ProtectedRulesSource.Apply(debug, protectedMode: false);
        Assert.Equal(ProtectedRulesSource.ShippedBlocklistPath, debug.ResolvedBlocklistPath);

        var configured = new SandboxOptions { BlocklistPath = @"C:\Program Files\sap-AV\hashes\blocklist.txt" };
        ProtectedRulesSource.Apply(configured, protectedMode: true);
        Assert.Equal(@"C:\Program Files\sap-AV\hashes\blocklist.txt", configured.ResolvedBlocklistPath);
        Assert.Equal(EngineDataFolders.Rules, configured.ResolvedRulesDirectory);
    }

    [Fact]
    public async Task ProtectedFolders_AreCreatedWithTheProtectedAcl_AndSeededFromATrustedInstallFolder()
    {
        var package = await Source().LoadAsync();

        Assert.Empty(package.ReadErrors);
        Assert.Equal(ShippedHash + "\n", Encoding.UTF8.GetString(package.Blocklist));
        Assert.Equal("shipped.yar", Assert.Single(package.RuleFiles).Name);
        foreach (var folder in new[] { Root, ManagedRules, Path.GetDirectoryName(ManagedBlocklist)! })
        {
            Assert.True(new DirectoryInfo(folder).GetAccessControl(AccessControlSections.Access).AreAccessRulesProtected, folder);
        }
    }

    [Fact]
    public async Task AnUntrustedInstallFolder_IsNeverCopied_AndTheReasonIsAReadError()
    {
        _trust.Bad.Add(Path.GetDirectoryName(ShippedBlocklist)!);
        _trust.Bad.Add(ShippedRules);

        var package = await Source().LoadAsync();

        Assert.Empty(package.Blocklist);
        Assert.Empty(package.RuleFiles);
        Assert.Contains(package.ReadErrors, e => e.Contains("can't be used", StringComparison.Ordinal));
        Assert.False(File.Exists(ManagedBlocklist));
    }

    [Fact]
    public async Task AnAdministratorsNewerCopy_IsKept_UntilTheShippedFileIsNewer()
    {
        await Source().LoadAsync();
        File.WriteAllText(ManagedBlocklist, PlantedHash + "\n"); // an administrator's edit, newer than the shipped file

        Assert.Equal(PlantedHash + "\n", Encoding.UTF8.GetString((await Source().LoadAsync()).Blocklist));

        File.SetLastWriteTimeUtc(ShippedBlocklist, DateTime.UtcNow.AddMinutes(5)); // an engine update ships a newer list
        Assert.Equal(ShippedHash + "\n", Encoding.UTF8.GetString((await Source().LoadAsync()).Blocklist));
    }

    [Fact]
    public async Task AConfiguredUserWritableFolder_IsRefused_AndNothingIsReadFromIt()
    {
        var writable = Directory.CreateDirectory(Path.Combine(_temp.Path, "user-writable")).FullName;
        File.WriteAllText(Path.Combine(writable, "blocklist.txt"), PlantedHash + "\n");
        File.WriteAllText(Path.Combine(writable, "planted.yar"), "rule planted { condition: false }");
        _trust.Bad.Add(writable);

        var package = await Source(new SandboxOptions { RulesDirectory = writable, BlocklistPath = Path.Combine(writable, "blocklist.txt") }).LoadAsync();

        Assert.Empty(package.Blocklist);
        Assert.Empty(package.RuleFiles);
        Assert.Equal(2, package.ReadErrors.Count(e => e.Contains("was refused", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task APreCreatedDataRoot_WithAUserMadeBlocklistFolder_IsRefused_ThePlantedListIsNeverLoaded_AndTheShippedOneIs()
    {
        // A standard user pre-created %ProgramData%\sap-AV\Blocklist (inherited ProgramData ACL) holding an empty list, to take
        // their malware off the blocklist. The root can't be fixed (it holds content a user made). Review D3 H1: the engine then
        // reads the trusted shipped files directly instead of running with no rules, and says so (rules health alert).
        var planted = Directory.CreateDirectory(Path.GetDirectoryName(ManagedBlocklist)!).FullName;
        File.WriteAllText(Path.Combine(planted, "blocklist.txt"), "# nothing blocked\n");

        var package = await Source().LoadAsync();

        Assert.Equal(ShippedHash + "\n", Encoding.UTF8.GetString(package.Blocklist));
        Assert.Equal("shipped.yar", Assert.Single(package.RuleFiles).Name);
        Assert.Contains(package.ReadErrors, e => e.StartsWith("The protected blocklist folder was refused", StringComparison.Ordinal)
            && e.Contains("loaded from the install folder", StringComparison.Ordinal));
        Assert.Equal("# nothing blocked\n", File.ReadAllText(Path.Combine(planted, "blocklist.txt"))); // never deleted or rewritten

        // ... and the engine raises the rules health alert for it, while YARA and the blocklist work.
        using var broker = new InProcessScanBroker(Source(), Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
        var summary = await broker.ReloadRulesAsync();
        Assert.Equal((1, 1), (summary!.RuleCount, summary.BlocklistCount));
        Assert.NotNull(RulesPreflight.Judge(summary).AlertText);
    }

    [Fact]
    public async Task ARefusedDataRoot_AndAnUntrustedInstallFolder_LoadNothing_AndSayWhy()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(ManagedBlocklist)!);
        _trust.Bad.Add(Path.GetDirectoryName(ShippedBlocklist)!);
        _trust.Bad.Add(ShippedRules);

        var package = await Source().LoadAsync();

        Assert.Empty(package.Blocklist);
        Assert.Empty(package.RuleFiles);
        Assert.Contains(package.ReadErrors, e => e.StartsWith("Not loaded (blocklist)", StringComparison.Ordinal));
    }

    [RequiresFact(Requires.RunningElevated)]
    public async Task ADataRootPreCreatedAndOwnedByAStandardUserGroup_StillLoadsTheShippedRulesAndBlocklist()
    {
        // Review D3 H1 as reported: `mkdir %ProgramData%\sap-AV` by a user before the first start (UntrustedOwner).
        var root = Directory.CreateDirectory(Root);
        Assert.Equal(0, SapAV.Engine.Quarantine.Native.RestorePrivilege.Run(() =>
        {
            var owner = new DirectorySecurity();
            owner.SetOwner(new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null));
            root.SetAccessControl(owner);
            return 0;
        }));
        var source = new ProtectedRulesSource(new SandboxOptions { RulesDirectory = ManagedRules, BlocklistPath = ManagedBlocklist },
            QuarantineAccessPolicy.Default, _trust, ShippedRules, ShippedBlocklist, ManagedRules, ManagedBlocklist, parentIsDataRoot: true);

        var package = await source.LoadAsync();

        Assert.Equal(ShippedHash + "\n", Encoding.UTF8.GetString(package.Blocklist));
        Assert.Single(package.RuleFiles);
        Assert.Contains(package.ReadErrors, e => e.Contains("owner", StringComparison.Ordinal) && e.Contains("install folder", StringComparison.Ordinal));
    }

    private sealed class FakeTrust : IFolderTrust
    {
        public HashSet<string> Bad { get; } = new(StringComparer.OrdinalIgnoreCase);

        public string? Problem(string folder) => Bad.Contains(Path.GetFullPath(folder).TrimEnd('\\')) ? "a user may write to it" : null;
    }
}
