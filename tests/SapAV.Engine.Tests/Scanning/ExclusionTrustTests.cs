using System.Security.AccessControl;
using SapAV.Core.Models;
using SapAV.Engine.Quarantine;
using SapAV.Engine.Scanning;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Scanning;

/// <summary>
/// Review B H1 (ROADMAP D3 M5): only verified engine folders are excluded, never the whole <c>%ProgramData%\sap-AV</c>; an
/// engine folder a user could write to is scanned and reported.
/// </summary>
public sealed class ExclusionTrustTests
{
    private static byte[] Sd(string sddl)
    {
        var sd = new RawSecurityDescriptor(sddl);
        var bytes = new byte[sd.BinaryLength];
        sd.GetBinaryForm(bytes, 0);
        return bytes;
    }

    [Theory]
    [InlineData("O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", true)]                                   // the protected data DACL
    [InlineData("O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:P(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;OICI;0x1200a9;;;BU)(A;OICIIO;GA;;;CO)", true)] // Program Files style
    [InlineData("O:BAD:(A;OICI;FA;;;BA)(A;CI;0x116;;;BU)", false)]                                  // ProgramData style: Users add files/folders
    [InlineData("O:BAD:P(A;OICI;FA;;;BA)(A;OICIIO;FA;;;AU)", false)]                                // inheritable write for others
    [InlineData("O:AUD:P(A;OICI;FA;;;BA)", false)]                                                   // untrusted owner
    [InlineData("O:BAD:P(A;OICI;FA;;;BA)(D;OICI;FA;;;BU)", true)]                                   // a deny entry never widens
    public void Judge_AcceptsOnlyAdminOnlyFolders(string sddl, bool trusted)
    {
        Assert.Equal(trusted, FolderTrust.Default.Judge(Sd(sddl), FolderTrust.WriteRights, inheritable: true) is null);
    }

    [Fact]
    public void ARealFolder_WithTheUsersInheritedAcl_IsNotVerified_AProtectedOneIs()
    {
        using var temp = new TempDir();
        var plain = Directory.CreateDirectory(Path.Combine(temp.Path, "plain")).FullName;
        var store = Path.Combine(temp.Path, "store");
        QuarantineStore.Open(store, new QuarantineAccessPolicy([QuarantineTestContext.CurrentUser]), parentIsDataRoot: false).Dispose();
        var testTrust = new FolderTrust([QuarantineTestContext.CurrentUser]);

        Assert.NotNull(FolderTrust.Default.Problem(plain));
        Assert.Null(testTrust.Problem(store));
        Assert.NotNull(FolderTrust.Default.Problem(store)); // owned by the (untrusted) test user
    }

    [Fact]
    public async Task AFilePlantedInAUserWritableDataRootSubfolder_IsScanned_WhileTheVerifiedStoreIsExcluded()
    {
        using var h = new ScanJobHarness();
        var policy = new QuarantineAccessPolicy([QuarantineTestContext.CurrentUser]);
        var dataRoot = Path.Combine(h.Root, "sap-AV");
        var store = Path.Combine(dataRoot, "Quarantine");
        QuarantineStore.Open(store, policy, parentIsDataRoot: true).Dispose();
        var planted = Path.Combine(dataRoot, "x", "mal-dropped.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(planted)!);
        File.WriteAllText(planted, "planted");
        File.WriteAllText(Path.Combine(store, "mal-stored"), "an engine file");
        var untrusted = new List<string>();
        h.Exclusions = new ExclusionSet(new FolderSet([store, Path.Combine(dataRoot, "Sandbox")]), new FolderSet([]),
            new FolderTrust([QuarantineTestContext.CurrentUser]), h.Time, (folder, _) => untrusted.Add(folder));

        var (job, _) = h.Start(dataRoot);
        await JobWait.Done(job);

        var result = Assert.Single(job.Results);
        Assert.Equal(planted, result.Path);
        Assert.Equal(Verdict.Malicious, result.Verdict);
        Assert.Equal(1, job.GetProgress().Counters.Excluded); // the store folder
        Assert.Empty(untrusted);
    }

    [Fact]
    public async Task AnUnverifiedEngineFolder_IsScanned_AndReported()
    {
        using var h = new ScanJobHarness();
        var engine = Path.Combine(h.Root, "ScanWorker");
        var file = h.Write(@"ScanWorker\mal-hidden.exe");
        var untrusted = new List<(string Folder, string Why)>();
        h.Exclusions = new ExclusionSet(new FolderSet([engine]), new FolderSet([]), FolderTrust.Default, h.Time,
            (folder, why) => untrusted.Add((folder, why)));

        var (job, _) = h.Start();
        await JobWait.Done(job);

        Assert.Equal(file, Assert.Single(job.Results).Path);
        Assert.Equal(0, job.GetProgress().Counters.Excluded);
        var reported = Assert.Single(untrusted);
        Assert.StartsWith(engine, reported.Folder, StringComparison.OrdinalIgnoreCase);
        Assert.False(string.IsNullOrWhiteSpace(reported.Why));
    }

    [Fact]
    public void ANestedEngineFolder_IsExcludedOnlyIfEveryContainingEngineFolderIsVerified()
    {
        var trust = new FakeTrust { Bad = { @"C:\Install\data\rules\" } };
        var set = new ExclusionSet(new FolderSet([@"C:\Install", @"C:\Install\data\rules", @"C:\Install\ScanWorker"]), new FolderSet([@"D:\Extra"]),
            trust, new ManualTime());

        Assert.True(set.Contains(@"C:\Install\ScanWorker\SapAV.ScanWorker.exe"));
        Assert.False(set.Contains(@"C:\Install\data\rules\self.yar"));
        Assert.True(set.Contains(@"D:\Extra\anything")); // configured: honored as is
        Assert.False(set.Contains(@"C:\Elsewhere\x.exe"));
    }

    [Fact]
    public void Verification_IsCachedForAMinute_ThenCheckedAgain()
    {
        var time = new ManualTime();
        var trust = new FakeTrust { Bad = { @"C:\Engine\" } };
        int reports = 0;
        var set = new ExclusionSet(new FolderSet([@"C:\Engine"]), new FolderSet([]), trust, time, (_, _) => reports++);

        for (int i = 0; i < 50; i++)
        {
            Assert.False(set.Contains($@"C:\Engine\f{i}.exe"));
        }

        Assert.Equal((1, 1), (trust.Checks, reports));
        trust.Bad.Clear(); // an administrator fixed it
        time.Now += ExclusionSet.TrustCacheTime + TimeSpan.FromSeconds(1);
        Assert.True(set.Contains(@"C:\Engine\f.exe"));
        Assert.Equal(2, trust.Checks);
    }

    private sealed class FakeTrust : IFolderTrust
    {
        public HashSet<string> Bad { get; } = new(StringComparer.OrdinalIgnoreCase);

        public int Checks { get; private set; }

        public string? Problem(string folder)
        {
            Checks++;
            return Bad.Contains(folder) ? "a user may write to it" : null;
        }
    }
}
