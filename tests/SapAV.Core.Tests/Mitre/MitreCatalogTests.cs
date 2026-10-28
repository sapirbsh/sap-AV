using SapAV.Core.Mitre;

namespace SapAV.Core.Tests.Mitre;

public class MitreCatalogTests
{
    /// <summary>Every technique ID from ROADMAP.md X1, with its official ATT&amp;CK name.</summary>
    public static TheoryData<string, string> X1Techniques => new()
    {
        { "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder" },
        { "T1547.004", "Boot or Logon Autostart Execution: Winlogon Helper DLL" },
        { "T1546.012", "Event Triggered Execution: Image File Execution Options Injection" },
        { "T1543.003", "Create or Modify System Process: Windows Service" },
        { "T1053.005", "Scheduled Task/Job: Scheduled Task" },
        { "T1036.007", "Masquerading: Double File Extension" },
        { "T1027.002", "Obfuscated Files or Information: Software Packing" },
        { "T1204.002", "User Execution: Malicious File" },
        { "T1566.001", "Phishing: Spearphishing Attachment" },
        { "T1059", "Command and Scripting Interpreter" },
        { "T1059.001", "Command and Scripting Interpreter: PowerShell" },
        { "T1059.003", "Command and Scripting Interpreter: Windows Command Shell" },
        { "T1059.005", "Command and Scripting Interpreter: Visual Basic" },
        { "T1059.007", "Command and Scripting Interpreter: JavaScript" },
        { "T1486", "Data Encrypted for Impact" },
        { "T1091", "Replication Through Removable Media" },
        { "T1565.001", "Data Manipulation: Stored Data Manipulation" },
    };

    /// <summary>
    /// Techniques added after the X1 starting map (A5 heuristics). Listed separately so the X1 rows stay a copy
    /// of ROADMAP.md; X1 should gain these rows.
    /// </summary>
    public static TheoryData<string, string> AddedTechniques => new()
    {
        { "T1027.001", "Obfuscated Files or Information: Binary Padding" },
        { "T1036.002", "Masquerading: Right-to-Left Override" },
        { "T1211", "Exploitation for Defense Evasion" }, // B5: a file that crashes or hangs the scan worker
        { "T1562.001", "Impair Defenses: Disable or Modify Tools" }, // B3: engine-health alerts (no rules, store full)
        // C3: persistence judgement
        { "T1574.009", "Hijack Execution Flow: Path Interception by Unquoted Path" },
        { "T1574.010", "Hijack Execution Flow: Services File Permissions Weakness" },
        { "T1546.008", "Event Triggered Execution: Accessibility Features" },
        { "T1546.015", "Event Triggered Execution: Component Object Model Hijacking" },
        { "T1218.005", "System Binary Proxy Execution: Mshta" },
        { "T1218.010", "System Binary Proxy Execution: Regsvr32" },
        { "T1218.011", "System Binary Proxy Execution: Rundll32" },
    };

    [Theory]
    [MemberData(nameof(X1Techniques))]
    [MemberData(nameof(AddedTechniques))]
    public void TryGet_ReturnsOfficialName_ForEveryX1Technique(string id, string expectedName)
    {
        Assert.True(MitreCatalog.TryGet(id, out var technique));
        Assert.Equal(id, technique.Id);
        Assert.Equal(expectedName, technique.Name);
        Assert.True(MitreCatalog.IsKnown(id));
    }

    [Fact]
    public void All_ContainsExactlyTheX1Techniques()
    {
        var expected = X1Techniques.Concat(AddedTechniques).Select(row => (string)row[0]).Order(StringComparer.Ordinal);
        var actual = MitreCatalog.All.Select(t => t.Id).Order(StringComparer.Ordinal);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void AllCatalogIds_HaveValidFormat_AndNonEmptyNames()
    {
        Assert.All(MitreCatalog.All, t =>
        {
            Assert.True(MitreTechniqueIdFormat.IsValid(t.Id));
            Assert.False(string.IsNullOrWhiteSpace(t.Name));
        });
    }

    [Fact]
    public void Constants_MatchCatalogEntries()
    {
        var constants = typeof(MitreTechniqueIds)
            .GetFields()
            .Where(f => f.IsLiteral)
            .Select(f => (string)f.GetRawConstantValue()!)
            .ToList();

        Assert.Equal(MitreCatalog.All.Count, constants.Count);
        Assert.All(constants, id => Assert.True(MitreCatalog.IsKnown(id), id));
    }

    [Theory]
    [InlineData("T9999")]
    [InlineData("T1547.999")]
    [InlineData("t1547.001")]
    [InlineData(" T1547.001")]
    [InlineData("")]
    [InlineData(null)]
    public void UnknownOrMalformedIds_AreNotFound(string? id)
    {
        Assert.False(MitreCatalog.TryGet(id, out var technique));
        Assert.Null(technique);
        Assert.False(MitreCatalog.IsKnown(id));
    }
}
