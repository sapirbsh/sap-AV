using System.Text;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Tests.TestSupport;
using SapAV.Core.Yara;

namespace SapAV.Core.Tests.Yara;

/// <summary>Loading, compiling and the rule meta (verdict / mitre) of <see cref="YaraRuleSet"/>.</summary>
public sealed class YaraRuleSetTests : IDisposable
{
    private readonly TempDirectory _dir = new();

    public void Dispose() => _dir.Dispose();

    private static YaraScanResult ScanBytes(YaraRuleSet rules, byte[] data) => new YaraScanner(rules).ScanMemory(data);

    // --- The shipped EICAR rule ---

    [Fact]
    public void ShippedEicarRule_MatchesRuntimeEicarBytes_InMemory()
    {
        using var rules = YaraRuleSet.LoadDirectory(RepoPaths.RulesDirectory);
        Assert.Empty(rules.FileErrors);
        Assert.Empty(rules.Warnings);

        var result = ScanBytes(rules, Eicar.Bytes());

        Assert.True(result.IsScanned, result.ErrorMessage);
        var match = Assert.Single(result.Matches);
        Assert.Equal("EICAR_Test_File", match.Identifier);
        Assert.Equal("antivirus-test-file.yar", match.File);

        var detection = Assert.Single(result.Detections);
        Assert.Equal(Verdict.Malicious, detection.Verdict);
        Assert.Equal(DetectionSource.Yara, detection.Source);
        Assert.Equal(MitreTechniqueIds.MaliciousFile, detection.TechniqueId);
        Assert.Contains("EICAR_Test_File", detection.Reason);
    }

    [Theory]
    [InlineData("prefix")] // not at offset 0
    [InlineData("long")]   // over 128 bytes
    [InlineData("clean")]
    public void ShippedEicarRule_DoesNotMatchNearMisses(string variant)
    {
        using var rules = YaraRuleSet.LoadDirectory(RepoPaths.RulesDirectory);
        var eicar = Eicar.Bytes();
        byte[] data = variant switch
        {
            "prefix" => [(byte)' ', .. eicar],
            "long" => [.. eicar, .. new byte[100]],
            _ => Encoding.ASCII.GetBytes("just an ordinary text file"),
        };

        var result = ScanBytes(rules, data);

        Assert.True(result.IsScanned);
        Assert.Empty(result.Matches);
    }

    [Fact]
    public void ShippedEicarRuleFile_HasMitreMetaAndDescription()
    {
        using var rules = YaraRuleSet.LoadDirectory(RepoPaths.RulesDirectory);
        var rule = Assert.Single(rules.Rules, r => r.Identifier == "EICAR_Test_File");

        Assert.Equal("T1204.002", rule.Mitre.PrimaryId);
        Assert.Contains("antivirus test file", rule.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void NativeLibyara_IsCopiedToTheOutput()
    {
        Assert.True(File.Exists(Path.Combine(AppContext.BaseDirectory, "libyara.dll")), "libyara.dll missing from the test output");
    }

    // --- Loading a directory ---

    [Fact]
    public void BrokenFile_IsSkippedAndReported_OthersStillLoad()
    {
        File.WriteAllText(_dir.File("good.yar"), YaraTestRules.MarkerRule("Good_Rule"));
        File.WriteAllText(_dir.File("broken.yar"), "rule Broken { condition: $undefined }");
        Directory.CreateDirectory(_dir.File("third-party"));
        File.WriteAllText(_dir.File(Path.Combine("third-party", "nested.yar")), "rule Nested { condition: filesize == 3 }");
        File.WriteAllText(_dir.File("notes.txt"), "not a rule");

        using var rules = YaraRuleSet.LoadDirectory(_dir.Path);

        Assert.Equal(["good.yar", "third-party/nested.yar"], rules.LoadedFiles);
        var error = Assert.Single(rules.FileErrors);
        Assert.Equal("broken.yar", error.File);
        Assert.Contains(error.Errors, e => e.Contains("line 1", StringComparison.Ordinal) && e.Contains("undefined"));

        var result = ScanBytes(rules, YaraTestRules.MarkerBytes());
        Assert.Equal(["Good_Rule"], result.Matches.Select(m => m.Identifier));
        Assert.Equal("third-party/nested.yar", Assert.Single(ScanBytes(rules, [1, 2, 3]).Matches).File);
    }

    [Fact]
    public void SameRuleNameInTwoFiles_BothLoad_InTheirOwnNamespace()
    {
        using var rules = YaraRuleSet.FromSources(
        [
            new YaraRuleSource("a.yar", YaraTestRules.MarkerRule("Dup")),
            new YaraRuleSource("b.yar", YaraTestRules.MarkerRule("Dup")),
        ]);

        Assert.Empty(rules.FileErrors);
        var result = ScanBytes(rules, YaraTestRules.MarkerBytes());
        Assert.Equal(["a.yar", "b.yar"], result.Matches.Select(m => m.File));
    }

    [Fact]
    public void Include_IsDisabled()
    {
        File.WriteAllText(_dir.File("target.yara"), "rule Included { condition: true }");
        using var rules = YaraRuleSet.FromSource("inc.yar", $"include \"{_dir.File("target.yara").Replace("\\", "\\\\")}\"");

        var error = Assert.Single(rules.FileErrors);
        Assert.Contains(error.Errors, e => e.Contains("include", StringComparison.OrdinalIgnoreCase));
        Assert.Empty(rules.Rules);
    }

    [Fact]
    public void Utf8TextStrings_AndBom_AreHandled()
    {
        // ANSI marshalling (dnYara's AddRuleString) would mangle the non-ASCII text.
        File.WriteAllBytes(_dir.File("utf8.yar"),
            [0xEF, 0xBB, 0xBF, .. Encoding.UTF8.GetBytes("rule Utf8 { strings: $s = \"שלום-漢字\" condition: $s }")]);
        using var rules = YaraRuleSet.LoadDirectory(_dir.Path);

        Assert.Empty(rules.FileErrors);
        Assert.Single(ScanBytes(rules, Encoding.UTF8.GetBytes("x שלום-漢字 y")).Matches);
    }

    [Fact]
    public void OversizedOrBinaryRuleFiles_AreReported()
    {
        File.WriteAllText(_dir.File("big.yar"), new string(' ', 200));
        File.WriteAllBytes(_dir.File("binary.yar"), [0x72, 0x00, 0x75]);

        using var rules = YaraRuleSet.LoadDirectory(_dir.Path, maxRuleFileBytes: 100);

        Assert.Equal(["big.yar", "binary.yar"], rules.FileErrors.Select(e => e.File));
        Assert.Empty(rules.LoadedFiles);
        Assert.True(ScanBytes(rules, [1]).IsScanned); // an empty rule set still scans (no matches)
    }

    [Fact]
    public void MissingDirectory_Throws()
    {
        Assert.Throws<DirectoryNotFoundException>(() => YaraRuleSet.LoadDirectory(_dir.File("nope")));
    }

    // --- Fingerprint ---

    [Fact]
    public void Fingerprint_DependsOnLoadedContent_NotOnBrokenFilesOrOrder()
    {
        string Fp(params (string Name, string Text)[] sources)
        {
            using var set = YaraRuleSet.FromSources(sources.Select(s => new YaraRuleSource(s.Name, s.Text)));
            return set.Fingerprint;
        }

        var a = ("a.yar", "rule A { condition: true }");
        var b = ("b.yar", "rule B { condition: false }");
        var broken = ("c.yar", "rule {");

        Assert.Matches("^[0-9a-f]{64}$", Fp(a, b));
        Assert.Equal(Fp(a, b), Fp(b, a));
        Assert.Equal(Fp(a, b), Fp(a, b, broken));
        Assert.NotEqual(Fp(a, b), Fp(a));
        Assert.NotEqual(Fp(a, b), Fp(a, ("b.yar", "rule B { condition: true }")));
        Assert.NotEqual(Fp(a), Fp(("renamed.yar", a.Item2)));
    }

    // --- Meta: verdict ---

    [Theory]
    [InlineData("", Verdict.Malicious, false)]
    [InlineData("verdict = \"malicious\"", Verdict.Malicious, false)]
    [InlineData("verdict = \" Suspicious \"", Verdict.Suspicious, false)]
    [InlineData("verdict = \"pup\"", Verdict.Suspicious, false)]
    [InlineData("verdict = \"bad-ish\"", Verdict.Suspicious, true)]
    [InlineData("verdict = 2", Verdict.Suspicious, true)]
    public void VerdictMeta_IsInterpreted(string meta, Verdict expected, bool warns)
    {
        using var rules = YaraTestRules.MarkerSet(meta);

        Assert.Equal(expected, Assert.Single(rules.Rules).Verdict);
        Assert.Equal(warns, rules.Warnings.Any(w => w.Kind == YaraWarningKind.Verdict));
        Assert.Equal(expected, Assert.Single(ScanBytes(rules, YaraTestRules.MarkerBytes()).Detections).Verdict);
    }

    // --- Meta: mitre (carried over from the A1 review) ---

    public static TheoryData<string, string, string[], string?> MitreCases => new()
    {
        // meta line, primary, secondaries, raw value in the warning (null = no warning)
        { "mitre = \"T1059.001\"", "T1059.001", [], null },
        { "mitre = \"  t1059.001 ,T1027 \"", "T1059.001", ["T1027"], null },     // trim/upper-case only
        { "mitre = \"T1059.001, t1059.001\"", "T1059.001", [], null },           // duplicate: same meaning
        { "mitre = \"T1059,001\"", "T1059", [], "T1059,001" },                   // token dropped
        { "mitre = \"T1059.001; T99\"", "T1059.001", [], "T1059.001; T99" },
        { "mitre = \"credential theft\"", "T1204.002", [], "credential theft" }, // nothing valid: fallback
        { "mitre = \"\"", "T1204.002", [], "" },
        { "mitre = 1059", "T1204.002", [], "1059" },                             // not a string
        { "", "T1204.002", [], null },                                           // missing: documented default
    };

    [Theory]
    [MemberData(nameof(MitreCases))]
    public void MitreMeta_IsNormalized_AndChangesAreWarned(string meta, string primary, string[] secondaries, string? warnedRaw)
    {
        using var rules = YaraTestRules.MarkerSet(meta);

        var rule = Assert.Single(rules.Rules);
        Assert.Equal(primary, rule.Mitre.PrimaryId);
        Assert.Equal(secondaries, rule.Mitre.SecondaryIds);

        var detection = Assert.Single(ScanBytes(rules, YaraTestRules.MarkerBytes()).Detections);
        Assert.Equal(primary, detection.TechniqueId);

        var warnings = rules.Warnings.Where(w => w.Kind == YaraWarningKind.Mitre).ToArray();
        if (warnedRaw is null)
        {
            Assert.Empty(warnings);
        }
        else
        {
            var warning = Assert.Single(warnings);
            Assert.Equal("Test_Marker", warning.Rule);
            Assert.Equal("marker.yar", warning.File);
            Assert.Contains("Test_Marker", warning.Message);
            Assert.Contains(warnedRaw, warning.Message);
            Assert.Contains(primary, warning.Message);
        }
    }

    [Theory]
    [InlineData("T1059,001", new[] { "001" })]
    [InlineData(" t1059.001 ; T1027 ", new string[0])]
    [InlineData("T1059.001 T1059.001", new string[0])]
    [InlineData("x T1.2 T1059", new[] { "x", "T1.2" })]
    [InlineData(null, new string[0])]
    public void InvalidTokens_ListsWhatTryNormalizeDrops(string? raw, string[] expected)
    {
        Assert.Equal(expected, MitreTechniqueIdFormat.InvalidTokens(raw));
    }

    [Fact]
    public void CompilerWarnings_AreReported_ForTheFileAndRule()
    {
        // A loop over every byte makes YARA warn that the rule may slow down scanning.
        using var rules = YaraRuleSet.FromSource("slow.yar",
            "rule Slow { strings: $a = { 00 } condition: for all i in (1..#a) : (@a[i] >= 0) }");

        Assert.Empty(rules.FileErrors);
        var warning = Assert.Single(rules.Warnings, w => w.Kind == YaraWarningKind.Compiler);
        Assert.Equal("slow.yar", warning.File);
    }

    [Fact]
    public void PrivateRules_AreNotListedOrReported()
    {
        using var rules = YaraRuleSet.FromSource("p.yar",
            "private rule Helper { condition: true } rule Uses { condition: Helper }");

        Assert.Equal(["Uses"], rules.Rules.Select(r => r.Identifier));
        Assert.Equal(["Uses"], ScanBytes(rules, [1]).Matches.Select(m => m.Identifier));
    }
}
