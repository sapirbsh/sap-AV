using System.Text;
using System.Text.RegularExpressions;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Tests.TestSupport;
using SapAV.Core.Yara;

namespace SapAV.Core.Tests.Yara;

/// <summary>
/// E2: the vendored YARA-Forge subset in <c>data/rules/third-party/</c>: it compiles, every rule's verdict / category / MITRE
/// comes from <c>curated-rules.txt</c> (review M2: nothing defaults silently), only approved licenses are committed, and the
/// loader's stricter third-party meta rules. Synthetic strings and in-memory bytes only, never samples.
/// </summary>
public sealed partial class ThirdPartyRulesTests
{
    private static readonly string ThirdPartyDirectory = Path.Combine(RepoPaths.RulesDirectory, "third-party");

    private static readonly string[] ApprovedLicenses = ["DRL-1.1", "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "CC0-1.0", "CC-BY-4.0"];

    private static readonly Dictionary<string, string> DefaultMitre = new(StringComparer.Ordinal)
    {
        ["infostealer"] = "T1555.003",
        ["miner"] = "T1496.001",
        ["hacktool"] = "T1003",
        ["pup"] = "T1204.002",
    };

    /// <summary>The shipped rules folder, loaded like the engine does, so the vendored files get their <c>third-party/</c> namespace.</summary>
    private static readonly Lazy<YaraRuleSet> Vendored = new(() => YaraRuleSet.LoadDirectory(RepoPaths.RulesDirectory));

    private sealed record CuratedRule(string Name, string Category, string Verdict, string? Mitre);

    private static Dictionary<string, CuratedRule> Curated()
    {
        var rules = new Dictionary<string, CuratedRule>(StringComparer.Ordinal);
        foreach (var line in File.ReadAllLines(Path.Combine(ThirdPartyDirectory, "curated-rules.txt")))
        {
            var t = line.Trim();
            if (t.Length == 0 || t.StartsWith('#'))
            {
                continue;
            }

            var parts = t.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            rules.Add(parts[0], new CuratedRule(parts[0], parts[1], parts[2], parts.Length > 3 ? parts[3] : null));
        }

        return rules;
    }

    private static IEnumerable<YaraRuleInfo> VendoredRules() => Vendored.Value.Rules.Where(r => ThirdPartyRules.IsThirdParty(r.File));

    // --- Compile / skip reporting ---

    [Fact]
    public void EveryVendoredFile_Compiles_WithoutWarnings_AndTheRuleCountIsModerate()
    {
        var set = Vendored.Value;

        Assert.Empty(set.FileErrors);
        var files = Directory.GetFiles(ThirdPartyDirectory, "*.yar").Select(f => ThirdPartyRules.Folder + Path.GetFileName(f)).Order(StringComparer.Ordinal);
        Assert.Equal(files, set.LoadedFiles.Where(ThirdPartyRules.IsThirdParty).Order(StringComparer.Ordinal));
        Assert.InRange(VendoredRules().Count(), 100, 400); // curated and moderate, not the whole release
        // No verdict / category / mitre warning (nothing defaults silently) and no compiler warning (update.ps1 ports them).
        Assert.Empty(set.Warnings);
    }

    [Fact]
    public void ABadThirdPartyFile_IsSkippedAndReported_WhileTheOthersLoad()
    {
        const string Good = "rule TP_Good { meta: verdict = \"malicious\" category = \"infostealer\" strings: $a = \"sapav-e2-good\" condition: $a }";
        using var set = YaraRuleSet.FromSources(
        [
            new YaraRuleSource("third-party/good.yar", Good),
            new YaraRuleSource("third-party/dotnet.yar", "import \"dotnet\"\nrule TP_Net { meta: verdict = \"malicious\" category = \"malware\" condition: dotnet.is_dotnet }"),
            new YaraRuleSource("third-party/legacy.yar", "rule TP_Legacy { meta: verdict = \"malicious\" category = \"malware\" strings: $r = /a\\Rb/ condition: $r }"),
        ]);

        Assert.Equal(["third-party/good.yar"], set.LoadedFiles);
        Assert.Equal(["third-party/dotnet.yar", "third-party/legacy.yar"], set.FileErrors.Select(e => e.File));
        Assert.Contains("dotnet", set.FileErrors[0].Errors[0], StringComparison.Ordinal);
        Assert.Equal("TP_Good", Assert.Single(set.Rules).Identifier);
    }

    // --- Mapping (review M2) ---

    [Fact]
    public void EveryVendoredRule_TakesVerdictCategoryAndMitre_FromTheCuratedTable()
    {
        var curated = Curated();
        var rules = VendoredRules().ToList();

        Assert.NotEmpty(rules);
        Assert.All(rules, rule =>
        {
            Assert.True(curated.TryGetValue(rule.Identifier, out var entry), $"{rule.Identifier} is not in curated-rules.txt");
            var (verdict, category) = (entry.Category, entry.Verdict) switch
            {
                ("infostealer", "malicious") => (Verdict.Malicious, ThreatCategory.Infostealer),
                ("infostealer", "suspicious") => (Verdict.Suspicious, ThreatCategory.Infostealer),
                ("miner", "malicious") => (Verdict.Malicious, ThreatCategory.Miner),
                ("miner", "suspicious") => (Verdict.Suspicious, ThreatCategory.Miner),
                ("hacktool", "hacktool") => (Verdict.PotentiallyUnwanted, ThreatCategory.HackTool),
                ("pup", "pup") => (Verdict.PotentiallyUnwanted, ThreatCategory.Pup),
                _ => throw new Xunit.Sdk.XunitException($"{rule.Identifier}: unexpected mapping {entry.Category}/{entry.Verdict}"),
            };
            Assert.Equal((verdict, category), (rule.Verdict, rule.Category));

            string primary = entry.Mitre?.Split(',')[0] ?? DefaultMitre[entry.Category];
            Assert.Equal(primary, rule.Mitre.PrimaryId);
            Assert.True(MitreCatalog.IsKnown(rule.Mitre.PrimaryId), $"{rule.Identifier}: {rule.Mitre.PrimaryId} is not in the catalog");
            Assert.All(rule.Mitre.SecondaryIds, id => Assert.True(MitreCatalog.IsKnown(id), $"{rule.Identifier}: {id}"));
        });
    }

    [Fact]
    public void RuleNames_AndCategories_AgreeBothWays()
    {
        Assert.All(VendoredRules(), rule =>
        {
            if (ThirdPartyRules.HasMalwareName(rule.Identifier))
            {
                Assert.False(ThreatCategories.IsPotentiallyUnwanted(rule.Category), $"{rule.Identifier} is malware but mapped to {rule.Category}");
            }

            if (ThirdPartyRules.HasUnwantedName(rule.Identifier))
            {
                Assert.True(ThreatCategories.IsPotentiallyUnwanted(rule.Category), $"{rule.Identifier} is a hack tool / PUA but mapped to {rule.Category}");
                Assert.Equal(Verdict.PotentiallyUnwanted, rule.Verdict);
            }
        });
    }

    [Theory]
    // Third-party: both metas present -> as declared.
    [InlineData("third-party/a.yar", "X_HKTL_Tool", "verdict = \"hacktool\" category = \"hacktool\"", Verdict.PotentiallyUnwanted, ThreatCategory.HackTool, null)]
    // Third-party: a missing verdict or category never defaults to Malicious.
    [InlineData("third-party/a.yar", "X_MALWARE_Thing", "", Verdict.Suspicious, ThreatCategory.Malware, YaraWarningKind.Verdict)]
    [InlineData("third-party/a.yar", "X_MALWARE_Thing", "verdict = \"malicious\"", Verdict.Suspicious, ThreatCategory.Malware, YaraWarningKind.Verdict)]
    // Third-party: a malware-named rule can't be a hack tool (it would never be quarantined).
    [InlineData("third-party/a.yar", "X_Infostealer_Win_Fake", "verdict = \"hacktool\" category = \"hacktool\"", Verdict.Suspicious, ThreatCategory.Malware, YaraWarningKind.Category)]
    // Our own rules keep the documented Malicious default.
    [InlineData("own.yar", "X_MALWARE_Thing", "", Verdict.Malicious, ThreatCategory.Malware, null)]
    public void Loader_EnforcesExplicitThirdPartyMapping(string file, string rule, string meta, Verdict verdict, ThreatCategory category, YaraWarningKind? warning)
    {
        using var set = YaraRuleSet.FromSource(file, $"rule {rule} {{ meta: {meta} description = \"x\" strings: $a = \"sapav-e2-loader\" condition: $a }}");

        var info = Assert.Single(set.Rules);
        Assert.Equal((verdict, category), (info.Verdict, info.Category));
        Assert.Equal(warning, set.Warnings.SingleOrDefault()?.Kind);
    }

    // --- Licensing ---

    [GeneratedRegex(@"(?ms)^rule\s+(?<name>\w+).*?^\}")]
    private static partial Regex RuleBlock();

    private static string? Meta(string rule, string name) =>
        Regex.Match(rule, $@"(?m)^\s*{name}\s*=\s*""(?<v>[^""]*)""") is { Success: true } m ? m.Groups["v"].Value : null;

    [Fact]
    public void EveryCommittedRule_HasAnApprovedLicense_AnAuthor_AndALicenseTextThatShips()
    {
        int rules = 0;
        foreach (var path in Directory.GetFiles(ThirdPartyDirectory, "*.yar"))
        {
            foreach (Match block in RuleBlock().Matches(File.ReadAllText(path)))
            {
                rules++;
                string name = block.Groups["name"].Value;
                string? spdx = Meta(block.Value, "license_spdx");
                string? license = Meta(block.Value, "license");
                Assert.True(spdx is not null && ApprovedLicenses.Contains(spdx), $"{name}: license_spdx {spdx}");
                Assert.False(string.IsNullOrWhiteSpace(license), $"{name}: no license meta");
                Assert.DoesNotMatch(@"(?i)GPL|General Public|NonCommercial|Non-Commercial|BY-NC|BY-SA|ShareAlike|^N/A$", license!);
                Assert.False(string.IsNullOrWhiteSpace(Meta(block.Value, "author")), $"{name}: no author meta");
                if (Regex.Match(license!, @"licenses/(?<f>[\w.-]+\.txt)") is { Success: true } file)
                {
                    Assert.True(File.Exists(Path.Combine(ThirdPartyDirectory, "licenses", file.Groups["f"].Value)), $"{name}: {file.Value} is missing");
                }
            }
        }

        Assert.Equal(VendoredRules().Count(), rules);
        string notice = File.ReadAllText(Path.Combine(ThirdPartyDirectory, "NOTICE.md"));
        Assert.Contains("yara-forge-rules-", notice, StringComparison.Ordinal);
        Assert.All(Directory.GetFiles(ThirdPartyDirectory, "*.yar"), f => Assert.Contains($"`{Path.GetFileName(f)}`", notice, StringComparison.Ordinal));
        Assert.True(File.Exists(Path.Combine(ThirdPartyDirectory, "licenses", "standard-DRL-1.1.txt")));
        Assert.True(File.Exists(Path.Combine(ThirdPartyDirectory, "licenses", "standard-Apache-2.0.txt")));
    }

    [Fact]
    public void TheFolder_HoldsRulesAndTextOnly_NeverBinaries()
    {
        Assert.All(Directory.GetFiles(ThirdPartyDirectory, "*", SearchOption.AllDirectories), path =>
        {
            Assert.Contains(Path.GetExtension(path).ToLowerInvariant(), new[] { ".yar", ".txt", ".md", ".ps1" });
            Assert.DoesNotContain((byte)0, File.ReadAllBytes(path));
        });
    }

    [Fact]
    public void NormalWindowsBinaries_GetNoMalwareMatch()
    {
        // False-positive smoke test: 150 executables and DLLs that ship with every Windows (read only, never changed).
        string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var files = Directory.EnumerateFiles(system32, "*.exe").Order(StringComparer.OrdinalIgnoreCase).Take(75)
            .Concat(Directory.EnumerateFiles(system32, "*.dll").Order(StringComparer.OrdinalIgnoreCase).Take(75)).ToList();
        var scanner = new YaraScanner(Vendored.Value);

        var hits = files.Select(f => (File: f, Result: scanner.ScanFile(f)))
            .SelectMany(x => x.Result.Matches.Where(m => ThirdPartyRules.IsThirdParty(m.File) && !ThreatCategories.IsPotentiallyUnwanted(m.Category))
                .Select(m => $"{Path.GetFileName(x.File)}: {m.Identifier}"))
            .ToList();

        Assert.True(files.Count >= 100, $"only {files.Count} system files found");
        Assert.Empty(hits);
    }

    // --- Synthetic matches (test strings in memory only) ---

    private static YaraScanResult ScanVendored(byte[] data) => new YaraScanner(Vendored.Value).ScanMemory(data);

    [Fact]
    public void SyntheticInfostealerStrings_AreMalicious_Infostealer()
    {
        // All eight strings of SEKOIA_Clipper_Win_Atlas_Strings, nothing else: a text blob, not a program.
        string text = string.Join("\n", "C:/Users/box/Desktop/ATLAS/ATLAS/main.go", "ATLAS Clipper", "Victim: %s", "Attacker: %s",
            "Install Path: %s", "HWID: %s", "Install Date: %s", "https://t.me/atlasclipper_channel");

        var result = ScanVendored(Encoding.ASCII.GetBytes(text));

        var match = Assert.Single(result.Matches);
        Assert.Equal("SEKOIA_Clipper_Win_Atlas_Strings", match.Identifier);
        Assert.Equal((Verdict.Malicious, ThreatCategory.Infostealer, MitreTechniqueIds.CredentialsFromWebBrowsers),
            (match.Verdict, match.Category, match.Mitre.PrimaryId));
    }

    [Fact]
    public void SyntheticHackToolStrings_ArePotentiallyUnwanted_NeverMalicious()
    {
        // DITEKSHEN_INDICATOR_TOOL_Chromecookiesview: "MZ" at 0 plus five of its UTF-16 strings, built in memory (never on disk).
        // The strings are split so this test assembly doesn't contain them whole.
        var data = new List<byte> { (byte)'M', (byte)'Z', 0, 0 };
        foreach (var s in new[] { "AddRemark" + "CookiesTXT", "Decrypt " + "cookies", "/scookies" + "txt", "/deleteregkey", "Cookies.txt " + "Format" })
        {
            data.AddRange(Encoding.Unicode.GetBytes(s));
            data.AddRange(new byte[] { 0, 0, 0, 0 });
        }

        var result = ScanVendored([.. data]);

        var match = Assert.Single(result.Matches);
        Assert.Equal("DITEKSHEN_INDICATOR_TOOL_Chromecookiesview", match.Identifier);
        Assert.Equal((Verdict.PotentiallyUnwanted, ThreatCategory.HackTool, MitreTechniqueIds.StealWebSessionCookie),
            (match.Verdict, match.Category, match.Mitre.PrimaryId));
    }

    [Fact]
    public void SyntheticMinerCommandLine_IsAPup_AndOrdinaryTextMatchesNothing()
    {
        var miner = ScanVendored(Encoding.ASCII.GetBytes("start /min worker.exe --donate-" + "level=0 --threads 2\r\n"));
        var plain = ScanVendored(Encoding.ASCII.GetBytes("Quarterly report: revenue grew; see attached spreadsheet.\r\n"));

        var match = Assert.Single(miner.Matches);
        Assert.Equal("SIGNATURE_BASE_PUA_Crypto_Mining_Commandline_Indicators_Oct21", match.Identifier);
        Assert.Equal((Verdict.PotentiallyUnwanted, ThreatCategory.Pup, MitreTechniqueIds.ComputeHijacking),
            (match.Verdict, match.Category, match.Mitre.PrimaryId));
        Assert.True(plain.IsScanned);
        Assert.Empty(plain.Matches);
    }
}
