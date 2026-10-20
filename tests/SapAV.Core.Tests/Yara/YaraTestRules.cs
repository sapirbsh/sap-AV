using System.Text;
using SapAV.Core.Yara;

namespace SapAV.Core.Tests.Yara;

/// <summary>Harmless test rules and the marker they look for.</summary>
internal static class YaraTestRules
{
    public const string Marker = "SAPAV-YARA-TEST-MARKER-7F3C";

    public static byte[] MarkerBytes(string prefix = "some harmless text ", string suffix = " more text") =>
        Encoding.ASCII.GetBytes(prefix + Marker + suffix);

    public static string MarkerRule(string name = "Test_Marker", string meta = "") => $$"""
        rule {{name}}
        {
            meta:
                description = "test marker"
                {{meta}}
            strings:
                $m = "{{Marker}}"
            condition:
                $m
        }
        """;

    public static YaraRuleSet MarkerSet(string meta = "") => YaraRuleSet.FromSource("marker.yar", MarkerRule(meta: meta));
}
