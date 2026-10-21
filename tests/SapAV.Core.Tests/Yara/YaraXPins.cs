using System.Xml.Linq;
using SapAV.Core.Tests.TestSupport;

namespace SapAV.Core.Tests.Yara;

/// <summary>The pinned YARA-X version and hashes, read from <c>native/yara-x/YaraX.targets</c> (one source of truth).</summary>
internal static class YaraXPins
{
    public static string TargetsPath => Path.Combine(RepoPaths.Root, "native", "yara-x", "YaraX.targets");

    private static readonly Lazy<XElement> Properties = new(() =>
        XDocument.Load(TargetsPath).Root!.Elements("PropertyGroup").First());

    public static string Version => Property("YaraXVersion");

    public static string AssetSha256 => Property("YaraXAssetSha256");

    public static string DllSha256 => Property("YaraXDllSha256");

    public static string AssetName => $"yara-x-capi-v{Version}-x86_64-pc-windows-msvc.zip";

    private static string Property(string name) =>
        Properties.Value.Element(name)?.Value.Trim() ?? throw new InvalidOperationException($"{name} not found in {TargetsPath}");
}
