using System.Text.Json;
using System.Text.Json.Nodes;
using SapAV.Core.Mitre;
using SapAV.Core.Persistence;

namespace SapAV.Core.Tests.Persistence;

/// <summary>The C2 contract: strict JSON like the A1 models, validation as a whole, sanitized untrusted text.</summary>
public class PersistenceEntryTests
{
    private const string Sid = "S-1-5-21-1000-2000-3000-1001";

    private static PersistenceEntry Sample() => new(
        PersistenceKind.RunKey, Sid, $@"HKU\{Sid}\Software\Microsoft\Windows\CurrentVersion\Run", "Updater",
        @"""C:\Users\alice\AppData\Roaming\upd.exe"" /s",
        ResolvedCommand.Resolved(@"C:\Users\alice\AppData\Roaming\upd.exe", "/s", flags: [ResolutionFlag.UserEnvironment]),
        enabled: true);

    [Fact]
    public void Json_RoundTrips_AndWritesTheTechnique()
    {
        var entry = Sample();
        var json = JsonSerializer.Serialize(entry);

        Assert.Equal(entry, JsonSerializer.Deserialize<PersistenceEntry>(json));
        Assert.Equal("T1547.001", JsonNode.Parse(json)!["TechniqueId"]!.GetValue<string>());
        Assert.Equal("RunKey", JsonNode.Parse(json)!["Kind"]!.GetValue<string>());
    }

    [Fact]
    public void Json_MissingKindOrNumericEnum_Throws()
    {
        var node = JsonNode.Parse(JsonSerializer.Serialize(Sample()))!.AsObject();
        node.Remove("Kind");
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<PersistenceEntry>(node.ToJsonString()));

        node["Kind"] = 0;
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<PersistenceEntry>(node.ToJsonString()));
    }

    [Fact]
    public void Json_TargetAndReasonTogether_OrAnUnnormalizedPath_Throws()
    {
        var both = JsonNode.Parse(JsonSerializer.Serialize(Sample()))!.AsObject();
        both["Resolution"]!["UnresolvedReason"] = "NotFoundOnSearchPath";
        Assert.ThrowsAny<ArgumentException>(() => JsonSerializer.Deserialize<PersistenceEntry>(both.ToJsonString()));

        var unc = JsonNode.Parse(JsonSerializer.Serialize(Sample()))!.AsObject();
        unc["Resolution"]!["TargetPath"] = @"\\server\share\a.exe";
        Assert.ThrowsAny<ArgumentException>(() => JsonSerializer.Deserialize<PersistenceEntry>(unc.ToJsonString()));

        Assert.ThrowsAny<ArgumentException>(() => ResolvedCommand.Resolved(@"C:\a\..\b.exe"));
    }

    [Fact]
    public void Scope_MustBeMachineOrASid_AndKindSpecificFieldsStayOnTheirKind()
    {
        var resolution = ResolvedCommand.Unresolved(TargetUnresolvedReason.EmptyCommand);

        Assert.ThrowsAny<ArgumentException>(() => new PersistenceEntry(PersistenceKind.RunKey, "alice", "HKU\\x", null, "", resolution, true));
        Assert.ThrowsAny<ArgumentException>(() =>
            new PersistenceEntry(PersistenceKind.RunKey, null, "HKLM\\x", null, "", resolution, true, ServiceStartType.Automatic));
        Assert.ThrowsAny<ArgumentException>(() =>
            new PersistenceEntry(PersistenceKind.Service, null, "HKLM\\x", null, "", resolution, true, comClassId: Guid.NewGuid()));
        Assert.True(new PersistenceEntry(PersistenceKind.Service, null, "HKLM\\x", "ImagePath", "", resolution, false, ServiceStartType.Disabled).IsMachineScope);
    }

    [Fact]
    public void UntrustedText_IsSanitizedAndCapped()
    {
        var longCommand = "C:\\a.exe " + new string('x', PersistenceEntry.MaxCommandLineLength + 100);
        var entry = new PersistenceEntry(PersistenceKind.RunKey, null, "HKLM\\Run\r\nFAKE", "na\u0000me", longCommand + "\r\nInjected",
            ResolvedCommand.Resolved(@"C:\a.exe"), true);

        Assert.DoesNotContain('\n', entry.Location);
        Assert.DoesNotContain('\0', entry.ValueName!);
        Assert.Equal(PersistenceEntry.MaxCommandLineLength, entry.CommandLine.Length);
        Assert.DoesNotContain('\n', entry.CommandLine);
        Assert.Contains(ResolutionFlag.CommandLineTruncated, entry.Resolution.Flags);
    }

    [Fact]
    public void EveryKind_HasTheX1Technique()
    {
        var expected = new Dictionary<PersistenceKind, string>
        {
            [PersistenceKind.RunKey] = MitreTechniqueIds.RegistryRunKeysStartupFolder,
            [PersistenceKind.RunOnceKey] = MitreTechniqueIds.RegistryRunKeysStartupFolder,
            [PersistenceKind.StartupFolder] = MitreTechniqueIds.RegistryRunKeysStartupFolder,
            [PersistenceKind.WinlogonShell] = MitreTechniqueIds.WinlogonHelperDll,
            [PersistenceKind.WinlogonUserinit] = MitreTechniqueIds.WinlogonHelperDll,
            [PersistenceKind.IfeoDebugger] = MitreTechniqueIds.ImageFileExecutionOptionsInjection,
            [PersistenceKind.IfeoSilentProcessExit] = MitreTechniqueIds.ImageFileExecutionOptionsInjection,
            [PersistenceKind.Service] = MitreTechniqueIds.WindowsService,
            [PersistenceKind.ScheduledTask] = MitreTechniqueIds.ScheduledTask,
        };

        Assert.Equal(Enum.GetValues<PersistenceKind>().Order(), expected.Keys.Order());
        foreach (var (kind, technique) in expected)
        {
            Assert.Equal(technique, PersistenceKinds.TechniqueId(kind));
            Assert.True(MitreCatalog.IsKnown(technique));
        }
    }

    [Fact]
    public void Collection_RoundTrips_WithIssues()
    {
        var collection = new PersistenceCollection(
            [Sample()],
            [new PersistenceIssue(null, Sid, $@"HKU\{Sid}", PersistenceIssueReason.HiveNotLoaded, "Not logged on.\r\nsecond line")],
            TimeSpan.FromMilliseconds(250));

        var copy = JsonSerializer.Deserialize<PersistenceCollection>(JsonSerializer.Serialize(collection))!;

        Assert.Equal(collection.Entries, copy.Entries);
        Assert.Equal(collection.Issues, copy.Issues);
        Assert.DoesNotContain('\n', copy.Issues[0].Message);
        Assert.False(copy.IsComplete);
    }
}
