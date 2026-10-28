using SapAV.Core.Hashing;
using SapAV.Core.Mitre;
using SapAV.Core.Models;
using SapAV.Core.Persistence;
using SapAV.Core.Scanning;
using SapAV.Core.Signatures;

namespace SapAV.Core.Tests.Persistence;

/// <summary>Synthetic entries, scan reports and ACL answers for the C3 judgement tests (no files, no registry).</summary>
internal static class Judging
{
    public const string Sid = "S-1-5-21-1000-2000-3000-1001";
    public const string SystemRoot = @"C:\Windows";
    public const string MachineRun = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    public const string UserRun = @"HKU\" + Sid + @"\Software\Microsoft\Windows\CurrentVersion\Run";
    public const string Ifeo = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

    public static PersistenceJudge Judge { get; } = new(new PersistenceJudgeOptions { SystemRoot = SystemRoot });

    public static PersistenceEntry Entry(
        string? target, PersistenceKind kind = PersistenceKind.RunKey, string? sid = null, string? location = null, string? valueName = "App",
        string? host = null, bool enabled = true, TargetUnresolvedReason? unresolved = null, params ResolutionFlag[] flags)
    {
        var resolution = target is null
            ? ResolvedCommand.Unresolved(unresolved ?? TargetUnresolvedReason.InlineCommand, host, "", flags)
            : ResolvedCommand.Resolved(target, "", host, flags);
        location ??= kind switch
        {
            PersistenceKind.IfeoDebugger => Ifeo + @"\notepad.exe",
            PersistenceKind.Service => @"HKLM\SYSTEM\CurrentControlSet\Services\TestSvc",
            PersistenceKind.WinlogonShell or PersistenceKind.WinlogonUserinit => @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            _ => sid is null ? MachineRun : UserRun,
        };
        return new PersistenceEntry(kind, sid, location, valueName, target ?? "inline", resolution, enabled,
            kind == PersistenceKind.Service ? ServiceStartType.Automatic : null);
    }

    public static FileScanReport Report(string path, Verdict? verdict = null, SignatureCheckResult? signature = null)
    {
        var item = new ScanItem(path, ScanTrigger.Persistence);
        Detection[] detections = verdict switch
        {
            Verdict.Malicious => [new Detection(Verdict.Malicious, "YARA rule Test_Marker matched", MitreTechniqueIds.MaliciousFile, DetectionSource.Yara)],
            Verdict.Suspicious => [new Detection(Verdict.Suspicious, "Heuristic score 75: test", MitreTechniqueIds.SoftwarePacking, DetectionSource.Heuristic)],
            _ => [],
        };
        signature ??= SignatureCheckResult.NotSigned();
        string sha = new('a', 64);
        var result = new ScanResult(item, detections, DateTimeOffset.UtcNow, sha, ScanStatus.Scanned, signature.Status, signature.TrustedSignerName);
        return new FileScanReport(result, HashResult.Hashed(sha, 100), signature, null, null, null, []);
    }

    public static FileScanReport NotFound(string path)
    {
        var hash = HashResult.NotHashed(HashFailureReason.NotFound, "not found");
        return new FileScanReport(ScanResult.NotScanned(new ScanItem(path, ScanTrigger.Persistence), hash.Status, DateTimeOffset.UtcNow), hash,
            null, null, null, null, []);
    }

    public static SignatureCheckResult MicrosoftSigned() =>
        SignatureCheckResult.Trusted(SignatureStatus.Microsoft, SignatureKind.Catalog,
            new SignatureSigner([new SignatureCertificate("CN=Microsoft Windows", "CN=Microsoft Windows Production PCA 2011", new string('B', 40), new string('B', 64))], null));

    public static SignatureCheckResult VendorSigned() =>
        SignatureCheckResult.Trusted(SignatureStatus.OtherTrusted, SignatureKind.Embedded,
            new SignatureSigner([new SignatureCertificate("CN=Contoso", "CN=Contoso CA", new string('A', 40), new string('A', 64))], null));

    public static PersistenceJudgement Run(PersistenceEntry entry, FileScanReport? target = null, FileScanReport? host = null, IPathWritability? acl = null) =>
        Judge.Judge(entry, target, host, acl ?? new FakeAcl());

    public static bool Has(this PersistenceJudgement judgement, string rule) => judgement.Signals.Any(s => s.Rule == rule);
}

/// <summary>
/// ACL answers by path: files listed in <see cref="Modifiable"/> are user-modifiable; a path whose folder (or an ancestor)
/// is in <see cref="UserFolders"/> is user-creatable. Everything else is AdminOnly.
/// </summary>
internal sealed class FakeAcl : IPathWritability
{
    public HashSet<string> Modifiable { get; } = new(StringComparer.OrdinalIgnoreCase);

    public HashSet<string> UserFolders { get; } = new(StringComparer.OrdinalIgnoreCase);

    public List<string> Asked { get; } = [];

    public FakeAcl WithFolder(string folder)
    {
        UserFolders.Add(folder);
        return this;
    }

    public Writability FileModifiable(string filePath)
    {
        Asked.Add(filePath);
        return Modifiable.Contains(filePath) ? Writability.UserWritable : Writability.AdminOnly;
    }

    public Writability FileCreatable(string filePath)
    {
        Asked.Add(filePath);
        for (var folder = Path.GetDirectoryName(filePath); folder is not null; folder = Path.GetDirectoryName(folder))
        {
            if (UserFolders.Contains(folder))
            {
                return Writability.UserWritable;
            }
        }

        return Writability.AdminOnly;
    }
}
