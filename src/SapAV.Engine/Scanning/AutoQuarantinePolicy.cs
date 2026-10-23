using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Models;
using SapAV.Core.Scanning;
using SapAV.Engine.Scanning.Native;

namespace SapAV.Engine.Scanning;

/// <summary>Reads a file's owner and DACL from its handle. Fake it in tests (a test can't create SYSTEM-owned files unelevated).</summary>
internal interface IFileSecurityReader
{
    RawSecurityDescriptor? Read(SafeFileHandle handle);
}

internal sealed class HandleSecurityReader : IFileSecurityReader
{
    public static HandleSecurityReader Instance { get; } = new();

    public RawSecurityDescriptor? Read(SafeFileHandle handle) => ScanNative.TryGetOwnerAndDacl(handle);
}

/// <summary>
/// Where scan jobs may quarantine on their own (review B5 M3). A compromised worker could report any file Malicious, so
/// files a normal user can't change are never moved automatically; they are flagged "needs user confirmation" instead:
/// <list type="bullet">
/// <item>anything under Windows, Program Files (both views) or a configured protected folder (requested or final path; a
/// path that can't be normalised counts as protected, review L1);</item>
/// <item>files owned by SYSTEM or TrustedInstaller;</item>
/// <item>review M4: files no non-admin principal may modify or delete, i.e. the owner is SYSTEM / Administrators /
/// TrustedInstaller and no allow ACE grants write, delete, WRITE_DAC or WRITE_OWNER to anyone else (Users, Authenticated
/// Users, Everyone, INTERACTIVE, a user). An Administrators-owned file in a user's folder that the user can modify (the
/// usual inherited ACL) stays eligible.</item>
/// </list>
/// Owner or DACL unreadable = protected (fail closed). Only <see cref="Verdict.Malicious"/> is ever eligible: Suspicious,
/// and the PUP / HackTool category (E1), never are.
/// </summary>
internal sealed class AutoQuarantinePolicy
{
    /// <summary>NT SERVICE\TrustedInstaller.</summary>
    public static readonly SecurityIdentifier TrustedInstaller = new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    public static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);

    public static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    /// <summary>OWNER RIGHTS and CREATOR OWNER stand for the (admin) owner here, not for another principal.</summary>
    private static readonly SecurityIdentifier OwnerRights = new("S-1-3-4");
    private static readonly SecurityIdentifier CreatorOwner = new(WellKnownSidType.CreatorOwnerSid, null);

    /// <summary>FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE.</summary>
    private const int ModifyMask = 0x2 | 0x4 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;

    private readonly FolderSet _protected;
    private readonly IFileSecurityReader _security;

    public AutoQuarantinePolicy(IEnumerable<string> extraProtectedFolders, IFileSecurityReader? security = null)
    {
        _protected = new FolderSet(DefaultProtectedFolders().Concat(extraProtectedFolders));
        _security = security ?? HandleSecurityReader.Instance;
    }

    public FolderSet ProtectedFolders => _protected;

    /// <summary>The Windows folder and both Program Files folders.</summary>
    public static IEnumerable<string> DefaultProtectedFolders() =>
    [
        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        Environment.GetEnvironmentVariable("ProgramW6432") ?? string.Empty,
    ];

    /// <summary>True only for a scanned, Malicious result. Never for Suspicious or PUP.</summary>
    public static bool IsEligibleVerdict(FileScanReport report) =>
        report.Result.Status == ScanStatus.Scanned && report.Result.Verdict == Verdict.Malicious;

    /// <summary>Why the file must not be auto-quarantined (it needs the user), or null if it may be.</summary>
    /// <param name="opened">The scan's handle (for owner and DACL); null = no handle, which is refused.</param>
    public string? ProtectedReason(FileScanReport report, OpenedScanFile? opened)
    {
        string path = report.Result.Item.Path;
        string? finalPath = report.Identity?.FinalPath;
        if (FolderSet.Normalize(path) is null || (finalPath is not null && FolderSet.Normalize(finalPath) is null))
        {
            return "the file's location could not be checked against the protected folders";
        }

        if (_protected.Contains(path) || _protected.Contains(finalPath))
        {
            return "the file is in a protected system folder (Windows or Program Files)";
        }

        return opened is null ? "the scan has no open handle to the file" : JudgeSecurity(_security.Read(opened.Handle));
    }

    /// <summary>The refusal for a file's owner and DACL, or null if a non-admin principal may change it.</summary>
    internal static string? JudgeSecurity(RawSecurityDescriptor? descriptor)
    {
        var owner = descriptor?.Owner;
        return owner is null ? "the file's owner and permissions could not be read"
            : owner == LocalSystem ? "the file is owned by SYSTEM"
            : owner == TrustedInstaller ? "the file is owned by TrustedInstaller"
            : !NonAdminCanModify(descriptor!) ? "only SYSTEM, Administrators or TrustedInstaller may change or delete the file"
            : null;
    }

    /// <summary>True if a non-admin owner, a NULL DACL, or an allow ACE for a non-admin SID lets someone else modify or delete it.</summary>
    internal static bool NonAdminCanModify(RawSecurityDescriptor descriptor)
    {
        if (descriptor.Owner is not { } owner || !IsAdmin(owner))
        {
            return true; // a user owner can always rewrite the DACL
        }

        if (descriptor.DiscretionaryAcl is not { } dacl)
        {
            return true; // NULL DACL: everyone has full access
        }

        foreach (var ace in dacl)
        {
            if (ace is QualifiedAce { AceQualifier: AceQualifier.AccessAllowed } allow
                && (allow.AceFlags & AceFlags.InheritOnly) == 0
                && (allow.AccessMask & ModifyMask) != 0
                && !IsAdmin(allow.SecurityIdentifier))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsAdmin(SecurityIdentifier sid) =>
        sid == LocalSystem || sid == Administrators || sid == TrustedInstaller || sid == OwnerRights || sid == CreatorOwner;
}

/// <summary>Sliding-window limit on automatic quarantines (review B5 M3); thread-safe.</summary>
internal sealed class AutoQuarantineLimiter(TimeProvider time, int maxPerWindow, TimeSpan window)
{
    private readonly Queue<DateTimeOffset> _recent = new();
    private readonly Lock _lock = new();
    private DateTimeOffset _burstReportedAt = DateTimeOffset.MinValue;

    public int MaxPerWindow => maxPerWindow;

    public TimeSpan Window => window;

    /// <summary>Takes one slot; false when <see cref="MaxPerWindow"/> were used in the last <see cref="Window"/>.</summary>
    /// <param name="firstRefusalInWindow">True for the first refusal of a burst (raise the burst alert once).</param>
    public bool TryAcquire(out bool firstRefusalInWindow)
    {
        var now = time.GetUtcNow();
        lock (_lock)
        {
            while (_recent.TryPeek(out var oldest) && now - oldest >= window)
            {
                _recent.Dequeue();
            }

            if (_recent.Count < maxPerWindow)
            {
                _recent.Enqueue(now);
                firstRefusalInWindow = false;
                return true;
            }

            firstRefusalInWindow = now - _burstReportedAt >= window;
            if (firstRefusalInWindow)
            {
                _burstReportedAt = now;
            }

            return false;
        }
    }
}
