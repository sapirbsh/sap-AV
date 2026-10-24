using System.Security.AccessControl;
using System.Security.Principal;
using SapAV.Engine.Scanning;

namespace SapAV.Engine.EventLogging;

/// <summary>Decides whether a message DLL may be registered for the sap-AV source (B1 review M3). Faked in installer tests.</summary>
public interface IMessageFileLocationCheck
{
    /// <summary>Why <paramref name="messageFile"/> must not be registered, or null if it sits in an admin-only location.</summary>
    string? FindProblem(string messageFile);
}

/// <summary>
/// The real check (B1 review M3). Every reader of the sap-AV log (Event Viewer, a SIEM agent, often as an administrator
/// or SYSTEM) loads the registered message DLL, so a DLL a normal user can replace is a code-loading point for them. The
/// DLL is accepted only if all of these hold:
/// <list type="bullet">
/// <item>it is a fully qualified local path (<c>X:\...</c>; no UNC, device or relative path, no <c>%</c>, because the
/// value is REG_EXPAND_SZ) to an existing file;</item>
/// <item>no part of the path (file, folder, ancestors) is a reparse point, so the checked objects are the loaded ones;</item>
/// <item>the DLL and its folder are owned by SYSTEM, Administrators or TrustedInstaller, and no allow ACE gives anyone
/// else write, append, extended-attribute or attribute write, delete, delete-child, WRITE_DAC, WRITE_OWNER, GENERIC_WRITE
/// or GENERIC_ALL;</item>
/// <item>every ancestor folder is owned by one of them too, and grants nobody else DELETE, delete-child, WRITE_DAC,
/// WRITE_OWNER or GENERIC_ALL, so the folder can't be renamed away and replaced. (Creating new folders, like
/// Authenticated Users may in <c>C:\</c>, is fine.)</item>
/// </list>
/// Inherit-only ACEs don't apply to the object and are ignored; deny ACEs are ignored too (a deny can only make the real
/// access smaller, so the check stays conservative). Anything unreadable is a refusal (fail closed). Program Files and
/// the Windows folder pass; a build output under a user's profile or <c>C:\Projects</c> does not.
/// </summary>
public sealed class MessageFileLocationCheck : IMessageFileLocationCheck
{
    /// <summary>
    /// FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_DELETE_CHILD | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC
    /// | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE: any of them lets a user change or replace the DLL or its folder.
    /// </summary>
    internal const int TargetWriteMask = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;

    /// <summary>DELETE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER | GENERIC_ALL: lets a user rename an ancestor or its children.</summary>
    internal const int AncestorWriteMask = 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000;

    private static readonly SecurityIdentifier OwnerRights = new("S-1-3-4");
    private static readonly SecurityIdentifier CreatorOwner = new(WellKnownSidType.CreatorOwnerSid, null);

    public static MessageFileLocationCheck Instance { get; } = new();

    public string? FindProblem(string messageFile)
    {
        if (PathProblem(messageFile) is { } pathProblem)
        {
            return pathProblem;
        }

        try
        {
            var file = new FileInfo(messageFile);
            if (!file.Exists)
            {
                return $"the message file '{messageFile}' does not exist";
            }

            if (Judge(file, file.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access), TargetWriteMask) is { } fileProblem)
            {
                return $"the message file '{file.FullName}' {fileProblem}";
            }

            var folder = file.Directory!;
            if (Judge(folder, folder.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access), TargetWriteMask) is { } folderProblem)
            {
                return $"the message file's folder '{folder.FullName}' {folderProblem}";
            }

            for (var ancestor = folder.Parent; ancestor is not null; ancestor = ancestor.Parent)
            {
                if (Judge(ancestor, ancestor.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access), AncestorWriteMask) is { } problem)
                {
                    return $"the folder '{ancestor.FullName}' above the message file {problem}";
                }
            }

            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException
                                       or ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            return $"the permissions of '{messageFile}' could not be checked ({ex.GetType().Name}: {ex.Message})";
        }
    }

    /// <summary>The refusal for the path's form, or null if it is a plain fully qualified local path.</summary>
    internal static string? PathProblem(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return "no message file is configured";
        }

        bool localDrive = path.Length >= 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' && path[2] == '\\';
        if (!localDrive || path.Contains('%') || path.Contains('/') || path.Contains("\\\\", StringComparison.Ordinal)
            || !string.Equals(Path.GetFullPath(path), path, StringComparison.OrdinalIgnoreCase))
        {
            return $"the message file path '{path}' is not a plain, fully qualified local path";
        }

        return null;
    }

    /// <summary>The refusal for one path component, or null if only admins can change it in the ways <paramref name="writeMask"/> covers.</summary>
    internal static string? Judge(FileSystemInfo item, FileSystemSecurity security, int writeMask)
    {
        if ((item.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            return "is a reparse point (junction or symbolic link)";
        }

        return Judge(new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0), writeMask);
    }

    /// <summary>The refusal for an owner + DACL, or null if no non-admin principal gets any right in <paramref name="writeMask"/>.</summary>
    internal static string? Judge(RawSecurityDescriptor? descriptor, int writeMask)
    {
        if (descriptor?.Owner is not { } owner)
        {
            return "has an owner that could not be read";
        }

        if (!IsTrustedOwner(owner))
        {
            return $"is owned by {Describe(owner)}, not SYSTEM, Administrators or TrustedInstaller";
        }

        if (descriptor.DiscretionaryAcl is not { } dacl)
        {
            return "has no DACL (everyone has full access)";
        }

        foreach (var ace in dacl)
        {
            if (ace is QualifiedAce { AceQualifier: AceQualifier.AccessAllowed } allow
                && (allow.AceFlags & AceFlags.InheritOnly) == 0
                && (allow.AccessMask & writeMask) != 0
                && !IsAdminPrincipal(allow.SecurityIdentifier))
            {
                return $"can be changed by {Describe(allow.SecurityIdentifier)} (access mask 0x{allow.AccessMask:x})";
            }
        }

        return null;
    }

    private static bool IsTrustedOwner(SecurityIdentifier sid) =>
        sid == AutoQuarantinePolicy.LocalSystem || sid == AutoQuarantinePolicy.Administrators
        || sid == AutoQuarantinePolicy.TrustedInstaller;

    /// <summary>OWNER RIGHTS stands for the (trusted) owner; an effective CREATOR OWNER ACE matches nobody.</summary>
    private static bool IsAdminPrincipal(SecurityIdentifier sid) =>
        IsTrustedOwner(sid) || sid == OwnerRights || sid == CreatorOwner;

    private static string Describe(SecurityIdentifier sid)
    {
        try
        {
            return $"{sid.Translate(typeof(NTAccount))} ({sid.Value})";
        }
        catch (Exception ex) when (ex is IdentityNotMappedException or SystemException)
        {
            return sid.Value;
        }
    }
}
