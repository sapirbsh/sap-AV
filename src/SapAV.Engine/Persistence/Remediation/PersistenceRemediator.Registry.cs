using SapAV.Core.Persistence;
using SapAV.Core.Pipe;
using SapAV.Core.Text;
using SapAV.Engine.Pipe;

namespace SapAV.Engine.Persistence.Remediation;

internal sealed partial class PersistenceRemediator
{
    /// <summary>
    /// Run / RunOnce / Policies Run, IFEO <c>Debugger</c>, SilentProcessExit <c>MonitorProcess</c>: the exact value (name, type,
    /// raw bytes) is backed up, then deleted only if it still holds those bytes. Nothing else in the key is touched.
    /// </summary>
    private RemediationResult BlockValue(BlockContext context)
    {
        var entry = context.Entry;
        if (!TryRegistryLocation(entry, out var root, out var path) || entry.ValueName is null)
        {
            return NotAddressable();
        }

        if (ClientMaySet(context.Client, root, path) is { } denied)
        {
            return denied;
        }

        if (ResolveValueName(root, path, entry.ValueName, out var name) is { } unresolved)
        {
            return unresolved;
        }

        var read = _registry.Read(root, path, name, out var before);
        if (read != RegistryEditStatus.Ok)
        {
            return FromRegistry(read);
        }

        if (!Stores(before!, entry.CommandLine, program: null))
        {
            return Changed();
        }

        var record = context.NewRecord(PersistenceBackupAction.ValueDeleted) with
        {
            Root = root, KeyPath = path, RawValueName = PersistenceBackupRecord.NameBytes(name), ValueType = before!.Type, ValueData = before.Data,
        };
        if (SaveFirst(context, record) is { } failed)
        {
            return failed;
        }

        var deleted = _registry.DeleteIf(root, path, name, before);
        if (deleted != RegistryEditStatus.Ok)
        {
            Discard(context);
            return FromRegistry(deleted);
        }

        return new(RemediationStatus.Blocked, "The registry value was backed up and deleted.", record);
    }

    /// <summary>
    /// Winlogon <c>Shell</c> / <c>Userinit</c>: never deleted. The whole value is backed up and set back to the Windows default
    /// (<c>explorer.exe</c> / <c>%SystemRoot%\system32\userinit.exe,</c>), which drops every extra program in it.
    /// </summary>
    private RemediationResult BlockWinlogon(BlockContext context)
    {
        var entry = context.Entry;
        string name = entry.Kind == PersistenceKind.WinlogonShell ? "Shell" : "Userinit";
        if (!TryRegistryLocation(entry, out var root, out var path) || entry.ValueName is null || ProgramIndex(entry.ValueName, name) is not { } program)
        {
            return NotAddressable();
        }

        if (ClientMaySet(context.Client, root, path) is { } denied)
        {
            return denied;
        }

        var read = _registry.Read(root, path, name, out var before);
        if (read != RegistryEditStatus.Ok)
        {
            return FromRegistry(read);
        }

        if (!Stores(before!, entry.CommandLine, program))
        {
            return Changed();
        }

        var replacement = RawRegistryValue.String(WinlogonDefault(entry.Kind));
        if (before!.Texts().Any(t => string.Equals(t.Trim(), WinlogonDefault(entry.Kind), StringComparison.OrdinalIgnoreCase)))
        {
            return new(RemediationStatus.NothingToDo, $"Winlogon {name} already holds the Windows default; nothing to block.");
        }

        var record = context.NewRecord(PersistenceBackupAction.ValueReset) with
        {
            Root = root, KeyPath = path, RawValueName = PersistenceBackupRecord.NameBytes(name), ValueType = before.Type, ValueData = before.Data,
            ReplacementType = replacement.Type, ReplacementData = replacement.Data,
        };
        if (SaveFirst(context, record) is { } failed)
        {
            return failed;
        }

        var written = _registry.WriteIf(root, path, name, before, replacement);
        if (written != RegistryEditStatus.Ok)
        {
            Discard(context);
            return FromRegistry(written);
        }

        return new(RemediationStatus.Blocked, $"Winlogon {name} was backed up and set back to the Windows default ({WinlogonDefault(entry.Kind)}).", record);
    }

    /// <summary>A deleted value comes back only where nothing holds its name now; a reset Winlogon value only while it still holds the default.</summary>
    private RemediationResult RestoreValue(PersistenceBackupRecord record, IClientIdentity client)
    {
        var root = record.Root!.Value;
        if (ClientMaySet(client, root, record.KeyPath!) is { } denied)
        {
            return denied.Status == RemediationStatus.EntryChanged
                ? new(RemediationStatus.LocationMissing, "The registry key (or the user's hive) isn't there now; log the user on, or ask an administrator.")
                : denied;
        }

        var written = _registry.WriteIf(root, record.KeyPath!, record.RawName, record.Replacement, record.Before!);
        return written switch
        {
            RegistryEditStatus.Ok => new(RemediationStatus.Restored, record.Action == PersistenceBackupAction.ValueReset
                ? "The Winlogon value was put back as it was."
                : "The registry value was put back exactly as it was."),
            RegistryEditStatus.Changed => new(RemediationStatus.LocationChanged, record.Action == PersistenceBackupAction.ValueReset
                ? "The Winlogon value no longer holds the default sap-AV set; it was changed since, so nothing was overwritten."
                : "A value with that name exists again; nothing was overwritten."),
            RegistryEditStatus.KeyMissing => new(RemediationStatus.LocationMissing, "The registry key (or the user's hive) isn't there now; log the user on, or ask an administrator."),
            RegistryEditStatus.Redirected => new(RemediationStatus.Redirected, "A registry link is on the key's path now; not followed."),
            _ => new(RemediationStatus.Failed, $"The registry value couldn't be written ({written})."),
        };
    }

    /// <summary>KEY_SET_VALUE: what a user needs on a key to change its values themselves.</summary>
    private const uint KeySetValue = 0x0002;

    /// <summary>
    /// A standard user acts only on values they could change themselves: AccessCheck of KEY_SET_VALUE with their own token
    /// against the key's descriptor (read through the no-follow open). Their own hive is theirs, but not every key in it is
    /// (e.g. <c>Policies\Explorer\Run</c> set by an administrator), and SYSTEM must not change those for them. (The check uses
    /// the file generic mapping; for KEY_SET_VALUE = 0x2 it maps GENERIC_WRITE / GENERIC_ALL the same way the key mapping does.)
    /// </summary>
    private RemediationResult? ClientMaySet(IClientIdentity client, RegistryRoot root, string path)
    {
        if (client.IsAdmin)
        {
            return null;
        }

        var status = _registry.Security(root, path, out var descriptor);
        if (status != RegistryEditStatus.Ok)
        {
            return FromRegistry(status);
        }

        return client.IsGranted(descriptor!, KeySetValue)
            ? null
            : new(RemediationStatus.AccessDenied, "You may not change this registry key yourself (an administrator or a policy controls it); ask an administrator.");
    }

    /// <summary>The Windows default of a Winlogon value (Userinit from the machine's SystemRoot).</summary>
    private string WinlogonDefault(PersistenceKind kind) => kind == PersistenceKind.WinlogonShell
        ? "explorer.exe"
        : $@"{RegistryEnvironment.Machine(_collector.Registry).SystemRoot ?? @"C:\Windows"}\system32\userinit.exe,";

    /// <summary>The collector's display location back to a root and path; only a location that wasn't sanitised or cut, and whose scope fits.</summary>
    private static bool TryRegistryLocation(PersistenceEntry entry, out RegistryRoot root, out string path)
    {
        string location = entry.Location;
        root = RegistryRoot.LocalMachine;
        path = string.Empty;
        if (location.Contains('\uFFFD') || location.Length >= PersistenceEntry.MaxLocationLength)
        {
            return false;
        }

        if (location.StartsWith(@"HKLM\", StringComparison.Ordinal) && entry.UserSid is null)
        {
            path = location[5..];
            return true;
        }

        if (location.StartsWith(@"HKU\", StringComparison.Ordinal) && entry.UserSid is { } sid && location[4..].StartsWith(sid + @"\", StringComparison.OrdinalIgnoreCase))
        {
            root = RegistryRoot.Users;
            path = location[4..];
            return true;
        }

        return false;
    }

    /// <summary>
    /// The stored value name behind the entry's (sanitised, capped) one: the one value whose sanitised name is exactly it.
    /// Two that look the same (e.g. differing only in a control character) can't be told apart: refused.
    /// </summary>
    private RemediationResult? ResolveValueName(RegistryRoot root, string path, string shown, out string name)
    {
        name = string.Empty;
        var listed = _registry.ValueNames(root, path, out var names);
        if (listed != RegistryEditStatus.Ok)
        {
            return FromRegistry(listed);
        }

        var matches = names.Where(n => PersistenceText.Identifier(n, PersistenceEntry.MaxValueNameLength) == shown).Take(2).ToArray();
        if (matches.Length != 1)
        {
            return matches.Length == 0 ? Changed() : new(RemediationStatus.NotSupported, "Several values in this key look the same; block them from the registry editor.");
        }

        name = matches[0];
        return null;
    }

    /// <summary>The value still holds the entry's command (or, for Winlogon, that program at its place in the list).</summary>
    private static bool Stores(RawRegistryValue value, string commandLine, int? program) =>
        value.Texts().Any(text =>
        {
            if (program is not { } index)
            {
                return SafeText.SingleLine(text, PersistenceEntry.MaxCommandLineLength) == commandLine;
            }

            var programs = text.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            return index < programs.Length && SafeText.SingleLine(programs[index], PersistenceEntry.MaxCommandLineLength) == commandLine;
        });

    /// <summary>"Shell" → 0, "Shell[2]" → 2 (the collector's naming); null for anything else.</summary>
    private static int? ProgramIndex(string valueName, string name)
    {
        if (string.Equals(valueName, name, StringComparison.Ordinal))
        {
            return 0;
        }

        return valueName.StartsWith(name + "[", StringComparison.Ordinal) && valueName.EndsWith(']')
            && int.TryParse(valueName.AsSpan(name.Length + 1, valueName.Length - name.Length - 2), System.Globalization.NumberStyles.None, null, out int i) && i is > 0 and < 32
            ? i
            : null;
    }

    private static RemediationResult Changed() =>
        new(RemediationStatus.EntryChanged, "The autostart entry changed since it was collected; nothing was changed. Refresh and try again.");

    private static RemediationResult NotAddressable() =>
        new(RemediationStatus.NotSupported, "This entry's location can't be addressed exactly (its name holds characters that were replaced for display).");

    private static RemediationResult FromRegistry(RegistryEditStatus status) => status switch
    {
        RegistryEditStatus.KeyMissing or RegistryEditStatus.ValueMissing or RegistryEditStatus.Changed => Changed(),
        RegistryEditStatus.Redirected => new(RemediationStatus.Redirected, "A registry symbolic link is on the key's path; it was not followed and nothing was changed."),
        RegistryEditStatus.TooLarge => new(RemediationStatus.NotSupported, "The value is too large to back up."),
        RegistryEditStatus.AccessDenied => new(RemediationStatus.Failed, "The engine was denied access to the registry key; nothing was changed."),
        _ => new(RemediationStatus.Failed, "The registry key couldn't be changed; nothing was changed."),
    };
}
