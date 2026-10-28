using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;

namespace SapAV.Core.Mitre;

/// <summary>
/// Lookup of MITRE ATT&amp;CK technique names (Enterprise matrix). Covers the techniques sap-AV maps
/// its detections to. IDs outside the catalog can still be valid (see <see cref="MitreTechniqueIdFormat"/>).
/// </summary>
public static class MitreCatalog
{
    private static readonly FrozenDictionary<string, MitreTechnique> Techniques = new MitreTechnique[]
    {
        new(MitreTechniqueIds.RegistryRunKeysStartupFolder, "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"),
        new(MitreTechniqueIds.WinlogonHelperDll, "Boot or Logon Autostart Execution: Winlogon Helper DLL"),
        new(MitreTechniqueIds.ImageFileExecutionOptionsInjection, "Event Triggered Execution: Image File Execution Options Injection"),
        new(MitreTechniqueIds.WindowsService, "Create or Modify System Process: Windows Service"),
        new(MitreTechniqueIds.ScheduledTask, "Scheduled Task/Job: Scheduled Task"),
        new(MitreTechniqueIds.DoubleFileExtension, "Masquerading: Double File Extension"),
        new(MitreTechniqueIds.SoftwarePacking, "Obfuscated Files or Information: Software Packing"),
        new(MitreTechniqueIds.BinaryPadding, "Obfuscated Files or Information: Binary Padding"),
        new(MitreTechniqueIds.RightToLeftOverride, "Masquerading: Right-to-Left Override"),
        new(MitreTechniqueIds.MaliciousFile, "User Execution: Malicious File"),
        new(MitreTechniqueIds.SpearphishingAttachment, "Phishing: Spearphishing Attachment"),
        new(MitreTechniqueIds.CommandAndScriptingInterpreter, "Command and Scripting Interpreter"),
        new(MitreTechniqueIds.PowerShell, "Command and Scripting Interpreter: PowerShell"),
        new(MitreTechniqueIds.WindowsCommandShell, "Command and Scripting Interpreter: Windows Command Shell"),
        new(MitreTechniqueIds.VisualBasic, "Command and Scripting Interpreter: Visual Basic"),
        new(MitreTechniqueIds.JavaScript, "Command and Scripting Interpreter: JavaScript"),
        new(MitreTechniqueIds.DataEncryptedForImpact, "Data Encrypted for Impact"),
        new(MitreTechniqueIds.ReplicationThroughRemovableMedia, "Replication Through Removable Media"),
        new(MitreTechniqueIds.StoredDataManipulation, "Data Manipulation: Stored Data Manipulation"),
        new(MitreTechniqueIds.ExploitationForDefenseEvasion, "Exploitation for Defense Evasion"),
        new(MitreTechniqueIds.DisableOrModifyTools, "Impair Defenses: Disable or Modify Tools"),
        new(MitreTechniqueIds.PathInterceptionByUnquotedPath, "Hijack Execution Flow: Path Interception by Unquoted Path"),
        new(MitreTechniqueIds.ServicesFilePermissionsWeakness, "Hijack Execution Flow: Services File Permissions Weakness"),
        new(MitreTechniqueIds.AccessibilityFeatures, "Event Triggered Execution: Accessibility Features"),
        new(MitreTechniqueIds.ComponentObjectModelHijacking, "Event Triggered Execution: Component Object Model Hijacking"),
        new(MitreTechniqueIds.Mshta, "System Binary Proxy Execution: Mshta"),
        new(MitreTechniqueIds.Regsvr32, "System Binary Proxy Execution: Regsvr32"),
        new(MitreTechniqueIds.Rundll32, "System Binary Proxy Execution: Rundll32"),
    }.ToFrozenDictionary(t => t.Id, StringComparer.Ordinal);

    /// <summary>All techniques in the catalog.</summary>
    public static IReadOnlyCollection<MitreTechnique> All => Techniques.Values;

    /// <summary>Looks up a technique by exact ID (case-sensitive, e.g. <c>T1547.001</c>).</summary>
    public static bool TryGet(string? id, [NotNullWhen(true)] out MitreTechnique? technique)
    {
        if (id is not null && Techniques.TryGetValue(id, out var found))
        {
            technique = found;
            return true;
        }

        technique = null;
        return false;
    }

    public static bool IsKnown(string? id) => id is not null && Techniques.ContainsKey(id);
}
