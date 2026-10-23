namespace SapAV.Core.Mitre;

/// <summary>Technique IDs used by sap-AV detections (ROADMAP.md, X1).</summary>
public static class MitreTechniqueIds
{
    public const string RegistryRunKeysStartupFolder = "T1547.001";
    public const string WinlogonHelperDll = "T1547.004";
    public const string ImageFileExecutionOptionsInjection = "T1546.012";
    public const string WindowsService = "T1543.003";
    public const string ScheduledTask = "T1053.005";
    public const string DoubleFileExtension = "T1036.007";
    public const string SoftwarePacking = "T1027.002";
    public const string BinaryPadding = "T1027.001";
    public const string RightToLeftOverride = "T1036.002";
    public const string MaliciousFile = "T1204.002";
    public const string SpearphishingAttachment = "T1566.001";
    public const string CommandAndScriptingInterpreter = "T1059";
    public const string PowerShell = "T1059.001";
    public const string WindowsCommandShell = "T1059.003";
    public const string VisualBasic = "T1059.005";
    public const string JavaScript = "T1059.007";
    public const string DataEncryptedForImpact = "T1486";
    public const string ReplicationThroughRemovableMedia = "T1091";
    public const string StoredDataManipulation = "T1565.001";

    /// <summary>A file that crashes or hangs the sandboxed scan worker (B5): built to break or evade the scanner.</summary>
    public const string ExploitationForDefenseEvasion = "T1211";

    /// <summary>
    /// Impair Defenses: Disable or Modify Tools. Used by the engine-health alerts (B3) when protection is degraded
    /// (no YARA rules loaded, quarantine store full), whether by accident or by an attacker.
    /// </summary>
    public const string DisableOrModifyTools = "T1562.001";
}
