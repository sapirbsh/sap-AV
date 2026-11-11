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
    public const string HideArtifacts = "T1564";
    public const string ShortcutModification = "T1547.009";
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

    // C3: persistence judgement (autostart entries).

    /// <summary>An unquoted program path with spaces where a standard user can plant the shorter path.</summary>
    public const string PathInterceptionByUnquotedPath = "T1574.009";

    /// <summary>A service (or other machine-wide autostart) whose program standard users can replace or plant.</summary>
    public const string ServicesFilePermissionsWeakness = "T1574.010";

    /// <summary>IFEO Debugger on an accessibility program (sethc, utilman, osk, ...): a logon-screen backdoor.</summary>
    public const string AccessibilityFeatures = "T1546.008";

    /// <summary>A scheduled-task COM handler taken from the user's own <c>Software\Classes</c>.</summary>
    public const string ComponentObjectModelHijacking = "T1546.015";

    public const string Mshta = "T1218.005";
    public const string Regsvr32 = "T1218.010";
    public const string Rundll32 = "T1218.011";

    // Section E (threat pack, X1). Infostealers.

    /// <summary>Reading browser credential stores (Login Data, logins.json, key4.db).</summary>
    public const string CredentialsFromWebBrowsers = "T1555.003";

    /// <summary>Reading browser cookie stores.</summary>
    public const string StealWebSessionCookie = "T1539";

    /// <summary>Discord tokens, password and token files.</summary>
    public const string CredentialsInFiles = "T1552.001";

    /// <summary>Crypto wallet files.</summary>
    public const string DataFromLocalSystem = "T1005";

    /// <summary>Cryptominers: CPU / GPU use, miner command lines, stopping when Task Manager opens (T1496 sub-technique since ATT&amp;CK v16).</summary>
    public const string ComputeHijacking = "T1496.001";

    /// <summary>Encoded PowerShell and other obfuscated command lines (secondary to T1059.001).</summary>
    public const string CommandObfuscation = "T1027.010";

    /// <summary>Proxy / PAC hijack (closest fit).</summary>
    public const string AdversaryInTheMiddle = "T1557";

    /// <summary>E4: a Microsoft binary that runs another program from its arguments (forfiles, pcalua, conhost, explorer).</summary>
    public const string IndirectCommandExecution = "T1202";

    /// <summary>E4: msiexec installing a package from the network or a user folder.</summary>
    public const string Msiexec = "T1218.007";

    // Pre-Flight capabilities (G3a) and Attack Story (G2b), listed in X1.

    public const string DebuggerEvasion = "T1622";
    public const string ProcessInjection = "T1055";
    public const string Keylogging = "T1056.001";
    public const string CredentialsFromPasswordStores = "T1555";
    public const string ApplicationLayerProtocol = "T1071";

    // E2: third-party YARA rules (data/rules/third-party/curated-rules.txt).

    /// <summary>E2: credential dumpers (mimikatz, pwdump, WCE, LSASS dumpers); the default for hack-tool rules.</summary>
    public const string OsCredentialDumping = "T1003";

    /// <summary>E2: password sniffers (SniffPass).</summary>
    public const string NetworkSniffing = "T1040";

    /// <summary>E2: password spraying / brute-force tools (CrackMapExec).</summary>
    public const string BruteForce = "T1110";

    /// <summary>E2: password-manager extractors (Pandora).</summary>
    public const string PasswordManagers = "T1555.005";

    /// <summary>E2: Kerberos ticket tools (Rubeus).</summary>
    public const string StealOrForgeKerberosTickets = "T1558";

    /// <summary>E2: keygens, patchers and other obtained tools.</summary>
    public const string ObtainTool = "T1588.002";
}
