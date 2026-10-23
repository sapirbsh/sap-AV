namespace SapAV.Engine.Sandbox;

/// <summary>
/// Process mitigation policies for the worker (PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, two 64-bit words), limited to
/// what the .NET runtime, WinVerifyTrust and YARA-X tolerate. Measured on Windows 11 26200 / .NET 10 (see
/// <c>Sandbox/README.md</c>); left out on purpose:
/// <list type="bullet">
/// <item>PROHIBIT_DYNAMIC_CODE (ACG): the JIT writes executable code.</item>
/// <item>BLOCK_NON_MICROSOFT_BINARIES: the worker's own assemblies and <c>yara_x_capi.dll</c> are not Microsoft-signed.</item>
/// <item>WIN32K_SYSTEM_CALL_DISABLE: user32 is loaded during start (by the runtime host / crypt32), which then fails.</item>
/// <item>STRICT_CONTROL_FLOW_GUARD and CET strict mode: not every loaded module is CFG/CET-compatible.</item>
/// </list>
/// </summary>
internal readonly record struct WorkerMitigations(ulong Policy1, ulong Policy2)
{
    // Word 1 (PROCESS_CREATION_MITIGATION_POLICY_*_ALWAYS_ON).
    public const ulong ForceRelocateImages = 0x1UL << 8;
    public const ulong HeapTerminate = 0x1UL << 12;
    public const ulong BottomUpAslr = 0x1UL << 16;
    public const ulong HighEntropyAslr = 0x1UL << 20;
    public const ulong StrictHandleChecks = 0x1UL << 24;
    public const ulong Win32kSystemCallDisable = 0x1UL << 28;
    public const ulong ExtensionPointDisable = 0x1UL << 32;
    public const ulong FontDisable = 0x1UL << 48;
    public const ulong ImageLoadNoRemote = 0x1UL << 52;
    public const ulong ImageLoadNoLowLabel = 0x1UL << 56;
    public const ulong ImageLoadPreferSystem32 = 0x1UL << 60;

    // Word 2 (PROCESS_CREATION_MITIGATION_POLICY2_*_ALWAYS_ON).
    public const ulong LoaderIntegrityContinuity = 0x1UL << 4;
    public const ulong ModuleTamperingProtection = 0x1UL << 12;
    public const ulong RestrictIndirectBranchPrediction = 0x1UL << 16;
    public const ulong SpeculativeStoreBypassDisable = 0x1UL << 24;

    /// <summary>The set the worker runs with.</summary>
    public static WorkerMitigations Default { get; } = new(
        ForceRelocateImages | HeapTerminate | BottomUpAslr | HighEntropyAslr | StrictHandleChecks | ExtensionPointDisable
        | FontDisable | ImageLoadNoRemote | ImageLoadNoLowLabel | ImageLoadPreferSystem32,
        ModuleTamperingProtection | RestrictIndirectBranchPrediction | SpeculativeStoreBypassDisable);

    /// <summary>No mitigations (diagnostics only).</summary>
    public static WorkerMitigations None { get; } = new(0, 0);
}
