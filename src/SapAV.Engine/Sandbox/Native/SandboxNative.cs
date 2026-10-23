using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SapAV.Engine.Sandbox.Native;

/// <summary>Win32 declarations for the scan worker sandbox (AppContainer, Job Object, process attributes, handles).</summary>
internal static class SandboxNative
{
    // ---- Process creation ----
    public const uint ExtendedStartupInfoPresent = 0x00080000;
    public const uint CreateSuspended = 0x00000004;
    public const uint CreateNoWindow = 0x08000000;
    public const uint CreateUnicodeEnvironment = 0x00000400;
    /// <summary>No console: a console app would otherwise get a conhost.exe child, which the child-process policy,
    /// the Job process limit and the AppContainer all (rightly) block, failing start with STATUS_DLL_INIT_FAILED.</summary>
    public const uint DetachedProcess = 0x00000008;

    public static readonly IntPtr ProcThreadAttributeHandleList = 0x00020002;
    public static readonly IntPtr ProcThreadAttributeMitigationPolicy = 0x00020007;
    public static readonly IntPtr ProcThreadAttributeSecurityCapabilities = 0x00020009;
    public static readonly IntPtr ProcThreadAttributeJobList = 0x0002000D;
    public static readonly IntPtr ProcThreadAttributeChildProcessPolicy = 0x0002000E;

    /// <summary>PROCESS_CREATION_CHILD_PROCESS_RESTRICTED: the process can't create child processes.</summary>
    public const uint ChildProcessRestricted = 0x01;

    public const uint SemFailCriticalErrors = 0x0001;
    public const uint SemNoGpFaultErrorBox = 0x0002;
    public const uint SemNoOpenFileErrorBox = 0x8000;

    [DllImport("kernel32.dll", ExactSpelling = true)]
    public static extern uint SetErrorMode(uint mode);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    public static extern uint GetErrorMode();

    public const uint HandleFlagInherit = 0x00000001;
    public const uint DuplicateCloseSource = 0x00000001;
    public const uint DuplicateSameAccess = 0x00000002;

    public const uint WaitObject0 = 0;
    public const uint StillActive = 259;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct StartupInfo
    {
        public uint cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct StartupInfoEx
    {
        public StartupInfo StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessInformation
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecurityCapabilities
    {
        public IntPtr AppContainerSid;
        public IntPtr Capabilities;
        public uint CapabilityCount;
        public uint Reserved;
    }

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool InitializeProcThreadAttributeList(IntPtr attributeList, int attributeCount, int flags, ref IntPtr size);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool UpdateProcThreadAttribute(
        IntPtr attributeList, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previousValue, IntPtr returnSize);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    public static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

    [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreateProcess(
        string? applicationName, char[] commandLine, IntPtr processAttributes, IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint creationFlags, IntPtr environment, string? currentDirectory,
        ref StartupInfoEx startupInfo, out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetHandleInformation(SafeHandle handle, uint mask, uint flags);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DuplicateHandle(
        IntPtr sourceProcess, IntPtr sourceHandle, SafeProcessHandle targetProcess, out IntPtr targetHandle,
        uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint options);

    /// <summary>Closes a handle inside another process (DUPLICATE_CLOSE_SOURCE with no target).</summary>
    [DllImport("kernel32.dll", EntryPoint = "DuplicateHandle", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseRemoteHandle(
        SafeProcessHandle sourceProcess, IntPtr sourceHandle, IntPtr targetProcess, IntPtr targetHandle,
        uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint options);

    // ---- Job objects ----
    public const uint JobObjectLimitActiveProcess = 0x00000008;
    public const uint JobObjectLimitPriorityClass = 0x00000020;
    public const uint JobObjectLimitProcessMemory = 0x00000100;
    public const uint JobObjectLimitDieOnUnhandledException = 0x00000400;
    public const uint JobObjectLimitKillOnJobClose = 0x00002000;

    public const uint JobObjectUiLimitAll = 0x000000FF;
    public const uint BelowNormalPriorityClass = 0x00004000;

    public const uint JobObjectCpuRateControlEnable = 0x1;
    public const uint JobObjectCpuRateControlHardCap = 0x4;

    public const int JobObjectBasicUiRestrictions = 4;
    public const int JobObjectExtendedLimitInformation = 9;
    public const int JobObjectCpuRateControlInformation = 15;

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectExtendedLimitInformationData
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectCpuRateControlInformationData
    {
        public uint ControlFlags;
        public uint CpuRate;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateJobObjectW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    public static extern SafeJobHandle CreateJobObject(IntPtr jobAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern unsafe bool SetInformationJobObject(SafeJobHandle job, int infoClass, void* info, uint length);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern unsafe bool QueryInformationJobObject(SafeJobHandle job, int infoClass, void* info, uint length, out uint returned);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool TerminateJobObject(SafeJobHandle job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsProcessInJob(SafeProcessHandle process, SafeJobHandle job, [MarshalAs(UnmanagedType.Bool)] out bool result);

    // ---- AppContainer profiles (userenv) ----
    public const int HResultAlreadyExists = unchecked((int)0x800700B7);
    public const int HResultFileNotFound = unchecked((int)0x80070002);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int CreateAppContainerProfile(
        string appContainerName, string displayName, string description, IntPtr capabilities, uint capabilityCount, out IntPtr sid);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int DeriveAppContainerSidFromAppContainerName(string appContainerName, out IntPtr sid);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int DeleteAppContainerProfile(string appContainerName);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    public static extern IntPtr FreeSid(IntPtr sid);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    public static extern int GetLengthSid(IntPtr sid);

    // ---- Tokens ----
    public const uint TokenQuery = 0x0008;
    public const int TokenIntegrityLevel = 25;
    public const int TokenIsAppContainer = 29;
    public const int TokenCapabilities = 30;
    public const int TokenAppContainerSid = 31;

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(SafeProcessHandle process, uint desiredAccess, out SafeAccessTokenHandle token);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern unsafe bool GetTokenInformation(SafeAccessTokenHandle token, int infoClass, void* info, uint length, out uint returned);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);

    // ---- Handles held by the worker (review M1) ----
    public const int ProcessHandleInformation = 51;
    public const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetProcessHandleCount(SafeProcessHandle process, out uint count);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    public static extern unsafe int NtQueryInformationProcess(SafeProcessHandle process, int infoClass, void* info, uint length, out uint returned);

    /// <summary>STATUS_SUCCESS (0) when both handles refer to the same kernel object (Windows 10 1607+).</summary>
    [DllImport("ntdll.dll", ExactSpelling = true)]
    public static extern int NtCompareObjects(IntPtr first, IntPtr second);

    [DllImport("kernel32.dll", EntryPoint = "DuplicateHandle", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DuplicateHandleFrom(
        SafeProcessHandle sourceProcess, IntPtr sourceHandle, IntPtr targetProcess, out IntPtr targetHandle,
        uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint options);

    // ---- Pipes (review L3: unsolicited worker output) ----
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool PeekNamedPipe(
        SafeHandle pipe, IntPtr buffer, uint bufferSize, IntPtr bytesRead, out uint totalBytesAvailable, IntPtr bytesLeftThisMessage);

    // ---- Object security (worker process / thread DACL) ----
    public const int SeKernelObject = 6;
    public const uint DaclSecurityInformation = 0x00000004;
    public const uint ProtectedDaclSecurityInformation = 0x80000000;

    [StructLayout(LayoutKind.Sequential)]
    public struct SecurityAttributes
    {
        public uint nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [DllImport("advapi32.dll", ExactSpelling = true)]
    public static extern int SetSecurityInfo(
        SafeHandle handle, int objectType, uint securityInformation, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    public static extern int GetSecurityInfo(
        SafeHandle handle, int objectType, uint securityInformation, IntPtr owner, IntPtr group, out IntPtr dacl, IntPtr sacl,
        out IntPtr securityDescriptor);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    public static extern uint GetSecurityDescriptorLength(IntPtr securityDescriptor);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    public static extern IntPtr LocalFree(IntPtr memory);

    // ---- Mitigation policies as applied (tests) ----
    public const int ProcessStrictHandleCheckPolicy = 3;
    public const int ProcessExtensionPointDisablePolicy = 6;
    public const int ProcessImageLoadPolicy = 10;
    public const int ProcessChildProcessPolicy = 13;

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern unsafe bool GetProcessMitigationPolicy(SafeProcessHandle process, int policy, void* buffer, nuint length);

    // ---- Object queries (tests: granted access of a duplicated handle) ----
    [StructLayout(LayoutKind.Sequential)]
    public struct ObjectBasicInformation
    {
        public uint Attributes;
        public uint GrantedAccess;
        public uint HandleCount;
        public uint PointerCount;
        public uint PagedPoolCharge;
        public uint NonPagedPoolCharge;
        public uint Reserved1;
        public uint Reserved2;
        public uint Reserved3;
        public uint NameInfoSize;
        public uint TypeInfoSize;
        public uint SecurityDescriptorSize;
        public long CreationTime;
    }

    [DllImport("ntdll.dll", ExactSpelling = true)]
    public static extern unsafe int NtQueryObject(SafeHandle handle, int infoClass, void* info, uint length, out uint returned);
}

/// <summary>An owned Job Object handle.</summary>
internal sealed class SafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeJobHandle()
        : base(ownsHandle: true)
    {
    }

    protected override bool ReleaseHandle() => SandboxNative.CloseHandle(handle);
}
