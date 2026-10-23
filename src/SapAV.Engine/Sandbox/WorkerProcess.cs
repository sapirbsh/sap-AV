using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SapAV.Engine.Sandbox.Native;

namespace SapAV.Engine.Sandbox;

/// <summary>How the worker process is isolated.</summary>
internal enum WorkerIsolation
{
    /// <summary>AppContainer token (no capabilities, Low integrity) in a locked-down Job Object. The production mode.</summary>
    AppContainer,

    /// <summary>
    /// Test only: the same process, pipes and Job Object, but the engine's own token. Used to test the protocol and the
    /// supervision (crash, hang, restart) on machines where the AppContainer tests skip. Not reachable from configuration.
    /// </summary>
    UnsandboxedForTests,
}

/// <summary>Everything needed to start one worker.</summary>
internal sealed record WorkerLaunchSpec(
    string ExecutablePath,
    WorkerIsolation Isolation,
    SecurityIdentifier? AppContainerSid,
    long MemoryLimitBytes,
    int CpuRatePercent,
    WorkerMitigations Mitigations,
    bool TestHooks);

/// <summary>What the worker's primary token actually is, read by the engine from the process (never self-reported).</summary>
internal sealed record SandboxTokenInfo(bool IsAppContainer, string? AppContainerSid, int CapabilityCount, int IntegrityRid)
{
    /// <summary>SECURITY_MANDATORY_LOW_RID.</summary>
    public const int LowIntegrityRid = 0x1000;
}

/// <summary>
/// One running scan worker: the process (created suspended, checked, then resumed), its Job Object and the two
/// anonymous pipes. The worker inherits <b>only</b> its two pipe ends (PROC_THREAD_ATTRIBUTE_HANDLE_LIST); file
/// handles are duplicated into it per request, read-only, and closed in it again by the broker.
/// </summary>
internal sealed class WorkerProcess : IDisposable
{
    /// <summary>FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE: what a duplicated file handle may do.</summary>
    public const uint ReadOnlyFileAccess = 0x0001 | 0x0080 | 0x00020000 | 0x00100000;

    /// <summary>The environment variable that enables the worker's test hooks (see the worker's TestHooks).</summary>
    public const string TestHooksVariable = "SAPAV_SCANWORKER_TEST_HOOKS";

    private static readonly object LaunchLock = new();

    private readonly SafeJobHandle _job;
    private readonly AnonymousPipeServerStream _requests;
    private readonly AnonymousPipeServerStream _responses;
    private int _disposed;

    private WorkerProcess(SafeProcessHandle process, int processId, SafeJobHandle job, AnonymousPipeServerStream requests, AnonymousPipeServerStream responses)
    {
        Process = process;
        ProcessId = processId;
        _job = job;
        _requests = requests;
        _responses = responses;
    }

    public SafeProcessHandle Process { get; }

    public int ProcessId { get; }

    /// <summary>Engine to worker.</summary>
    public Stream Requests => _requests;

    /// <summary>Worker to engine (untrusted).</summary>
    public Stream Responses => _responses;

    public bool HasExited => Process.IsClosed || SandboxNative.WaitForSingleObject(Process, 0) == SandboxNative.WaitObject0;

    /// <summary>The exit code, or null while it runs.</summary>
    public uint? ExitCode =>
        !Process.IsClosed && SandboxNative.GetExitCodeProcess(Process, out uint code) && code != SandboxNative.StillActive ? code : null;

    /// <summary>Starts a worker as described by <paramref name="spec"/>.</summary>
    /// <exception cref="SandboxUnavailableException">The process can't be created or its token isn't what was asked for.</exception>
    public static WorkerProcess Start(WorkerLaunchSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (spec.Isolation == WorkerIsolation.AppContainer && spec.AppContainerSid is null)
        {
            throw new ArgumentException("An AppContainer launch needs the AppContainer SID.", nameof(spec));
        }

        var job = CreateJob(spec);
        var requests = new AnonymousPipeServerStream(PipeDirection.Out, HandleInheritability.None);
        var responses = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.None);
        try
        {
            var info = Launch(spec, job, requests.ClientSafePipeHandle, responses.ClientSafePipeHandle);
            var process = new SafeProcessHandle(info.hProcess, ownsHandle: true);
            var worker = new WorkerProcess(process, (int)info.dwProcessId, job, requests, responses)
            {
                InitialThread = new SafeWaitHandle(info.hThread, ownsHandle: true),
            };
            try
            {
                // Review H1: the creation attributes set the protected SYSTEM + Administrators DACL. If Windows added
                // anything (or ignored them), set it again by handle; VerifyBeforeResume refuses the worker otherwise.
                // (The creation DACL gives the creator only READ_CONTROL via OWNER RIGHTS, so a non-admin broker can
                // read it but not change it: that is exactly the lock-down.)
                foreach (var (handle, what) in new (SafeHandle, string)[] { (worker.Process, "process"), (worker.InitialThread, "thread") })
                {
                    if (!WorkerObjectSecurity.IsLockedDown(WorkerObjectSecurity.Read(handle)))
                    {
                        WorkerObjectSecurity.Apply(handle, what);
                    }
                }

                worker.VerifyBeforeResume(spec);
                if (SandboxNative.ResumeThread(info.hThread) == uint.MaxValue)
                {
                    throw new SandboxUnavailableException($"ResumeThread failed: {new Win32Exception().Message}");
                }
            }
            catch
            {
                worker.Dispose();
                throw;
            }

            requests.DisposeLocalCopyOfClientHandle();
            responses.DisposeLocalCopyOfClientHandle();
            return worker;
        }
        catch
        {
            requests.Dispose();
            responses.Dispose();
            job.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Duplicates <paramref name="handle"/> into the worker with exactly <paramref name="access"/> (never
    /// DUPLICATE_SAME_ACCESS) and returns its value there. The worker doesn't own it: <see cref="CloseInWorker"/>.
    /// </summary>
    /// <exception cref="Win32Exception">DuplicateHandle failed (e.g. the worker exited).</exception>
    public IntPtr DuplicateInto(SafeHandle handle, uint access)
    {
        bool added = false;
        handle.DangerousAddRef(ref added);
        try
        {
            if (!SandboxNative.DuplicateHandle(SandboxNative.GetCurrentProcess(), handle.DangerousGetHandle(), Process, out IntPtr remote,
                    access, inheritHandle: false, options: 0))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "DuplicateHandle into the scan worker failed.");
            }

            return remote;
        }
        finally
        {
            if (added)
            {
                handle.DangerousRelease();
            }
        }
    }

    /// <summary>Closes a handle value inside the worker (best effort; harmless if the worker already exited).</summary>
    public void CloseInWorker(IntPtr remote)
    {
        if (remote != IntPtr.Zero && !Process.IsClosed)
        {
            SandboxNative.CloseRemoteHandle(Process, remote, IntPtr.Zero, IntPtr.Zero, 0, false, SandboxNative.DuplicateCloseSource);
        }
    }

    /// <summary>
    /// True if the worker has written bytes nobody asked for (review L3): between requests the response pipe must be
    /// empty. A broken pipe counts as unsolicited too, so the worker gets replaced either way.
    /// </summary>
    public bool HasUnsolicitedOutput =>
        !SandboxNative.PeekNamedPipe(_responses.SafePipeHandle, IntPtr.Zero, 0, IntPtr.Zero, out uint available, IntPtr.Zero) || available > 0;

    /// <summary>Kills the worker (and anything in its job). Idempotent.</summary>
    public void Kill()
    {
        if (!_job.IsClosed)
        {
            SandboxNative.TerminateJobObject(_job, 0xDEAD);
        }
    }

    /// <summary>Waits until the process has exited.</summary>
    public bool WaitForExit(TimeSpan timeout) =>
        Process.IsClosed || SandboxNative.WaitForSingleObject(Process, (uint)Math.Clamp(timeout.TotalMilliseconds, 0, uint.MaxValue - 1)) == SandboxNative.WaitObject0;

    /// <summary>The worker's real token (AppContainer, capabilities, integrity), read from the process.</summary>
    public unsafe SandboxTokenInfo QueryToken()
    {
        if (!SandboxNative.OpenProcessToken(Process, SandboxNative.TokenQuery, out var token))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "OpenProcessToken on the scan worker failed.");
        }

        using (token)
        {
            uint isAppContainer = 0;
            if (!SandboxNative.GetTokenInformation(token, SandboxNative.TokenIsAppContainer, &isAppContainer, 4, out _))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "TokenIsAppContainer");
            }

            var buffer = stackalloc byte[1024];
            string? appContainerSid = null;
            if (isAppContainer != 0 && SandboxNative.GetTokenInformation(token, SandboxNative.TokenAppContainerSid, buffer, 1024, out _))
            {
                IntPtr sid = *(IntPtr*)buffer;
                appContainerSid = sid == IntPtr.Zero ? null : new SecurityIdentifier(sid).Value;
            }

            int capabilities = 0;
            if (SandboxNative.GetTokenInformation(token, SandboxNative.TokenCapabilities, buffer, 1024, out _))
            {
                capabilities = (int)*(uint*)buffer; // TOKEN_GROUPS.GroupCount
            }

            if (!SandboxNative.GetTokenInformation(token, SandboxNative.TokenIntegrityLevel, buffer, 1024, out _))
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "TokenIntegrityLevel");
            }

            IntPtr labelSid = *(IntPtr*)buffer; // TOKEN_MANDATORY_LABEL.Label.Sid
            byte count = *(byte*)SandboxNative.GetSidSubAuthorityCount(labelSid);
            int rid = (int)*(uint*)SandboxNative.GetSidSubAuthority(labelSid, (uint)(count - 1));
            return new SandboxTokenInfo(isAppContainer != 0, appContainerSid, capabilities, rid);
        }
    }

    /// <summary>The Job Object's limit flags and process limit, as the kernel reports them (tests).</summary>
    public unsafe (uint LimitFlags, uint ActiveProcessLimit, ulong ProcessMemoryLimit) QueryJobLimits()
    {
        SandboxNative.JobObjectExtendedLimitInformationData info;
        if (!SandboxNative.QueryInformationJobObject(_job, SandboxNative.JobObjectExtendedLimitInformation, &info, (uint)sizeof(SandboxNative.JobObjectExtendedLimitInformationData), out _))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "QueryInformationJobObject");
        }

        return (info.BasicLimitInformation.LimitFlags, info.BasicLimitInformation.ActiveProcessLimit, (ulong)info.ProcessMemoryLimit);
    }

    /// <summary>The flags DWORD of a mitigation policy as the kernel applied it to the worker (tests).</summary>
    public unsafe uint QueryMitigationFlags(int policy)
    {
        uint flags = 0;
        if (!SandboxNative.GetProcessMitigationPolicy(Process, policy, &flags, 4))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), $"GetProcessMitigationPolicy({policy})");
        }

        return flags;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        Kill();
        _requests.Dispose();
        _responses.Dispose();
        _job.Dispose(); // KILL_ON_JOB_CLOSE as well
        InitialThread?.Dispose();
        Process.Dispose();
    }

    /// <summary>
    /// A SYNCHRONIZE-only copy of the broker's process handle, so a caller can wait for the exit after this object is
    /// disposed (the process DACL rightly refuses opening the worker by PID).
    /// </summary>
    internal WaitHandle ExitWaitHandle()
    {
        if (!SandboxNative.DuplicateHandle(SandboxNative.GetCurrentProcess(), Process.DangerousGetHandle(),
                new SafeProcessHandle(SandboxNative.GetCurrentProcess(), ownsHandle: false), out IntPtr copy, 0x00100000 /* SYNCHRONIZE */, false, 0))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "DuplicateHandle(SYNCHRONIZE)");
        }

        return new ManualResetEvent(false) { SafeWaitHandle = new SafeWaitHandle(copy, ownsHandle: true) };
    }

    /// <summary>The worker's first thread (kept so its DACL can be checked).</summary>
    internal SafeWaitHandle? InitialThread { get; private init; }

    private void VerifyBeforeResume(WorkerLaunchSpec spec)
    {
        if (!SandboxNative.IsProcessInJob(Process, _job, out bool inJob) || !inJob)
        {
            throw new SandboxUnavailableException("The scan worker is not in its Job Object.");
        }

        if (!WorkerObjectSecurity.IsLockedDown(WorkerObjectSecurity.Read(Process))
            || !WorkerObjectSecurity.IsLockedDown(WorkerObjectSecurity.Read(InitialThread!)))
        {
            throw new SandboxUnavailableException("The scan worker's process or thread DACL is not limited to SYSTEM and Administrators.");
        }

        if (spec.Isolation != WorkerIsolation.AppContainer)
        {
            return;
        }

        var token = QueryToken();
        if (!token.IsAppContainer || token.AppContainerSid != spec.AppContainerSid!.Value || token.CapabilityCount != 0
            || token.IntegrityRid > SandboxTokenInfo.LowIntegrityRid)
        {
            throw new SandboxUnavailableException(
                $"The scan worker's token is not the expected sandbox (AppContainer {token.IsAppContainer}, SID {token.AppContainerSid}, " +
                $"{token.CapabilityCount} capabilities, integrity 0x{token.IntegrityRid:X}).");
        }
    }

    private static unsafe SafeJobHandle CreateJob(WorkerLaunchSpec spec)
    {
        var job = SandboxNative.CreateJobObject(IntPtr.Zero, null);
        if (job.IsInvalid)
        {
            throw new SandboxUnavailableException($"CreateJobObject failed: {new Win32Exception().Message}");
        }

        try
        {
            var limits = new SandboxNative.JobObjectExtendedLimitInformationData
            {
                BasicLimitInformation = new SandboxNative.JobObjectBasicLimitInformation
                {
                    LimitFlags = SandboxNative.JobObjectLimitKillOnJobClose | SandboxNative.JobObjectLimitActiveProcess
                        | SandboxNative.JobObjectLimitProcessMemory | SandboxNative.JobObjectLimitDieOnUnhandledException
                        | SandboxNative.JobObjectLimitPriorityClass,
                    ActiveProcessLimit = 1,
                    PriorityClass = SandboxNative.BelowNormalPriorityClass,
                },
                ProcessMemoryLimit = (UIntPtr)(ulong)spec.MemoryLimitBytes,
            };
            Check(SandboxNative.SetInformationJobObject(job, SandboxNative.JobObjectExtendedLimitInformation, &limits,
                (uint)sizeof(SandboxNative.JobObjectExtendedLimitInformationData)), "job limits");

            uint ui = SandboxNative.JobObjectUiLimitAll;
            Check(SandboxNative.SetInformationJobObject(job, SandboxNative.JobObjectBasicUiRestrictions, &ui, 4), "job UI restrictions");

            if (spec.CpuRatePercent is > 0 and < 100)
            {
                var cpu = new SandboxNative.JobObjectCpuRateControlInformationData
                {
                    ControlFlags = SandboxNative.JobObjectCpuRateControlEnable | SandboxNative.JobObjectCpuRateControlHardCap,
                    CpuRate = (uint)(spec.CpuRatePercent * 100),
                };
                Check(SandboxNative.SetInformationJobObject(job, SandboxNative.JobObjectCpuRateControlInformation, &cpu,
                    (uint)sizeof(SandboxNative.JobObjectCpuRateControlInformationData)), "job CPU rate");
            }

            return job;
        }
        catch
        {
            job.Dispose();
            throw;
        }
    }

    private static unsafe SandboxNative.ProcessInformation Launch(
        WorkerLaunchSpec spec, SafeJobHandle job, SafePipeHandle requestClient, SafePipeHandle responseClient)
    {
        string exe = spec.ExecutablePath;
        string commandLine = $"\"{exe}\" --request-pipe {requestClient.DangerousGetHandle()} --response-pipe {responseClient.DangerousGetHandle()}";
        string environment = BuildEnvironment(spec.TestHooks);

        var allocations = new List<IntPtr>();
        IntPtr attributeList = IntPtr.Zero;
        IntPtr environmentBlock = IntPtr.Zero;
        IntPtr objectSecurity = IntPtr.Zero;
        try
        {
            int attributeCount = spec.Isolation == WorkerIsolation.AppContainer ? 5 : 4;
            IntPtr size = IntPtr.Zero;
            SandboxNative.InitializeProcThreadAttributeList(IntPtr.Zero, attributeCount, 0, ref size);
            attributeList = Marshal.AllocHGlobal(size);
            Check(SandboxNative.InitializeProcThreadAttributeList(attributeList, attributeCount, 0, ref size), "InitializeProcThreadAttributeList");

            // Only these two handles are inherited.
            IntPtr handles = Alloc(allocations, 2 * IntPtr.Size);
            Marshal.WriteIntPtr(handles, 0, requestClient.DangerousGetHandle());
            Marshal.WriteIntPtr(handles, IntPtr.Size, responseClient.DangerousGetHandle());
            Update(attributeList, SandboxNative.ProcThreadAttributeHandleList, handles, 2 * IntPtr.Size);

            // In the Job Object from its first instruction.
            IntPtr jobs = Alloc(allocations, IntPtr.Size);
            Marshal.WriteIntPtr(jobs, job.DangerousGetHandle());
            Update(attributeList, SandboxNative.ProcThreadAttributeJobList, jobs, IntPtr.Size);

            IntPtr childPolicy = Alloc(allocations, 4);
            Marshal.WriteInt32(childPolicy, (int)SandboxNative.ChildProcessRestricted);
            Update(attributeList, SandboxNative.ProcThreadAttributeChildProcessPolicy, childPolicy, 4);

            IntPtr mitigations = Alloc(allocations, 16);
            Marshal.WriteInt64(mitigations, 0, (long)spec.Mitigations.Policy1);
            Marshal.WriteInt64(mitigations, 8, (long)spec.Mitigations.Policy2);
            Update(attributeList, SandboxNative.ProcThreadAttributeMitigationPolicy, mitigations, 16);

            if (spec.Isolation == WorkerIsolation.AppContainer)
            {
                IntPtr sid = AppContainerProfile.ToNative(spec.AppContainerSid!);
                allocations.Add(sid);
                IntPtr capabilities = Alloc(allocations, sizeof(SandboxNative.SecurityCapabilities));
                *(SandboxNative.SecurityCapabilities*)capabilities = new SandboxNative.SecurityCapabilities
                {
                    AppContainerSid = sid,
                    Capabilities = IntPtr.Zero,
                    CapabilityCount = 0, // no network, no libraries, no devices
                };
                Update(attributeList, SandboxNative.ProcThreadAttributeSecurityCapabilities, capabilities, sizeof(SandboxNative.SecurityCapabilities));
            }

            environmentBlock = Marshal.StringToHGlobalUni(environment);

            // Review H1: process and initial thread get a protected SYSTEM + Administrators DACL (WorkerObjectSecurity).
            var descriptor = WorkerObjectSecurity.DescriptorBytes();
            IntPtr descriptorPtr = Alloc(allocations, descriptor.Length);
            Marshal.Copy(descriptor, 0, descriptorPtr, descriptor.Length);
            objectSecurity = Alloc(allocations, sizeof(SandboxNative.SecurityAttributes));
            *(SandboxNative.SecurityAttributes*)objectSecurity = new SandboxNative.SecurityAttributes
            {
                nLength = (uint)sizeof(SandboxNative.SecurityAttributes),
                lpSecurityDescriptor = descriptorPtr,
                bInheritHandle = 0,
            };
            var startup = new SandboxNative.StartupInfoEx
            {
                StartupInfo = new SandboxNative.StartupInfo { cb = (uint)sizeof(SandboxNative.StartupInfoEx) },
                lpAttributeList = attributeList,
            };

            // No CREATE_DEFAULT_ERROR_MODE: the worker inherits the broker's hard-error mode (set just below), so a
            // loader or crash failure in the worker can never put a modal "Application Error" box on anyone's desktop.
            // DETACHED_PROCESS: no console and so no conhost.exe child (blocked by the sandbox, see SandboxNative). Windows
            // ignores CREATE_NO_WINDOW next to it; it stays as a second guarantee that no window is ever created.
            const uint flags = SandboxNative.ExtendedStartupInfoPresent | SandboxNative.CreateSuspended | SandboxNative.DetachedProcess
                | SandboxNative.CreateNoWindow | SandboxNative.CreateUnicodeEnvironment;
            lock (LaunchLock)
            {
                SuppressHardErrorDialogs();

                // The handle list needs inheritable handles; they are inheritable only for this call.
                SetInheritable(requestClient, true);
                SetInheritable(responseClient, true);
                try
                {
                    if (!SandboxNative.CreateProcess(exe, (commandLine + "\0").ToCharArray(), objectSecurity, objectSecurity, inheritHandles: true,
                            flags, environmentBlock, Path.GetDirectoryName(exe), ref startup, out var info))
                    {
                        int error = Marshal.GetLastPInvokeError();
                        throw new SandboxUnavailableException(
                            $"Could not start the scan worker {exe} ({spec.Isolation}): {new Win32Exception(error).Message} (Win32 error {error}).");
                    }

                    return info;
                }
                finally
                {
                    SetInheritable(requestClient, false);
                    SetInheritable(responseClient, false);
                }
            }
        }
        finally
        {
            if (attributeList != IntPtr.Zero)
            {
                SandboxNative.DeleteProcThreadAttributeList(attributeList);
                Marshal.FreeHGlobal(attributeList);
            }

            Marshal.FreeHGlobal(environmentBlock);
            foreach (var p in allocations)
            {
                Marshal.FreeHGlobal(p);
            }
        }
    }

    /// <summary>
    /// A fresh, minimal environment: nothing from the engine's environment is passed on (so no DOTNET_STARTUP_HOOKS,
    /// DOTNET_ROOT, PATH or profiler variables an attacker might have planted), only what Windows and the .NET host need.
    /// </summary>
    internal static string BuildEnvironment(bool testHooks)
    {
        string systemRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
        var variables = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["SystemRoot"] = systemRoot,
            ["windir"] = systemRoot,
            ["SystemDrive"] = Path.GetPathRoot(systemRoot)?.TrimEnd('\\') ?? "C:",
            ["PATH"] = Path.Combine(systemRoot, "System32"),
            ["DOTNET_EnableDiagnostics"] = "0",
            ["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1",
        };

        // AppContainer creation rewrites these to the container's own folders (…\Packages\<name>\AC\...) and fails with
        // ERROR_ENVVAR_NOT_FOUND without them. They are plain paths of the engine's own profile.
        foreach (var name in (string[])["USERPROFILE", "LOCALAPPDATA", "APPDATA", "TEMP", "TMP"])
        {
            if (Environment.GetEnvironmentVariable(name) is { Length: > 0 } value)
            {
                variables[name] = value;
            }
        }

        if (DotnetRoot() is { } root)
        {
            variables["DOTNET_ROOT"] = root;
        }

        if (testHooks)
        {
            variables[TestHooksVariable] = "1";
        }

        var sb = new StringBuilder();
        foreach (var (key, value) in variables)
        {
            sb.Append(key).Append('=').Append(value).Append('\0');
        }

        return sb.Append('\0').ToString();
    }

    /// <summary>The root of the .NET install the engine itself runs on (…\dotnet), so the worker uses the same runtime.</summary>
    private static string? DotnetRoot()
    {
        // <root>\shared\Microsoft.NETCore.App\<version>\
        var runtimeDir = Path.GetDirectoryName(typeof(object).Assembly.Location);
        var root = runtimeDir is null ? null : Directory.GetParent(runtimeDir)?.Parent?.Parent;
        return root is not null && Directory.Exists(Path.Combine(root.FullName, "host", "fxr")) ? root.FullName : null;
    }

    /// <summary>
    /// SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX on the broker process, inherited by every
    /// worker: loader failures (e.g. STATUS_DLL_INIT_FAILED) and crashes end the worker silently instead of raising a
    /// hard-error box. The engine has no UI, so it loses nothing by having the same mode.
    /// </summary>
    internal static void SuppressHardErrorDialogs()
    {
        const uint wanted = SandboxNative.SemFailCriticalErrors | SandboxNative.SemNoGpFaultErrorBox | SandboxNative.SemNoOpenFileErrorBox;
        uint current = SandboxNative.GetErrorMode();
        if ((current & wanted) != wanted)
        {
            SandboxNative.SetErrorMode(current | wanted);
        }
    }

    private static void SetInheritable(SafeHandle handle, bool inheritable) =>
        Check(SandboxNative.SetHandleInformation(handle, SandboxNative.HandleFlagInherit, inheritable ? SandboxNative.HandleFlagInherit : 0),
            "SetHandleInformation");

    private static IntPtr Alloc(List<IntPtr> allocations, int bytes)
    {
        var p = Marshal.AllocHGlobal(bytes);
        allocations.Add(p);
        return p;
    }

    private static void Update(IntPtr list, IntPtr attribute, IntPtr value, int size) =>
        Check(SandboxNative.UpdateProcThreadAttribute(list, 0, attribute, value, size, IntPtr.Zero, IntPtr.Zero),
            $"UpdateProcThreadAttribute(0x{attribute:X})");

    private static void Check(bool ok, string what)
    {
        if (!ok)
        {
            int error = Marshal.GetLastPInvokeError();
            throw new SandboxUnavailableException($"{what} failed: {new Win32Exception(error).Message} (Win32 error {error}).");
        }
    }
}
