using System.Runtime.InteropServices;

namespace SapAV.Engine.Persistence.Remediation;

/// <summary>A service as the Service Control Manager reports it.</summary>
/// <param name="StartType">SERVICE_BOOT_START (0) … SERVICE_DISABLED (4).</param>
/// <param name="Running">The service isn't stopped (running, starting, stopping, paused).</param>
/// <param name="ErrorControl">Review M3: SERVICE_ERROR_IGNORE (0) … SERVICE_ERROR_CRITICAL (3).</param>
internal sealed record ServiceState(int StartType, bool Running, int ErrorControl = 1);

internal enum ServiceControlStatus
{
    Ok,
    NotFound,
    AccessDenied,

    /// <summary>The stop request wasn't accepted (the service doesn't accept stops, or has dependants running).</summary>
    StopRefused,

    Failed,
}

/// <summary>
/// D5: what Block &amp; remove does to a service, through the Service Control Manager (never by editing the Services key, never
/// deleting a service). Fake it in tests: normal tests never change a real service.
/// </summary>
internal interface IServiceControl
{
    ServiceControlStatus Query(string name, out ServiceState? state);

    /// <summary>ChangeServiceConfig with only the start type (everything else unchanged).</summary>
    ServiceControlStatus SetStartType(string name, int startType);

    /// <summary>Asks the service to stop (doesn't wait for it).</summary>
    ServiceControlStatus Stop(string name);
}

/// <summary>The real Service Control Manager (advapi32).</summary>
internal sealed class ScmServiceControl : IServiceControl
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryConfig = 0x0001;
    private const uint ServiceChangeConfig = 0x0002;
    private const uint ServiceQueryStatus = 0x0004;
    private const uint ServiceStop = 0x0020;
    private const uint ServiceNoChange = 0xFFFFFFFF;
    private const uint ServiceControlStop = 0x1;
    private const uint ServiceStopped = 0x1;
    private const int ErrorAccessDenied = 5;
    private const int ErrorServiceDoesNotExist = 1060;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorServiceNotActive = 1062;

    public static ScmServiceControl Instance { get; } = new();

    public ServiceControlStatus Query(string name, out ServiceState? state)
    {
        state = null;
        using var service = Open(name, ServiceQueryConfig | ServiceQueryStatus, out var status);
        if (service is null)
        {
            return status;
        }

        QueryServiceConfigW(service, IntPtr.Zero, 0, out uint needed);
        if (Marshal.GetLastWin32Error() != ErrorInsufficientBuffer || needed is 0 or > 64 * 1024)
        {
            return Map(Marshal.GetLastWin32Error());
        }

        IntPtr buffer = Marshal.AllocHGlobal((int)needed);
        try
        {
            if (!QueryServiceConfigW(service, buffer, needed, out _))
            {
                return Map(Marshal.GetLastWin32Error());
            }

            int startType = Marshal.ReadInt32(buffer, 4); // QUERY_SERVICE_CONFIGW: dwServiceType, dwStartType, dwErrorControl, ...
            int errorControl = Marshal.ReadInt32(buffer, 8);
            if (!QueryServiceStatus(service, out var serviceStatus))
            {
                return Map(Marshal.GetLastWin32Error());
            }

            state = new ServiceState(startType, serviceStatus.CurrentState != ServiceStopped, errorControl);
            return ServiceControlStatus.Ok;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public ServiceControlStatus SetStartType(string name, int startType)
    {
        using var service = Open(name, ServiceChangeConfig, out var status);
        if (service is null)
        {
            return status;
        }

        return ChangeServiceConfigW(service, ServiceNoChange, (uint)startType, ServiceNoChange, null, null, IntPtr.Zero, null, null, null, null)
            ? ServiceControlStatus.Ok
            : Map(Marshal.GetLastWin32Error());
    }

    public ServiceControlStatus Stop(string name)
    {
        using var service = Open(name, ServiceStop, out var status);
        if (service is null)
        {
            return status;
        }

        if (ControlService(service, ServiceControlStop, out _))
        {
            return ServiceControlStatus.Ok;
        }

        int error = Marshal.GetLastWin32Error();
        return error == ErrorServiceNotActive ? ServiceControlStatus.Ok : error == ErrorAccessDenied ? ServiceControlStatus.AccessDenied : ServiceControlStatus.StopRefused;
    }

    private static ServiceHandle? Open(string name, uint access, out ServiceControlStatus status)
    {
        using var manager = OpenSCManagerW(null, null, ScManagerConnect);
        if (manager.IsInvalid)
        {
            status = Map(Marshal.GetLastWin32Error());
            return null;
        }

        var service = OpenServiceW(manager, name, access);
        if (service.IsInvalid)
        {
            status = Map(Marshal.GetLastWin32Error());
            service.Dispose();
            return null;
        }

        status = ServiceControlStatus.Ok;
        return service;
    }

    private static ServiceControlStatus Map(int error) => error switch
    {
        0 => ServiceControlStatus.Ok,
        ErrorServiceDoesNotExist => ServiceControlStatus.NotFound,
        ErrorAccessDenied => ServiceControlStatus.AccessDenied,
        _ => ServiceControlStatus.Failed,
    };

    internal sealed class ServiceHandle() : Microsoft.Win32.SafeHandles.SafeHandleZeroOrMinusOneIsInvalid(ownsHandle: true)
    {
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern ServiceHandle OpenSCManagerW(string? machine, string? database, uint access);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern ServiceHandle OpenServiceW(ServiceHandle manager, string name, uint access);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfigW(ServiceHandle service, IntPtr config, uint size, out uint needed);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatus(ServiceHandle service, out ServiceStatus status);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ChangeServiceConfigW(
        ServiceHandle service, uint serviceType, uint startType, uint errorControl, string? binaryPath, string? loadOrderGroup, IntPtr tagId,
        string? dependencies, string? startName, string? password, string? displayName);

    [DllImport("advapi32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ControlService(ServiceHandle service, uint control, out ServiceStatus status);
}
