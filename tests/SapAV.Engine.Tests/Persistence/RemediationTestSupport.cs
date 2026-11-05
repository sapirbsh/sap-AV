using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using SapAV.Core.Persistence;
using SapAV.Engine.Persistence;
using SapAV.Engine.Persistence.Remediation;
using SapAV.Engine.Tests.TestSupport;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>A Service Control Manager in memory: what Block &amp; remove asked of it (no real service is touched).</summary>
internal sealed class FakeServiceControl : IServiceControl
{
    public Dictionary<string, ServiceState> Services { get; } = new(StringComparer.OrdinalIgnoreCase);

    public List<string> Stopped { get; } = [];

    /// <summary>Called after a start-type change (the harness writes it into the fake registry, as the real SCM does).</summary>
    public Action<string, int>? Changed { get; set; }

    public ServiceControlStatus Query(string name, out ServiceState? state) =>
        (state = Services.GetValueOrDefault(name)) is null ? ServiceControlStatus.NotFound : ServiceControlStatus.Ok;

    public ServiceControlStatus SetStartType(string name, int startType)
    {
        if (!Services.TryGetValue(name, out var state))
        {
            return ServiceControlStatus.NotFound;
        }

        Services[name] = state with { StartType = startType };
        Changed?.Invoke(name, startType); // the real SCM writes the Services key's Start too
        return ServiceControlStatus.Ok;
    }

    public ServiceControlStatus Stop(string name)
    {
        Stopped.Add(name);
        if (Services.TryGetValue(name, out var state))
        {
            Services[name] = state with { Running = false };
        }

        return ServiceControlStatus.Ok;
    }
}

/// <summary>A Task Scheduler in memory. Disabling rewrites the definition's Enabled element, as the real one does.</summary>
internal sealed class FakeTaskScheduler : ITaskSchedulerControl
{
    public Dictionary<string, ScheduledTaskState> Tasks { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Called after Enabled changed (task path, old and new Settings element); the harness rewrites the task file.</summary>
    public Action<string, string, string>? Changed { get; set; }

    public TaskControlStatus Get(string taskPath, out ScheduledTaskState? state) =>
        (state = Tasks.GetValueOrDefault(taskPath)) is null ? TaskControlStatus.NotFound : TaskControlStatus.Ok;

    public TaskControlStatus SetEnabled(string taskPath, bool enabled)
    {
        if (!Tasks.TryGetValue(taskPath, out var state))
        {
            return TaskControlStatus.NotFound;
        }

        string from = $"<Enabled>{(enabled ? "false" : "true")}</Enabled>", to = $"<Enabled>{(enabled ? "true" : "false")}</Enabled>";
        Tasks[taskPath] = state with { Enabled = enabled, Xml = state.Xml.Replace(from, to, StringComparison.Ordinal) };
        Changed?.Invoke(taskPath, from, to); // the real Task Scheduler rewrites the task's file too
        return TaskControlStatus.Ok;
    }
}

/// <summary>
/// One Block &amp; remove test: a throwaway registry (fake HKLM / HKU under <c>HKCU\Software\sap-AV-tests</c>) with two loaded
/// users, a temp profile with a Startup folder for Alice, a temp Tasks folder, the real collector and link-safe registry
/// editor on those roots, the real quarantine on a temp store, fake SCM and Task Scheduler, an HMAC'd backup store in a temp
/// folder, and a manual clock. Nothing real (HKLM, services, tasks, ProgramData) is touched.
/// </summary>
internal sealed class RemediationHarness : IDisposable
{
    public const string Alice = MonitorHarness.Alice;
    public const string Bob = MonitorHarness.Bob;
    public const string UserRun = MonitorHarness.UserRun;
    public const string MachineRun = MonitorHarness.MachineRun;

    private readonly TempDir _temp = new();
    private readonly List<IDisposable> _clients = [];

    /// <param name="collector">D4 tests: the monitor harness's collector (with <paramref name="registry"/>, its registry).</param>
    public RemediationHarness(
        IScopedPersistenceCollector? collector = null, PersistenceActionLedger? ledger = null, ManualTime? time = null, RegistryTestRoot? registry = null,
        TimeSpan? actionTimeout = null)
    {
        _ownsRegistry = registry is null;
        Registry = registry ?? new RegistryTestRoot();
        Time = time ?? new ManualTime();
        AliceStartup = Directory.CreateDirectory(Path.Combine(_temp.Path, "alice", @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")).FullName;
        Tasks = Directory.CreateDirectory(Path.Combine(_temp.Path, "Tasks")).FullName;
        Registry.AddUser(Alice, Path.Combine(_temp.Path, "alice"), loaded: true);
        Registry.AddUser(Bob, Path.Combine(_temp.Path, "bob"), loaded: true);
        Collector = new PersistenceCollector(Registry.View, new SafePathProbe(),
            [new RegistryAutorunSource(), new ServiceSource(), new StartupFolderSource(), new ScheduledTaskSource(Tasks, (_, _) => true)], parser: WireTestParser.Instance);
        Store = new FilePersistenceBackupStore(Directory.CreateDirectory(Path.Combine(_temp.Path, "backups")).FullName, RandomNumberGenerator.GetBytes(32));
        Ledger = ledger ?? new PersistenceActionLedger(Time);
        Services.Changed = (name, start) =>
        {
            using var key = Registry.Machine($@"SYSTEM\CurrentControlSet\Services\{name}");
            key.SetValue("Start", start, RegistryValueKind.DWord);
        };
        TaskScheduler.Changed = (taskPath, from, to) =>
        {
            string file = Path.Combine(Tasks, taskPath.TrimStart('\\'));
            if (File.Exists(file))
            {
                string text = Encoding.Unicode.GetString(File.ReadAllBytes(file)[2..]);
                File.WriteAllBytes(file, [.. Encoding.Unicode.GetPreamble(), .. Encoding.Unicode.GetBytes(text.Replace(from, to, StringComparison.Ordinal))]);
            }
        };
        Remediator = new PersistenceRemediator(collector ?? Collector, () => Store, new NoFollowRegistryEditor(Registry.MachineKey, Registry.UsersKey),
            Services, TaskScheduler, Quarantine.Manager, Ledger, Time, alerts: Alerts)
        {
            ActionTimeout = actionTimeout ?? TimeSpan.FromMinutes(2),
            LockWait = actionTimeout is null ? TimeSpan.FromSeconds(30) : TimeSpan.FromMilliseconds(200),
        };
    }

    private readonly bool _ownsRegistry;

    public RegistryTestRoot Registry { get; }

    public QuarantineTestContext Quarantine { get; } = new();

    public string AliceStartup { get; }

    public string Tasks { get; }

    public PersistenceCollector Collector { get; }

    public FilePersistenceBackupStore Store { get; }

    public FakeServiceControl Services { get; } = new();

    public FakeTaskScheduler TaskScheduler { get; } = new();

    public RecordingAlertSink Alerts { get; } = new();

    public ManualTime Time { get; }

    public PersistenceActionLedger Ledger { get; }

    public PersistenceRemediator Remediator { get; }

    /// <summary>A standard user (access checks answered by this test process's own token).</summary>
    public FakeClientIdentity User(string sid) => Track(new FakeClientIdentity(new SecurityIdentifier(sid), isAdmin: false));

    public FakeClientIdentity Admin() => Track(new FakeClientIdentity(FakeClientIdentity.NewUserSid(), isAdmin: true));

    private FakeClientIdentity Track(FakeClientIdentity client)
    {
        _clients.Add(client);
        return client;
    }

    public RegistryKey UserRunKey(string sid) => Registry.Users($@"{sid}\{UserRun}");

    public PersistenceEntry Entry(Func<PersistenceEntry, bool> match) => Assert.Single(Collector.Collect().Entries, e => match(e));

    public PersistenceEntry Entry(string valueName) => Entry(e => e.ValueName == valueName);

    public string IdOf(string valueName) => PersistenceEntryId.Compute(Entry(valueName));

    public RemediationResult Block(FakeClientIdentity client, string id, bool confirmCritical = false) =>
        Remediator.BlockAsync(client, id, confirmCritical: confirmCritical).GetAwaiter().GetResult();

    public RemediationResult Restore(FakeClientIdentity client, string backupId) => Remediator.RestoreAsync(client, backupId).GetAwaiter().GetResult();

    /// <summary>A task descriptor (SDDL) that lets this test process's user change the task.</summary>
    public static string WritableByMe { get; } = $"O:SYG:SYD:(A;;FA;;;SY)(A;;FA;;;{QuarantineTestContext.CurrentUser.Value})";

    /// <summary>A task descriptor only SYSTEM may change (everyone may read it), like an administrator-deployed task.</summary>
    public const string SystemOnly = "O:SYG:SYD:(A;;FA;;;SY)(A;;FR;;;WD)";

    /// <summary>A task definition file in the temp Tasks folder, and the same task registered in the fake Task Scheduler.</summary>
    public string AddTask(string name, string command, string principal, bool registered = true)
    {
        string xml = $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <Principals><Principal id="Author"><UserId>{principal}</UserId></Principal></Principals>
              <Settings><Enabled>true</Enabled></Settings>
              <Actions Context="Author"><Exec><Command>{command}</Command></Exec></Actions>
            </Task>
            """;
        File.WriteAllBytes(Path.Combine(Tasks, name), [.. Encoding.Unicode.GetPreamble(), .. Encoding.Unicode.GetBytes(xml)]);
        if (registered)
        {
            TaskScheduler.Tasks[@"\" + name] = new ScheduledTaskState(true, xml, principal, null, WritableByMe);
        }

        return @"\" + name;
    }

    /// <summary>A service key in the fake HKLM (what the collector reads) and the same service in the fake SCM.</summary>
    public void AddService(string name, string imagePath, int start = 2, bool running = true, int errorControl = 1)
    {
        using var key = Registry.Machine($@"SYSTEM\CurrentControlSet\Services\{name}");
        key.SetValue("Type", 16, RegistryValueKind.DWord);
        key.SetValue("Start", start, RegistryValueKind.DWord);
        key.SetValue("ImagePath", imagePath, RegistryValueKind.ExpandString);
        Services.Services[name] = new ServiceState(start, running, errorControl);
    }

    public void Dispose()
    {
        foreach (var client in _clients)
        {
            client.Dispose();
        }

        Quarantine.Dispose();
        if (_ownsRegistry)
        {
            Registry.Dispose();
        }

        _temp.Dispose();
    }
}

/// <summary>
/// A volatile registry symbolic link key inside a test root (HKCU, same hive), pointing at another test key; deleted as the
/// link itself (opened with REG_OPTION_OPEN_LINK) on dispose, so cleanup never follows it.
/// </summary>
internal sealed class RegistryLink : IDisposable
{
    private const uint RegOptionVolatile = 0x1;
    private const uint RegOptionCreateLink = 0x2;
    private const uint RegOptionOpenLink = 0x8;
    private const uint KeyAllAccess = 0xF003F;
    private const uint Delete = 0x10000;
    private const uint RegLink = 6;

    private readonly RegistryKey _parent;
    private readonly string _name;

    private RegistryLink(RegistryKey parent, string name)
    {
        _parent = parent;
        _name = name;
    }

    public static RegistryLink Create(RegistryKey linkRoot, string linkPath, RegistryKey targetRoot, string targetPath)
    {
        int cut = linkPath.LastIndexOf('\\');
        var parent = linkRoot.CreateSubKey(linkPath[..cut]);
        string name = linkPath[(cut + 1)..];
        string target = NativeName(targetRoot) + @"\" + targetPath;
        int error = RegCreateKeyExW(parent.Handle, name, 0, null, RegOptionCreateLink | RegOptionVolatile, KeyAllAccess, IntPtr.Zero, out var link, out _);
        Assert.True(error == 0, $"Creating a registry link failed (Win32 error {error}).");
        using (link)
        {
            byte[] bytes = System.Text.Encoding.Unicode.GetBytes(target);
            error = RegSetValueExW(link, "SymbolicLinkValue", 0, RegLink, bytes, (uint)bytes.Length);
        }

        var created = new RegistryLink(parent, name);
        if (error != 0)
        {
            created.Dispose();
            Assert.Fail($"Setting the registry link's target failed (Win32 error {error}).");
        }

        return created;
    }

    public void Dispose()
    {
        if (RegOpenKeyExW(_parent.Handle, _name, RegOptionOpenLink, Delete, out var link) == 0)
        {
            using (link)
            {
                NtDeleteKey(link);
            }
        }

        _parent.Dispose();
    }

    /// <summary>The kernel name of an open key (<c>\REGISTRY\USER\S-1-5-…\…</c>), from NtQueryKey(KeyNameInformation).</summary>
    private static string NativeName(RegistryKey key)
    {
        var buffer = new byte[4096];
        int status = NtQueryKey(key.Handle, 3, buffer, buffer.Length, out int length);
        Assert.True(status == 0, $"NtQueryKey failed (0x{status:X8}).");
        int bytes = BitConverter.ToInt32(buffer, 0);
        return System.Text.Encoding.Unicode.GetString(buffer, 4, bytes);
    }

    [System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, ExactSpelling = true)]
    private static extern int RegCreateKeyExW(
        Microsoft.Win32.SafeHandles.SafeRegistryHandle key, string subKey, uint reserved, string? @class, uint options, uint desired, IntPtr security,
        out Microsoft.Win32.SafeHandles.SafeRegistryHandle result, out uint disposition);

    [System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, ExactSpelling = true)]
    private static extern int RegSetValueExW(Microsoft.Win32.SafeHandles.SafeRegistryHandle key, string name, uint reserved, uint type, byte[] data, uint size);

    [System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, ExactSpelling = true)]
    private static extern int RegOpenKeyExW(Microsoft.Win32.SafeHandles.SafeRegistryHandle key, string subKey, uint options, uint desired, out Microsoft.Win32.SafeHandles.SafeRegistryHandle result);

    [System.Runtime.InteropServices.DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtDeleteKey(Microsoft.Win32.SafeHandles.SafeRegistryHandle key);

    [System.Runtime.InteropServices.DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern int NtQueryKey(Microsoft.Win32.SafeHandles.SafeRegistryHandle key, int infoClass, byte[] info, int length, out int resultLength);
}
