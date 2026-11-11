using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Scanning.Isolation;
using SapAV.Core.Persistence;
using SapAV.Engine.Persistence;

namespace SapAV.Engine.Tests.Persistence;

/// <summary>
/// A throwaway <c>HKCU\Software\sap-AV-tests\&lt;guid&gt;</c> key with <c>HKLM</c> and <c>HKU</c> subkeys that stand in
/// for the real roots, read through the real <see cref="WindowsRegistryView"/>. Tests never write HKLM. Deleted on dispose.
/// </summary>
internal sealed class RegistryTestRoot : IDisposable
{
    public const string UserSid = "S-1-5-21-1000-2000-3000-1001";
    private const string Parent = @"Software\sap-AV-tests";

    private readonly string _path = $@"{Parent}\{Guid.NewGuid():N}";
    private readonly RegistryKey _machine;
    private readonly RegistryKey _users;

    public RegistryTestRoot()
    {
        _machine = Registry.CurrentUser.CreateSubKey(_path + @"\HKLM");
        _users = Registry.CurrentUser.CreateSubKey(_path + @"\HKU");
        View = new WindowsRegistryView(_machine, _users);
        Machine(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion").SetValue("SystemRoot", @"C:\Windows");
        using (var environment = Machine(@"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"))
        {
            environment.SetValue("Path", @"%SystemRoot%\system32;%SystemRoot%;C:\Tools", RegistryValueKind.ExpandString);
            environment.SetValue("windir", "%SystemRoot%", RegistryValueKind.ExpandString);
        }
        Machine(@"SOFTWARE\Microsoft\Windows\CurrentVersion").SetValue("ProgramFilesDir", @"C:\Program Files");
    }

    public WindowsRegistryView View { get; }

    /// <summary>The keys standing in for HKLM and HKU (D4: the same roots for the real registry watches).</summary>
    public RegistryKey MachineKey => _machine;

    public RegistryKey UsersKey => _users;

    public RegistryKey Machine(string path) => _machine.CreateSubKey(path);

    public RegistryKey Users(string path) => _users.CreateSubKey(path);

    /// <summary>D4: the fake "hive" of <paramref name="sid"/> goes away from HKU (a logoff); its ProfileList entry stays.</summary>
    public void UnloadUser(string sid) => _users.DeleteSubKeyTree(sid, throwOnMissingSubKey: false);

    /// <summary>A ProfileList entry, and (when <paramref name="loaded"/>) a hive under HKU with a Volatile Environment.</summary>
    public void AddUser(string sid, string profile, bool loaded)
    {
        Machine($@"{RegistryEnvironment.ProfileListPath}\{sid}").SetValue("ProfileImagePath", profile, RegistryValueKind.ExpandString);
        if (loaded)
        {
            Users($@"{sid}\Volatile Environment").SetValue("APPDATA", profile + @"\AppData\Roaming");
        }
    }

    public void Dispose()
    {
        _machine.Dispose();
        _users.Dispose();
        Registry.CurrentUser.DeleteSubKeyTree(_path, throwOnMissingSubKey: false);
        using var parent = Registry.CurrentUser.OpenSubKey(Parent, writable: true);
        if (parent is not null && parent.SubKeyCount == 0 && parent.ValueCount == 0)
        {
            try
            {
                Registry.CurrentUser.DeleteSubKey(Parent, throwOnMissingSubKey: false);
            }
            catch (InvalidOperationException)
            {
                // A test class running in parallel created its own root under Parent after the check: leave it to that test.
            }
        }
    }
}

/// <summary>An <see cref="IPathProbe"/> over a fixed set of paths.</summary>
internal sealed class SetProbe(params string[] existing) : IPathProbe
{
    private readonly HashSet<string> _existing = new(existing, StringComparer.OrdinalIgnoreCase);

    public void Add(string path) => _existing.Add(path);

    public bool FileExists(string path) => _existing.Contains(path);
}

internal static class PersistenceTestExtensions
{
    public static PersistenceCollection Collect(this RegistryTestRoot root, IPathProbe probe, params IPersistenceSource[] sources) =>
        new PersistenceCollector(root.View, probe, sources, parser: WireTestParser.Instance).Collect();

    public static PersistenceEntry Single(this PersistenceCollection collection, string valueName) =>
        Assert.Single(collection.Entries, e => e.ValueName == valueName);
}

/// <summary>
/// A stand-in for the sandboxed worker for collector tests that aren't about the sandbox: reads the handle and runs the
/// same worker entry point + engine validation, in the test process. The worker path itself is tested in
/// <c>PersistenceParsingInWorkerTests</c>.
/// </summary>
internal sealed class WireTestParser : IPersistenceFileParser
{
    public static WireTestParser Instance { get; } = new();

    public int Calls { get; private set; }

    public Task<PersistenceParseResult> ParseAsync(SafeFileHandle file, WorkerParseKind kind, string displayPath, CancellationToken cancellationToken)
    {
        Calls++;
        var content = new byte[RandomAccess.GetLength(file)];
        int read = RandomAccess.Read(file, content, 0);
        var parsed = WireParsedFileCodec.FromWire(WireParsedFileCodec.ParseInWorker(kind, content[..read]), kind);
        return Task.FromResult(parsed.Error is { } error
            ? PersistenceParseResult.Malformed(error)
            : new PersistenceParseResult(PersistenceParseStatus.Parsed, parsed.Task, parsed.Link, null));
    }
}
