using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Extensions.Options;
using SapAV.Core.Alerts;
using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Scanning;
using SapAV.Engine.Alerts;
using SapAV.Engine.Quarantine;

namespace SapAV.Engine.Tests.TestSupport;

/// <summary>Thrown by a step hook to simulate a crash at that point.</summary>
internal sealed class SimulatedCrashException(string step) : Exception($"Simulated crash at {step}.");

/// <summary>Collects alerts.</summary>
internal sealed class RecordingAlertSink : IAlertSink
{
    public List<Alert> Alerts { get; } = [];

    public ValueTask WriteAsync(Alert alert, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(alert);
        lock (Alerts)
        {
            Alerts.Add(alert);
        }

        return ValueTask.CompletedTask;
    }
}

/// <summary>A fixed in-memory HMAC key.</summary>
internal sealed class FixedKeyProvider(byte[] key) : IQuarantineKeyProvider
{
    public byte[] GetOrCreateKey(string storeRoot, QuarantineAccessPolicy policy) => key;
}

/// <summary>A unique temp folder (deleted on dispose, read-only attributes cleared first).</summary>
internal sealed class TempDir : IDisposable
{
    public TempDir(string? parent = null)
    {
        Path = System.IO.Path.Combine(parent ?? System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sapav-tests"), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
        Path = new DirectoryInfo(Path).FullName;
    }

    public string Path { get; }

    /// <summary>Deletes a folder tree, removing junctions/symlinks first without following them.</summary>
    public static void DeleteTree(string root)
    {
        var pending = new Stack<string>([root]);
        while (pending.TryPop(out var dir))
        {
            foreach (var sub in Directory.EnumerateDirectories(dir))
            {
                if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) != 0)
                {
                    new DirectoryInfo(sub).Delete(recursive: false);
                }
                else
                {
                    pending.Push(sub);
                }
            }
        }

        Directory.Delete(root, recursive: true);
    }

    /// <summary>Adds full control for the current user to every folder below <paramref name="root"/> we own (best effort).</summary>
    private static void GrantSelf(string root)
    {
        var user = QuarantineTestContext.CurrentUser;
        var pending = new Stack<string>([root]);
        while (pending.TryPop(out var dir))
        {
            try
            {
                var info = new DirectoryInfo(dir);
                var security = info.GetAccessControl(System.Security.AccessControl.AccessControlSections.Access);
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(user,
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
                info.SetAccessControl(security);
                foreach (var sub in Directory.EnumerateDirectories(dir))
                {
                    if ((File.GetAttributes(sub) & FileAttributes.ReparsePoint) == 0)
                    {
                        pending.Push(sub);
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
            {
            }
        }
    }

    public void Dispose()
    {
        for (int attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                if (!Directory.Exists(Path))
                {
                    return;
                }

                // Extended form, so names ending in a dot or space (B3 H1 tests) are deleted exactly.
                string root = @"\\?\" + Path;
                foreach (var file in Directory.EnumerateFiles(root, "*", new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = 0 }))
                {
                    File.SetAttributes(file, FileAttributes.Normal);
                }

                DeleteTree(root);
                return;
            }
            catch (DirectoryNotFoundException)
            {
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (ex is UnauthorizedAccessException)
                {
                    GrantSelf(Path); // e.g. a store created with the SYSTEM + Administrators-only ACL; we are its owner
                }

                Thread.Sleep(20 * (attempt + 1));
            }
        }
    }
}

/// <summary>
/// One quarantine test: a temp folder with <c>store\</c> (the quarantine root, trusting the test user so a
/// non-elevated run can use it) and <c>files\</c> (the "user" files), a manager with a fixed key, fake alerts and clock.
/// </summary>
internal sealed class QuarantineTestContext : IDisposable
{
    private readonly TempDir _temp;

    public QuarantineTestContext(
        Action<QuarantineStep>? hook = null, bool forceCrossVolume = false, string? filesParent = null, Action<QuarantineOptions>? configure = null)
    {
        _temp = new TempDir();
        StoreRoot = System.IO.Path.Combine(_temp.Path, "store");
        Files = Directory.CreateDirectory(System.IO.Path.Combine(filesParent ?? _temp.Path, filesParent is null ? "files" : Guid.NewGuid().ToString("N"))).FullName;
        ForceCrossVolume = forceCrossVolume;
        Configure = configure;
        Manager = Create(hook);
        Manager.Initialize();
    }

    public string Base => _temp.Path;

    public string StoreRoot { get; }

    public string Files { get; }

    public bool ForceCrossVolume { get; }

    /// <summary>Applied to the options of every manager this context creates.</summary>
    public Action<QuarantineOptions>? Configure { get; }

    private QuarantineOptions Configured(QuarantineOptions options)
    {
        Configure?.Invoke(options);
        return options;
    }

    public byte[] Key { get; } = RandomNumberGenerator.GetBytes(32);

    public RecordingAlertSink Alerts { get; } = new();

    public ListLogger<QuarantineManager> Log { get; } = new();

    public ManualTime Time { get; } = new();

    public QuarantineManager Manager { get; private set; }

    public static SecurityIdentifier CurrentUser
    {
        get
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.User!;
        }
    }

    /// <summary>A manager on this context's store (not initialised).</summary>
    public QuarantineManager Create(Action<QuarantineStep>? hook = null) =>
        new(Options.Create(Configured(new QuarantineOptions { Root = StoreRoot, AdditionalTrustedSids = [CurrentUser] })),
            Alerts, Log, Time, new FixedKeyProvider(Key))
        {
            StepHook = hook,
            ForceCrossVolume = ForceCrossVolume,
        };

    /// <summary>Simulates an engine restart: drop the manager, start a new one, return what recovery did.</summary>
    public IReadOnlyList<QuarantineRecoveryAction> Restart(Action<QuarantineStep>? hook = null)
    {
        Manager.Dispose();
        Manager = Create(hook);
        return Manager.Initialize();
    }

    public string WriteFile(string relativePath, byte[] content)
    {
        var path = System.IO.Path.Combine(Files, relativePath);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, content);
        return path;
    }

    /// <summary>Files in the store other than the key file, by name.</summary>
    public string[] StoreFiles() =>
        Directory.GetFiles(StoreRoot).Select(System.IO.Path.GetFileName).Where(n => n != DpapiQuarantineKeyProvider.KeyFileName).Order().ToArray()!;

    /// <summary>A scan report for <paramref name="path"/> as if it had <paramref name="scannedContent"/>.</summary>
    /// <remarks>The identity (file ID + final path) is captured from the file now at <paramref name="path"/>, as the scanner does.</remarks>
    public static FileScanReport ReportFor(string path, byte[] scannedContent, Verdict verdict = Verdict.Malicious)
    {
        FileIdentity? identity;
        using (var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            identity = FileIdentity.TryCapture(handle);
        }

        return ReportFor(path, scannedContent, identity, verdict);
    }

    /// <summary>A scan report with an explicit identity (or none).</summary>
    public static FileScanReport ReportFor(string path, byte[] scannedContent, FileIdentity? identity, Verdict verdict = Verdict.Malicious)
    {
        string sha = Convert.ToHexStringLower(SHA256.HashData(scannedContent));
        var item = new ScanItem(path, ScanTrigger.RealTime);
        var detection = new Detection(verdict, "YARA rule Test_Rule matched (test.yar)", "T1204.002", DetectionSource.Yara, ["T1036.007"]);
        var result = new ScanResult(item, [detection], new DateTimeOffset(2026, 10, 22, 9, 0, 0, TimeSpan.Zero), sha);
        return new FileScanReport(result, HashResult.Hashed(sha, scannedContent.Length), null, null, null, null, []) { Identity = identity };
    }

    /// <summary>Synthetic "malware": a marker string in random bytes (no MZ header, so a real antivirus leaves it alone; never real malware, never EICAR).</summary>
    /// <remarks>Fixed seed (default 1), so a real antivirus sees the same bytes on every run (review L6).</remarks>
    public static byte[] SampleContent(int size = 10_000, int seed = 1)
    {
        var bytes = new byte[size];
        new Random(seed).NextBytes(bytes);
        Marker.CopyTo(bytes, 64);
        return bytes;
    }

    /// <summary>A distinctive byte string inside <see cref="SampleContent"/>.</summary>
    public static byte[] Marker { get; } = "SAPAV-TEST-MARKER-STRING-0123456789"u8.ToArray();

    public void Dispose()
    {
        Manager.Dispose();
        _temp.Dispose();
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreateHardLink(string newFile, string existingFile, IntPtr reserved);
}
