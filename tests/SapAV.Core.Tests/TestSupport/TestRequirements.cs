using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SapAV.Core.Hashing;
using SapAV.Core.Signatures;

namespace SapAV.Core.Tests.TestSupport;

/// <summary>
/// Things a test needs that exist on this PC but may be missing on a clean Windows 10/11 machine or a CI runner.
/// Tests that need one use <see cref="RequiresFactAttribute"/> / <see cref="RequiresTheoryAttribute"/>, so the
/// runner reports them as Skipped (with the reason) instead of failing or passing without assertions.
/// </summary>
public enum Requires
{
    /// <summary>File and directory symlinks can be created (Developer Mode or SeCreateSymbolicLinkPrivilege).</summary>
    Symlinks,

    /// <summary><c>mklink /J</c> works in the temp folder (NTFS).</summary>
    Junctions,

    /// <summary>A raw junction to <c>\??\pipe\</c> can be written (FSCTL_SET_REPARSE_POINT on the temp volume).</summary>
    PipeNamespaceJunction,

    /// <summary>A local named pipe is reachable over SMB loopback (<c>\\localhost\pipe\...</c>; needs the Server service).</summary>
    SmbLoopbackPipe,

    /// <summary>The local admin share of the temp drive (<c>\\localhost\C$\...</c>) is readable.</summary>
    AdminShare,

    /// <summary>Windows 11 or later (build 22000+). Windows Server 2022 (20348) and Windows 10 don't qualify.</summary>
    Windows11,

    /// <summary>A small DLL of the running .NET runtime with an embedded Authenticode signature.</summary>
    SignedDotNetRuntime,

    /// <summary>System32\notepad.exe is a regular file (not missing, not an app alias).</summary>
    NotepadRegularFile,

    /// <summary>Program Files has at least one trusted, embedded-signed executable under a non-Microsoft root.</summary>
    ThirdPartySignedSoftware,

    /// <summary>The DriverStore has at least one trusted WHQL-signed catalog ("Hardware Compatibility Publisher").</summary>
    WhqlDriverCatalog,

    /// <summary>"Microsoft Root Certificate Authority 2010" is in a local certificate store.</summary>
    RootCa2010InStore,

    /// <summary>"Microsoft Root Certificate Authority 2011" is in a local certificate store.</summary>
    RootCa2011InStore,

    /// <summary>At least one certificate of <see cref="MicrosoftCodeSigningCertificates"/> is in a local store.</summary>
    AnyKnownCertificateInStore,

    /// <summary>
    /// Opt-in (<c>SAPAV_TEST_EICAR_ON_DISK=1</c>): the EICAR test file can be written to %TEMP% and read back,
    /// i.e. no real antivirus removes or blocks it. Off by default because a real antivirus alerts on it.
    /// </summary>
    EicarFileOnDisk,
}

/// <summary>Probes each <see cref="Requires"/> once per test process (lazily, at discovery time).</summary>
internal static class TestRequirements
{
    /// <summary>Set to 1 / true to make every requirement unmet, as on a clean machine with nothing extra.</summary>
    public const string SimulateCleanMachineVariable = "SAPAV_TEST_SIMULATE_CLEAN_MACHINE";

    private static readonly Dictionary<Requires, Lazy<string?>> Probes = new()
    {
        [Requires.Symlinks] = new(ProbeSymlinks),
        [Requires.Junctions] = new(ProbeJunctions),
        [Requires.PipeNamespaceJunction] = new(ProbePipeNamespaceJunction),
        [Requires.SmbLoopbackPipe] = new(ProbeSmbLoopbackPipe),
        [Requires.AdminShare] = new(ProbeAdminShare),
        [Requires.Windows11] = new(() => OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000)
            ? null
            : $"needs Windows 11 (build 22000+); this is {Environment.OSVersion.Version}"),
        [Requires.SignedDotNetRuntime] = new(() => SignedSamples.EmbeddedSignedMicrosoftDll() is null
            ? "no embedded-signed DLL in the running .NET runtime folder"
            : null),
        [Requires.NotepadRegularFile] = new(ProbeNotepad),
        [Requires.ThirdPartySignedSoftware] = new(() => SignedSamples.TrustedThirdPartySample() is null
            ? "no trusted third-party signed executable under Program Files"
            : null),
        [Requires.WhqlDriverCatalog] = new(() => SignedSamples.WhqlDriverCatalog() is null
            ? "no trusted WHQL-signed catalog in the DriverStore"
            : null),
        [Requires.RootCa2010InStore] = new(() => CertificateStores.Find(MicrosoftCodeSigningCertificates.RootCa2010.Sha1) is null
            ? "Microsoft Root Certificate Authority 2010 is not in any local certificate store"
            : null),
        [Requires.RootCa2011InStore] = new(() => CertificateStores.Find(MicrosoftCodeSigningCertificates.RootCa2011.Sha1) is null
            ? "Microsoft Root Certificate Authority 2011 is not in any local certificate store"
            : null),
        [Requires.AnyKnownCertificateInStore] = new(() => MicrosoftCodeSigningCertificates.ProductRoots
                .Concat(MicrosoftCodeSigningCertificates.FirstPartyIssuingCas.Select(e => e.Certificate))
                .Concat(MicrosoftCodeSigningCertificates.ThirdPartyContentCas)
                .Any(k => CertificateStores.Find(k.Sha1) is not null)
            ? null
            : "none of the known Microsoft certificates is in a local certificate store"),
        [Requires.EicarFileOnDisk] = new(ProbeEicarOnDisk),
    };

    /// <summary>Set to 1 to run the tests that write the EICAR test file to disk.</summary>
    public const string EicarOnDiskVariable = "SAPAV_TEST_EICAR_ON_DISK";

    public static bool SimulateCleanMachine
    {
        get
        {
            var value = Environment.GetEnvironmentVariable(SimulateCleanMachineVariable);
            return value is not null && (value.Trim() == "1" || value.Trim().Equals("true", StringComparison.OrdinalIgnoreCase));
        }
    }

    /// <summary>Null if every requirement is met, otherwise the skip reason (all unmet ones).</summary>
    public static string? SkipReason(IEnumerable<Requires> requirements) => SkipReason(requirements, SimulateCleanMachine);

    public static string? SkipReason(IEnumerable<Requires> requirements, bool simulateCleanMachine)
    {
        var unmet = new List<string>();
        foreach (var requirement in requirements.Distinct())
        {
            if (simulateCleanMachine)
            {
                unmet.Add($"{requirement}: simulated clean machine ({SimulateCleanMachineVariable}=1)");
                continue;
            }

            string? why;
            try
            {
                why = Probes[requirement].Value;
            }
            catch (Exception ex)
            {
                why = $"probe failed: {ex.GetType().Name}: {ex.Message}";
            }

            if (why is not null)
            {
                unmet.Add($"{requirement}: {why}");
            }
        }

        return unmet.Count == 0 ? null : "Requirement not met on this machine. " + string.Join("; ", unmet);
    }

    /// <summary>All requirements, for the self-tests.</summary>
    public static IReadOnlyCollection<Requires> All => Probes.Keys;

    // --- Probes: each returns null when the requirement is met, else a short reason ---

    private static string ProbeDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sapav-tests", "probe-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static void DeleteProbeDir(string dir)
    {
        try
        {
            // Remove link entries first, without following them.
            foreach (var entry in new DirectoryInfo(dir).EnumerateFileSystemInfos())
            {
                if (entry.Attributes.HasFlag(FileAttributes.ReparsePoint) && entry is DirectoryInfo d)
                {
                    d.Delete(recursive: false);
                }
            }

            Directory.Delete(dir, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // best effort
        }
    }

    private static string? ProbeSymlinks()
    {
        var dir = ProbeDir();
        try
        {
            File.WriteAllBytes(Path.Combine(dir, "t"), [1]);
            File.CreateSymbolicLink(Path.Combine(dir, "l"), Path.Combine(dir, "t"));
            Directory.CreateSymbolicLink(Path.Combine(dir, "dl"), dir);
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return $"cannot create symlinks (needs Developer Mode or SeCreateSymbolicLinkPrivilege): {ex.Message}";
        }
        finally
        {
            DeleteProbeDir(dir);
        }
    }

    private static string? ProbeJunctions()
    {
        var dir = ProbeDir();
        try
        {
            var target = Directory.CreateDirectory(Path.Combine(dir, "t")).FullName;
            var link = Path.Combine(dir, "j");
            var psi = new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var p = Process.Start(psi)!;
            string err = p.StandardError.ReadToEnd();
            p.WaitForExit(10_000);
            return p.ExitCode == 0 && Directory.Exists(link) ? null : $"mklink /J failed: {err.Trim()}";
        }
        finally
        {
            DeleteProbeDir(dir);
        }
    }

    private static string? ProbePipeNamespaceJunction()
    {
        var dir = ProbeDir();
        try
        {
            return RawJunction.TryCreate(Path.Combine(dir, "j"), @"\??\pipe\") is { } why
                ? $"cannot write a junction to the pipe namespace: {why}"
                : null;
        }
        finally
        {
            DeleteProbeDir(dir);
        }
    }

    private static string? ProbeSmbLoopbackPipe()
    {
        var probe = new PipeProbe(acceptRemoteClients: true);
        try
        {
            using var handle = PipeProbe.OpenClient(@"\\localhost\pipe\" + probe.Name, NativeFile.HashingFlags);
            return null;
        }
        catch (IOException ex)
        {
            return $"SMB loopback to a local pipe not possible (Server service / firewall): {ex.Message}";
        }
        finally
        {
            probe.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }

    private static string? ProbeAdminShare()
    {
        var dir = ProbeDir();
        try
        {
            var path = Path.Combine(dir, "f.bin");
            File.WriteAllBytes(path, [1, 2, 3]);
            var unc = $@"\\localhost\{path[0]}$" + path[2..];
            return File.ReadAllBytes(unc).Length == 3 ? null : "admin share returned different content";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return $"admin share not reachable (needs elevation / file sharing): {ex.Message}";
        }
        finally
        {
            DeleteProbeDir(dir);
        }
    }

    private static string? ProbeEicarOnDisk()
    {
        if (Environment.GetEnvironmentVariable(EicarOnDiskVariable)?.Trim() != "1")
        {
            return $"opt-in: set {EicarOnDiskVariable}=1 to write the EICAR test file to %TEMP% (a real antivirus may alert)";
        }

        var dir = ProbeDir();
        try
        {
            var path = Path.Combine(dir, "probe.txt");
            File.WriteAllBytes(path, Eicar.Bytes());
            Thread.Sleep(1000); // give a real-time scanner the chance to act
            return File.ReadAllBytes(path).AsSpan().SequenceEqual(Eicar.Bytes())
                ? null
                : "the EICAR test file was changed on disk (by an antivirus?)";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return $"an antivirus blocked or removed the EICAR test file: {ex.Message}";
        }
        finally
        {
            DeleteProbeDir(dir);
        }
    }

    private static string? ProbeNotepad()
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
        if (!File.Exists(path))
        {
            return "System32\\notepad.exe is missing";
        }

        return File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint) ? "System32\\notepad.exe is an app alias" : null;
    }
}

/// <summary>Read-only lookups in the local certificate stores; a missing store or certificate is just null.</summary>
internal static class CertificateStores
{
    public static readonly (StoreName Name, StoreLocation Location)[] Stores =
    [
        (StoreName.Root, StoreLocation.LocalMachine),
        (StoreName.AuthRoot, StoreLocation.LocalMachine),
        (StoreName.CertificateAuthority, StoreLocation.LocalMachine),
        (StoreName.Root, StoreLocation.CurrentUser),
        (StoreName.CertificateAuthority, StoreLocation.CurrentUser),
    ];

    public sealed record StoreCertificate(string Sha1, string Sha256, string Name);

    /// <param name="log">Optional: receives a line for each store that can't be opened.</param>
    public static StoreCertificate? Find(string sha1, Action<string>? log = null)
    {
        foreach (var (name, location) in Stores)
        {
            using var store = new X509Store(name, location);
            try
            {
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            }
            catch (CryptographicException ex)
            {
                // e.g. CurrentUser\CA never created for a service account or a fresh CI profile.
                log?.Invoke($"store {location}\\{name} not available: {ex.Message}");
                continue;
            }

            var all = store.Certificates;
            try
            {
                var match = all.FirstOrDefault(c => string.Equals(c.Thumbprint, sha1, StringComparison.OrdinalIgnoreCase));
                if (match is not null)
                {
                    return new StoreCertificate(match.Thumbprint, Convert.ToHexString(match.GetCertHash(HashAlgorithmName.SHA256)),
                        match.GetNameInfo(X509NameType.SimpleName, forIssuer: false));
                }
            }
            finally
            {
                foreach (var c in all)
                {
                    c.Dispose();
                }
            }
        }

        return null;
    }
}

/// <summary>A <see cref="FactAttribute"/> that is reported as Skipped when a <see cref="Requires"/> is not met.</summary>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public sealed class RequiresFactAttribute : FactAttribute
{
    public RequiresFactAttribute(params Requires[] requirements)
    {
        Requirements = requirements;
        if (TestRequirements.SkipReason(requirements) is { } reason)
        {
            Skip = reason;
        }
    }

    public Requires[] Requirements { get; }
}

/// <summary>A <see cref="TheoryAttribute"/> that is reported as Skipped when a <see cref="Requires"/> is not met.</summary>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public sealed class RequiresTheoryAttribute : TheoryAttribute
{
    public RequiresTheoryAttribute(params Requires[] requirements)
    {
        Requirements = requirements;
        if (TestRequirements.SkipReason(requirements) is { } reason)
        {
            Skip = reason;
        }
    }

    public Requires[] Requirements { get; }
}
