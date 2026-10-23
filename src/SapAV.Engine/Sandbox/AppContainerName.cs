using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using SapAV.Engine.Quarantine;

namespace SapAV.Engine.Sandbox;

/// <summary>
/// The worker's AppContainer profile name: <c>sap-AV.ScanWorker.&lt;32 hex&gt;</c>, with a per-install random suffix
/// generated once. The suffix is <b>not a secret</b>: an AppContainer SID is visible in the object namespace (e.g. the
/// container's named-object directory) while a worker runs. What protects the worker is the explicit process/thread
/// DACL (<see cref="WorkerObjectSecurity"/>, no AppContainer SID in it) together with the lowbox double access check
/// (an AppContainer token needs both a user/group grant and a package grant). The suffix only keeps two installs, or a
/// test run, from sharing one profile, and stops a profile with a well-known name being prepared in advance.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>As SYSTEM (the service): <c>%ProgramData%\sap-AV\Sandbox\sandbox.id</c>. The folder is opened through
/// <see cref="QuarantineStore.Open"/>, so it is created with, or must already have, the protected SYSTEM + Administrators
/// DACL and a trusted owner, and is never reached through a reparse point.</item>
/// <item>Console / debug runs under a user account: <c>%LOCALAPPDATA%\sap-AV\Sandbox\sandbox.id</c> (that user's
/// private profile).</item>
/// <item>An explicit <see cref="SandboxOptions.AppContainerName"/> wins (tests use throwaway names).</item>
/// </list>
/// </remarks>
internal static class AppContainerName
{
    public const string Prefix = "sap-AV.ScanWorker.";
    public const string IdFileName = "sandbox.id";
    private const int SuffixBytes = 16;

    /// <exception cref="SandboxUnavailableException">The suffix can't be stored or read safely.</exception>
    public static string Resolve(SandboxOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!string.IsNullOrWhiteSpace(options.AppContainerName))
        {
            return options.AppContainerName;
        }

        try
        {
            if (IsLocalSystem())
            {
                string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "sap-AV", "Sandbox");
                using var store = QuarantineStore.Open(root, QuarantineAccessPolicy.Default);
                return FromDirectory(store.RootPath);
            }

            string user = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "sap-AV", "Sandbox");
            Directory.CreateDirectory(user);
            return FromDirectory(user);
        }
        catch (Exception ex) when (ex is QuarantineStoreException or IOException or UnauthorizedAccessException)
        {
            throw new SandboxUnavailableException($"The scan worker's AppContainer name can't be set up: {ex.Message}", ex);
        }
    }

    /// <summary>The name from <paramref name="directory"/>'s id file, creating (or replacing an invalid) one.</summary>
    internal static string FromDirectory(string directory)
    {
        string path = Path.Combine(directory, IdFileName);
        if (TryRead(path) is { } existing)
        {
            return Prefix + existing;
        }

        string suffix = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(SuffixBytes));
        string temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        File.WriteAllText(temp, suffix, Encoding.ASCII);
        try
        {
            File.Move(temp, path, overwrite: TryRead(path) is null);
        }
        catch (IOException) when (TryRead(path) is not null)
        {
            // another start created it concurrently: use theirs
        }
        finally
        {
            File.Delete(temp);
        }

        return Prefix + (TryRead(path) ?? throw new IOException($"Could not store the sandbox id in {path}."));
    }

    internal static bool IsValidName(string name) =>
        name.StartsWith(Prefix, StringComparison.Ordinal) && IsSuffix(name[Prefix.Length..]);

    private static string? TryRead(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > 64)
            {
                return null;
            }

            var text = File.ReadAllText(path, Encoding.ASCII).Trim();
            return IsSuffix(text) ? text : null;
        }
        catch (FileNotFoundException)
        {
            return null;
        }
    }

    private static bool IsSuffix(string text) => text.Length == SuffixBytes * 2 && text.All(char.IsAsciiHexDigitLower);

    internal static bool IsLocalSystem()
    {
        using var self = WindowsIdentity.GetCurrent();
        return self.User?.IsWellKnown(WellKnownSidType.LocalSystemSid) == true;
    }
}
