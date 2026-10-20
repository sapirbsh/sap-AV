namespace SapAV.Core.Tests.TestSupport;

/// <summary>
/// Benign signed files that exist on Windows 10/11 or wherever the tests run. Never malware: only Windows
/// binaries, the .NET runtime that runs the tests, and installed third-party software.
/// </summary>
internal static class SignedSamples
{
    private static readonly string System32 = Environment.GetFolderPath(Environment.SpecialFolder.System);

    /// <summary>
    /// A System32 binary that is signed only through a Windows catalog (no embedded certificate table).
    /// cmd.exe and notepad.exe are catalog-only on Windows 10 and 11; on this machine's Windows 11 26200
    /// some core DLLs (e.g. kernel32.dll) also carry an embedded signature, so the candidates are checked.
    /// </summary>
    public static string? CatalogOnlyWindowsBinary() =>
        new[] { "cmd.exe", "notepad.exe", "where.exe", "findstr.exe", "help.exe" }
            .Select(name => Path.Combine(System32, name))
            .FirstOrDefault(path => File.Exists(path) && !PeImage.HasEmbeddedSignature(path));

    /// <summary>
    /// A small DLL of the running .NET runtime. Microsoft signs these with an embedded Authenticode signature
    /// (Microsoft Code Signing PCA 2011/2024), and they are always present when the tests run.
    /// </summary>
    public static string? EmbeddedSignedMicrosoftDll()
    {
        string runtimeDir = Path.GetDirectoryName(typeof(object).Assembly.Location)!;
        return new[] { "Microsoft.Win32.Primitives.dll", "System.Runtime.dll", "System.Console.dll" }
            .Select(name => Path.Combine(runtimeDir, name))
            .FirstOrDefault(path => File.Exists(path) && PeImage.HasEmbeddedSignature(path));
    }

    /// <summary>
    /// <see cref="CatalogOnlyWindowsBinary"/> as a HARD requirement: System32\cmd.exe is catalog-signed by
    /// Microsoft on every supported Windows 10/11 and Windows Server, so its absence is a real failure.
    /// </summary>
    public static string RequireCatalogOnlyWindowsBinary() =>
        CatalogOnlyWindowsBinary()
        ?? throw new Xunit.Sdk.XunitException(
            "No catalog-only signed System32 binary (cmd.exe, notepad.exe, where.exe, findstr.exe, help.exe) found. " +
            "Every supported Windows ships these catalog-signed; check the System32 path and the verifier.");

    /// <summary>
    /// <see cref="EmbeddedSignedMicrosoftDll"/> for tests marked <c>[RequiresFact(Requires.SignedDotNetRuntime)]</c>.
    /// </summary>
    public static string RequireEmbeddedSignedMicrosoftDll() =>
        EmbeddedSignedMicrosoftDll()
        ?? throw new Xunit.Sdk.XunitException("No embedded-signed .NET runtime DLL, although the requirement probe found one.");

    /// <summary>
    /// The first installed executable that verifies as trusted and chains to a non-Microsoft root, or null.
    /// Cached: used both by the requirement probe (at discovery) and by the test.
    /// </summary>
    public static string? TrustedThirdPartySample() => LazyThirdParty.Value;

    private static readonly Lazy<string?> LazyThirdParty = new(() =>
    {
        var verifier = new SapAV.Core.Signatures.AuthenticodeVerifier();
        foreach (var path in InstalledThirdPartyCandidates())
        {
            var result = verifier.Verify(path);
            if (result.IsTrusted && !IsMicrosoftOperatedRoot(result.Signer.Chain[^1]))
            {
                return path;
            }
        }

        return null;
    });

    /// <summary>A root that Microsoft operates (product roots or the Identity Verification root).</summary>
    public static bool IsMicrosoftOperatedRoot(SapAV.Core.Signatures.SignatureCertificate root) =>
        SapAV.Core.Signatures.MicrosoftCodeSigningCertificates.ProductRoots.Any(r => r.Matches(root))
        || SapAV.Core.Signatures.MicrosoftCodeSigningCertificates.IdentityVerificationRoot2020.Matches(root);

    /// <summary>The first trusted WHQL-signed DriverStore catalog (among the first 400), or null. Cached.</summary>
    public static string? WhqlDriverCatalog() => LazyWhql.Value;

    private static readonly Lazy<string?> LazyWhql = new(() =>
    {
        var verifier = new SapAV.Core.Signatures.AuthenticodeVerifier();
        foreach (var cat in DriverStoreCatalogs().Take(400))
        {
            var result = verifier.Verify(cat);
            if (result.IsTrusted && result.Signer.CommonName == "Microsoft Windows Hardware Compatibility Publisher")
            {
                return cat;
            }
        }

        return null;
    });

    /// <summary>
    /// Embedded-signed executables from well-known installed software, up to <paramref name="max"/> files,
    /// at most two folder levels deep under Program Files. Which ones exist depends on the machine.
    /// </summary>
    public static IEnumerable<string> InstalledThirdPartyCandidates(int max = 200)
    {
        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        };

        int yielded = 0;
        foreach (var root in roots.Where(r => !string.IsNullOrEmpty(r) && Directory.Exists(r)).Distinct())
        {
            foreach (var file in SafeEnumerate(root, depth: 2))
            {
                if (yielded >= max)
                {
                    yield break;
                }

                if (PeImage.HasEmbeddedSignature(file))
                {
                    yielded++;
                    yield return file;
                }
            }
        }
    }

    /// <summary>Signed driver catalogs in the DriverStore (WHQL / attestation-signed ones are common).</summary>
    public static IEnumerable<string> DriverStoreCatalogs()
    {
        var repository = Path.Combine(System32, "DriverStore", "FileRepository");
        if (!Directory.Exists(repository))
        {
            yield break;
        }

        IEnumerable<string> dirs;
        try
        {
            dirs = Directory.EnumerateDirectories(repository).ToArray();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            yield break;
        }

        foreach (var dir in dirs)
        {
            string[] cats;
            try
            {
                cats = Directory.GetFiles(dir, "*.cat");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var cat in cats)
            {
                yield return cat;
            }
        }
    }

    private static IEnumerable<string> SafeEnumerate(string dir, int depth)
    {
        string[] files;
        string[] subdirs;
        try
        {
            files = Directory.GetFiles(dir, "*.exe");
            subdirs = depth > 0 ? Directory.GetDirectories(dir) : [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            yield break;
        }

        foreach (var file in files)
        {
            yield return file;
        }

        foreach (var sub in subdirs)
        {
            if (new DirectoryInfo(sub).Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                continue;
            }

            foreach (var file in SafeEnumerate(sub, depth - 1))
            {
                yield return file;
            }
        }
    }
}
