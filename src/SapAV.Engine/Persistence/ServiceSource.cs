using SapAV.Core.Persistence;

namespace SapAV.Engine.Persistence;

/// <summary>
/// Services and drivers from <c>HKLM\SYSTEM\CurrentControlSet\Services</c> (ROADMAP C2), read from the registry (no SCM
/// call), read-only. Each service gives its <c>ImagePath</c>; a svchost service whose ImagePath is the system svchost gives
/// its <c>ServiceDll</c> instead (the code that really runs), with svchost as the host. A ServiceDll next to any other
/// ImagePath adds a second entry. Disabled services (Start = 4) are reported with Enabled false (C4 may skip scanning
/// them, but they are listed: they can be switched back on).
/// </summary>
/// <remarks>
/// Driver ImagePaths follow the kernel's rules, not CreateProcess: <c>\SystemRoot\…</c>, <c>\??\C:\…</c>, a path relative
/// to SystemRoot (<c>System32\drivers\x.sys</c>), or empty for <c>System32\drivers\&lt;name&gt;.sys</c>. Keys without a
/// Type and ImagePath (event-log or configuration keys) aren't services and are skipped.
/// </remarks>
internal sealed class ServiceSource : IPersistenceSource
{
    public const string ServicesKey = @"SYSTEM\CurrentControlSet\Services";

    private const long KernelDriver = 0x1;
    private const long FileSystemDriver = 0x2;

    public string Name => "services";

    public void Collect(PersistenceContext context)
    {
        using var services = context.TryOpen(RegistryRoot.LocalMachine, ServicesKey, PersistenceKind.Service, null, out var display);
        if (services is null)
        {
            return;
        }

        foreach (var name in context.Names(services, subKeys: true, PersistenceKind.Service, null, display))
        {
            if (!context.CanContinue)
            {
                return;
            }

            using var key = PersistenceContext.OpenSub(services, name);
            if (key is not null)
            {
                CollectService(context, key, name, $@"{display}\{name}");
            }
        }
    }

    private static void CollectService(PersistenceContext context, IRegistryKeyReader key, string name, string display)
    {
        long? type = PersistenceContext.ReadValue(key, "Type")?.AsNumber();
        string? imagePath = PersistenceContext.ReadValue(key, "ImagePath")?.AsString();
        if (type is null && imagePath is null)
        {
            return;
        }

        var start = StartType(PersistenceContext.ReadValue(key, "Start")?.AsNumber());
        bool enabled = start != ServiceStartType.Disabled;
        bool driver = type is { } t && (t & (KernelDriver | FileSystemDriver)) != 0;
        var image = driver
            ? ResolveDriver(context, name, imagePath)
            : context.Resolver.Resolve(imagePath?.StartsWith(@"\??\", StringComparison.Ordinal) == true ? imagePath[4..] : imagePath, context.Machine);

        string? dllDisplay = display;
        string? serviceDll = null;
        using (var parameters = PersistenceContext.OpenSub(key, "Parameters"))
        {
            if (parameters is not null && PersistenceContext.ReadValue(parameters, "ServiceDll")?.AsString() is { Length: > 0 } fromParameters)
            {
                serviceDll = fromParameters;
                dllDisplay = display + @"\Parameters";
            }
        }

        serviceDll ??= PersistenceContext.ReadValue(key, "ServiceDll")?.AsString() is { Length: > 0 } direct ? direct : null;

        bool systemSvchost = image.TargetPath is { } target && context.Machine.SystemRoot is { } root
            && string.Equals(target, Core.Persistence.PersistenceText.NormalizeLocalPath(Path.Join(root, @"System32\svchost.exe")), StringComparison.OrdinalIgnoreCase);
        if (serviceDll is null || !systemSvchost)
        {
            context.Add(new PersistenceEntry(PersistenceKind.Service, null, display, "ImagePath", imagePath ?? string.Empty, image, enabled, start));
        }

        if (serviceDll is not null)
        {
            var dll = context.Resolver.ResolveLibrary(serviceDll, context.Machine, image.TargetPath, image.Arguments);
            context.Add(new PersistenceEntry(PersistenceKind.Service, null, dllDisplay, "ServiceDll", serviceDll, dll, enabled, start));
        }
    }

    /// <summary>A driver's ImagePath, by the kernel's rules (no search, no arguments).</summary>
    private static ResolvedCommand ResolveDriver(PersistenceContext context, string name, string? imagePath)
    {
        string? root = context.Machine.SystemRoot;
        string path = imagePath?.Trim().Trim('"') ?? string.Empty;
        if (path.Length == 0)
        {
            path = $@"System32\drivers\{name}.sys";
        }

        if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            path = path["\\SystemRoot\\".Length..];
        }
        else if (path.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            path = path[4..];
        }

        if (!(path.Length >= 3 && path[1] == ':') && !path.StartsWith('\\') && !path.Contains('%'))
        {
            if (root is null)
            {
                return ResolvedCommand.Unresolved(TargetUnresolvedReason.UnknownEnvironmentVariable);
            }

            path = Path.Join(root, path); // relative to SystemRoot
        }

        return context.Resolver.ResolveProgram("\"" + path + "\"", null, context.Machine);
    }

    private static ServiceStartType StartType(long? value) => value switch
    {
        0 => ServiceStartType.Boot,
        1 => ServiceStartType.System,
        2 => ServiceStartType.Automatic,
        3 => ServiceStartType.Manual,
        4 => ServiceStartType.Disabled,
        _ => ServiceStartType.Unknown,
    };
}
