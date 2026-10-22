using SapAV.Engine.Alerts;
using SapAV.Engine.EventLogging;
using SapAV.Engine.Quarantine;

namespace SapAV.Engine;

/// <summary>The engine's service and logging setup, in one place so tests check the same host that runs.</summary>
public static class EngineHost
{
    public const string ServiceName = "SapAV Engine";

    /// <summary>Registers the engine's services and logging on <paramref name="builder"/>.</summary>
    /// <remarks>
    /// <b>No Event Log logger provider.</b> <c>Host.CreateApplicationBuilder</c> adds <c>EventLogLoggerProvider</c> on
    /// Windows, and <c>AddWindowsService</c> adds it again when running as a service, with source "SapAV.Engine".
    /// That provider writes through <c>EventLog.WriteEvent</c>, which registers a missing source, so as SYSTEM it
    /// would silently create <c>HKLM\...\EventLog\Application\SapAV.Engine</c> that nothing ever removes. So all
    /// providers are cleared <b>after</b> <c>AddWindowsService</c> and only Console and Debug are added back. Engine
    /// diagnostics in the Event Log come later through our own non-registering writer (event IDs 9000-9999).
    /// </remarks>
    public static HostApplicationBuilder Configure(HostApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddWindowsService(options => options.ServiceName = ServiceName);
        builder.Logging.ClearProviders();
        builder.Logging.AddConsole();
        builder.Logging.AddDebug();

        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<IWindowsEventLog, WindowsEventLog>();
        builder.Services.AddSingleton<IAlertSink, EventLogAlertSink>();

        // Quarantine (B2): store opened + recovered at startup; the pipe (B4) and scan queue (B3) use IQuarantineService.
        builder.Services.Configure<QuarantineOptions>(builder.Configuration.GetSection(QuarantineOptions.SectionName));
        builder.Services.AddSingleton<IQuarantineKeyProvider, DpapiQuarantineKeyProvider>();
        builder.Services.AddSingleton<QuarantineManager>();
        builder.Services.AddSingleton<IQuarantineService>(sp => sp.GetRequiredService<QuarantineManager>());
        builder.Services.AddHostedService<QuarantineStartupService>();
        builder.Services.AddHostedService<Worker>();
        return builder;
    }
}
