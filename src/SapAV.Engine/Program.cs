using SapAV.Engine;
using SapAV.Engine.Alerts;
using SapAV.Engine.EventLogging;

// Service installer path (needs an elevated prompt): register / remove the "sap-AV" Event Log source, then exit.
if (EngineCommands.TryRun(args, new WindowsEventLog(), Console.Out, Console.Error) is { } exitCode)
{
    return exitCode;
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "SapAV Engine");
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<IWindowsEventLog, WindowsEventLog>();
builder.Services.AddSingleton<IAlertSink, EventLogAlertSink>();
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
return 0;
