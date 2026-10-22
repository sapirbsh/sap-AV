using SapAV.Engine;
using SapAV.Engine.EventLogging;

// Service installer path (needs an elevated prompt): register / remove the "sap-AV" Event Log source, then exit.
if (EngineCommands.TryRun(args, new WindowsEventLog(), Console.Out, Console.Error) is { } exitCode)
{
    return exitCode;
}

var host = EngineHost.Configure(Host.CreateApplicationBuilder(args)).Build();
host.Run();
return 0;
