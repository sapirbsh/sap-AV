using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;
using SapAV.Engine.Alerts;

namespace SapAV.Engine.Tests;

public sealed class EngineHostTests
{
    [Fact]
    public void BuiltHost_HasNoEventLogLoggerProvider()
    {
        using var host = EngineHost.Configure(Host.CreateApplicationBuilder([])).Build();

        var providers = host.Services.GetServices<ILoggerProvider>().ToArray();

        Assert.DoesNotContain(providers, p => p is EventLogLoggerProvider);
        Assert.Contains(providers, p => p.GetType().Name == "ConsoleLoggerProvider");
        Assert.IsType<EventLogAlertSink>(host.Services.GetRequiredService<IAlertSink>());
    }

    [Fact]
    public void BuiltHost_HasNoEventLogLoggerProvider_EvenIfOneWasAddedBeforehand()
    {
        // When the process really runs as a service, AddWindowsService registers AddEventLog(); a test process
        // isn't a service, so add it the same way before Configure to cover that path.
        var builder = Host.CreateApplicationBuilder([]);
        builder.Services.AddLogging(logging => logging.AddEventLog());

        using var host = EngineHost.Configure(builder).Build();

        Assert.DoesNotContain(host.Services.GetServices<ILoggerProvider>(), p => p is EventLogLoggerProvider);
    }
}
