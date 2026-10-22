using System.Diagnostics;
using Microsoft.Extensions.Logging;
using SapAV.Core.Alerts;
using SapAV.Core.Models;
using SapAV.Engine.EventLogging;

namespace SapAV.Engine.Tests.TestSupport;

/// <summary>In-memory Event Log: source registrations (source to log) and written entries.</summary>
internal sealed class FakeWindowsEventLog : IWindowsEventLog
{
    public sealed record Entry(string Source, string LogName, string Message, EventLogEntryType EntryType, int EventId);

    public Dictionary<string, string> Sources { get; } = new(StringComparer.OrdinalIgnoreCase);

    public List<Entry> Entries { get; } = [];

    public int CreateCalls { get; private set; }

    public int DeleteCalls { get; private set; }

    /// <summary>Thrown by every write / create / delete when set (e.g. a SecurityException for "not elevated").</summary>
    public Exception? Failure { get; set; }

    public string? FindLogForSource(string source) => Sources.GetValueOrDefault(source);

    /// <summary>Runs inside CreateSource before registering, e.g. to simulate a concurrent installer.</summary>
    public Action<string>? BeforeCreate { get; set; }

    public void CreateSource(string source, string logName)
    {
        CreateCalls++;
        ThrowIfFailing();
        BeforeCreate?.Invoke(source);
        Sources.Add(source, logName); // throws ArgumentException if it exists, like CreateEventSource
    }

    public void DeleteSource(string source)
    {
        DeleteCalls++;
        ThrowIfFailing();
        Sources.Remove(source);
    }

    public void ReportEvent(string source, string logName, string message, EventLogEntryType entryType, int eventId)
    {
        ThrowIfFailing();
        if (FindLogForSource(source) != logName)
        {
            throw new InvalidOperationException("The fake requires a registered source, like the real API without admin rights.");
        }

        Entries.Add(new(source, logName, message, entryType, eventId));
    }

    private void ThrowIfFailing()
    {
        if (Failure is not null)
        {
            throw Failure;
        }
    }
}

/// <summary>Collects log lines (level + formatted message).</summary>
internal sealed class ListLogger<T> : ILogger<T>
{
    public List<(LogLevel Level, string Message)> Lines { get; } = [];

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
        Lines.Add((logLevel, formatter(state, exception)));

    public int Count(LogLevel level) => Lines.Count(l => l.Level == level);
}

/// <summary>A clock the test moves by hand.</summary>
internal sealed class ManualTime : TimeProvider
{
    public DateTimeOffset Now { get; set; } = new(2026, 10, 21, 12, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow() => Now;
}

internal static class SampleAlerts
{
    public const string Sha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    public static Alert Create(
        AlertType type = AlertType.MaliciousFile,
        string path = @"C:\Users\test\Downloads\invoice.pdf.exe",
        IReadOnlyList<string>? reasons = null,
        IReadOnlyList<string>? secondaries = null,
        string? sourceUrl = "https://cdn.test/invoice.pdf.exe")
    {
        var verdict = type == AlertType.MaliciousFile ? Verdict.Malicious : Verdict.Suspicious;
        return new Alert(
            Alert.ComputeAlertId(type, new DateTimeOffset(2026, 10, 21, 12, 0, 0, TimeSpan.Zero), path, Sha, ScanTrigger.RealTime),
            new DateTimeOffset(2026, 10, 21, 12, 0, 0, TimeSpan.Zero), type, verdict, path, Sha, null, null,
            type == AlertType.QuarantineRestored ? null : "T1204.002", secondaries ?? ["T1036.007"],
            reasons ?? ["YARA rule Antivirus_Test_File matched (antivirus-test-file.yar)"], sourceUrl,
            AlertAction.Quarantined, ScanTrigger.RealTime, EngineInfo.Version);
    }
}
