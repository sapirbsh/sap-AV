using System.Diagnostics;
using Microsoft.Extensions.Logging;
using SapAV.Core.Alerts;
using SapAV.Core.Models;
using SapAV.Engine.EventLogging;

namespace SapAV.Engine.Tests.TestSupport;

/// <summary>
/// In-memory Event Log: logs (with their settings and sources) and written entries. Every change is recorded in
/// <see cref="Changes"/> (e.g. "WriteSource sap-AV@sap-AV"), so tests can check order and "nothing changed".
/// </summary>
internal sealed class FakeWindowsEventLog : IWindowsEventLog
{
    public sealed record Entry(string Source, string LogName, string Message, EventLogEntryType EntryType, int EventId);

    public sealed class Log
    {
        public EventLogSettings? Settings { get; set; }

        /// <summary>Source name to message file.</summary>
        public Dictionary<string, string> Sources { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    public Dictionary<string, Log> Logs { get; } = new(StringComparer.OrdinalIgnoreCase);

    public List<Entry> Entries { get; } = [];

    public List<string> Changes { get; } = [];

    /// <summary>Thrown by every change and write when set (e.g. a SecurityException for "not elevated").</summary>
    public Exception? Failure { get; set; }

    /// <summary>Thrown by <see cref="FindLogsForSource"/> when set.</summary>
    public Exception? LookupFailure { get; set; }

    /// <summary>Replaces what <see cref="ReadLogSettings"/> returns (e.g. a CustomSD the service rewrote).</summary>
    public Func<EventLogSettings, EventLogSettings>? ReadBack { get; set; }

    /// <summary>Registers <paramref name="source"/> in <paramref name="log"/> without recording a change (test setup).</summary>
    public void Register(string source, string log, string messageFile = @"C:\fake\messages.dll")
    {
        if (!Logs.TryGetValue(log, out var entry))
        {
            Logs[log] = entry = new Log();
        }

        entry.Sources[source] = messageFile;
    }

    public void Unregister(string source)
    {
        foreach (var log in Logs.Values)
        {
            log.Sources.Remove(source);
        }
    }

    public IReadOnlyList<string> FindLogsForSource(string source)
    {
        if (LookupFailure is not null)
        {
            throw LookupFailure;
        }

        return Logs.Where(l => l.Value.Sources.ContainsKey(source)).Select(l => l.Key).Order(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public bool LogExists(string logName) => Logs.ContainsKey(logName);

    public EventLogSettings? ReadLogSettings(string logName) =>
        Logs.TryGetValue(logName, out var log) && log.Settings is { } settings
            ? ReadBack?.Invoke(settings) ?? settings
            : Logs.ContainsKey(logName) ? new EventLogSettings(string.Empty, 0, 0, false) : null;

    public void WriteLogSettings(string logName, EventLogSettings settings)
    {
        Change($"WriteLogSettings {logName}");
        if (!Logs.TryGetValue(logName, out var log))
        {
            Logs[logName] = log = new Log();
        }

        log.Settings = settings;
    }

    public void WriteSource(string source, string logName, string messageFile)
    {
        Change($"WriteSource {source}@{logName}");
        if (!Logs.TryGetValue(logName, out var log))
        {
            throw new InvalidOperationException($"The '{logName}' log is not registered.");
        }

        log.Sources[source] = messageFile;
    }

    public string? ReadMessageFile(string source, string logName) =>
        Logs.TryGetValue(logName, out var log) ? log.Sources.GetValueOrDefault(source) : null;

    public void DeleteSource(string source, string logName)
    {
        Change($"DeleteSource {source}@{logName}");
        if (Logs.TryGetValue(logName, out var log))
        {
            log.Sources.Remove(source);
        }
    }

    public void DeleteLog(string logName)
    {
        Change($"DeleteLog {logName}");
        Logs.Remove(logName);
    }

    public void ClearLog(string logName)
    {
        Change($"ClearLog {logName}");
        Entries.RemoveAll(e => string.Equals(e.LogName, logName, StringComparison.OrdinalIgnoreCase));
    }

    public void ReportEvent(string source, string logName, string message, EventLogEntryType entryType, int eventId)
    {
        ThrowIfFailing();
        if (!FindLogsForSource(source).SequenceEqual([logName], StringComparer.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("The fake requires the source registered in exactly that log.");
        }

        Entries.Add(new(source, logName, message, entryType, eventId));
    }

    private void Change(string change)
    {
        ThrowIfFailing();
        Changes.Add(change);
    }

    private void ThrowIfFailing()
    {
        if (Failure is not null)
        {
            throw Failure;
        }
    }
}

/// <summary>A message DLL check with a fixed answer.</summary>
internal sealed class FakeMessageFileCheck(string? problem = null) : IMessageFileLocationCheck
{
    public List<string> Checked { get; } = [];

    public string? FindProblem(string messageFile)
    {
        Checked.Add(messageFile);
        return problem;
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
