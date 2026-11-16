using SapAV.Core.Processes;

namespace SapAV.Engine.Tests.Processes;

/// <summary>E8: the shared hub behaviour through the fake feed (table, PID reuse, bounded buffers, health, text caps).</summary>
public sealed class ProcessEventFeedTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 16, 10, 0, 0, TimeSpan.Zero);

    internal static ProcessEvent Start(int pid, DateTimeOffset start, int? parent = null, string? image = null, string? commandLine = null) =>
        new(ProcessEventKind.Started, pid, parent, start, image ?? $@"C:\Apps\p{pid}.exe", commandLine, false, 1, "S-1-5-21-1-2-3-1001",
            ProcessIntegrityLevel.Medium, start);

    internal static ProcessEvent Stop(int pid, DateTimeOffset start, int exitCode = 0) =>
        new(ProcessEventKind.Stopped, pid, null, start, $"p{pid}.exe", null, false, null, null, ProcessIntegrityLevel.Unknown,
            start.AddSeconds(5), exitCode);

    [Fact]
    public async Task StopEvent_IsCompletedFromItsStart_AndLeavesTheTable()
    {
        using var source = new FakeProcessEventSource();
        await source.StartAsync();
        using var sub = source.Subscribe();

        source.Publish(Start(100, T0, parent: 4, commandLine: "p100.exe --flag"));
        Assert.NotNull(source.FindProcess(new ProcessKey(100, T0)));
        var stop = source.Publish(Stop(100, T0, exitCode: 3));

        Assert.NotNull(stop);
        Assert.Equal(ProcessEventKind.Stopped, stop.Kind);
        Assert.Equal(@"C:\Apps\p100.exe", stop.ImagePath); // the short stop-event name is replaced by the start's full path
        Assert.Equal("p100.exe --flag", stop.CommandLine);
        Assert.Equal(4, stop.ParentProcessId);
        Assert.Equal("S-1-5-21-1-2-3-1001", stop.UserSid);
        Assert.Equal(3, stop.ExitCode);
        Assert.Empty(source.GetKnownProcesses());
        Assert.True(sub.Reader.TryRead(out var first) && first.Kind == ProcessEventKind.Started);
        Assert.True(sub.Reader.TryRead(out var second) && second.Kind == ProcessEventKind.Stopped);
    }

    [Fact]
    public async Task PidReuse_SamePidDifferentStartTime_NeverMatchesTheOldProcess()
    {
        using var source = new FakeProcessEventSource();
        await source.StartAsync();
        var t1 = T0;
        var t2 = T0.AddMinutes(10);

        source.Publish(Start(100, t1, image: @"C:\Apps\old.exe", commandLine: "old"));
        // A stop for PID 100 with another start time is a different process: it doesn't borrow the old one's details or remove it.
        var strayStop = source.Publish(Stop(100, t2));
        Assert.Null(strayStop!.CommandLine);
        Assert.NotNull(source.FindProcess(new ProcessKey(100, t1)));

        source.Publish(Stop(100, t1));
        source.Publish(Start(100, t2, image: @"C:\Apps\new.exe"));

        // A child that started between t1 and t2 named PID 100 as parent: that was the old process, which is gone. The new PID 100
        // is younger than the child, so it can't be its parent.
        var orphan = Start(200, t1.AddMinutes(1), parent: 100);
        Assert.Null(source.FindParent(orphan));
        var child = Start(201, t2.AddSeconds(1), parent: 100);
        Assert.Equal(@"C:\Apps\new.exe", source.FindParent(child)?.ImagePath);
    }

    [Fact]
    public async Task FullBuffer_DropsOldest_CountsDrops_AndDoesNotAffectOtherSubscribers()
    {
        using var source = new FakeProcessEventSource();
        await source.StartAsync();
        using var small = source.Subscribe(capacity: 3);
        using var large = source.Subscribe(capacity: 100);

        for (int i = 0; i < 10; i++)
        {
            source.Publish(Start(1000 + i, T0.AddSeconds(i)));
        }

        var kept = new List<int>();
        while (small.Reader.TryRead(out var e))
        {
            kept.Add(e.ProcessId);
        }

        Assert.Equal([1007, 1008, 1009], kept);
        Assert.Equal(7, small.Dropped);
        Assert.Equal(0, large.Dropped);
        Assert.Equal(10, large.Reader.Count);
        Assert.Equal(7, source.Status.DroppedEvents);
        Assert.Equal(10, source.Status.EventsReceived);

        small.Dispose(); // drops of a closed subscription stay counted
        Assert.Equal(7, source.Status.DroppedEvents);
    }

    [Fact]
    public async Task Health_AccessDenied_LostEvents_AndStop()
    {
        using var denied = new FakeProcessEventSource { StartResult = ProcessEventSourceHealth.AccessDenied };
        var status = await denied.StartAsync();
        Assert.Equal(ProcessEventSourceHealth.AccessDenied, status.Health);
        Assert.False(status.IsReceiving);

        using var source = new FakeProcessEventSource();
        Assert.Equal(ProcessEventSourceHealth.Stopped, source.Status.Health);
        await source.StartAsync();
        Assert.Equal(ProcessEventSourceHealth.Running, source.Status.Health);
        source.ReportLost(5);
        source.ReportLost(2); // totals are monotonic
        Assert.Equal(ProcessEventSourceHealth.LostEvents, source.Status.Health);
        Assert.Equal(5, source.Status.LostEvents);
        Assert.True(source.Status.IsReceiving);

        await source.StopAsync();
        Assert.Equal(ProcessEventSourceHealth.Stopped, source.Status.Health);
    }

    [Fact]
    public async Task PreExisting_IsMarked_AndNotRepeatedForAProcessAlreadyReported()
    {
        var running = Start(10, T0.AddHours(-1), parent: 4);
        using var source = new FakeProcessEventSource([running]);
        using var sub = source.Subscribe();
        await source.StartAsync();

        Assert.True(sub.Reader.TryRead(out var existing));
        Assert.True(existing.IsPreExisting);
        Assert.Null(source.Publish(running with { Kind = ProcessEventKind.Existing })); // duplicate of a known process
        Assert.Single(source.GetKnownProcesses());
    }

    [Fact]
    public async Task Dispose_CompletesReaders_AndLaterSubscriptionsAreCompleted()
    {
        var source = new FakeProcessEventSource();
        await source.StartAsync();
        var sub = source.Subscribe();
        source.Publish(Start(1, T0));

        source.Dispose();
        source.Dispose();

        Assert.True(sub.Reader.TryRead(out _)); // buffered events are still readable
        await sub.Reader.Completion.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Null(source.Publish(Start(2, T0)));
        var late = source.Subscribe();
        Assert.True(late.Reader.Completion.IsCompleted);
        Assert.Equal(ProcessEventSourceHealth.Stopped, source.Status.Health);
    }

    [Fact]
    public void ProcessTable_IsBounded_EvictingTheOldest()
    {
        var table = new ProcessTable(capacity: 2);
        table.TryAdd(Start(1, T0));
        table.TryAdd(Start(2, T0));
        table.TryAdd(Start(3, T0));

        Assert.Equal(2, table.Count);
        Assert.Equal(1, table.Evicted);
        Assert.Null(table.FindLatestByPid(1));
        Assert.NotNull(table.FindLatestByPid(3));
    }

    [Fact]
    public void FullTable_PrunesGoneProcessesFirst_AndNeverStoresEntriesWithoutStartTime()
    {
        var table = new ProcessTable(capacity: 3, isGone: p => p.ProcessId == 1);
        table.TryAdd(Start(1, T0));
        table.TryAdd(Start(2, T0));
        table.TryAdd(Start(3, T0));
        table.TryAdd(Start(4, T0));

        Assert.Null(table.FindLatestByPid(1)); // gone: pruned
        Assert.NotNull(table.FindLatestByPid(2)); // live: not evicted
        Assert.Equal((0L, 1L), (table.Evicted, table.Pruned));
        Assert.False(table.TryAdd(Start(5, T0) with { StartTime = null }));
        Assert.Equal(3, table.Count);
    }

    [Fact]
    public async Task SecondStartForAKnownProcess_IsRejected_AndCannotRewriteItsParent()
    {
        using var source = new FakeProcessEventSource();
        await source.StartAsync();
        source.Publish(Start(100, T0, parent: 4, image: @"C:\Apps\real.exe"));

        Assert.Null(source.Publish(Start(100, T0, parent: 666, image: @"C:\Apps\forged.exe")));

        Assert.Equal(1, source.Status.RejectedEvents);
        var known = source.FindProcess(new ProcessKey(100, T0));
        Assert.Equal((4, @"C:\Apps\real.exe"), (known?.ParentProcessId, known?.ImagePath));
    }

    [Fact]
    public async Task SpoofedParent_KeepsBothTheClaimedParentAndTheRealCreator()
    {
        using var source = new FakeProcessEventSource();
        await source.StartAsync();
        source.Publish(Start(7, T0, image: @"C:\Office\winword.exe"));
        source.Publish(Start(666, T0.AddSeconds(1), image: @"C:\Users\u\AppData\Local\Temp\dropper.exe"));
        var child = Start(42, T0.AddSeconds(2), parent: 7, image: @"C:\x\powershell.exe") with { CreatorProcessId = 666, ParentMismatch = true };
        source.Publish(child);

        Assert.Equal(@"C:\Office\winword.exe", source.FindParent(child)?.ImagePath); // claimed (attacker-controlled)
        Assert.Equal(@"C:\Users\u\AppData\Local\Temp\dropper.exe", source.FindCreator(child)?.ImagePath); // real creator
        var stored = source.FindProcess(child.Key)!;
        Assert.Equal((7, 666, true), (stored.ParentProcessId, stored.CreatorProcessId, stored.ParentMismatch));

        var stop = source.Publish(Stop(42, child.StartTime!.Value))!;
        Assert.Equal((666, true), (stop.CreatorProcessId, stop.ParentMismatch)); // carried into the stop
    }

    [Fact]
    public void CommandLine_IsCappedHeadAndTail_WithTruncatedFlag()
    {
        string head = "miner.exe --donate-level 1 ";
        string tail = " -o stratum+tcp://pool.example:3333";
        string raw = head + new string(' ', 50_000) + tail;

        var (text, truncated) = ProcessText.CommandLine(raw);

        Assert.True(truncated);
        Assert.Equal(ProcessText.MaxCommandLineChars, text!.Length);
        Assert.StartsWith(head, text);
        Assert.EndsWith(tail, text); // padding can't push the end of the command line out of view
        Assert.Contains('\u2026', text);
    }

    [Theory]
    [InlineData("cmd.exe /c \"a b\"", "cmd.exe /c \"a b\"", false)]
    [InlineData("evil.exe\r\nFAKE LOG LINE", "evil.exe\uFFFD\uFFFDFAKE LOG LINE", false)]
    [InlineData("tool.exe\0\0", "tool.exe", false)]
    public void CommandLine_ControlCharactersAreReplaced_RestStaysRaw(string raw, string expected, bool truncated)
    {
        Assert.Equal((expected, truncated), ProcessText.CommandLine(raw));
    }

    [Fact]
    public void CommandLine_Cap_DoesNotSplitASurrogatePair_AndNullStaysNull()
    {
        string raw = new string('a', ProcessText.CommandLineHeadChars - 1) + "\U0001F600" + new string('b', 10_000);
        var (text, truncated) = ProcessText.CommandLine(raw);
        Assert.True(truncated);
        Assert.DoesNotContain(text!, c => char.IsSurrogate(c));
        Assert.Equal((null, false), ProcessText.CommandLine(null));
    }

    [Theory]
    [InlineData("S-1-5-18", "S-1-5-18")]
    [InlineData("S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1001")]
    [InlineData("S-1-5-18\r\nX", null)]
    [InlineData("Administrator", null)]
    public void Sid_OnlyWellFormedSidStringsPass(string raw, string? expected) => Assert.Equal(expected, ProcessText.Sid(raw));
}
