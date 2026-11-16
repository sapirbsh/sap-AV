using SapAV.Core.Processes;
using SapAV.Engine.Processes;

namespace SapAV.Engine.Tests.Processes;

/// <summary>E8: mapping fake Kernel-Process records and snapshot rows, payload conversion and the native-buffer helpers.</summary>
public sealed class KernelProcessMappingTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 16, 10, 0, 0, TimeSpan.Zero);

    private static readonly DevicePathMapper Paths = new(() => [("C:", @"\Device\HarddiskVolume1"), ("D:", @"\Device\HarddiskVolume10")], () => 0);

    [Fact]
    public void Start_IsEnrichedFromTheLiveProcess_WhenItsCreationTimeMatches()
    {
        var info = new EtwProcessEventSourceTests.FixedInfo
        {
            [42] = new(T0, @"C:\Tools\a.exe", "a.exe --x\n--y", 2, "S-1-5-21-9-9-9-1001", ProcessIntegrityLevel.High),
        };
        var mapper = new KernelProcessEventMapper(info, Paths.ToWin32);

        var e = mapper.Map(new KernelProcessRecord(ProcessEventKind.Started, 7, 42, 7, T0, 2, @"\Device\HarddiskVolume1\Tools\a.exe", T0), out _)!;

        Assert.Equal(ProcessEventKind.Started, e.Kind);
        Assert.Equal(new ProcessKey(42, T0), e.Key);
        Assert.Equal(7, e.ParentProcessId);
        Assert.Equal(@"C:\Tools\a.exe", e.ImagePath);
        Assert.Equal("a.exe --x\uFFFD--y", e.CommandLine); // sanitized, not trimmed or cut
        Assert.Equal("S-1-5-21-9-9-9-1001", e.UserSid);
        Assert.Equal(ProcessIntegrityLevel.High, e.IntegrityLevel);
    }

    [Fact]
    public void Start_IgnoresLiveDetails_OfAProcessThatReusedThePid()
    {
        var info = new EtwProcessEventSourceTests.FixedInfo
        {
            [42] = new(T0.AddSeconds(3), @"C:\Other\b.exe", "b.exe", 1, "S-1-5-18", ProcessIntegrityLevel.System),
        };
        var mapper = new KernelProcessEventMapper(info, Paths.ToWin32);

        var e = mapper.Map(new KernelProcessRecord(ProcessEventKind.Started, 7, 42, 7, T0, 2, @"\Device\HarddiskVolume10\x\a.exe", T0), out _)!;

        Assert.Equal(@"D:\x\a.exe", e.ImagePath); // from the event itself, Volume10 not confused with Volume1
        Assert.Null(e.CommandLine);
        Assert.Null(e.UserSid);
        Assert.Equal(ProcessIntegrityLevel.Unknown, e.IntegrityLevel);
        Assert.Equal(2, e.SessionId);
    }

    [Fact]
    public void ForgedStart_NotLoggedByItsParent_IsRejected()
    {
        var mapper = new KernelProcessEventMapper(new EtwProcessEventSourceTests.FixedInfo(), Paths.ToWin32);

        // A user-mode process (PID 666) logs a "start" under the Kernel-Process GUID claiming winword.exe (PID 7) as the parent.
        var forged = mapper.Map(new KernelProcessRecord(ProcessEventKind.Started, 666, 42, 7, T0, 1, @"C:\x\powershell.exe", T0), out var why);

        Assert.Null(forged);
        Assert.Equal(KernelProcessRejection.HeaderMismatch, why);
    }

    [Fact]
    public void ForgedStop_LoggedByAnotherProcess_OrForAProcessThatStillRuns_IsRejected()
    {
        var info = new EtwProcessEventSourceTests.FixedInfo { Running = { 42 } };
        var mapper = new KernelProcessEventMapper(info, Paths.ToWin32);

        Assert.Null(mapper.Map(new KernelProcessRecord(ProcessEventKind.Stopped, 666, 42, null, T0, null, "xmrig.exe", T0, 0), out var why));
        Assert.Equal(KernelProcessRejection.HeaderMismatch, why);

        // Even logged "by" the miner itself: it still runs, so the stop is forged (a miner hiding itself from the monitors).
        Assert.Null(mapper.Map(new KernelProcessRecord(ProcessEventKind.Stopped, 42, 42, null, T0, null, "xmrig.exe", T0, 0), out why));
        Assert.Equal(KernelProcessRejection.StillRunning, why);

        info.Running.Clear();
        var real = mapper.Map(new KernelProcessRecord(ProcessEventKind.Stopped, 42, 42, null, T0, null, "xmrig.exe", T0, 0), out why);
        Assert.Equal(KernelProcessRejection.None, why);
        Assert.Equal(ProcessEventKind.Stopped, real?.Kind);
    }

    [Fact]
    public void MissingPayloadPidOrCreateTime_IsRejected_NeverFallsBackToTheHeader()
    {
        var mapper = new KernelProcessEventMapper(new EtwProcessEventSourceTests.FixedInfo(), Paths.ToWin32);

        Assert.Null(mapper.Map(new KernelProcessRecord(ProcessEventKind.Started, 7, null, 7, T0, 1, "a.exe", T0), out var why));
        Assert.Equal(KernelProcessRejection.Malformed, why);
        Assert.Null(mapper.Map(new KernelProcessRecord(ProcessEventKind.Started, 7, 42, 7, null, 1, "a.exe", T0), out why));
        Assert.Equal(KernelProcessRejection.Malformed, why);
    }

    [Fact]
    public void LongImagePath_IsCappedHeadAndTail_WithTruncatedFlag()
    {
        string path = @"C:\" + string.Join('\\', Enumerable.Repeat("deep", 2000)) + @"\miner.exe";
        var mapper = new KernelProcessEventMapper(new EtwProcessEventSourceTests.FixedInfo(), Paths.ToWin32);

        var e = mapper.Map(new KernelProcessRecord(ProcessEventKind.Started, 7, 42, 7, T0, 1, path, T0), out _)!;

        Assert.True(e.ImagePathTruncated);
        Assert.Equal(ProcessText.MaxPathChars, e.ImagePath!.Length);
        Assert.StartsWith(@"C:\deep", e.ImagePath);
        Assert.EndsWith(@"\miner.exe", e.ImagePath); // the file name stays visible
        Assert.Equal("miner.exe", e.ImageName);
    }

    [Fact]
    public void Existing_IsMarkedPreExisting_AndSkippedWhenItStartedAfterTheSession()
    {
        var info = new EtwProcessEventSourceTests.FixedInfo
        {
            [10] = new(T0.AddHours(-2), @"C:\Windows\explorer.exe", null, 1, null, ProcessIntegrityLevel.Medium),
            [11] = new(T0.AddSeconds(1), @"C:\new.exe", null, 1, null, ProcessIntegrityLevel.Medium),
        };
        var mapper = new KernelProcessEventMapper(info, Paths.ToWin32);

        var old = mapper.MapExisting(new RunningProcessEntry(10, 4, "explorer.exe"), T0, T0);
        Assert.NotNull(old);
        Assert.True(old.IsPreExisting);
        Assert.Equal(4, old.ParentProcessId);
        Assert.Null(mapper.MapExisting(new RunningProcessEntry(11, 10, "new.exe"), T0, T0)); // its start event reports it
        var unreadable = mapper.MapExisting(new RunningProcessEntry(12, 4, "secure.exe"), T0, T0);
        Assert.Equal("secure.exe", unreadable?.ImagePath); // short name only, start time unknown
        Assert.Null(unreadable?.StartTime);
    }

    [Fact]
    public void Payload_ConvertsTraceEventValues_AndRejectsGarbage()
    {
        var local = T0.UtcDateTime.ToLocalTime();
        Assert.Equal(T0, KernelProcessPayload.ToUtc(local));
        Assert.Equal(T0, KernelProcessPayload.ToUtc(T0.ToFileTime()));
        Assert.Equal(T0, KernelProcessPayload.ToUtc(DateTime.FromFileTime(T0.ToFileTime()))); // TraceEvent's FILETIME decoding
        Assert.Null(KernelProcessPayload.ToUtc("2026-11-16"));
        Assert.Null(KernelProcessPayload.ToUtc(0L));
        Assert.Equal(1234, KernelProcessPayload.ToInt32(1234u));
        Assert.Null(KernelProcessPayload.ToInt32("1234"));
        Assert.Null(KernelProcessPayload.ToInt32(long.MaxValue));
    }

    [Theory]
    [InlineData("S-1-16-4096", ProcessIntegrityLevel.Low)]
    [InlineData("S-1-16-8192", ProcessIntegrityLevel.Medium)]
    [InlineData("S-1-16-12288", ProcessIntegrityLevel.High)]
    [InlineData("S-1-16-16384", ProcessIntegrityLevel.System)]
    [InlineData("S-1-5-18", ProcessIntegrityLevel.Unknown)]
    [InlineData("S-1-16-x", ProcessIntegrityLevel.Unknown)]
    public void IntegrityLevel_FromMandatoryLabel(string sid, ProcessIntegrityLevel expected) =>
        Assert.Equal(expected, NativeProcessInfoReader.IntegrityFromLabelSid(sid));

    [Fact]
    public void CommandLineBuffer_IsReadOnlyInsideTheBuffer()
    {
        const nint Base = 0x10000;
        var text = System.Text.Encoding.Unicode.GetBytes("app.exe -a");
        var buffer = new byte[16 + text.Length];
        BitConverter.GetBytes((ushort)text.Length).CopyTo(buffer, 0);
        BitConverter.GetBytes((long)(Base + 16)).CopyTo(buffer, 8);
        text.CopyTo(buffer, 16);
        Assert.Equal("app.exe -a", NativeProcessInfoReader.CommandLineFromBuffer(buffer.AsSpan(), Base));

        BitConverter.GetBytes((ushort)(text.Length + 2)).CopyTo(buffer, 0); // length past the end
        Assert.Null(NativeProcessInfoReader.CommandLineFromBuffer(buffer.AsSpan(), Base));
        BitConverter.GetBytes((ushort)text.Length).CopyTo(buffer, 0);
        BitConverter.GetBytes((long)0x7FFF0000).CopyTo(buffer, 8); // pointer outside the buffer
        Assert.Null(NativeProcessInfoReader.CommandLineFromBuffer(buffer.AsSpan(), Base));
    }

    [Fact]
    public void DevicePaths_NonDevicePathsPassThrough_UnknownDevicesAreNull()
    {
        Assert.Equal(@"C:\a.exe", Paths.ToWin32(@"C:\a.exe"));
        Assert.Null(Paths.ToWin32(@"\Device\Mup\server\share\a.exe"));
        Assert.Null(Paths.ToWin32(null));
    }
}
