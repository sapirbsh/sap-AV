using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Models;
using SapAV.Core.Pipe;
using SapAV.Core.Scanning;
using SapAV.Engine.Pipe;
using SapAV.Engine.Quarantine;

namespace SapAV.Engine.Tests.TestSupport;

/// <summary>
/// A simulated pipe client identity (B4 tests): any user SID and admin flag, with access checks answered by the current
/// process's real token (so deny ACEs set by a test take effect) or by <see cref="Grant"/>.
/// </summary>
internal sealed class FakeClientIdentity : IClientIdentity
{
    private static int _next;

    public FakeClientIdentity(SecurityIdentifier? user = null, bool isAdmin = false, bool realAccess = true)
    {
        User = user ?? NewUserSid();
        IsAdmin = isAdmin;
        Real = realAccess ? TokenClientIdentity.ForCurrentProcess() : null;
    }

    public SecurityIdentifier User { get; }

    public int SessionId => 1;

    public int ProcessId => Environment.ProcessId;

    public bool IsAdmin { get; }

    public TokenClientIdentity? Real { get; }

    /// <summary>Used when there is no real token: grants everything unless set.</summary>
    public Func<byte[], uint, bool> Grant { get; set; } = (_, _) => true;

    public bool Disposed { get; private set; }

    /// <summary>A made-up user SID (S-1-5-21-…), distinct per call.</summary>
    public static SecurityIdentifier NewUserSid() => new($"S-1-5-21-1111-2222-3333-{1000 + Interlocked.Increment(ref _next)}");

    public bool IsGranted(byte[] securityDescriptor, uint desiredAccess) =>
        Real?.IsGranted(securityDescriptor, desiredAccess) ?? Grant(securityDescriptor, desiredAccess);

    public IClientIdentity Duplicate() => new FakeClientIdentity(User, IsAdmin, Real is not null) { Grant = Grant };

    public void Dispose()
    {
        Disposed = true;
        Real?.Dispose();
    }
}

/// <summary>Resolves connections to identities from a queue (falls back to the real pipe resolver when empty).</summary>
internal sealed class QueuedIdentityResolver : IClientIdentityResolver
{
    private readonly Queue<Func<IClientIdentity>> _next = new();
    private readonly PipeClientIdentityResolver _real = new();

    public void Enqueue(Func<IClientIdentity> identity)
    {
        lock (_next)
        {
            _next.Enqueue(identity);
        }
    }

    public IClientIdentity? Resolve(NamedPipeServerStream pipe, out string failure)
    {
        lock (_next)
        {
            if (_next.TryDequeue(out var make))
            {
                failure = string.Empty;
                return make();
            }
        }

        return _real.Resolve(pipe, out failure);
    }
}

/// <summary>An in-memory quarantine that records what it was asked to do.</summary>
internal sealed class RecordingQuarantine : IQuarantineService
{
    public bool IsAvailable { get; set; } = true;

    public List<FileScanReport> Quarantined { get; } = [];

    public List<string> Restored { get; } = [];

    public List<QuarantineEntry> Entries { get; } = [];

    /// <summary>The requester of each quarantine, in order (null = engine-initiated).</summary>
    public List<QuarantineRequester?> Requesters { get; } = [];

    /// <summary>When set, every quarantine returns this status instead.</summary>
    public QuarantineStatus? Answer { get; set; }

    public Task<QuarantineResult> QuarantineAsync(
        FileScanReport report, Guid? alertId = null, CancellationToken cancellationToken = default, QuarantineRequester? requester = null)
    {
        lock (Quarantined)
        {
            Quarantined.Add(report);
            Requesters.Add(requester);
        }

        if (Answer is { } answer)
        {
            return Task.FromResult(new QuarantineResult(answer, "answer"));
        }

        return Task.FromResult(new QuarantineResult(QuarantineStatus.Quarantined, "ok",
            Entry(report.Result.Item.Path, "q" + Quarantined.Count)));
    }

    public Task<QuarantineResult> QuarantineHandleAsync(SafeFileHandle handle, FileScanReport report, Guid? alertId = null,
        CancellationToken cancellationToken = default, QuarantineRequester? requester = null) => QuarantineAsync(report, alertId, cancellationToken, requester);

    /// <summary>The requester of each restore, in order.</summary>
    public List<SecurityIdentifier?> RestoreRequesters { get; } = [];

    public Task<RestoreResult> RestoreAsync(string itemId, CancellationToken cancellationToken = default, SecurityIdentifier? requester = null)
    {
        Restored.Add(itemId);
        RestoreRequesters.Add(requester);
        return Task.FromResult(new RestoreResult(RestoreStatus.Restored, "restored", Get(itemId)?.OriginalPath));
    }

    public IReadOnlyList<QuarantineEntry> List() => Entries.ToArray();

    public QuarantineEntry? Get(string itemId) => Entries.FirstOrDefault(e => e.Id == itemId);

    /// <param name="sddl">The recorded original security descriptor (default: Everyone may read it).</param>
    public static QuarantineEntry Entry(string originalPath, string id = "item1", IReadOnlyList<string>? reasons = null, string? sddl = EveryoneReads) =>
        new(id, QuarantineEntryIntegrity.Valid, Core.Quarantine.QuarantineState.Quarantined, originalPath, 3, new string('a', 64),
            Verdict.Malicious, reasons ?? ["YARA rule Test matched"], ["T1204.002"], DateTimeOffset.UnixEpoch, null, false)
        {
            OriginalSecurityDescriptor = sddl,
        };

    public const string EveryoneReads = "O:BAG:BAD:(A;;FA;;;BA)(A;;FR;;;WD)";
}

/// <summary>Deny ACEs for the current user on a test folder or file, removed again on dispose.</summary>
internal sealed class DenyAce : IDisposable
{
    private readonly FileSystemInfo _target;
    private readonly FileSystemAccessRule _rule;

    public DenyAce(string path, FileSystemRights rights)
    {
        _target = Directory.Exists(path) ? new DirectoryInfo(path) : new FileInfo(path);
        using var me = WindowsIdentity.GetCurrent();
        _rule = new FileSystemAccessRule(me.User!, rights, AccessControlType.Deny);
        Change(add: true);
    }

    public void Dispose() => Change(add: false);

    private void Change(bool add)
    {
        switch (_target)
        {
            case DirectoryInfo dir:
                var dirAcl = dir.GetAccessControl();
                if (add) { dirAcl.AddAccessRule(_rule); } else { dirAcl.RemoveAccessRuleSpecific(_rule); }
                dir.SetAccessControl(dirAcl);
                break;
            case FileInfo file:
                var fileAcl = file.GetAccessControl();
                if (add) { fileAcl.AddAccessRule(_rule); } else { fileAcl.RemoveAccessRuleSpecific(_rule); }
                file.SetAccessControl(fileAcl);
                break;
        }
    }
}

/// <summary>
/// A real <see cref="EnginePipeServer"/> on a unique test pipe name around a <see cref="ScanJobHarness"/>, plus clients.
/// Everything is stopped and disposed at the end (no pipe, thread or job is left behind).
/// </summary>
internal sealed class PipeTestServer : IAsyncDisposable
{
    private readonly List<EnginePipeClient> _clients = [];

    public PipeTestServer(Action<PipeServerOptions>? configure = null, SecurityIdentifier? serverAccount = null, bool start = true)
    {
        Options.PipeName = "sap-AV.engine.test." + Guid.NewGuid().ToString("N");
        configure?.Invoke(Options);
        Server = new EnginePipeServer(Options, Harness.Service, Quarantine, Harness.Time, NullLogger.Instance, Resolver,
            serverAccount ?? EnginePipeSecurity.CurrentAccount(), _ => 3 /* DRIVE_FIXED */);
        if (start)
        {
            Server.StartAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
    }

    public ScanJobHarness Harness { get; } = new();

    public RecordingQuarantine Quarantine { get; } = new();

    public QueuedIdentityResolver Resolver { get; } = new();

    public PipeServerOptions Options { get; } = new();

    public EnginePipeServer Server { get; }

    public async Task<EnginePipeClient> ConnectAsync(IClientIdentity? identity = null)
    {
        if (identity is not null)
        {
            Resolver.Enqueue(() => identity);
        }

        await Server.Listening.WaitAsync(TimeSpan.FromSeconds(10));
        var client = await EnginePipeClient.ConnectAsync(Options.PipeName, requireSystemServer: false, TimeSpan.FromSeconds(10), "test");
        lock (_clients)
        {
            _clients.Add(client);
        }

        return client;
    }

    /// <summary>Waits until the server has no connection left.</summary>
    public async Task WaitForNoConnectionsAsync()
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(15);
        while (Server.ActiveConnections > 0)
        {
            Assert.True(DateTime.UtcNow < deadline, "connections did not end");
            await Task.Delay(20);
        }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            foreach (var client in _clients)
            {
                await client.DisposeAsync();
            }

            await Server.StopAsync(CancellationToken.None);
            Server.Dispose();
        }
        finally
        {
            Harness.Dispose(); // the temp tree goes even if a client or the server failed to close
        }
    }
}
