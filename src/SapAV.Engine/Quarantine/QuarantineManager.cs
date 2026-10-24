using System.ComponentModel;
using Microsoft.Extensions.Options;
using SapAV.Core.Quarantine;
using SapAV.Core.Scanning;
using SapAV.Engine.Alerts;

namespace SapAV.Engine.Quarantine;

/// <summary>Points where a test can simulate a crash (the hook throws; handles close as on process exit).</summary>
internal enum QuarantineStep
{
    QuarantineJournalWritten,
    QuarantineStaged,
    QuarantineStoredCopyWritten,
    QuarantineSourceDeleted,
    RestoreJournalWritten,
    RestoreTempWritten,
    RestoreRenamed,
    RestoreMarkedRestored,
    RestoreDataDeleted,
}

/// <summary>
/// The reversible quarantine (ROADMAP B2), running in the SYSTEM engine.
/// </summary>
/// <remarks>
/// <para><b>Journal.</b> Every operation writes the item's signed metadata <i>before</i> the step it announces:</para>
/// <list type="table">
/// <item><term>Quarantining</term><description>metadata written → (same volume) original renamed by handle to
/// <c>&lt;id&gt;.staged</c> → neutralised copy written to <c>&lt;id&gt;.partial</c>, verified, renamed to <c>&lt;id&gt;</c>
/// → source (staged raw file, or the cross-volume original) deleted <b>through the same handle</b>.</description></item>
/// <item><term>Quarantined</term><description>final state; only the neutralised copy and metadata remain.</description></item>
/// <item><term>Restoring</term><description>metadata (with a random temp name) written → temp file created relative to
/// the verified target folder handle, filled, verified, attributes/times/DACL/MOTW applied → renamed (no replace) to
/// the original name or <c>name (restored N).ext</c>.</description></item>
/// <item><term>Restored</term><description>the restored file is in place; the stored copy, then the metadata, are removed.</description></item>
/// </list>
/// <para>At every point at least one intact copy exists (the original, the staged raw file, the stored copy, or the
/// restored file); <see cref="Initialize"/> recovers half-done items (see <c>QuarantineManager.Recovery.cs</c>).</para>
/// <para><b>Concurrency.</b> One operation per original path and per item at a time (others get Busy).</para>
/// </remarks>
public sealed partial class QuarantineManager : IQuarantineService, IDisposable
{
    private readonly QuarantineOptions _options;
    private readonly IAlertSink _alerts;
    private readonly ILogger<QuarantineManager> _logger;
    private readonly TimeProvider _time;
    private readonly IQuarantineKeyProvider _keys;
    private readonly QuarantineAccessPolicy _policy;
    private readonly Scanning.FolderSet _ownStore;
    private readonly Scanning.ExclusionSet _engineFolders;
    private readonly KeyedLocks _locks = new();
    private readonly Lock _initLock = new();
    private QuarantineStore? _store;
    private byte[]? _key;

    public QuarantineManager(
        IOptions<QuarantineOptions> options,
        IAlertSink alerts,
        ILogger<QuarantineManager> logger,
        TimeProvider time,
        IQuarantineKeyProvider keys,
        Scanning.ExclusionSet? engineFolders = null)
    {
        _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        _alerts = alerts ?? throw new ArgumentNullException(nameof(alerts));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _keys = keys ?? throw new ArgumentNullException(nameof(keys));
        _policy = _options.AdditionalTrustedSids.Count == 0
            ? QuarantineAccessPolicy.Default
            : new QuarantineAccessPolicy(_options.AdditionalTrustedSids);

        // Review B2 follow-up Medium: never quarantine the engine's own data (rules match themselves), store or install folders.
        // Review B H1: the other engine folders only while their owner and ACL are verified (the open store always is).
        _ownStore = new Scanning.FolderSet([_options.EffectiveRoot]);
        _engineFolders = engineFolders ?? new Scanning.ExclusionSet(new Scanning.FolderSet(Scanning.EngineDataFolders.Defaults()), new Scanning.FolderSet([]),
            Scanning.FolderTrust.Default, _time);
    }

    /// <summary>Test seam: called at each <see cref="QuarantineStep"/>; throwing simulates a crash there.</summary>
    internal Action<QuarantineStep>? StepHook { get; init; }

    /// <summary>Test seam: take the cross-volume path (copy + delete by handle) even on the store's volume.</summary>
    internal bool ForceCrossVolume { get; init; }

    /// <inheritdoc/>
    public bool IsAvailable => Volatile.Read(ref _store) is not null;

    /// <summary>The open store's root (null until initialised).</summary>
    public string? StoreRoot => Volatile.Read(ref _store)?.RootPath;

    /// <summary>
    /// Opens and verifies the store (ACL, reparse points), loads the metadata key and recovers half-done items.
    /// Idempotent. Until it succeeds every operation returns StoreUnavailable.
    /// </summary>
    /// <exception cref="QuarantineStoreException">The store can't be used safely (logged by the caller).</exception>
    public IReadOnlyList<QuarantineRecoveryAction> Initialize()
    {
        lock (_initLock)
        {
            if (_store is not null)
            {
                return [];
            }

            var store = QuarantineStore.Open(_options.EffectiveRoot, _policy);
            try
            {
                var key = _keys.GetOrCreateKey(store.RootPath, _policy);
                var actions = Recover(store, key);
                _key = key;
                Volatile.Write(ref _store, store);
                _logger.LogInformation("Quarantine store ready at {Root} ({Count} item(s) recovered).", store.RootPath, actions.Count);
                return actions;
            }
            catch
            {
                store.Dispose();
                throw;
            }
        }
    }

    /// <inheritdoc/>
    public IReadOnlyList<QuarantineEntry> List()
    {
        if (!TryGetStore(out var store, out var key))
        {
            return [];
        }

        return store.EnumerateItemIds().Select(id => Load(store, key, id)).OfType<QuarantineEntry>().ToArray();
    }

    /// <inheritdoc/>
    public QuarantineEntry? Get(string itemId) =>
        QuarantineItemId.IsValid(itemId) && TryGetStore(out var store, out var key) ? Load(store, key, itemId) : null;

    public void Dispose()
    {
        lock (_initLock)
        {
            Volatile.Read(ref _store)?.Dispose();
            Volatile.Write(ref _store, null);
        }
    }

    private QuarantineEntry? Load(QuarantineStore store, byte[] key, string id)
    {
        try
        {
            return QuarantineEntry.From(store.ReadMetadata(id, key));
        }
        catch (QuarantineMetadataException ex)
        {
            _logger.LogWarning("Quarantine item {Id} has invalid metadata ({Error}): {Message}", id, ex.Error, ex.Message);
            return QuarantineEntry.Invalid(id);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
        catch (Exception ex) when (IsIoFailure(ex))
        {
            _logger.LogWarning("Quarantine item {Id} can't be read: {Message}", id, ex.Message);
            return QuarantineEntry.Invalid(id);
        }
    }

    private bool TryGetStore(out QuarantineStore store, out byte[] key)
    {
        lock (_initLock)
        {
            store = _store!;
            key = _key!;
            return _store is not null && _key is not null;
        }
    }

    private void Hook(QuarantineStep step) => StepHook?.Invoke(step);

    /// <summary>File-system failures an operation handles. Anything else (bugs, simulated crashes) propagates.</summary>
    private static bool IsIoFailure(Exception ex) =>
        ex is IOException or UnauthorizedAccessException or Win32Exception or InvalidDataException;

    /// <summary>Non-blocking named locks: a second operation on the same key gets Busy instead of waiting.</summary>
    private sealed class KeyedLocks
    {
        private readonly HashSet<string> _held = new(StringComparer.OrdinalIgnoreCase);

        public IDisposable? TryAcquire(string key)
        {
            lock (_held)
            {
                return _held.Add(key) ? new Lease(this, key) : null;
            }
        }

        private void Release(string key)
        {
            lock (_held)
            {
                _held.Remove(key);
            }
        }

        private sealed class Lease(KeyedLocks owner, string key) : IDisposable
        {
            private int _disposed;

            public void Dispose()
            {
                if (Interlocked.Exchange(ref _disposed, 1) == 0)
                {
                    owner.Release(key);
                }
            }
        }
    }
}
