using System.Management;

namespace SapAV.Engine.Defender;

/// <summary>
/// The real <see cref="IWmiReader"/> on System.Management (E5). The only file in src/ that uses System.Management, and it
/// only enumerates (<c>SELECT * FROM class</c>): no method calls, no Put / Delete (guarded by DefenderReadOnlyGuardTests).
/// </summary>
/// <remarks>
/// A WMI call is a synchronous COM call that can't be cancelled. Each read runs on its own thread and the caller waits at most
/// <see cref="WmiClassQuery.Timeout"/> (WMI also gets the same connect and enumeration timeouts). A call past its timeout is
/// abandoned; while <see cref="MaxAbandonedCalls"/> abandoned calls are still running, new reads return TimedOut at once, so a
/// hung WMI never piles up threads or blocks a scan.
/// </remarks>
public sealed class ManagementWmiReader : IWmiReader
{
    public const int MaxAbandonedCalls = 2;

    /// <summary>At most this many instances are copied per read.</summary>
    public const int MaxInstances = 256;

    private readonly Func<WmiClassQuery, WmiReadResult> _readNow;
    private int _abandoned;

    public ManagementWmiReader()
        : this(ReadNow)
    {
    }

    /// <summary>Test seam: the blocking read.</summary>
    internal ManagementWmiReader(Func<WmiClassQuery, WmiReadResult> readNow)
    {
        _readNow = readNow ?? throw new ArgumentNullException(nameof(readNow));
    }

    /// <summary>Abandoned calls still running.</summary>
    internal int AbandonedCalls => Volatile.Read(ref _abandoned);

    public async Task<WmiReadResult> ReadAsync(WmiClassQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        cancellationToken.ThrowIfCancellationRequested();
        if (Volatile.Read(ref _abandoned) >= MaxAbandonedCalls)
        {
            return WmiReadResult.Failure(WmiReadStatus.TimedOut, "earlier WMI calls are still hung");
        }

        var work = Task.Factory.StartNew(() => SafeRead(query), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        try
        {
            return await work.WaitAsync(query.Timeout, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            Abandon(work);
            return WmiReadResult.Failure(WmiReadStatus.TimedOut, $"no answer within {query.Timeout.TotalSeconds:0.#} s");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            Abandon(work);
            throw;
        }
    }

    /// <summary>Maps a WMI / COM HRESULT to a status (ManagementStatus values are HRESULTs).</summary>
    internal static WmiReadStatus Classify(int hresult) => unchecked((uint)hresult) switch
    {
        // Only "this namespace / class doesn't exist" means not installed; a generic WBEM_E_NOT_FOUND (0x80041002) is Failed.
        0x8004100E or 0x80041010 => WmiReadStatus.NotFound,                   // invalid namespace, invalid class
        0x80041003 or 0x80070005 => WmiReadStatus.AccessDenied,               // WBEM_E_ACCESS_DENIED, E_ACCESSDENIED
        0x80043001 or 0x80041032 => WmiReadStatus.TimedOut,                   // WBEM_E_TIMED_OUT (2 forms), WBEM_E_CALL_CANCELLED
        0x800106BA => WmiReadStatus.ServiceNotRunning,                        // Defender's provider: its service isn't running
        0x800706BA or 0x80080005 or 0x80070422 or 0x80041014 => WmiReadStatus.Unavailable, // RPC unavailable, server exec failure, service disabled, initialization failure
        _ => WmiReadStatus.Failed,
    };

    private void Abandon(Task work)
    {
        if (work.IsCompleted)
        {
            return;
        }

        Interlocked.Increment(ref _abandoned);
        _ = work.ContinueWith(_ => Interlocked.Decrement(ref _abandoned), CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    private WmiReadResult SafeRead(WmiClassQuery query)
    {
        try
        {
            return _readNow(query);
        }
        catch (Exception ex)
        {
            return FromException(ex);
        }
    }

    private static WmiReadResult FromException(Exception ex)
    {
        int hresult = ex switch
        {
            ManagementException management => (int)management.ErrorCode,
            UnauthorizedAccessException => unchecked((int)0x80070005),
            _ => ex.HResult,
        };

        var status = ex is TypeInitializationException or PlatformNotSupportedException or DllNotFoundException
            ? WmiReadStatus.Unavailable
            : Classify(hresult);
        return WmiReadResult.Failure(status, $"{ex.GetType().Name} 0x{unchecked((uint)hresult):X8}");
    }

    private static WmiReadResult ReadNow(WmiClassQuery query)
    {
        var connection = new ConnectionOptions
        {
            Timeout = query.Timeout,
            Impersonation = ImpersonationLevel.Impersonate,
            Authentication = AuthenticationLevel.PacketPrivacy,
        };
        var scope = new ManagementScope(query.NamespacePath, connection);
        scope.Connect();

        var enumeration = new System.Management.EnumerationOptions
        {
            Timeout = query.Timeout,
            ReturnImmediately = true,
            Rewindable = false,
            EnsureLocatable = false,
        };

        // The class name was validated as an identifier (WmiClassQuery), so this is a fixed-shape query.
        using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM " + query.ClassName), enumeration);
        using var results = searcher.Get();
        var instances = new List<IReadOnlyDictionary<string, object?>>();
        foreach (ManagementBaseObject item in results)
        {
            using (item)
            {
                if (instances.Count < MaxInstances)
                {
                    instances.Add(Copy(item, query.Properties));
                }
            }
        }

        return WmiReadResult.Ok(instances);
    }

    private static Dictionary<string, object?> Copy(ManagementBaseObject item, IReadOnlyCollection<string> wanted)
    {
        var values = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (PropertyData property in item.Properties)
        {
            if (wanted.Contains(property.Name, StringComparer.OrdinalIgnoreCase))
            {
                values[property.Name] = CopyValue(property.Value);
            }
        }

        return values;
    }

    /// <summary>Plain values only: strings, primitives and arrays of them. Embedded objects become null.</summary>
    private static object? CopyValue(object? value) => value switch
    {
        null => null,
        string or bool or byte or sbyte or short or ushort or int or uint or long or ulong or float or double => value,
        string[] strings => (string[])strings.Clone(),
        Array array when array.GetType().GetElementType() is { IsPrimitive: true } => array.Clone(),
        _ => null,
    };
}
