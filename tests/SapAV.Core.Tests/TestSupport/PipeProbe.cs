using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace SapAV.Core.Tests.TestSupport;

/// <summary>
/// A named-pipe server that is actively waiting for a client, so a connect is observable.
/// <see cref="NamedPipeServerStream.IsConnected"/> only turns true after WaitForConnection completes,
/// so checking it without waiting can't see a client.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class PipeProbe : IAsyncDisposable
{
    private readonly NamedPipeServerStream _server;
    private readonly Task _wait;

    public PipeProbe()
        : this(acceptRemoteClients: false)
    {
    }

    /// <param name="acceptRemoteClients">
    /// False (default): a .NET server, which always sets PIPE_REJECT_REMOTE_CLIENTS. True: created with
    /// CreateNamedPipeW without that flag, like a hostile server would be, so it is also reachable over SMB
    /// loopback (<c>\\localhost\pipe\name</c>).
    /// </param>
    public PipeProbe(bool acceptRemoteClients)
    {
        Name = "sapav-test-" + Guid.NewGuid().ToString("N");
        if (acceptRemoteClients)
        {
            // PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED; PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT; 1 instance.
            var handle = CreateNamedPipeW(@"\\.\pipe\" + Name, 0x00000003 | 0x40000000, 0, 1, 4096, 4096, 0, IntPtr.Zero);
            if (handle.IsInvalid)
            {
                int error = Marshal.GetLastPInvokeError();
                handle.Dispose();
                throw new IOException($"CreateNamedPipeW failed: {Marshal.GetPInvokeErrorMessage(error)}", error);
            }

            _server = new NamedPipeServerStream(PipeDirection.InOut, isAsync: true, isConnected: false, handle);
        }
        else
        {
            // Non-zero buffers: with the default of 0, a client write blocks until the server reads.
            _server = new NamedPipeServerStream(
                Name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous,
                inBufferSize: 4096, outBufferSize: 4096);
        }

        _wait = _server.WaitForConnectionAsync();
    }

    public string Name { get; }

    public string Path => @"\\.\pipe\" + Name;

    /// <summary>True if a client connected (waits briefly for the connect to be reported).</summary>
    public async Task<bool> WasConnectedAsync()
    {
        await Task.WhenAny(_wait, Task.Delay(500));
        return _wait.IsCompletedSuccessfully;
    }

    /// <summary>
    /// Bytes the client wrote before closing (0 if it never connected or wrote nothing).
    /// Reads until end-of-pipe or a short timeout.
    /// </summary>
    public async Task<int> BytesWrittenByClientAsync()
    {
        if (!await WasConnectedAsync())
        {
            return 0;
        }

        int total = 0;
        var buffer = new byte[256];
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        try
        {
            int n;
            while ((n = await _server.ReadAsync(buffer, timeout.Token)) > 0)
            {
                total += n;
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException)
        {
            // timeout or broken pipe: nothing more to read
        }

        return total;
    }

    /// <summary>
    /// True if a connected client has closed its end (a read returns end-of-pipe, or the pipe is broken)
    /// within <paramref name="timeout"/>. False if no client connected or it still holds its handle.
    /// </summary>
    public async Task<bool> ClientDisconnectedAsync(TimeSpan timeout)
    {
        if (!await WasConnectedAsync())
        {
            return false;
        }

        var buffer = new byte[256];
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            while (await _server.ReadAsync(buffer, cts.Token) > 0)
            {
            }

            return true;
        }
        catch (IOException)
        {
            return true; // broken pipe: the client end is closed
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    /// <summary>
    /// Reads one byte the client sent, then tries to act as the client. Returns the identity the server
    /// got, or null if impersonation failed (e.g. anonymous level, or the client never wrote anything:
    /// Windows only allows impersonation after data has been read from the pipe).
    /// </summary>
    public async Task<string?> ClientIdentityAfterOneByteAsync()
    {
        if (!await WasConnectedAsync())
        {
            return null;
        }

        var one = new byte[1];
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        try
        {
            if (await _server.ReadAsync(one, timeout.Token) != 1)
            {
                return null;
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException)
        {
            return null;
        }

        string? name = null;
        try
        {
            _server.RunAsClient(() => name = WindowsIdentity.GetCurrent(TokenAccessLevels.Query).Name);
        }
        catch (Exception)
        {
            // Any failure means the server could not act as the client.
            return null;
        }

        return name;
    }

    public async ValueTask DisposeAsync()
    {
        await _server.DisposeAsync();
        try
        {
            await _wait; // observe the pending wait so nothing is left running
        }
        catch (Exception ex) when (ex is ObjectDisposedException or IOException or OperationCanceledException)
        {
        }
    }

    public static bool Exists(string name) =>
        Directory.GetFiles(@"\\.\pipe\").Any(p => p.EndsWith(name, StringComparison.OrdinalIgnoreCase));

    /// <summary>Opens a pipe client for read+write with the given CreateFileW flags (test control).</summary>
    public static SafeFileHandle OpenClient(string path, uint flags)
    {
        var handle = CreateFileW(path, 0x80000000 | 0x40000000, 0x7, IntPtr.Zero, 3, flags, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new IOException($"CreateFileW failed: {Marshal.GetPInvokeErrorMessage(error)}", error);
        }

        return handle;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", EntryPoint = "CreateNamedPipeW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafePipeHandle CreateNamedPipeW(
        string lpName, uint dwOpenMode, uint dwPipeMode, uint nMaxInstances, uint nOutBufferSize,
        uint nInBufferSize, uint nDefaultTimeOut, IntPtr lpSecurityAttributes);
}
