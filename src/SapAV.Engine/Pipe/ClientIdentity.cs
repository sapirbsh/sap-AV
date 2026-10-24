using System.IO.Pipes;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SapAV.Engine.Pipe.Native;

namespace SapAV.Engine.Pipe;

/// <summary>
/// Who is on the other end of a pipe connection. Production identities come only from the pipe
/// (<see cref="PipeClientIdentityResolver"/>); tests inject others through <see cref="IClientIdentityResolver"/>.
/// </summary>
public interface IClientIdentity : IDisposable
{
    SecurityIdentifier User { get; }

    int SessionId { get; }

    int ProcessId { get; }

    /// <summary>An administrator: the token has BUILTIN\Administrators enabled (an elevated token), or it is LocalSystem.</summary>
    bool IsAdmin { get; }

    /// <summary>AccessCheck of this client's token against a self-relative security descriptor (owner, group, DACL).</summary>
    bool IsGranted(byte[] securityDescriptor, uint desiredAccess);

    /// <summary>An independent copy (its own token handle) that can outlive the connection, e.g. for a scan job.</summary>
    IClientIdentity Duplicate();
}

/// <summary>Resolves the identity of a connected client (called after the first frame was read: impersonation needs it).</summary>
public interface IClientIdentityResolver
{
    /// <summary>Null when the client can't be identified (anonymous, impersonation refused, too low integrity).</summary>
    IClientIdentity? Resolve(NamedPipeServerStream pipe, out string failure);
}

/// <summary>An identity backed by the client's own token (identification level is enough: it is only used for checks).</summary>
public sealed class TokenClientIdentity : IClientIdentity
{
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);

    private readonly SafeAccessTokenHandle _token;

    private TokenClientIdentity(SafeAccessTokenHandle token, SecurityIdentifier user, int sessionId, int processId, bool isAdmin)
    {
        _token = token;
        User = user;
        SessionId = sessionId;
        ProcessId = processId;
        IsAdmin = isAdmin;
    }

    public SecurityIdentifier User { get; }

    public int SessionId { get; }

    public int ProcessId { get; }

    public bool IsAdmin { get; }

    /// <summary>Takes ownership of <paramref name="token"/> (disposed on failure too).</summary>
    /// <exception cref="InvalidOperationException">The token can't be queried.</exception>
    internal static TokenClientIdentity FromToken(SafeAccessTokenHandle token, int processId)
    {
        try
        {
            var sid = PipeNative.TokenUserSid(token) ?? throw new InvalidOperationException("The client token has no user SID.");
            var user = new SecurityIdentifier(sid, 0);
            int session = PipeNative.TokenSessionId(token) ?? throw new InvalidOperationException("The client token has no session.");
            byte[] admins = new byte[Administrators.BinaryLength];
            Administrators.GetBinaryForm(admins, 0);
            bool isAdmin = user == LocalSystem || PipeNative.IsMember(token, admins);
            return new TokenClientIdentity(token, user, session, processId, isAdmin);
        }
        catch
        {
            token.Dispose();
            throw;
        }
    }

    /// <summary>The current process's own identity (console runs and tests).</summary>
    public static TokenClientIdentity ForCurrentProcess() =>
        FromToken(PipeNative.DuplicateProcessTokenForIdentification(), Environment.ProcessId);

    /// <summary>The held token's SECURITY_IMPERSONATION_LEVEL (1 = identification), for tests.</summary>
    internal int? TokenImpersonationLevel => PipeNative.TokenImpersonationLevel(_token);

    public bool IsGranted(byte[] securityDescriptor, uint desiredAccess)
    {
        ArgumentNullException.ThrowIfNull(securityDescriptor);
        return PipeNative.IsGranted(_token, securityDescriptor, desiredAccess);
    }

    public IClientIdentity Duplicate() =>
        new TokenClientIdentity(PipeNative.DuplicateIdentification(_token), User, SessionId, ProcessId, IsAdmin);

    public void Dispose() => _token.Dispose();
}

/// <summary>
/// The production resolver: <c>GetNamedPipeClientProcessId</c>, then the client's token via
/// <c>ImpersonateNamedPipeClient</c> → <c>OpenThreadToken</c> → <c>RevertToSelf</c> (in <c>finally</c>, see
/// <see cref="PipeNative.CaptureClientToken"/>). Anonymous clients and tokens below Medium integrity are refused.
/// </summary>
public sealed class PipeClientIdentityResolver : IClientIdentityResolver
{
    private const int MediumIntegrityRid = 0x2000;

    public IClientIdentity? Resolve(NamedPipeServerStream pipe, out string failure)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        var handle = pipe.SafePipeHandle;
        if (!PipeNative.TryGetClientProcessId(handle, out int pid))
        {
            failure = "the client process ID is not available";
            return null;
        }

        var token = PipeNative.CaptureClientToken(handle, out int error);
        if (token is null)
        {
            failure = error == PipeNative.ErrorCantOpenAnonymous ? "anonymous clients are not accepted" : $"the client can't be impersonated (Win32 error {error})";
            return null;
        }

        if (PipeNative.TokenImpersonationLevel(token) is not >= 1)
        {
            token.Dispose();
            failure = "the client token is anonymous";
            return null;
        }

        // Review B4 L5: keep only an identification-level copy (enough for AccessCheck and membership); the engine never
        // holds a token it could impersonate the client with.
        var original = token;
        try
        {
            token = PipeNative.DuplicateIdentification(original);
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            failure = $"the client token can't be copied ({ex.NativeErrorCode})";
            return null;
        }
        finally
        {
            original.Dispose();
        }

        if (PipeNative.TokenIntegrityRid(token) is not { } rid || rid < MediumIntegrityRid)
        {
            token.Dispose();
            failure = "the client runs below Medium integrity";
            return null;
        }

        try
        {
            failure = string.Empty;
            return TokenClientIdentity.FromToken(token, pid);
        }
        catch (InvalidOperationException ex)
        {
            failure = ex.Message;
            return null;
        }
    }
}
