using System.Security.AccessControl;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Quarantine;
using N = SapAV.Engine.Quarantine.Native.QuarantineNative;

namespace SapAV.Engine.Quarantine;

/// <summary>
/// The protected quarantine folder. Layout (flat, every name chosen by the engine):
/// <code>
/// &lt;root&gt;\metadata.key          DPAPI (machine) blob of the metadata HMAC key
/// &lt;root&gt;\&lt;id&gt;.json            signed metadata envelope (the journal record)
/// &lt;root&gt;\&lt;id&gt;                 neutralised content (header + XOR), no extension
/// &lt;root&gt;\&lt;id&gt;.staged          same-volume only, transient: the original renamed in by handle
/// &lt;root&gt;\&lt;id&gt;.partial         transient: neutralised copy being written
/// &lt;root&gt;\&lt;id&gt;.json.tmp        transient: metadata being replaced
/// </code>
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Open"/>: the root path must be local and fully qualified. The parent must not be a reparse point and must
/// have a trusted owner. The engine's data root (<c>%ProgramData%\sap-AV</c>) as the parent is created, verified and if
/// possible fixed by <see cref="EngineDataRoot.Ensure"/> (protected SYSTEM + Administrators DACL); any other parent is
/// created with normal inheritance if missing (a configured <c>Root</c>). The root is created
/// atomically with the protected SYSTEM + Administrators DACL (<see cref="QuarantineAccessPolicy"/>); an existing
/// root must not be a reparse point and must have a trusted owner. A DACL that is wider is <b>fixed</b> only if the
/// folder is empty (nothing could have been planted); otherwise the store is <b>refused</b>.
/// </para>
/// <para>
/// While open, the store holds handles to the root and its parent <b>without FILE_SHARE_DELETE</b>, so neither can
/// be renamed or replaced (e.g. by a junction) while the engine runs; paths inside the root are therefore stable,
/// and only SYSTEM/Administrators can create anything in it.
/// </para>
/// </remarks>
public sealed class QuarantineStore : IDisposable
{
    private const uint PinShare = N.ShareRead | N.ShareWrite;
    private readonly SafeFileHandle _parent;

    private QuarantineStore(string rootPath, SafeFileHandle root, SafeFileHandle parent, uint volumeSerial, QuarantineAccessPolicy policy)
    {
        RootPath = rootPath;
        RootHandle = root;
        _parent = parent;
        VolumeSerial = volumeSerial;
        Policy = policy;
    }

    /// <summary>The root's final path (drive-letter form).</summary>
    public string RootPath { get; }

    /// <summary>Serial number of the store's volume (same-volume moves are renames).</summary>
    public uint VolumeSerial { get; }

    public QuarantineAccessPolicy Policy { get; }

    /// <summary>The pinned root directory handle (rename target for same-volume moves).</summary>
    internal SafeFileHandle RootHandle { get; }

    /// <summary>Opens (creating if needed) and verifies the store at <paramref name="root"/>.</summary>
    /// <param name="parentIsDataRoot">
    /// The parent is the engine's data root, so it is created and verified by <see cref="EngineDataRoot.Ensure"/> (review
    /// B H1) instead of inheriting <c>%ProgramData%</c>'s ACL. Default: true when the parent is
    /// <see cref="Scanning.EngineDataFolders.ProgramDataRoot"/>.
    /// </param>
    /// <exception cref="QuarantineStoreException">The store can't be used safely.</exception>
    public static QuarantineStore Open(string root, QuarantineAccessPolicy policy, bool? parentIsDataRoot = null)
    {
        ArgumentNullException.ThrowIfNull(policy);
        string full = ValidateRootPath(root);
        string parentPath = Path.GetDirectoryName(full)
            ?? throw new QuarantineStoreException($"The quarantine root {full} has no parent folder.");

        if (parentIsDataRoot ?? string.Equals(Scanning.FolderSet.Normalize(parentPath), Scanning.FolderSet.Normalize(Scanning.EngineDataFolders.ProgramDataRoot),
                StringComparison.OrdinalIgnoreCase))
        {
            EngineDataRoot.Ensure(parentPath, policy);
        }

        var parent = OpenParent(parentPath, policy);
        try
        {
            CreateRootIfMissing(full, policy);
            var rootHandle = OpenRoot(full, policy);
            try
            {
                string finalRoot = N.GetFinalDosPath(rootHandle)
                    ?? throw new QuarantineStoreException($"Can't determine the final path of {full}.");
                string? finalParent = N.GetFinalDosPath(parent);
                if (!string.Equals(Path.GetDirectoryName(finalRoot), finalParent?.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(Path.GetDirectoryName(finalRoot), finalParent, StringComparison.OrdinalIgnoreCase))
                {
                    throw new QuarantineStoreException($"The quarantine root {finalRoot} is not inside {finalParent}.");
                }

                uint serial = N.GetFileInformation(rootHandle).VolumeSerialNumber;
                return new QuarantineStore(finalRoot, rootHandle, parent, serial, policy);
            }
            catch
            {
                rootHandle.Dispose();
                throw;
            }
        }
        catch
        {
            parent.Dispose();
            throw;
        }
    }

    public string MetadataPath(string id) => Path.Combine(RootPath, Checked(id) + ".json");

    public string MetadataTempPath(string id) => Path.Combine(RootPath, Checked(id) + ".json.tmp");

    public string DataPath(string id) => Path.Combine(RootPath, Checked(id));

    public string PartialPath(string id) => Path.Combine(RootPath, Checked(id) + ".partial");

    public static string StagedName(string id) => Checked(id) + ".staged";

    public string StagedPath(string id) => Path.Combine(RootPath, StagedName(id));

    /// <summary>IDs of all metadata files (<c>&lt;32 hex&gt;.json</c>); anything else is ignored.</summary>
    public IReadOnlyList<string> EnumerateItemIds() =>
        Directory.EnumerateFiles(RootPath, "*.json")
            .Select(Path.GetFileNameWithoutExtension)
            .Where(QuarantineItemId.IsValid)
            .Select(id => id!)
            .Order(StringComparer.Ordinal)
            .ToArray();

    /// <summary>Atomically writes (create or replace) the signed metadata: temp file, flush, rename over.</summary>
    public void WriteMetadata(QuarantineMetadata metadata, byte[] key)
    {
        var bytes = QuarantineMetadataCodec.Encode(metadata, key);
        string temp = MetadataTempPath(metadata.Id);
        using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }

        File.Move(temp, MetadataPath(metadata.Id), overwrite: true);
    }

    /// <summary>Reads and verifies an item's metadata.</summary>
    /// <exception cref="FileNotFoundException">No such item.</exception>
    /// <exception cref="QuarantineMetadataException">Tampered, malformed or invalid.</exception>
    public QuarantineMetadata ReadMetadata(string id, byte[] key)
    {
        using var stream = new FileStream(MetadataPath(id), FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > QuarantineMetadataCodec.MaxFileBytes)
        {
            throw new QuarantineMetadataException(QuarantineMetadataError.Malformed, "The metadata file is too large.");
        }

        var bytes = new byte[stream.Length];
        stream.ReadExactly(bytes);
        return QuarantineMetadataCodec.Decode(bytes, id, key);
    }

    /// <summary>Deletes a store file of ours if it exists (never anything outside the root).</summary>
    public static void DeleteIfExists(string storePath)
    {
        if (File.Exists(storePath))
        {
            File.SetAttributes(storePath, FileAttributes.Normal);
            File.Delete(storePath);
        }
    }

    public void Dispose()
    {
        RootHandle.Dispose();
        _parent.Dispose();
    }

    private static string Checked(string id) =>
        QuarantineItemId.IsValid(id) ? id : throw new ArgumentException("Invalid quarantine item ID.", nameof(id));

    private static string ValidateRootPath(string root)
    {
        if (string.IsNullOrWhiteSpace(root) || root.Contains('\0') || !Path.IsPathFullyQualified(root))
        {
            throw new QuarantineStoreException($"The quarantine root '{root}' must be a fully qualified local path.");
        }

        string full = Path.GetFullPath(root).TrimEnd('\\');
        if (!QuarantinePath.TryValidateOriginalPath(full, out var why))
        {
            throw new QuarantineStoreException($"The quarantine root '{root}' is not a local drive path: {why}.");
        }

        return full;
    }

    private static SafeFileHandle OpenParent(string parentPath, QuarantineAccessPolicy policy)
    {
        try
        {
            Directory.CreateDirectory(parentPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new QuarantineStoreException($"Can't create the quarantine parent folder {parentPath}: {ex.Message}", ex);
        }

        var handle = OpenPinned(parentPath, N.ReadControl | N.FileReadAttributes | N.FileTraverse, "parent folder");
        try
        {
            EnsureTrustedOwner(handle, policy, parentPath);
            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static void CreateRootIfMissing(string root, QuarantineAccessPolicy policy)
    {
        if (N.CreateDirectoryWithSecurity(root, policy.CreateRootSecurityDescriptor(), out int error)
            || error == N.ErrorAlreadyExists)
        {
            return;
        }

        throw new QuarantineStoreException($"Can't create the quarantine folder {root} (Win32 error {error}).");
    }

    private static SafeFileHandle OpenRoot(string root, QuarantineAccessPolicy policy)
    {
        using (var check = OpenPinned(root, N.ReadControl | N.WriteDac | N.FileReadAttributes, "folder"))
        {
            var sd = N.TryGetSecurity(check, N.OwnerSecurityInformation | N.DaclSecurityInformation, out int error)
                ?? throw new QuarantineStoreException($"Can't read the ACL of {root} (Win32 error {error}).");
            switch (policy.Check(sd, out var reason))
            {
                case StoreAclStatus.Ok:
                    break;
                case StoreAclStatus.UntrustedOwner:
                    throw new QuarantineStoreException($"Refusing the quarantine folder {root}: {reason}.");
                default:
                    FixWiderAcl(check, root, policy, reason);
                    break;
            }
        }

        // The pin: FILE_TRAVERSE is a data access right, so the missing FILE_SHARE_DELETE is enforced against anyone
        // who tries to rename or delete the folder (share modes are ignored for handles with only READ_CONTROL / WRITE_DAC).
        // Reopened after the ACL check, so it is granted under the verified (or just fixed) DACL.
        return OpenPinned(root, N.FileTraverse | N.FileReadAttributes, "folder");
    }

    private static void FixWiderAcl(SafeFileHandle handle, string root, QuarantineAccessPolicy policy, string reason)
    {
        bool empty;
        try
        {
            empty = !Directory.EnumerateFileSystemEntries(root).Any();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new QuarantineStoreException($"Refusing the quarantine folder {root}: its ACL is too wide ({reason}) and it can't be listed.", ex);
        }

        if (!empty)
        {
            throw new QuarantineStoreException(
                $"Refusing the quarantine folder {root}: its ACL is too wide ({reason}) and it is not empty, so its content can't be trusted. "
                + "An administrator must check and fix or remove it.");
        }

        int result = N.SetSecurity(handle, N.DaclSecurityInformation | N.ProtectedDaclSecurityInformation, null, policy.CreateRootDaclBytes());
        if (result != 0)
        {
            throw new QuarantineStoreException($"Can't fix the ACL of {root} (Win32 error {result}).");
        }
    }

    private static SafeFileHandle OpenPinned(string path, uint access, string what)
    {
        var handle = N.OpenDirectoryNoReparse(path, access | N.Synchronize, PinShare, out int error);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw new QuarantineStoreException($"Can't open the quarantine {what} {path} (Win32 error {error}).");
        }

        if (!SafeDirectory.IsPlainDirectory(handle))
        {
            handle.Dispose();
            throw new QuarantineStoreException($"The quarantine {what} {path} is a reparse point or not a directory; refusing it.");
        }

        return handle;
    }

    private static void EnsureTrustedOwner(SafeFileHandle handle, QuarantineAccessPolicy policy, string path)
    {
        var sd = N.TryGetSecurity(handle, N.OwnerSecurityInformation, out int error)
            ?? throw new QuarantineStoreException($"Can't read the owner of {path} (Win32 error {error}).");
        var owner = new RawSecurityDescriptor(sd, 0).Owner;
        if (!policy.IsTrustedOwner(owner))
        {
            throw new QuarantineStoreException(
                $"Refusing the quarantine parent folder {path}: owner {owner?.Value ?? "none"} is not SYSTEM, Administrators or the engine account.");
        }
    }
}
