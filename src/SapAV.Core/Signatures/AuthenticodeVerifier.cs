using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;
using static SapAV.Core.Signatures.WinTrustNative;

namespace SapAV.Core.Signatures;

/// <summary>
/// Authenticode checker: embedded signatures and Windows catalog signatures through WinVerifyTrust, then
/// <see cref="MicrosoftSignerPolicy"/> for Microsoft vs other trusted. Thread-safe and stateless.
/// </summary>
/// <remarks>
/// <para>In order:</para>
/// <list type="number">
/// <item>The same path checks as <see cref="Sha256Hasher"/>: empty/NUL paths are InvalidPath; device-namespace
/// paths (raw or after <see cref="Path.GetFullPath(string)"/>, which maps <c>CON</c>, <c>NUL</c>, ... to
/// <c>\\.\...</c>) are NotRegularFile and never opened.</item>
/// <item>One open, with the hasher's flags minus overlapped I/O (<see cref="NativeFile.SignatureCheckFlags"/>:
/// shared, backup semantics, no cloud recall, anonymous SQOS for pipes). Then <c>GetFileType</c> must be
/// disk, and directories, offline files and placeholders are not checked. Files over
/// <see cref="MaxSizeBytes"/> are not checked (Authenticode hashing reads the whole file).</item>
/// <item>Every later step uses <b>that handle</b>, never the path: WinVerifyTrust gets it in
/// <c>WINTRUST_FILE_INFO.hFile</c>, the catalog hash is computed from it, and the catalog verification gets
/// it in <c>WINTRUST_CATALOG_INFO.hMemberFile</c>. So a link swapped after the open can't redirect the check.</item>
/// <item>Embedded signature (WINTRUST_ACTION_GENERIC_VERIFY_V2). If it isn't trusted, the catalog check runs:
/// SHA-256 catalog admin context, then SHA-1 for older catalogs; first matching catalog only.
/// A trusted catalog signature wins over a broken or missing embedded one, because the catalog vouches for
/// exactly these bytes.</item>
/// <item>Offline and silent: <c>WTD_REVOKE_NONE</c>, <c>WTD_REVOCATION_CHECK_NONE</c>,
/// <c>WTD_CACHE_ONLY_URL_RETRIEVAL</c>, <c>WTD_UI_NONE</c>, no window. The signer chain is read from the
/// provider state before <c>WTD_STATEACTION_CLOSE</c>, which always runs.</item>
/// <item>If size or last-write time changed during the check, the result is discarded (ChangedDuringHashing).</item>
/// </list>
/// <para>
/// The catalog admin context is not cached: Microsoft doesn't document an <c>HCATADMIN</c> as safe to share
/// across threads, and acquiring one is cheap next to hashing the file.
/// </para>
/// <para>
/// Limitation: the file path is still passed alongside the handle, because Windows uses it to pick the
/// subject interface package (SIP) for some file types. The built-in PE, cabinet and catalog SIPs read from
/// the handle; other SIPs (e.g. PowerShell scripts, MSI) may re-open the file by path.
/// </para>
/// </remarks>
public sealed class AuthenticodeVerifier : ISignatureVerifier
{
    /// <param name="maxSizeBytes">Largest file size that is checked (default: the hasher's limit, 256 MiB).</param>
    public AuthenticodeVerifier(long maxSizeBytes = Sha256Hasher.DefaultMaxSizeBytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maxSizeBytes);
        MaxSizeBytes = maxSizeBytes;
    }

    public long MaxSizeBytes { get; }

    /// <inheritdoc/>
    public SignatureCheckResult Verify(string path, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        cancellationToken.ThrowIfCancellationRequested();

        using var handle = SecureFile.OpenRegularFile(path, out var failure, out _);
        if (handle is null)
        {
            return SignatureCheckResult.NotChecked(failure.Reason, failure.Message);
        }

        return VerifyValidated(handle, Path.GetFullPath(path), cancellationToken);
    }

    /// <inheritdoc/>
    public SignatureCheckResult Verify(SafeFileHandle handle, string displayPath, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handle);
        ArgumentNullException.ThrowIfNull(displayPath);
        cancellationToken.ThrowIfCancellationRequested();

        if (!SecureFile.Validate(handle, out var failure, out _))
        {
            return SignatureCheckResult.NotChecked(failure.Reason, failure.Message);
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(displayPath);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return SignatureCheckResult.NotChecked(HashFailureReason.InvalidPath, ex.Message);
        }

        return VerifyValidated(handle, fullPath, cancellationToken);
    }

    private SignatureCheckResult VerifyValidated(SafeFileHandle handle, string fullPath, CancellationToken cancellationToken)
    {
        try
        {
            long length = RandomAccess.GetLength(handle);
            var lastWrite = File.GetLastWriteTimeUtc(handle);
            if (length > MaxSizeBytes)
            {
                return SignatureCheckResult.NotChecked(HashFailureReason.TooLarge,
                    $"File is {length} bytes, over the {MaxSizeBytes}-byte limit; signature not checked.");
            }

            var result = CheckOpenFile(fullPath, handle, cancellationToken);

            long lengthAfter = RandomAccess.GetLength(handle);
            var lastWriteAfter = File.GetLastWriteTimeUtc(handle);
            if (lengthAfter != length || lastWriteAfter != lastWrite)
            {
                return SignatureCheckResult.NotChecked(HashFailureReason.ChangedDuringHashing,
                    $"File changed during the signature check (size {length} -> {lengthAfter}, " +
                    $"last write {lastWrite:O} -> {lastWriteAfter:O}).");
            }

            return result;
        }
        catch (Exception ex) when (Sha256Hasher.TryClassify(ex, out var reason))
        {
            return SignatureCheckResult.NotChecked(reason, ex.Message);
        }
    }

    private static SignatureCheckResult CheckOpenFile(string fullPath, SafeFileHandle handle, CancellationToken cancellationToken)
    {
        bool addedRef = false;
        handle.DangerousAddRef(ref addedRef);
        try
        {
            var embedded = VerifyEmbedded(fullPath, handle);
            if (embedded.IsTrusted)
            {
                return embedded;
            }

            cancellationToken.ThrowIfCancellationRequested();

            var catalog = VerifyCatalog(fullPath, handle, "SHA256") ?? VerifyCatalog(fullPath, handle, "SHA1");
            if (catalog is null)
            {
                return embedded; // NotSigned, or the embedded signature's failure
            }

            if (catalog.IsTrusted)
            {
                return catalog;
            }

            // Both failed: report the file's own broken signature if it has one, else the catalog's failure.
            return embedded.FailureReason == SignatureFailureReason.NotSigned ? catalog : embedded;
        }
        finally
        {
            if (addedRef)
            {
                handle.DangerousRelease();
            }
        }
    }

    private static SignatureCheckResult VerifyEmbedded(string fullPath, SafeFileHandle handle)
    {
        IntPtr pathPtr = IntPtr.Zero;
        IntPtr infoPtr = IntPtr.Zero;
        try
        {
            pathPtr = Marshal.StringToHGlobalUni(fullPath);
            infoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(new WinTrustFileInfo
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                pcwszFilePath = pathPtr,
                hFile = handle.DangerousGetHandle(),
                pgKnownSubject = IntPtr.Zero,
            }, infoPtr, fDeleteOld: false);

            NativeFile.Rewind(handle);
            var data = CreateTrustData(WtdChoiceFile, infoPtr);
            return RunWinVerifyTrust(ref data, SignatureKind.Embedded, catalogPath: null);
        }
        finally
        {
            Marshal.FreeHGlobal(infoPtr);
            Marshal.FreeHGlobal(pathPtr);
        }
    }

    /// <summary>
    /// Looks the file up in the catalog database with <paramref name="hashAlgorithm"/> and verifies the first
    /// matching catalog. Returns <c>null</c> if no catalog lists the file (or it can't be hashed for catalogs).
    /// </summary>
    private static SignatureCheckResult? VerifyCatalog(string fullPath, SafeFileHandle handle, string hashAlgorithm)
    {
        if (!CryptCATAdminAcquireContext2(out IntPtr catAdmin, IntPtr.Zero, hashAlgorithm, IntPtr.Zero, 0))
        {
            int error = Marshal.GetLastPInvokeError();
            return SignatureCheckResult.Invalid(SignatureFailureReason.Error, SignatureKind.Catalog, HResultFromWin32(error),
                message: $"CryptCATAdminAcquireContext2({hashAlgorithm}) failed: {Marshal.GetPInvokeErrorMessage(error)}");
        }

        try
        {
            NativeFile.Rewind(handle);
            uint hashSize = 0;
            CryptCATAdminCalcHashFromFileHandle2(catAdmin, handle, ref hashSize, null, 0); // size query
            if (hashSize is 0 or > 64)
            {
                return null;
            }

            var hash = new byte[hashSize];
            NativeFile.Rewind(handle);
            if (!CryptCATAdminCalcHashFromFileHandle2(catAdmin, handle, ref hashSize, hash, 0) || hashSize != hash.Length)
            {
                return null;
            }

            IntPtr catInfo = CryptCATAdminEnumCatalogFromHash(catAdmin, hash, hashSize, 0, IntPtr.Zero);
            if (catInfo == IntPtr.Zero)
            {
                return null;
            }

            try
            {
                return VerifyAgainstCatalog(fullPath, handle, catAdmin, catInfo, hash);
            }
            finally
            {
                CryptCATAdminReleaseCatalogContext(catAdmin, catInfo, 0);
            }
        }
        finally
        {
            CryptCATAdminReleaseContext(catAdmin, 0);
        }
    }

    private static SignatureCheckResult VerifyAgainstCatalog(
        string fullPath, SafeFileHandle handle, IntPtr catAdmin, IntPtr catInfo, byte[] hash)
    {
        IntPtr catalogInfo = IntPtr.Zero;
        IntPtr catalogPathPtr = IntPtr.Zero;
        IntPtr memberTagPtr = IntPtr.Zero;
        IntPtr memberPathPtr = IntPtr.Zero;
        IntPtr hashPtr = IntPtr.Zero;
        IntPtr infoPtr = IntPtr.Zero;
        try
        {
            catalogInfo = Marshal.AllocHGlobal(CatalogInfoSize);
            Marshal.Copy(new byte[CatalogInfoSize], 0, catalogInfo, CatalogInfoSize);
            Marshal.WriteInt32(catalogInfo, CatalogInfoSize); // cbStruct
            if (!CryptCATCatalogInfoFromContext(catInfo, catalogInfo, 0))
            {
                int error = Marshal.GetLastPInvokeError();
                return SignatureCheckResult.Invalid(SignatureFailureReason.Error, SignatureKind.Catalog, HResultFromWin32(error),
                    message: $"CryptCATCatalogInfoFromContext failed: {Marshal.GetPInvokeErrorMessage(error)}");
            }

            string catalogPath = Marshal.PtrToStringUni(catalogInfo + 4) ?? string.Empty;

            catalogPathPtr = Marshal.StringToHGlobalUni(catalogPath);
            memberTagPtr = Marshal.StringToHGlobalUni(Convert.ToHexString(hash));
            memberPathPtr = Marshal.StringToHGlobalUni(fullPath);
            hashPtr = Marshal.AllocHGlobal(hash.Length);
            Marshal.Copy(hash, 0, hashPtr, hash.Length);

            infoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustCatalogInfo>());
            Marshal.StructureToPtr(new WinTrustCatalogInfo
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustCatalogInfo>(),
                dwCatalogVersion = 0,
                pcwszCatalogFilePath = catalogPathPtr,
                pcwszMemberTag = memberTagPtr,
                pcwszMemberFilePath = memberPathPtr,
                hMemberFile = handle.DangerousGetHandle(),
                pbCalculatedFileHash = hashPtr,
                cbCalculatedFileHash = (uint)hash.Length,
                pcCatalogContext = IntPtr.Zero,
                hCatAdmin = catAdmin,
            }, infoPtr, fDeleteOld: false);

            NativeFile.Rewind(handle);
            var data = CreateTrustData(WtdChoiceCatalog, infoPtr);
            return RunWinVerifyTrust(ref data, SignatureKind.Catalog, catalogPath);
        }
        finally
        {
            Marshal.FreeHGlobal(infoPtr);
            Marshal.FreeHGlobal(hashPtr);
            Marshal.FreeHGlobal(memberPathPtr);
            Marshal.FreeHGlobal(memberTagPtr);
            Marshal.FreeHGlobal(catalogPathPtr);
            Marshal.FreeHGlobal(catalogInfo);
        }
    }

    /// <summary>Verify, read the signer from the provider state, then always close the state.</summary>
    private static SignatureCheckResult RunWinVerifyTrust(ref WinTrustData data, SignatureKind kind, string? catalogPath)
    {
        var action = GenericVerifyV2;
        int hr;
        SignatureSigner? signer;
        try
        {
            hr = WinVerifyTrust(NoInteractiveUser, ref action, ref data);
            signer = ReadSigner(data.hWVTStateData);
        }
        finally
        {
            data.dwStateAction = WtdStateActionClose;
            WinVerifyTrust(NoInteractiveUser, ref action, ref data);
        }

        return Interpret(hr, kind, signer, catalogPath);
    }

    internal static SignatureCheckResult Interpret(int hr, SignatureKind kind, SignatureSigner? signer, string? catalogPath)
    {
        if (hr == 0)
        {
            if (signer is null)
            {
                return SignatureCheckResult.Invalid(SignatureFailureReason.Error, kind, hr, catalogPath: catalogPath,
                    message: "WinVerifyTrust succeeded but returned no signer chain.");
            }

            var classification = MicrosoftSignerPolicy.Classify(signer.Chain);
            return SignatureCheckResult.Trusted(classification.Status, kind, signer, catalogPath, classification.Reason);
        }

        var reason = MapTrustResult(hr);
        string message = $"WinVerifyTrust ({kind}) returned 0x{hr:X8}.";
        if (reason == SignatureFailureReason.NotSigned)
        {
            return kind == SignatureKind.Embedded
                ? SignatureCheckResult.NotSigned(message)
                : SignatureCheckResult.Invalid(SignatureFailureReason.Error, kind, hr, signer, catalogPath, message);
        }

        return SignatureCheckResult.Invalid(reason, kind, hr, signer, catalogPath, message);
    }

    /// <summary>Reads the primary signer's chain and timestamp from WinVerifyTrust state data.</summary>
    private static SignatureSigner? ReadSigner(IntPtr stateData)
    {
        const uint MaxChainLength = 16;
        if (stateData == IntPtr.Zero)
        {
            return null;
        }

        IntPtr providerData = WTHelperProvDataFromStateData(stateData);
        if (providerData == IntPtr.Zero)
        {
            return null;
        }

        IntPtr signerPtr = WTHelperGetProvSignerFromChain(providerData, 0, false, 0);
        if (signerPtr == IntPtr.Zero)
        {
            return null;
        }

        var sgnr = Marshal.PtrToStructure<CryptProviderSgnr>(signerPtr);
        var chain = new List<SignatureCertificate>();
        for (uint i = 0; i < Math.Min(sgnr.csCertChain, MaxChainLength); i++)
        {
            IntPtr providerCert = WTHelperGetProvCertFromChain(signerPtr, i);
            if (providerCert == IntPtr.Zero)
            {
                break;
            }

            var head = Marshal.PtrToStructure<CryptProviderCertHead>(providerCert);
            if (head.pCert == IntPtr.Zero)
            {
                break;
            }

            using var certificate = new X509Certificate2(head.pCert); // duplicates the context
            chain.Add(SignatureCertificate.FromCertificate(certificate));
        }

        if (chain.Count == 0)
        {
            return null;
        }

        DateTimeOffset? timestamp = null;
        if (sgnr.csCounterSigners > 0)
        {
            long fileTime = ((long)sgnr.sftVerifyAsOfHigh << 32) | sgnr.sftVerifyAsOfLow;
            if (fileTime > 0)
            {
                timestamp = new DateTimeOffset(DateTime.FromFileTimeUtc(fileTime), TimeSpan.Zero);
            }
        }

        return new SignatureSigner(chain, timestamp);
    }

    /// <summary>Maps a WinVerifyTrust HRESULT to a reason (exact codes from WinError.h).</summary>
    internal static SignatureFailureReason MapTrustResult(int hr) => unchecked((uint)hr) switch
    {
        0 => SignatureFailureReason.None,
        0x800B0100 or 0x800B0003 => SignatureFailureReason.NotSigned,          // TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN
        0x80096010 or 0x80091007 => SignatureFailureReason.HashMismatch,       // TRUST_E_BAD_DIGEST, CRYPT_E_HASH_VALUE
        0x800B0109 or 0x800B010A or 0x800B010D or 0x800B0112 =>
            SignatureFailureReason.UntrustedRoot,                               // UNTRUSTEDROOT, CHAINING, UNTRUSTEDTESTROOT, UNTRUSTEDCA
        0x800B0101 => SignatureFailureReason.Expired,                           // CERT_E_EXPIRED
        0x800B010C or 0x80092010 => SignatureFailureReason.Revoked,            // CERT_E_REVOKED, CRYPT_E_REVOKED
        0x800B0111 => SignatureFailureReason.ExplicitlyDistrusted,             // TRUST_E_EXPLICIT_DISTRUST
        0x800B0110 => SignatureFailureReason.WrongUsage,                       // CERT_E_WRONG_USAGE
        0x80092026 => SignatureFailureReason.BlockedByPolicy,                  // CRYPT_E_SECURITY_SETTINGS
        0x800B0001 or 0x800B0002 or 0x80096001 or 0x80092003 =>
            SignatureFailureReason.Error,                                       // PROVIDER/ACTION_UNKNOWN, SYSTEM_ERROR, CRYPT_E_FILE_ERROR
        0x80096004 or 0x80096002 or 0x80096003 or 0x80096005 or 0x80096019 or 0x8009601E or 0x800B010B or 0x800B0102 =>
            SignatureFailureReason.MalformedSignature,                          // CERT_SIGNATURE, NO_SIGNER_CERT, COUNTER_SIGNER, TIME_STAMP,
                                                                                // BASIC_CONSTRAINTS, FINANCIAL_CRITERIA, TRUST_E_FAIL, VALIDITYPERIODNESTING
        var code when (code & 0xFFFF0000) == 0x80090000 =>
            SignatureFailureReason.MalformedSignature,                          // other crypto/ASN.1 errors (FACILITY_SECURITY)
        _ => SignatureFailureReason.Error,                                      // incl. Win32 I/O errors (0x8007xxxx)
    };

    private static int HResultFromWin32(int error) => error <= 0 ? error : unchecked((int)(0x80070000u | (uint)(error & 0xFFFF)));
}
