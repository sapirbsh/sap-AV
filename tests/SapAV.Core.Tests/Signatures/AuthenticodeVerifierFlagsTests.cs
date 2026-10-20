using System.Runtime.InteropServices;
using SapAV.Core.Hashing;
using SapAV.Core.Signatures;
using static SapAV.Core.Signatures.WinTrustNative;

namespace SapAV.Core.Tests.Signatures;

/// <summary>
/// No network, no UI, the secure open flags, and the exact HRESULT -> reason mapping.
/// </summary>
public class AuthenticodeVerifierFlagsTests
{
    [Theory]
    [InlineData(WtdChoiceFile)]
    [InlineData(WtdChoiceCatalog)]
    public void TrustData_IsOffline_Silent_AndStateful(uint choice)
    {
        var data = CreateTrustData(choice, new IntPtr(0x1234));

        Assert.Equal((uint)Marshal.SizeOf<WinTrustData>(), data.cbStruct);
        Assert.Equal(WtdUiNone, data.dwUIChoice);                   // WTD_UI_NONE
        Assert.Equal(WtdRevokeNone, data.fdwRevocationChecks);      // WTD_REVOKE_NONE (0)
        Assert.Equal(0u, data.fdwRevocationChecks);
        Assert.Equal(choice, data.dwUnionChoice);
        Assert.Equal(new IntPtr(0x1234), data.pInfo);
        Assert.Equal(WtdStateActionVerify, data.dwStateAction);     // state kept so the chain can be read, then closed
        Assert.Equal(IntPtr.Zero, data.hWVTStateData);
        Assert.Equal(IntPtr.Zero, data.pwszURLReference);
        Assert.Equal(IntPtr.Zero, data.pPolicyCallbackData);

        Assert.True((data.dwProvFlags & WtdCacheOnlyUrlRetrieval) != 0, "WTD_CACHE_ONLY_URL_RETRIEVAL must be set");
        Assert.True((data.dwProvFlags & WtdRevocationCheckNone) != 0, "WTD_REVOCATION_CHECK_NONE must be set");
        Assert.Equal(0u, data.dwProvFlags & (WtdRevocationCheckEndCert | WtdRevocationCheckChain | WtdRevocationCheckChainExcludeRoot));
        Assert.Equal(0u, data.dwProvFlags & WtdHashOnlyFlag); // full trust check, not just the hash
        Assert.Equal(0x00003010u, data.dwProvFlags);          // exactly: no revocation, cache-only, no MD2/MD4
    }

    [Fact]
    public void PolicyIsGenericVerifyV2_AndNoInteractiveUser()
    {
        Assert.Equal(new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"), GenericVerifyV2);
        Assert.Equal(new IntPtr(-1), NoInteractiveUser);
    }

    [Fact]
    public void StructSizes_MatchTheNativeLayout()
    {
        // x64 sizes from WinTrust.h / MsCat.h.
        if (IntPtr.Size == 8)
        {
            Assert.Equal(32, Marshal.SizeOf<WinTrustFileInfo>());
            Assert.Equal(72, Marshal.SizeOf<WinTrustCatalogInfo>());
            Assert.Equal(88, Marshal.SizeOf<WinTrustData>());
            Assert.Equal(56, (int)Marshal.OffsetOf<CryptProviderSgnr>(nameof(CryptProviderSgnr.pChainContext)));
            Assert.Equal(8, (int)Marshal.OffsetOf<CryptProviderCertHead>(nameof(CryptProviderCertHead.pCert)));
        }
    }

    [Fact]
    public void SignatureCheckOpen_IsTheHashingOpen_WithoutOverlappedIo()
    {
        const uint overlapped = 0x40000000;
        Assert.Equal(NativeFile.HashingFlags & ~overlapped, NativeFile.SignatureCheckFlags);
        Assert.Equal(0u, NativeFile.SignatureCheckFlags & overlapped);
        Assert.True((NativeFile.SignatureCheckFlags & 0x00100000) != 0, "no-recall / SQOS");
        Assert.True((NativeFile.SignatureCheckFlags & 0x02000000) != 0, "backup semantics");
    }

    public static TheoryData<uint, SignatureFailureReason> TrustResults => new()
    {
        { 0x00000000, SignatureFailureReason.None },
        { 0x800B0100, SignatureFailureReason.NotSigned },            // TRUST_E_NOSIGNATURE
        { 0x800B0003, SignatureFailureReason.NotSigned },            // TRUST_E_SUBJECT_FORM_UNKNOWN
        { 0x80096010, SignatureFailureReason.HashMismatch },         // TRUST_E_BAD_DIGEST
        { 0x80091007, SignatureFailureReason.HashMismatch },         // CRYPT_E_HASH_VALUE
        { 0x800B0109, SignatureFailureReason.UntrustedRoot },        // CERT_E_UNTRUSTEDROOT
        { 0x800B010A, SignatureFailureReason.UntrustedRoot },        // CERT_E_CHAINING
        { 0x800B010D, SignatureFailureReason.UntrustedRoot },        // CERT_E_UNTRUSTEDTESTROOT
        { 0x800B0112, SignatureFailureReason.UntrustedRoot },        // CERT_E_UNTRUSTEDCA
        { 0x800B0101, SignatureFailureReason.Expired },              // CERT_E_EXPIRED
        { 0x800B010C, SignatureFailureReason.Revoked },              // CERT_E_REVOKED
        { 0x80092010, SignatureFailureReason.Revoked },              // CRYPT_E_REVOKED
        { 0x800B0111, SignatureFailureReason.ExplicitlyDistrusted }, // TRUST_E_EXPLICIT_DISTRUST
        { 0x800B0110, SignatureFailureReason.WrongUsage },           // CERT_E_WRONG_USAGE
        { 0x80092026, SignatureFailureReason.BlockedByPolicy },      // CRYPT_E_SECURITY_SETTINGS
        { 0x80096004, SignatureFailureReason.MalformedSignature },   // TRUST_E_CERT_SIGNATURE
        { 0x800B010B, SignatureFailureReason.MalformedSignature },   // TRUST_E_FAIL
        { 0x8009310B, SignatureFailureReason.MalformedSignature },   // CRYPT_E_ASN1_BADTAG
        { 0x800B0001, SignatureFailureReason.Error },                // TRUST_E_PROVIDER_UNKNOWN
        { 0x80092003, SignatureFailureReason.Error },                // CRYPT_E_FILE_ERROR
        { 0x80070005, SignatureFailureReason.Error },                // E_ACCESSDENIED
        { 0x80004005, SignatureFailureReason.Error },                // E_FAIL
    };

    [Theory]
    [MemberData(nameof(TrustResults))]
    public void TrustResults_AreMappedExactly(uint hr, SignatureFailureReason expected)
    {
        Assert.Equal(expected, AuthenticodeVerifier.MapTrustResult(unchecked((int)hr)));
    }

    [Fact]
    public void Interpret_NoSignature_OnCatalog_IsAnError_NotUnsigned()
    {
        // A catalog was found, so "no signature" from its verification is a failed check, not "never signed".
        var result = AuthenticodeVerifier.Interpret(unchecked((int)0x800B0100), SignatureKind.Catalog, null, @"C:\x.cat");

        Assert.Equal(SignatureFailureReason.Error, result.FailureReason);
        Assert.Equal(SignatureKind.Catalog, result.Kind);
    }

    [Fact]
    public void Interpret_SuccessWithoutChain_IsAnError_NeverTrusted()
    {
        var result = AuthenticodeVerifier.Interpret(0, SignatureKind.Embedded, null, null);

        Assert.Equal(SignatureStatus.UnsignedOrInvalid, result.Status);
        Assert.Equal(SignatureFailureReason.Error, result.FailureReason);
    }
}
