using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SapAV.Core.Signatures;

/// <summary>P/Invoke declarations for wintrust.dll (WinVerifyTrust, catalog admin, provider helpers).</summary>
/// <remarks>
/// All structs are blittable (only <see cref="uint"/> and <see cref="IntPtr"/> fields), so passing them by
/// <c>ref</c> pins them for the call and native writes (e.g. <c>hWVTStateData</c>) land in the managed copy.
/// Field layouts follow WinTrust.h / MsCat.h; sequential layout gives the native alignment on x86, x64 and ARM64.
/// </remarks>
internal static class WinTrustNative
{
    /// <summary>WINTRUST_ACTION_GENERIC_VERIFY_V2 (the Authenticode policy provider).</summary>
    internal static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    // WINTRUST_DATA.dwUIChoice
    internal const uint WtdUiNone = 2;

    // WINTRUST_DATA.fdwRevocationChecks
    internal const uint WtdRevokeNone = 0;

    // WINTRUST_DATA.dwUnionChoice
    internal const uint WtdChoiceFile = 1;
    internal const uint WtdChoiceCatalog = 2;

    // WINTRUST_DATA.dwStateAction
    internal const uint WtdStateActionVerify = 1;
    internal const uint WtdStateActionClose = 2;

    // WINTRUST_DATA.dwProvFlags
    internal const uint WtdRevocationCheckNone = 0x00000010;
    internal const uint WtdCacheOnlyUrlRetrieval = 0x00001000;
    internal const uint WtdDisableMd2Md4 = 0x00002000;

    // Flags that would make WinVerifyTrust go online or skip trust; asserted absent in tests.
    internal const uint WtdRevocationCheckEndCert = 0x00000020;
    internal const uint WtdRevocationCheckChain = 0x00000040;
    internal const uint WtdRevocationCheckChainExcludeRoot = 0x00000080;
    internal const uint WtdHashOnlyFlag = 0x00000200;

    // WINTRUST_DATA.dwUIContext
    internal const uint WtdUiContextExecute = 0;

    /// <summary>The provider flags used for every check: no revocation, cache-only URL retrieval, no MD2/MD4.</summary>
    internal const uint ProviderFlags = WtdRevocationCheckNone | WtdCacheOnlyUrlRetrieval | WtdDisableMd2Md4;

    /// <summary>INVALID_HANDLE_VALUE as the window handle: "there is no interactive user".</summary>
    internal static readonly IntPtr NoInteractiveUser = new(-1);

    [StructLayout(LayoutKind.Sequential)]
    internal struct WinTrustFileInfo
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WinTrustCatalogInfo
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WinTrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pInfo;               // union: WINTRUST_FILE_INFO* / WINTRUST_CATALOG_INFO*
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    /// <summary>CRYPT_PROVIDER_SGNR (WinTrust.h), up to <c>pChainContext</c>.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct CryptProviderSgnr
    {
        public uint cbStruct;
        public uint sftVerifyAsOfLow;      // FILETIME
        public uint sftVerifyAsOfHigh;
        public uint csCertChain;
        public IntPtr pasCertChain;
        public uint dwSignerType;
        public IntPtr psSigner;
        public uint dwError;
        public uint csCounterSigners;
        public IntPtr pasCounterSigners;
        public IntPtr pChainContext;
    }

    /// <summary>CRYPT_PROVIDER_CERT (WinTrust.h), first two members only (read-only use).</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct CryptProviderCertHead
    {
        public uint cbStruct;
        public IntPtr pCert;               // PCCERT_CONTEXT
    }

    /// <summary>A WINTRUST_DATA for one verify call with the fixed offline, no-UI settings.</summary>
    internal static WinTrustData CreateTrustData(uint unionChoice, IntPtr info) => new()
    {
        cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
        dwUIChoice = WtdUiNone,
        fdwRevocationChecks = WtdRevokeNone,
        dwUnionChoice = unionChoice,
        pInfo = info,
        dwStateAction = WtdStateActionVerify,
        dwProvFlags = ProviderFlags,
        dwUIContext = WtdUiContextExecute,
    };

    [DllImport("wintrust.dll", ExactSpelling = true)]
    internal static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WinTrustData pWVTData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    internal static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    internal static extern IntPtr WTHelperGetProvSignerFromChain(
        IntPtr pProvData, uint idxSigner, [MarshalAs(UnmanagedType.Bool)] bool fCounterSigner, uint idxCounterSigner);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    internal static extern IntPtr WTHelperGetProvCertFromChain(IntPtr pSgnr, uint idxCert);

    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCATAdminAcquireContext2(
        out IntPtr phCatAdmin, IntPtr pgSubsystem, string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr hCatAdmin, SafeFileHandle hFile, ref uint pcbHash, byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    /// <summary><c>CryptCATCatalogInfoFromContext</c>; <paramref name="psCatInfo"/> points to a CATALOG_INFO buffer.</summary>
    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, IntPtr psCatInfo, uint dwFlags);

    /// <summary>CATALOG_INFO: DWORD cbStruct + WCHAR wszCatalogFile[MAX_PATH].</summary>
    internal const int CatalogInfoSize = 4 + (260 * 2);
}
