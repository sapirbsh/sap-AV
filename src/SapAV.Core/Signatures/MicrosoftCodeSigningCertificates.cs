namespace SapAV.Core.Signatures;

/// <summary>A certificate identified by thumbprint, with where its identity was verified.</summary>
/// <param name="Name">Subject CN, for logs and review only. Never used for matching.</param>
/// <param name="Sha1">SHA-1 thumbprint (uppercase hex).</param>
/// <param name="Sha256">SHA-256 thumbprint (uppercase hex).</param>
/// <param name="VerifiedFrom">How the thumbprints were verified.</param>
public sealed record KnownCertificate(string Name, string Sha1, string Sha256, string VerifiedFrom)
{
    /// <summary>True if both thumbprints match (case-insensitive hex).</summary>
    public bool Matches(SignatureCertificate certificate) =>
        string.Equals(Sha256, certificate.Sha256Thumbprint, StringComparison.OrdinalIgnoreCase)
        && string.Equals(Sha1, certificate.Sha1Thumbprint, StringComparison.OrdinalIgnoreCase);
}

/// <summary>A Microsoft first-party issuing CA and the product root it must be directly under.</summary>
public sealed record FirstPartyIssuingCa(KnownCertificate Certificate, KnownCertificate Root);

/// <summary>
/// Thumbprints used by <see cref="MicrosoftSignerPolicy"/> to decide <see cref="SignatureStatus.Microsoft"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>How every thumbprint here was verified (2026-10-19, Windows 11 Pro 10.0.26200).</b> Each one was read
/// from a real certificate on the development machine: either from the chain Windows builds for a signed
/// file (<c>Get-AuthenticodeSignature</c> + <c>X509Chain</c>), or from the local certificate stores. The file
/// or store is named next to each entry. None was typed from memory. Names were cross-checked against
/// Microsoft's documentation where it exists:
/// </para>
/// <list type="bullet">
/// <item>"Windows support for the Application Control for Business new CA handling logic"
/// (support.microsoft.com, article 0be5df55-f4d7-458a-808f-7949d6a80850): lists Microsoft Code Signing PCA 2010
/// → Microsoft Windows Code Signing PCA 2024, Microsoft Code Signing PCA 2011 → Microsoft Code Signing PCA
/// 2024, Windows Production PCA 2011 → Windows Production PCA 2023, and Microsoft Windows Third Party
/// Component CA 2012 → ... CA 2024, as the CAs that sign Microsoft and Windows components.</item>
/// <item>"Preparing the Windows ecosystem for next-generation code signing" (support.microsoft.com,
/// servicing/os/windows/docs/2026/08): Microsoft Windows Production PCA 2011 expires 2026-10-19 and Windows
/// signing moves to "Microsoft Windows Production PCA 2026".</item>
/// </list>
/// <para>
/// <b>Maintenance.</b> The same Microsoft article warns against pinning Microsoft intermediates, because
/// they rotate (RSA-3072/SHA-384 CAs are announced for late 2026, post-quantum for 2027). Pinning is
/// deliberate here, and it fails safe: a file signed by a new Microsoft CA that isn't listed yet is
/// classified OtherTrusted, which still gets YARA and heuristics (only VirusTotal is skipped). It never
/// becomes Microsoft by accident. Add a new CA only after verifying it the same way.
/// </para>
/// <para>
/// <b>Deliberately left out</b> (so they classify as OtherTrusted):
/// </para>
/// <list type="bullet">
/// <item>Legacy roots "Microsoft Root Authority" (1997, SHA-1 A43489159A520F0D93D032CCAF37E7FE20A8B419) and
/// "Microsoft Root Certificate Authority" (2001, SHA-1 CDD4EEAE6000AC7F40C3802C171E30148030C072), both in
/// LocalMachine\Root and both expired. Old DirectX/VC++ redistributables in SysWOW64 chain to them through
/// "Microsoft Code Signing PCA" (2006/2007/2010 versions). They are MD5/SHA-1-era, and the 1997 root also
/// issued the old WHQL CA and the "Enforced Licensing" CAs abused by Flame. Such files still verify, as OtherTrusted.</item>
/// <item>"Microsoft Windows Phone Production PCA 2012" (SHA-1 194948ACF43F9B834CE154A8C2783BBF295FE2B9, seen on
/// Windows Kits\10\bin\...\DeployUtil.exe): first-party but only for the retired Windows Phone platform.</item>
/// <item>"Microsoft ECC Product Root Certificate Authority 2018" and "Microsoft RSA Root Certificate Authority
/// 2017" (in LocalMachine\Root): no first-party code-signing chain to them was found on this machine.</item>
/// <item>CAs named in Microsoft documentation but not present on this machine, so not verifiable here:
/// "Microsoft Windows PCA 2010", "Microsoft Windows Component Preproduction CA 2024" (pre-production), and
/// "Microsoft Windows Third Party Component CA 2024". (The last would be OtherTrusted anyway: anything not
/// on the allowlist is.)</item>
/// <item>The "Microsoft ID Verified CS EOC/AOC CA 01/02" intermediates of Trusted/Artifact Signing: none was
/// found in the stores or on any signed file on this machine, so their thumbprints are not listed. They
/// need no listing: their root, "Microsoft Identity Verification Root Certificate Authority 2020", is not a
/// product root, so the whole chain is OtherTrusted.</item>
/// </list>
/// </remarks>
public static class MicrosoftCodeSigningCertificates
{
    // ---------------------------------------------------------------------------------------------
    // Microsoft product roots. A Microsoft classification requires the chain to END in one of these.
    // ---------------------------------------------------------------------------------------------

    /// <summary>"Microsoft Root Certificate Authority 2010" (valid 2010-06-24 .. 2035-06-24).</summary>
    public static readonly KnownCertificate RootCa2010 = new(
        "Microsoft Root Certificate Authority 2010",
        "3B1EFD3A66EA28B16697394703A72CA340A05BD5",
        "DF545BF919A2439C36983B54CDFC903DFA4F37D3996D8D84B4C31EEC6F3C163E",
        "LocalMachine\\Root; root of the catalog chain of C:\\Windows\\System32\\kernel32.dll, cmd.exe, notepad.exe");

    /// <summary>"Microsoft Root Certificate Authority 2011" (valid 2011-03-23 .. 2036-03-23).</summary>
    public static readonly KnownCertificate RootCa2011 = new(
        "Microsoft Root Certificate Authority 2011",
        "8F43288AD272F3103B6FB1428485EA3014C0BCFE",
        "847DF6A78497943F27FC72EB93F9A637320A02B561D0A91B09E87A7807ED7C61",
        "LocalMachine\\Root; root of the embedded chain of C:\\Program Files\\dotnet\\dotnet.exe");

    // ---------------------------------------------------------------------------------------------
    // Microsoft first-party issuing CAs. The signing certificate must be issued DIRECTLY by one of
    // these, and that CA must be directly under the root given here (a 3-certificate chain).
    // ---------------------------------------------------------------------------------------------

    /// <summary>"Microsoft Windows Production PCA 2011": Windows OS files (catalog "Microsoft Windows" signer).</summary>
    public static readonly KnownCertificate WindowsProductionPca2011 = new(
        "Microsoft Windows Production PCA 2011",
        "580A6F4CC4E4B669B9EBDC1B2B3E087B80D0678D",
        "E8E95F0733A55E8BAD7BE0A1413EE23C51FCEA64B3C8FA6A786935FDDCC71961",
        "Catalog chain of C:\\Windows\\System32\\notepad.exe (issuer: Root CA 2010); MS doc 0be5df55 (\"Windows Production PCA 2011\")");

    /// <summary>"Microsoft Windows Production PCA 2026 RSA2048-SHA256": successor of PCA 2011 for Windows OS files.</summary>
    public static readonly KnownCertificate WindowsProductionPca2026 = new(
        "Microsoft Windows Production PCA 2026 RSA2048-SHA256",
        "5729E4C3DD4DB546929CA8760097E5FA49896AB5",
        "3727F477EFF0FDE6C1707EAEC91575888CCD9F429F9810E44DB39552C8C7E78D",
        "Catalog chain of C:\\Windows\\System32\\kernel32.dll, cmd.exe, ntoskrnl.exe (issuer: Root CA 2010); CurrentUser\\CA; "
        + "MS doc \"next-generation code signing\" (2026/08)");

    /// <summary>"Windows Production PCA 2023": Windows components (e.g. Defender driver), successor of PCA 2011.</summary>
    public static readonly KnownCertificate WindowsProductionPca2023 = new(
        "Windows Production PCA 2023",
        "15FF765C4DB07CDCEDDD86F992C072F1E6988649",
        "4F771E28419476AF6791F116F65E963812EE85F841A8184E85F592BA3D51A4BF",
        "Embedded chain of C:\\Windows\\System32\\drivers\\wd\\KslD.sys (issuer: Root CA 2010); MS doc 0be5df55");

    /// <summary>"Microsoft Windows Code Signing PCA 2024": successor of Microsoft Code Signing PCA 2010.</summary>
    public static readonly KnownCertificate WindowsCodeSigningPca2024 = new(
        "Microsoft Windows Code Signing PCA 2024",
        "D30F05F637E605239C0070D1EA9860D434AC2A94",
        "FE229EFC927F6D77B738896752A21803A59736BAA17BF5BE9A50C72E219CBCD2",
        "Embedded chain of C:\\Program Files (x86)\\Application Verifier\\vrfauto.dll (issuer: Root CA 2010); CurrentUser\\CA; MS doc 0be5df55");

    /// <summary>"Microsoft Code Signing PCA 2010": Microsoft products (e.g. Visual Studio components). Expired 2025-07-06; timestamped files still verify.</summary>
    public static readonly KnownCertificate CodeSigningPca2010 = new(
        "Microsoft Code Signing PCA 2010",
        "8BFE3107712B3C886B1C96AAEC89984914DC9B6B",
        "9AAD6C1A83A1B974BA574A995AF35B8CA772DA919270DB1605A8B81E1BBC896F",
        "Embedded chain of ~\\.nuget\\packages\\microsoft.codecoverage\\17.14.1\\...\\arm64\\msdia140.dll (issuer: Root CA 2010); MS doc 0be5df55");

    /// <summary>"Microsoft Code Signing PCA 2011": Microsoft products (.NET, Visual Studio, Office). Expires 2026-07-09; timestamped files still verify.</summary>
    public static readonly KnownCertificate CodeSigningPca2011 = new(
        "Microsoft Code Signing PCA 2011",
        "F252E794FE438E35ACE6E53762C0A234A2C52135",
        "56DA8722AFD94066FFE1E4595473A4854892B843A0827D53FB7D8F4AEED1E18B",
        "Embedded chain of C:\\Program Files\\dotnet\\dotnet.exe and System.Private.CoreLib.dll 10.0.3 (issuer: Root CA 2011); MS doc 0be5df55");

    /// <summary>"Microsoft Code Signing PCA 2024": successor of Microsoft Code Signing PCA 2011.</summary>
    public static readonly KnownCertificate CodeSigningPca2024 = new(
        "Microsoft Code Signing PCA 2024",
        "5039C8DC9ACE1CE039587E43486DE073FA459222",
        "3DADFAF812DD1BBAEF45834CCBD188F3CD97139E2ED1ACA69C2DD63082142F8F",
        "Embedded chain of ~\\.nuget\\packages\\microsoft.extensions.configuration\\10.0.13\\lib\\net10.0\\Microsoft.Extensions.Configuration.dll "
        + "(issuer: Root CA 2011); MS doc 0be5df55");

    // ---------------------------------------------------------------------------------------------
    // Microsoft-operated CAs that sign THIRD-PARTY content. Never Microsoft, even under a product root.
    // Not needed for the decision (they're not on the allowlist); listed so the reason is explicit.
    // ---------------------------------------------------------------------------------------------

    /// <summary>"Microsoft Windows Third Party Component CA 2012": WHQL / attestation-signed third-party drivers.</summary>
    public static readonly KnownCertificate ThirdPartyComponentCa2012 = new(
        "Microsoft Windows Third Party Component CA 2012",
        "77A10EBF07542725218CD83A01B521C57BC67F73",
        "9D08973E4D108DA40A1A0B274180E17371134B4DD1621FA5C1F131B739B4B823",
        "Chain of DriverStore\\FileRepository\\a-volutenhapo4swc.inf_*\\A-VoluteNhApo4Swc.cat, leaf \"Microsoft Windows Hardware "
        + "Compatibility Publisher\" (issuer: Root CA 2010); CurrentUser\\CA");

    /// <summary>"Microsoft Windows Third Party Component CA 2013": "Microsoft Windows Software Compatibility Publisher".</summary>
    public static readonly KnownCertificate ThirdPartyComponentCa2013 = new(
        "Microsoft Windows Third Party Component CA 2013",
        "2F5540201B5799E6A3E2131C3D05753D23879FE0",
        "8EF01BB5E07987053659E039E5A72580C88C444BC1A31AB412CE81A4AD53044E",
        "Embedded chain of C:\\Windows\\SysWOW64\\concrt140.dll (issuer: Root CA 2011)");

    /// <summary>"Microsoft Windows Third Party Component CA 2014": WHQL-signed third-party content.</summary>
    public static readonly KnownCertificate ThirdPartyComponentCa2014 = new(
        "Microsoft Windows Third Party Component CA 2014",
        "1906DCF62629B563252C826FDD874EFCEB6856C6",
        "A0F259A07039908EEB943E223FDF996E5E1E131D9AA6A602FF4672F7B9298AEE",
        "Catalog chain of Windows Kits\\10\\App Certification Kit\\msvcp110.dll (issuer: Root CA 2010)");

    /// <summary>"Microsoft MarketPlace PCA 2011": Store/Marketplace-signed apps (any publisher).</summary>
    public static readonly KnownCertificate MarketplacePca2011 = new(
        "Microsoft MarketPlace PCA 2011",
        "EB9204785126C26ADADCBBD44FE2B0C642A71078",
        "5A9D217E71180301A044E4CFBDE431FDF4C1CFC998B1B6343B5A10AA9E4CDE98",
        "Chain of %LOCALAPPDATA%\\Programs\\Microsoft VS Code\\...\\appx\\code_x64.appx (issuer: Root CA 2011)");

    /// <summary>"Microsoft Marketplace Production CA 2011" (2021 issue): issuing CA under MarketPlace PCA 2011.</summary>
    public static readonly KnownCertificate MarketplaceProductionCa2011 = new(
        "Microsoft Marketplace Production CA 2011",
        "E3795F7A0834111DCFF415E3371716AEFB0DAA54",
        "CA92943AB468CBB9604A97F909AE31C04577F5ADCBF7565F40C5837A072A5FE4",
        "Chain of %LOCALAPPDATA%\\Programs\\Microsoft VS Code\\...\\appx\\code_x64.appx");

    /// <summary>"Microsoft Marketplace Production CA 2011" (2011 issue).</summary>
    public static readonly KnownCertificate MarketplaceProductionCa2011Legacy = new(
        "Microsoft Marketplace Production CA 2011",
        "78195F6AED9521F9309362BE128003EA1674E5C7",
        "8E8A92EA4BCA5E3CE34B39BB1E5FDA1A76D14D7D513CB8900D193BEC11F79238",
        "Chain of Windows Kits\\10\\App Certification Kit\\winmds\\windowsKinect2\\WindowsPreview.Data.winmd");

    /// <summary>
    /// "Microsoft Identity Verification Root Certificate Authority 2020": root of Trusted/Artifact Signing
    /// ("Microsoft ID Verified CS ..." intermediates), which signs files for any verified customer.
    /// </summary>
    public static readonly KnownCertificate IdentityVerificationRoot2020 = new(
        "Microsoft Identity Verification Root Certificate Authority 2020",
        "F40042E2E5F7E8EF8189FED15519AECE42C3BFA2",
        "5367F20C7ADE0E2BCA790915056D086B720C33C1FA2A2661ACF787E3292E1270",
        "LocalMachine\\Root and LocalMachine\\AuthRoot");

    /// <summary>Roots a Microsoft chain must end in.</summary>
    public static IReadOnlyList<KnownCertificate> ProductRoots { get; } = [RootCa2010, RootCa2011];

    /// <summary>The first-party issuing CAs, each with the root it must be directly under.</summary>
    public static IReadOnlyList<FirstPartyIssuingCa> FirstPartyIssuingCas { get; } =
    [
        new(WindowsProductionPca2011, RootCa2010),
        new(WindowsProductionPca2026, RootCa2010),
        new(WindowsProductionPca2023, RootCa2010),
        new(WindowsCodeSigningPca2024, RootCa2010),
        new(CodeSigningPca2010, RootCa2010),
        new(CodeSigningPca2011, RootCa2011),
        new(CodeSigningPca2024, RootCa2011),
    ];

    /// <summary>
    /// Microsoft-operated CAs and roots that sign third-party content: WHQL/attestation, Marketplace/Store,
    /// Identity Verification. Any of these anywhere in a chain means OtherTrusted.
    /// </summary>
    public static IReadOnlyList<KnownCertificate> ThirdPartyContentCas { get; } =
    [
        ThirdPartyComponentCa2012,
        ThirdPartyComponentCa2013,
        ThirdPartyComponentCa2014,
        MarketplacePca2011,
        MarketplaceProductionCa2011,
        MarketplaceProductionCa2011Legacy,
        IdentityVerificationRoot2020,
    ];
}
