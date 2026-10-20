using SapAV.Core.Hashing;
using SapAV.Core.Signatures;
using SapAV.Core.Tests.TestSupport;
using Xunit.Abstractions;

namespace SapAV.Core.Tests.Signatures;

/// <summary>
/// WinVerifyTrust on real files: Windows catalog-signed binaries, embedded-signed .NET runtime DLLs, installed
/// third-party software, WHQL driver catalogs, and temp copies that are unsigned or tampered with. Only benign
/// signed files are used; tampered copies live in a temp folder.
/// </summary>
public sealed class AuthenticodeVerifierFileTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDirectory _dir = new();
    private readonly AuthenticodeVerifier _verifier = new();

    public void Dispose() => _dir.Dispose();

    private SignatureCheckResult Verify(string path)
    {
        var result = _verifier.Verify(path);
        output.WriteLine($"{path}: {result.Status} / {result.FailureReason} / {result.NotCheckedReason} / {result.Kind} / " +
            $"signer '{result.Signer?.CommonName}' / {result.Message}");
        return result;
    }

    // --- Microsoft, catalog ---

    [Fact]
    public void CatalogSignedWindowsBinary_IsMicrosoft_ViaCatalog()
    {
        var path = SignedSamples.RequireCatalogOnlyWindowsBinary(); // hard requirement

        var result = Verify(path);

        Assert.Equal(SignatureStatus.Microsoft, result.Status);
        Assert.Equal(SignatureKind.Catalog, result.Kind);
        Assert.Equal(SignatureFailureReason.None, result.FailureReason);
        Assert.Equal(0, result.TrustResult);
        Assert.NotNull(result.CatalogPath);
        Assert.EndsWith(".cat", result.CatalogPath, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(@"\CatRoot\", result.CatalogPath, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("Microsoft Windows", result.TrustedSignerName);
        Assert.Equal(3, result.Signer!.Chain.Count);
    }

    [RequiresFact(Requires.NotepadRegularFile)]
    public void Notepad_IsMicrosoft()
    {
        // The roadmap's example. On Windows 11 the inbox notepad.exe may be a stub or an app alias, so it is
        // checked only when it's a regular file here (see the requirement), and embedded or catalog is accepted.
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");

        var result = Verify(path);

        Assert.Equal(SignatureStatus.Microsoft, result.Status);
    }

    // --- Microsoft, embedded ---

    [RequiresFact(Requires.SignedDotNetRuntime)]
    public void EmbeddedSignedDotNetRuntimeDll_IsMicrosoft_Embedded_WithTimestamp()
    {
        var path = SignedSamples.RequireEmbeddedSignedMicrosoftDll();

        var result = Verify(path);

        Assert.Equal(SignatureStatus.Microsoft, result.Status);
        Assert.Equal(SignatureKind.Embedded, result.Kind);
        Assert.Null(result.CatalogPath);
        Assert.Equal(".NET", result.TrustedSignerName);

        // Microsoft timestamps its signatures, which is why they stay valid after the certificate expires.
        var signer = result.Signer!;
        Assert.NotNull(signer.Timestamp);
        Assert.InRange(signer.Timestamp!.Value.UtcDateTime, signer.Certificate.NotBeforeUtc, signer.Certificate.NotAfterUtc);
        Assert.Matches("^[0-9A-F]{40}$", signer.Thumbprint);
        Assert.Contains("Microsoft", signer.Issuer);
    }

    [RequiresFact(Requires.SignedDotNetRuntime)]
    public void TheVerifiedChain_IsTheSigningChain_LeafFirst()
    {
        var path = SignedSamples.RequireEmbeddedSignedMicrosoftDll();

        var chain = Verify(path).Signer!.Chain;

        for (int i = 0; i < chain.Count - 1; i++)
        {
            Assert.Equal(chain[i + 1].Subject, chain[i].Issuer);
        }

        Assert.Equal(chain[^1].Subject, chain[^1].Issuer); // self-signed root last
    }

    // --- Third party ---

    [RequiresFact(Requires.ThirdPartySignedSoftware)]
    public void InstalledThirdPartySoftware_WithANonMicrosoftRoot_IsNeverMicrosoft()
    {
        int trustedThirdParty = 0;
        foreach (var path in SignedSamples.InstalledThirdPartyCandidates())
        {
            var result = _verifier.Verify(path);
            if (!result.IsTrusted)
            {
                continue;
            }

            var root = result.Signer.Chain[^1];
            if (SignedSamples.IsMicrosoftOperatedRoot(root))
            {
                continue; // a Microsoft-operated root; covered by other tests
            }

            trustedThirdParty++;
            if (trustedThirdParty <= 5)
            {
                output.WriteLine($"{path}: '{result.Signer.CommonName}' under '{root.CommonName}' -> {result.Status}");
            }

            Assert.True(result.Status == SignatureStatus.OtherTrusted, $"{path} classified {result.Status}");
        }

        // The requirement probe found at least one, so finding none now is a real failure.
        Assert.True(trustedThirdParty > 0, "no trusted third-party signed executable found, although the requirement probe found one");
        output.WriteLine($"{trustedThirdParty} third-party signed files, all OtherTrusted.");
    }

    [RequiresFact(Requires.WhqlDriverCatalog)]
    public void WhqlSignedDriverCatalog_IsOtherTrusted()
    {
        // Third-party drivers signed through Microsoft's hardware program chain to Microsoft Root 2010, but
        // they are not Microsoft code.
        var cat = SignedSamples.WhqlDriverCatalog()
            ?? throw new Xunit.Sdk.XunitException("no WHQL catalog, although the requirement probe found one");

        var result = _verifier.Verify(cat);

        Assert.True(result.IsTrusted, $"{cat}: {result.FailureReason} {result.Message}");
        Assert.Equal("Microsoft Windows Hardware Compatibility Publisher", result.Signer.CommonName);
        output.WriteLine($"{cat}: issued by '{result.Signer.Chain[1].CommonName}' -> {result.Status}: {result.Message}");
        Assert.Equal(SignatureStatus.OtherTrusted, result.Status);
    }

    // --- Unsigned ---

    [Fact]
    public void TempUnsignedTextFile_IsUnsignedOrInvalid_NotSigned()
    {
        var path = _dir.WriteFile("unsigned.txt", "just some text, never signed"u8.ToArray());

        var result = Verify(path);

        Assert.True(result.IsChecked);
        Assert.Equal(SignatureStatus.UnsignedOrInvalid, result.Status);
        Assert.Equal(SignatureFailureReason.NotSigned, result.FailureReason);
        Assert.Equal(SignatureKind.None, result.Kind);
        Assert.Null(result.Signer);
        Assert.Null(result.TrustedSignerName);
        Assert.False(result.HasBrokenSignature);
    }

    [RequiresFact(Requires.SignedDotNetRuntime)]
    public void TempUnsignedPe_SignatureStripped_IsNotSigned()
    {
        var source = SignedSamples.RequireEmbeddedSignedMicrosoftDll();

        var path = _dir.WriteFile("stripped.dll", PeImage.StripSignature(File.ReadAllBytes(source)));

        var result = Verify(path);

        Assert.Equal(SignatureStatus.UnsignedOrInvalid, result.Status);
        Assert.Equal(SignatureFailureReason.NotSigned, result.FailureReason);
        Assert.False(result.HasBrokenSignature);
    }

    [Fact]
    public void EmptyTempFile_IsNotSigned()
    {
        var path = _dir.WriteFile("empty.exe", []);

        var result = Verify(path);

        Assert.Equal(SignatureStatus.UnsignedOrInvalid, result.Status);
        Assert.Equal(SignatureFailureReason.NotSigned, result.FailureReason);
    }

    // --- Lookalikes and scripts ---

    [Fact]
    public void UnsignedLookalike_NamedCmdExe_InATempSystem32Folder_IsNotSigned()
    {
        // The name and folder must not matter: only the bytes are checked (catalog lookup is by hash).
        var dir = Directory.CreateDirectory(Path.Combine(_dir.Path, "Windows", "System32")).FullName;
        var path = Path.Combine(dir, "cmd.exe");
        File.WriteAllBytes(path, [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]); // "MZ" stub, not a real program

        var result = Verify(path);

        Assert.True(result.IsChecked);
        Assert.Equal(SignatureStatus.UnsignedOrInvalid, result.Status);
        Assert.Equal(SignatureFailureReason.NotSigned, result.FailureReason);
        Assert.Equal(SignatureKind.None, result.Kind);
        Assert.Null(result.Signer);
        Assert.Null(result.TrustedSignerName);
        Assert.Null(result.CatalogPath);
    }

    [RequiresFact(Requires.SignedDotNetRuntime)]
    public void UnsignedRealPe_RenamedToCmdExe_IsNotSigned()
    {
        // A real but signature-stripped Microsoft PE, dressed up as cmd.exe.
        var source = SignedSamples.RequireEmbeddedSignedMicrosoftDll();

        var path = _dir.WriteFile("cmd.exe", PeImage.StripSignature(File.ReadAllBytes(source)));

        var result = Verify(path);

        Assert.Equal(SignatureStatus.UnsignedOrInvalid, result.Status);
        Assert.Equal(SignatureFailureReason.NotSigned, result.FailureReason);
        Assert.Null(result.TrustedSignerName);
    }

    [Theory]
    [InlineData("Write-Output 'hello from an unsigned test script'\r\n")]
    [InlineData("")]
    public void UnsignedPowerShellScript_IsNotSigned_WithoutException(string content)
    {
        var path = _dir.WriteFile("script.ps1", System.Text.Encoding.UTF8.GetBytes(content));

        var result = Verify(path); // must not throw (PowerShell SIP, or no SIP for the type)

        Assert.True(result.IsChecked, $"{result.NotCheckedReason}: {result.Message}");
        Assert.Equal(SignatureStatus.UnsignedOrInvalid, result.Status);
        Assert.Equal(SignatureFailureReason.NotSigned, result.FailureReason);
        Assert.Null(result.Signer);
    }

    [Fact]
    public void PowerShellScript_WithAGarbageSignatureBlock_IsNeverTrusted_AndDoesNotThrow()
    {
        var script = "Write-Output 'x'\r\n\r\n# SIG # Begin signature block\r\n# MIIFAKEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n# SIG # End signature block\r\n";
        var path = _dir.WriteFile("fake-signed.ps1", System.Text.Encoding.UTF8.GetBytes(script));

        var result = Verify(path);

        Assert.True(result.IsChecked, $"{result.NotCheckedReason}: {result.Message}");
        Assert.Equal(SignatureStatus.UnsignedOrInvalid, result.Status);
        Assert.False(result.IsTrusted);
        Assert.Null(result.TrustedSignerName);
    }

    // --- Tampered ---

    [RequiresFact(Requires.SignedDotNetRuntime)]
    public void SignedPeCopy_WithOneBodyByteFlipped_IsHashMismatch()
    {
        var source = SignedSamples.RequireEmbeddedSignedMicrosoftDll();

        var bytes = File.ReadAllBytes(source);
        int offset = PeImage.BodyByteOffset(bytes);
        Assert.True(offset < PeImage.SecurityDirectory(bytes)!.Value.Offset);
        bytes[offset] ^= 0x01;
        var path = _dir.WriteFile("tampered.dll", bytes);

        var result = Verify(path);

        Assert.Equal(SignatureStatus.UnsignedOrInvalid, result.Status);
        Assert.Equal(SignatureFailureReason.HashMismatch, result.FailureReason);
        Assert.Equal(SignatureKind.Embedded, result.Kind);
        Assert.Equal(unchecked((int)0x80096010), result.TrustResult); // TRUST_E_BAD_DIGEST
        Assert.True(result.HasBrokenSignature);
        Assert.Null(result.TrustedSignerName); // the claimed signer is not shown as "signed by"
    }

    [RequiresFact(Requires.SignedDotNetRuntime)]
    public void UntouchedCopy_OfTheSameDll_StillVerifies()
    {
        // Control for the tamper test: copying alone doesn't break the signature.
        var source = SignedSamples.RequireEmbeddedSignedMicrosoftDll();

        var path = _dir.WriteFile("copy.dll", File.ReadAllBytes(source));

        Assert.Equal(SignatureStatus.Microsoft, Verify(path).Status);
    }

    [Fact]
    public void CatalogSignedBinaryCopy_WithOneByteFlipped_IsNoLongerSigned()
    {
        // The catalog lists the original hash; a modified copy matches no catalog.
        var source = SignedSamples.RequireCatalogOnlyWindowsBinary(); // hard requirement

        var bytes = File.ReadAllBytes(source);
        bytes[PeImage.BodyByteOffset(bytes)] ^= 0x01;
        var path = _dir.WriteFile("tampered-catalog.exe", bytes);

        var result = Verify(path);

        Assert.Equal(SignatureStatus.UnsignedOrInvalid, result.Status);
        Assert.Equal(SignatureFailureReason.NotSigned, result.FailureReason);
    }

    [Fact]
    public void CatalogSignedBinaryCopy_Untouched_IsStillMicrosoft_ViaCatalog()
    {
        // The catalog vouches for the content, wherever the file is.
        var source = SignedSamples.RequireCatalogOnlyWindowsBinary(); // hard requirement

        var path = _dir.WriteFile("copy.exe", File.ReadAllBytes(source));

        var result = Verify(path);

        Assert.Equal(SignatureStatus.Microsoft, result.Status);
        Assert.Equal(SignatureKind.Catalog, result.Kind);
    }

    // --- Size limit ---

    [Fact]
    public void FileOverTheLimit_IsNotChecked_TooLarge()
    {
        var path = SignedSamples.RequireCatalogOnlyWindowsBinary(); // hard requirement

        var result = new AuthenticodeVerifier(maxSizeBytes: 1024).Verify(path);

        Assert.False(result.IsChecked);
        Assert.Null(result.Status);
        Assert.Equal(HashFailureReason.TooLarge, result.NotCheckedReason);
        Assert.Null(result.Signer);
    }

    [Fact]
    public void FileExactlyAtTheLimit_IsChecked()
    {
        var path = _dir.WriteFile("limit.txt", new byte[100]);

        var result = new AuthenticodeVerifier(maxSizeBytes: 100).Verify(path);

        Assert.True(result.IsChecked);
        Assert.Equal(SignatureFailureReason.NotSigned, result.FailureReason);
    }

    [Fact]
    public void DefaultLimit_IsTheHashersDefault()
    {
        Assert.Equal(Sha256Hasher.DefaultMaxSizeBytes, new AuthenticodeVerifier().MaxSizeBytes);
        Assert.Throws<ArgumentOutOfRangeException>(() => new AuthenticodeVerifier(-1));
    }

    // --- Concurrency ---

    [RequiresFact(Requires.SignedDotNetRuntime)]
    public async Task ParallelChecks_GiveTheSameResults()
    {
        var catalog = SignedSamples.RequireCatalogOnlyWindowsBinary(); // hard requirement
        var embedded = SignedSamples.RequireEmbeddedSignedMicrosoftDll();

        var unsigned = _dir.WriteFile("u.txt", [1, 2, 3]);

        var tasks = Enumerable.Range(0, 48).Select(i => Task.Run(() => (i % 3) switch
        {
            0 => (_verifier.Verify(catalog).Kind, SignatureKind.Catalog),
            1 => (_verifier.Verify(embedded).Kind, SignatureKind.Embedded),
            _ => (_verifier.Verify(unsigned).Kind, SignatureKind.None),
        }));

        foreach (var (actual, expected) in await Task.WhenAll(tasks))
        {
            Assert.Equal(expected, actual);
        }
    }
}
