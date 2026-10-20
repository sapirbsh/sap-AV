using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SapAV.Core.Hashing;
using SapAV.Core.Signatures;
using SapAV.Core.Tests.Hashing;
using SapAV.Core.Tests.TestSupport;
using Xunit.Abstractions;

namespace SapAV.Core.Tests.Signatures;

/// <summary>
/// Every path (embedded trusted, catalog trusted, not signed, hash mismatch, not checked) must close the file
/// handle, the WinVerifyTrust state (WTD_STATEACTION_CLOSE), the catalog context and the catalog admin
/// context. Checked by looping and watching <see cref="Process.HandleCount"/>, and by an exclusive open.
/// </summary>
[Collection(HandleCountCollection.Name)]
public sealed class AuthenticodeVerifierHandleLeakTests(ITestOutputHelper output) : IDisposable
{
    private const int AllowedGrowth = 60; // runtime/crypt32 noise; a leak of one handle per check would be >= the iterations

    private readonly TempDirectory _dir = new();
    private readonly AuthenticodeVerifier _verifier = new();

    public void Dispose() => _dir.Dispose();

    private static int HandleCount()
    {
        using var p = Process.GetCurrentProcess();
        return p.HandleCount;
    }

    private void AssertNoHandleGrowth(string path, Func<SignatureCheckResult, bool> expected, int iterations)
    {
        var first = _verifier.Verify(path);
        Assert.True(expected(first), $"{first.Status} {first.FailureReason} {first.NotCheckedReason}: {first.Message}");
        for (int i = 0; i < 30; i++)
        {
            _verifier.Verify(path); // warm up crypt32 caches, catalog database connection, JIT
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        int before = HandleCount();

        for (int i = 0; i < iterations; i++)
        {
            var r = _verifier.Verify(path);
            if (!expected(r))
            {
                Assert.Fail($"iteration {i}: {r.Status} {r.FailureReason} {r.NotCheckedReason}: {r.Message}");
            }
        }

        // No GC before reading: leaked SafeFileHandles must not be finalized away. (Native contexts have no
        // finalizer anyway, so a leak of those would show either way.)
        int after = HandleCount();
        output.WriteLine($"{Path.GetFileName(path)}: handles {before} -> {after} over {iterations} checks");
        Assert.True(after - before < AllowedGrowth, $"handle count grew by {after - before} over {iterations} checks");
    }

    /// <summary>Opens with no sharing: fails with a sharing violation if any handle to the path is still open.</summary>
    private static void AssertNoOtherHandleOpen(string path)
    {
        using var h = CreateFileW(path, 0x80000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
        Assert.False(h.IsInvalid, $"exclusive open failed (Win32 error {Marshal.GetLastPInvokeError()}): a handle is still open");
    }

    [Fact]
    public void CatalogTrusted_Loop_HandleCountStaysFlat()
    {
        var path = SignedSamples.RequireCatalogOnlyWindowsBinary(); // hard requirement

        AssertNoHandleGrowth(path, r => r.Status == SignatureStatus.Microsoft && r.Kind == SignatureKind.Catalog, 300);
    }

    [RequiresFact(Requires.SignedDotNetRuntime)]
    public void EmbeddedTrusted_Loop_HandleCountStaysFlat()
    {
        var source = SignedSamples.RequireEmbeddedSignedMicrosoftDll();

        var path = _dir.WriteFile("signed.dll", File.ReadAllBytes(source));
        AssertNoHandleGrowth(path, r => r.Status == SignatureStatus.Microsoft && r.Kind == SignatureKind.Embedded, 500);
        AssertNoOtherHandleOpen(path);
    }

    [Fact]
    public void NotSigned_Loop_HandleCountStaysFlat()
    {
        // Goes through the embedded check and both catalog lookups (SHA-256 and SHA-1), all finding nothing.
        var path = _dir.WriteFile("unsigned.exe", [0x4D, 0x5A, 1, 2, 3]);
        AssertNoHandleGrowth(path, r => r.FailureReason == SignatureFailureReason.NotSigned, 500);
        AssertNoOtherHandleOpen(path);
    }

    [RequiresFact(Requires.SignedDotNetRuntime)]
    public void HashMismatch_Loop_HandleCountStaysFlat()
    {
        var source = SignedSamples.RequireEmbeddedSignedMicrosoftDll();

        var bytes = File.ReadAllBytes(source);
        bytes[PeImage.BodyByteOffset(bytes)] ^= 0x01;
        var path = _dir.WriteFile("tampered.dll", bytes);
        AssertNoHandleGrowth(path, r => r.FailureReason == SignatureFailureReason.HashMismatch, 500);
        AssertNoOtherHandleOpen(path);
    }

    [Fact]
    public void NotChecked_TooLarge_Loop_HandleCountStaysFlat()
    {
        var path = _dir.WriteFile("big.bin", new byte[200]);
        var small = new AuthenticodeVerifier(maxSizeBytes: 100);
        Assert.Equal(HashFailureReason.TooLarge, small.Verify(path).NotCheckedReason);

        int before = HandleCount();
        for (int i = 0; i < 2000; i++)
        {
            small.Verify(path);
        }

        Assert.True(HandleCount() - before < AllowedGrowth);
        AssertNoOtherHandleOpen(path);
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
}
