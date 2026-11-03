using System.Text;
using SapAV.Core.Tests.TestSupport;
using SapAV.Core.VirusTotal;

namespace SapAV.Core.Tests.VirusTotal;

public sealed class VirusTotalKeyStoreTests
{
    [Fact]
    public void Key_RoundTripsThroughDpapi_IsNotStoredInPlaintext_AndClears()
    {
        using var dir = new TempDirectory();
        var store = new VirusTotalKeyStore(dir.Path);
        Assert.False(store.HasKey);

        Assert.Equal(SetKeyResult.Saved, store.Set(Vt.FakeKey));

        var reopened = new VirusTotalKeyStore(dir.Path);
        Assert.True(reopened.HasKey);
        Assert.Equal(Vt.Key().Fingerprint, reopened.GetKey()!.Fingerprint);
        var blob = File.ReadAllBytes(dir.File(VirusTotalKeyStore.FileName));
        Assert.True(blob.AsSpan().IndexOf(Encoding.UTF8.GetBytes(Vt.FakeKey)) < 0);
        Assert.True(blob.AsSpan().IndexOf(Encoding.Unicode.GetBytes(Vt.FakeKey)) < 0);

        Assert.True(reopened.Clear());

        Assert.False(reopened.HasKey);
        Assert.False(new VirusTotalKeyStore(dir.Path).HasKey);
        Assert.False(File.Exists(dir.File(VirusTotalKeyStore.FileName)));
    }

    [Fact]
    public void InvalidKey_IsRefused_AndNothingIsWritten()
    {
        using var dir = new TempDirectory();
        var store = new VirusTotalKeyStore(dir.Path);

        Assert.Equal(SetKeyResult.InvalidFormat, store.Set("bad key\r\nX-Injected: 1"));
        Assert.Equal(SetKeyResult.InvalidFormat, store.Set(null));

        Assert.False(store.HasKey);
        Assert.Empty(Directory.EnumerateFileSystemEntries(dir.Path));
    }

    public static TheoryData<string, byte[]> BadBlobs() => new()
    {
        { "random bytes", [1, 2, 3, 4, 5, 6, 7, 8] },
        { "empty", [] },
        { "oversized", new byte[100_000] },
        { "other purpose", MachineDpapi.Protect(Encoding.UTF8.GetBytes(Vt.FakeKey), Encoding.UTF8.GetBytes("some other purpose")) },
        { "not a key inside", MachineDpapi.Protect(Encoding.UTF8.GetBytes("not a key\n"), Encoding.UTF8.GetBytes("sap-AV VirusTotal API key v1")) },
    };

    [Theory]
    [MemberData(nameof(BadBlobs))]
    public void CorruptBlob_IsNoKey_WithoutThrowing(string what, byte[] blob)
    {
        using var dir = new TempDirectory();
        File.WriteAllBytes(dir.File(VirusTotalKeyStore.FileName), blob);

        var store = new VirusTotalKeyStore(dir.Path);

        Assert.False(store.HasKey, what);
        Assert.Null(store.GetKey());
        Assert.NotNull(store.LastProblem);
        Assert.DoesNotContain(Vt.FakeKey, store.LastProblem, StringComparison.Ordinal);
    }
}
