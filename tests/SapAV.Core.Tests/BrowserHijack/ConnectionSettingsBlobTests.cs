using System.Buffers.Binary;
using System.Text;
using SapAV.Core.BrowserHijack;

namespace SapAV.Core.Tests.BrowserHijack;

/// <summary>E6: WinINet DefaultConnectionSettings / WinHTTP WinHttpSettings blobs parse with bounds checks and never throw.</summary>
public sealed class ConnectionSettingsBlobTests
{
    /// <summary>A blob: version, counter, flags, then length-prefixed ANSI strings.</summary>
    internal static byte[] Blob(uint version, uint flags, params string[] strings)
    {
        var bytes = new List<byte>();
        void Dword(uint value)
        {
            var buffer = new byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(buffer, value);
            bytes.AddRange(buffer);
        }

        Dword(version);
        Dword(7);
        Dword(flags);
        foreach (var s in strings)
        {
            Dword((uint)s.Length);
            bytes.AddRange(Encoding.Latin1.GetBytes(s));
        }

        return bytes.ToArray();
    }

    [Fact]
    public void WinHttp_ValidProxy_IsParsed()
    {
        var blob = ConnectionSettingsBlob.ParseWinHttp(Blob(0x28, 3, "10.6.6.6:3128", "<local>"));

        Assert.Equal(BlobParseStatus.Parsed, blob.Status);
        Assert.Equal(0x28u, blob.Version);
        Assert.Equal(7u, blob.Counter);
        Assert.True(blob.ProxyEnabled);
        Assert.Equal("10.6.6.6:3128", blob.ProxyServer);
        Assert.Equal("<local>", blob.ProxyBypass);
        Assert.Null(blob.AutoConfigUrl);
    }

    [Fact]
    public void WinInet_PacUrlAndFlags_AreParsed()
    {
        var blob = ConnectionSettingsBlob.ParseWinInet(Blob(0x46, 0x5, "", "", "http://evil.example/proxy.pac"));

        Assert.Equal(BlobParseStatus.Parsed, blob.Status);
        Assert.True(blob.AutoConfigEnabled);
        Assert.False(blob.ProxyEnabled);
        Assert.Equal("http://evil.example/proxy.pac", blob.AutoConfigUrl);
        Assert.Equal(ConnectionFlags.Direct | ConnectionFlags.AutoProxyUrl, blob.Flags);
    }

    [Fact]
    public void Truncated_KeepsWhatWasRead()
    {
        var full = Blob(0x28, 3, "10.6.6.6:3128", "<local>");
        var blob = ConnectionSettingsBlob.ParseWinHttp(full.AsSpan(0, 12 + 4 + 5));

        Assert.Equal(BlobParseStatus.Truncated, blob.Status);
        Assert.True(blob.ProxyEnabled);
        Assert.Equal("10.6.", blob.ProxyServer); // partial: what was there
        Assert.Null(blob.ProxyBypass);
    }

    [Theory]
    [InlineData(new byte[0])]
    [InlineData(new byte[] { 0x28, 0, 0, 0, 1 })]
    public void TooShortForTheHeader_IsMalformed(byte[] data)
    {
        var blob = ConnectionSettingsBlob.ParseWinHttp(data);

        Assert.Equal(BlobParseStatus.Malformed, blob.Status);
        Assert.Null(blob.RawFlags);
        Assert.Null(blob.ProxyEnabled); // unknown, not "no proxy"
    }

    [Fact]
    public void Garbage_ImpossibleLength_IsMalformed_AndRandomBytesNeverThrow()
    {
        var garbage = Blob(0x28, 2);
        garbage = [.. garbage, 0xFF, 0xFF, 0xFF, 0x7F, 0x41];
        Assert.Equal(BlobParseStatus.Malformed, ConnectionSettingsBlob.ParseWinHttp(garbage).Status);

        var random = new Random(6);
        for (int i = 0; i < 500; i++)
        {
            var bytes = new byte[random.Next(0, 64)];
            random.NextBytes(bytes);
            _ = ConnectionSettingsBlob.ParseWinInet(bytes);
            _ = ConnectionSettingsBlob.ParseWinHttp(bytes);
        }
    }

    [Fact]
    public void LongAndControlCharacterStrings_AreCappedAndSanitized()
    {
        var blob = ConnectionSettingsBlob.ParseWinHttp(Blob(0x28, 2, new string('a', 10_000),"x\r\ny\0"));

        Assert.Equal(BlobParseStatus.Parsed, blob.Status);
        Assert.True(blob.StringsTruncated);
        Assert.Equal(ConnectionSettingsBlob.MaxStringLength, blob.ProxyServer!.Length);
        Assert.Equal("x��y", blob.ProxyBypass); // trailing NUL dropped, line breaks can't forge a log line
    }
}
