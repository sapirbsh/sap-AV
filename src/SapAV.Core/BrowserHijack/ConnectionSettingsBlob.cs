using System.Buffers.Binary;
using System.Text;

namespace SapAV.Core.BrowserHijack;

/// <summary>How far a connection-settings blob parsed.</summary>
public enum BlobParseStatus
{
    /// <summary>Every expected field was read.</summary>
    Parsed,

    /// <summary>The blob ends inside a field (or a length runs past its end): the fields read so far are kept, the rest is unknown.</summary>
    Truncated,

    /// <summary>The blob is too short for its header, or a length field is impossible (garbage). Fields read so far are kept.</summary>
    Malformed,
}

/// <summary>The flags DWORD of a connection-settings blob (<c>INTERNET_PER_CONN_FLAGS</c>).</summary>
[Flags]
public enum ConnectionFlags : uint
{
    None = 0,

    /// <summary>PROXY_TYPE_DIRECT.</summary>
    Direct = 0x1,

    /// <summary>PROXY_TYPE_PROXY: use the proxy server.</summary>
    Proxy = 0x2,

    /// <summary>PROXY_TYPE_AUTO_PROXY_URL: use the PAC script URL.</summary>
    AutoProxyUrl = 0x4,

    /// <summary>PROXY_TYPE_AUTO_DETECT: WPAD.</summary>
    AutoDetect = 0x8,
}

/// <summary>
/// A WinINet <c>DefaultConnectionSettings</c> or WinHTTP <c>WinHttpSettings</c> registry blob (ROADMAP E6). Both start the
/// same way: DWORD version / size, DWORD change counter, DWORD flags, then length-prefixed ANSI strings (proxy server, bypass
/// list, and for WinINet the PAC URL). The format is undocumented, so the parser is defensive: every read is bounds-checked,
/// it never throws, and whatever was read before a problem is kept with the status saying where it stopped.
/// </summary>
/// <remarks>Strings are decoded as Latin-1 and kept raw (<see cref="Text.SafeText.Identifier"/>), capped at <see cref="MaxStringLength"/>.</remarks>
public sealed record ConnectionSettingsBlob
{
    public const int MaxStringLength = ProxySettings.MaxValueLength;

    /// <summary>A length field above this is garbage, not a truncated blob (real proxy strings are short).</summary>
    public const int MaxPlausibleLength = 1024 * 1024;

    private const int HeaderLength = 12;

    public required BlobParseStatus Status { get; init; }

    /// <summary>The blob's size in bytes.</summary>
    public required int Length { get; init; }

    /// <summary>The first DWORD (a version or structure size; varies by Windows build), or null when the blob is shorter.</summary>
    public uint? Version { get; init; }

    /// <summary>The change counter, or null.</summary>
    public uint? Counter { get; init; }

    /// <summary>The raw flags (unknown bits kept), or null when not read.</summary>
    public uint? RawFlags { get; init; }

    public string? ProxyServer { get; init; }

    public string? ProxyBypass { get; init; }

    /// <summary>The PAC URL (WinINet blobs only).</summary>
    public string? AutoConfigUrl { get; init; }

    /// <summary>True when a string was cut at <see cref="MaxStringLength"/>.</summary>
    public bool StringsTruncated { get; init; }

    public ConnectionFlags? Flags => RawFlags is { } raw ? (ConnectionFlags)raw : null;

    /// <summary>The proxy flag; null when the flags weren't read.</summary>
    public bool? ProxyEnabled => RawFlags is { } raw ? (raw & (uint)ConnectionFlags.Proxy) != 0 : null;

    /// <summary>The PAC-URL flag; null when the flags weren't read.</summary>
    public bool? AutoConfigEnabled => RawFlags is { } raw ? (raw & (uint)ConnectionFlags.AutoProxyUrl) != 0 : null;

    /// <summary>The WPAD flag; null when the flags weren't read.</summary>
    public bool? AutoDetectEnabled => RawFlags is { } raw ? (raw & (uint)ConnectionFlags.AutoDetect) != 0 : null;

    /// <summary>Parses a WinINet <c>DefaultConnectionSettings</c> blob (proxy, bypass, PAC URL). Never throws.</summary>
    public static ConnectionSettingsBlob ParseWinInet(ReadOnlySpan<byte> data) => Parse(data, stringCount: 3);

    /// <summary>Parses a WinHTTP <c>WinHttpSettings</c> blob (proxy, bypass). Never throws.</summary>
    public static ConnectionSettingsBlob ParseWinHttp(ReadOnlySpan<byte> data) => Parse(data, stringCount: 2);

    private static ConnectionSettingsBlob Parse(ReadOnlySpan<byte> data, int stringCount)
    {
        if (data.Length < HeaderLength)
        {
            return new ConnectionSettingsBlob
            {
                Status = BlobParseStatus.Malformed,
                Length = data.Length,
                Version = data.Length >= 4 ? BinaryPrimitives.ReadUInt32LittleEndian(data) : null,
                Counter = data.Length >= 8 ? BinaryPrimitives.ReadUInt32LittleEndian(data[4..]) : null,
            };
        }

        var strings = new string?[3];
        bool cut = false;
        var status = BlobParseStatus.Parsed;
        int offset = HeaderLength;
        for (int i = 0; i < stringCount; i++)
        {
            status = ReadString(data, ref offset, out strings[i], ref cut);
            if (status != BlobParseStatus.Parsed)
            {
                break;
            }
        }

        return new ConnectionSettingsBlob
        {
            Status = status,
            Length = data.Length,
            Version = BinaryPrimitives.ReadUInt32LittleEndian(data),
            Counter = BinaryPrimitives.ReadUInt32LittleEndian(data[4..]),
            RawFlags = BinaryPrimitives.ReadUInt32LittleEndian(data[8..]),
            ProxyServer = strings[0],
            ProxyBypass = strings[1],
            AutoConfigUrl = strings[2],
            StringsTruncated = cut,
        };
    }

    private static BlobParseStatus ReadString(ReadOnlySpan<byte> data, ref int offset, out string? value, ref bool cut)
    {
        value = null;
        if (data.Length - offset < 4)
        {
            return BlobParseStatus.Truncated;
        }

        uint length = BinaryPrimitives.ReadUInt32LittleEndian(data[offset..]);
        offset += 4;
        if (length > MaxPlausibleLength)
        {
            return BlobParseStatus.Malformed;
        }

        int available = Math.Min((int)length, data.Length - offset);
        value = Decode(data.Slice(offset, available), ref cut);
        if (available < length)
        {
            return BlobParseStatus.Truncated;
        }

        offset += available;
        return BlobParseStatus.Parsed;
    }

    private static string Decode(ReadOnlySpan<byte> bytes, ref bool cut)
    {
        if (bytes.Length > MaxStringLength)
        {
            bytes = bytes[..MaxStringLength];
            cut = true;
        }

        // Some writers include the terminating NUL in the length; it isn't part of the value.
        if (bytes.Length > 0 && bytes[^1] == 0)
        {
            bytes = bytes[..^1];
        }

        return Text.SafeText.Identifier(Encoding.Latin1.GetString(bytes));
    }
}
