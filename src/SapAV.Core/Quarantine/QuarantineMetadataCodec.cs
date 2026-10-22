using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SapAV.Core.Quarantine;

/// <summary>Why metadata was refused.</summary>
public enum QuarantineMetadataError
{
    /// <summary>Not a well-formed envelope (too large, bad JSON, wrong format name or version).</summary>
    Malformed,

    /// <summary>The HMAC doesn't match: the file was changed, or belongs to another item ID.</summary>
    Tampered,

    /// <summary>The HMAC matches but the content is invalid (should never happen for files this code wrote).</summary>
    Invalid,
}

/// <summary>Metadata that failed to load. The item must not be restored.</summary>
public sealed class QuarantineMetadataException(QuarantineMetadataError error, string message, Exception? inner = null)
    : Exception(message, inner)
{
    public QuarantineMetadataError Error { get; } = error;
}

/// <summary>
/// The signed metadata file format. The file is a small JSON envelope:
/// <code>{"format":"sap-AV-quarantine-metadata","version":1,"payload":"&lt;base64 UTF-8 JSON&gt;","hmac":"&lt;hex&gt;"}</code>
/// where <c>hmac</c> = HMAC-SHA256(key, "sap-AV quarantine metadata v1\n" + itemId + "\n" + payloadBytes).
/// </summary>
/// <remarks>
/// The HMAC covers the exact payload bytes (base64 keeps them byte-exact, so there is no JSON canonicalisation
/// question) and the item ID (so a valid metadata file renamed onto another item is refused). It is checked, in
/// constant time, <b>before</b> the payload is parsed; then the payload is parsed strictly (unknown members are
/// errors) and <see cref="QuarantineMetadata.Validate"/> runs.
/// </remarks>
public static class QuarantineMetadataCodec
{
    public const string FormatName = "sap-AV-quarantine-metadata";
    public const int FormatVersion = 1;

    /// <summary>Largest metadata file read.</summary>
    public const int MaxFileBytes = 1024 * 1024;

    /// <summary>Shortest HMAC key accepted.</summary>
    public const int MinKeyBytes = 32;

    private static readonly byte[] Domain = Encoding.UTF8.GetBytes("sap-AV quarantine metadata v1\n");

    private static readonly JsonSerializerOptions PayloadOptions = new()
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        MaxDepth = 8,
        WriteIndented = false,
    };

    /// <summary>Serialises and signs <paramref name="metadata"/> (validated first).</summary>
    /// <exception cref="InvalidDataException">The metadata is invalid.</exception>
    /// <exception cref="ArgumentException">The key is too short.</exception>
    public static byte[] Encode(QuarantineMetadata metadata, ReadOnlySpan<byte> key)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        EnsureKey(key);
        metadata.Validate();
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(metadata, PayloadOptions);
        var envelope = new Envelope(FormatName, FormatVersion, Convert.ToBase64String(payload),
            Convert.ToHexStringLower(Mac(key, metadata.Id, payload)));
        return JsonSerializer.SerializeToUtf8Bytes(envelope, PayloadOptions);
    }

    /// <summary>Verifies and parses a metadata file that must belong to <paramref name="expectedId"/>.</summary>
    /// <exception cref="QuarantineMetadataException">Malformed, tampered (HMAC) or invalid.</exception>
    public static QuarantineMetadata Decode(ReadOnlySpan<byte> file, string expectedId, ReadOnlySpan<byte> key)
    {
        EnsureKey(key);
        if (!QuarantineItemId.IsValid(expectedId))
        {
            throw new QuarantineMetadataException(QuarantineMetadataError.Malformed, "Invalid item ID.");
        }

        if (file.Length is 0 or > MaxFileBytes)
        {
            throw new QuarantineMetadataException(QuarantineMetadataError.Malformed, $"Metadata file size {file.Length} is out of range.");
        }

        Envelope envelope;
        byte[] payload, mac;
        try
        {
            envelope = JsonSerializer.Deserialize<Envelope>(file, PayloadOptions)
                ?? throw new JsonException("null envelope");
            if (envelope.Format != FormatName || envelope.Version != FormatVersion || envelope.Payload is null || envelope.Hmac is null)
            {
                throw new JsonException("Unknown envelope format or version.");
            }

            payload = Convert.FromBase64String(envelope.Payload);
            mac = Convert.FromHexString(envelope.Hmac);
        }
        catch (Exception ex) when (ex is JsonException or FormatException or NotSupportedException)
        {
            throw new QuarantineMetadataException(QuarantineMetadataError.Malformed, $"Malformed metadata envelope: {ex.Message}", ex);
        }

        if (!CryptographicOperations.FixedTimeEquals(mac, Mac(key, expectedId, payload)))
        {
            throw new QuarantineMetadataException(QuarantineMetadataError.Tampered,
                "The metadata HMAC does not match: the file was modified or belongs to another item.");
        }

        try
        {
            var metadata = JsonSerializer.Deserialize<QuarantineMetadata>(payload, PayloadOptions)
                ?? throw new JsonException("null metadata");
            metadata.Validate();
            if (metadata.Id != expectedId)
            {
                throw new InvalidDataException("The metadata ID does not match its file name.");
            }

            return metadata;
        }
        catch (Exception ex) when (ex is JsonException or InvalidDataException or ArgumentException or NotSupportedException)
        {
            throw new QuarantineMetadataException(QuarantineMetadataError.Invalid, $"Invalid metadata: {ex.Message}", ex);
        }
    }

    private static byte[] Mac(ReadOnlySpan<byte> key, string id, byte[] payload)
    {
        byte[] idBytes = Encoding.ASCII.GetBytes(id + "\n");
        var message = new byte[Domain.Length + idBytes.Length + payload.Length];
        Domain.CopyTo(message, 0);
        idBytes.CopyTo(message, Domain.Length);
        payload.CopyTo(message, Domain.Length + idBytes.Length);
        return HMACSHA256.HashData(key, message);
    }

    private static void EnsureKey(ReadOnlySpan<byte> key)
    {
        if (key.Length < MinKeyBytes)
        {
            throw new ArgumentException($"The HMAC key must be at least {MinKeyBytes} bytes.", nameof(key));
        }
    }

    private sealed record Envelope(
        [property: JsonPropertyName("format")] string Format,
        [property: JsonPropertyName("version")] int Version,
        [property: JsonPropertyName("payload")] string Payload,
        [property: JsonPropertyName("hmac")] string Hmac);
}
