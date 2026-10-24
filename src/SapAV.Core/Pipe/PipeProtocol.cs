using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace SapAV.Core.Pipe;

/// <summary>Constants of the engine pipe protocol (ROADMAP B4).</summary>
public static class PipeProtocol
{
    /// <summary>
    /// The engine's pipe, <c>\\.\pipe\ProtectedPrefix\Administrators\sap-AV.engine</c> (review B M5). The named-pipe file
    /// system lets only members of Administrators (elevated) and SYSTEM create pipes under
    /// <c>ProtectedPrefix\Administrators\</c>, so a standard user can't squat the name before the service starts; who may
    /// connect is still decided by the pipe's own DACL (every authenticated local user).
    /// </summary>
    public const string PipeName = @"ProtectedPrefix\Administrators\sap-AV.engine";

    /// <summary>
    /// The pipe of an engine run from a console <b>without</b> elevation (debugging only): it can't create
    /// <see cref="PipeName"/>, and gives nothing away that the user doesn't already have. Clients must ask for it explicitly
    /// (and turn off the SYSTEM-owner check).
    /// </summary>
    public const string DebugPipeName = "sap-AV.engine.debug";

    /// <summary>The only protocol version this build speaks.</summary>
    public const int Version = 1;

    /// <summary>Largest client request frame (the length is checked before anything is allocated).</summary>
    public const int MaxRequestBytes = 64 * 1024;

    /// <summary>Largest engine frame (replies are paged to stay under it).</summary>
    public const int MaxServerFrameBytes = 4 * 1024 * 1024;

    /// <summary>Most bytes an oversized request may declare and still be drained (so the connection survives).</summary>
    public const int MaxDrainBytes = 1024 * 1024;

    /// <summary>JSON nesting limit for both directions.</summary>
    public const int MaxDepth = 16;

    /// <summary>Most paths in one scan request.</summary>
    public const int MaxScanPaths = 32;

    /// <summary>Most results in one <see cref="PipeRequestKind.ScanGet"/> page.</summary>
    public const int MaxResultsPage = 200;
}

/// <summary>
/// The JSON settings both ends use. Strict on purpose (review A1): no options-level enum converter (the models'
/// <see cref="Serialization.StrictEnumConverter{T}"/> attributes apply: names only, exact case), duplicate properties
/// refused (so a second <c>"Status"</c> can't override the first), unknown members refused, required and non-nullable
/// members enforced, depth 16, no comments or trailing commas, numbers only as numbers.
/// </summary>
public static class PipeJson
{
    public static JsonSerializerOptions Options { get; } = Create();

    private static JsonSerializerOptions Create()
    {
        var options = new JsonSerializerOptions
        {
            AllowDuplicateProperties = false,
            MaxDepth = PipeProtocol.MaxDepth,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            RespectNullableAnnotations = true,
            RespectRequiredConstructorParameters = true,
            PropertyNameCaseInsensitive = false,
            NumberHandling = JsonNumberHandling.Strict,
            ReadCommentHandling = JsonCommentHandling.Disallow,
            AllowTrailingCommas = false,
            DefaultIgnoreCondition = JsonIgnoreCondition.Never,
            TypeInfoResolver = new DefaultJsonTypeInfoResolver(),
        };
        options.MakeReadOnly();
        return options;
    }

    /// <summary>Serializes to UTF-8, or throws <see cref="PipeProtocolException"/> if the result is over <paramref name="maxBytes"/>.</summary>
    public static byte[] Serialize<T>(T value, int maxBytes)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value, Options);
        if (bytes.Length > maxBytes)
        {
            throw new PipeProtocolException($"The message is {bytes.Length} bytes; the limit is {maxBytes}.");
        }

        return bytes;
    }

    /// <summary>
    /// Deserializes a message body. Throws <see cref="JsonException"/> for bad JSON and <see cref="ArgumentException"/> (or a
    /// subclass) when a model's own validation refuses a value; a missing body is a <see cref="JsonException"/>.
    /// </summary>
    public static T Body<T>(JsonElement? body)
    {
        if (body is not { ValueKind: JsonValueKind.Object } element)
        {
            throw new JsonException($"A {typeof(T).Name} body (a JSON object) is required.");
        }

        return element.Deserialize<T>(Options) ?? throw new JsonException($"A {typeof(T).Name} body is required.");
    }

    public static JsonElement ToElement<T>(T value) => JsonSerializer.SerializeToElement(value, Options);
}

/// <summary>A framing or size violation (the stream can't be trusted to be in sync any more, unless documented).</summary>
public sealed class PipeProtocolException(string message) : Exception(message);

/// <summary>
/// Frames: a 4-byte little-endian length, then that many bytes of UTF-8 JSON. The length is checked against the cap
/// before the buffer is allocated.
/// </summary>
public static class PipeFraming
{
    /// <summary>What <see cref="ReadAsync"/> found.</summary>
    public enum FrameStatus
    {
        Ok,

        /// <summary>The stream ended cleanly before a header.</summary>
        EndOfStream,

        /// <summary>The frame was over the cap but small enough to drain; it was skipped and the stream is still in sync.</summary>
        TooLargeDrained,
    }

    /// <summary>Writes one frame (header + payload) in a single write.</summary>
    public static async Task WriteAsync(Stream stream, ReadOnlyMemory<byte> payload, int maxBytes, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (payload.Length == 0 || payload.Length > maxBytes)
        {
            throw new PipeProtocolException($"A frame must be 1-{maxBytes} bytes; this one is {payload.Length}.");
        }

        var buffer = new byte[4 + payload.Length];
        BinaryPrimitives.WriteInt32LittleEndian(buffer, payload.Length);
        payload.CopyTo(buffer.AsMemory(4));
        await stream.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads the 4-byte header. Null at a clean end of stream.</summary>
    /// <exception cref="PipeProtocolException">The stream ended inside the header.</exception>
    public static async Task<int?> ReadHeaderAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        int read = await ReadAtMostAsync(stream, header, cancellationToken).ConfigureAwait(false);
        if (read == 0)
        {
            return null;
        }

        if (read < 4)
        {
            throw new PipeProtocolException("The stream ended inside a frame header.");
        }

        return BinaryPrimitives.ReadInt32LittleEndian(header);
    }

    /// <summary>
    /// Reads a frame body of <paramref name="length"/> bytes (from <see cref="ReadHeaderAsync"/>). A length over
    /// <paramref name="maxBytes"/> but within <paramref name="maxDrainBytes"/> is read into a small buffer and dropped
    /// (<see cref="FrameStatus.TooLargeDrained"/>, payload null).
    /// </summary>
    /// <exception cref="PipeProtocolException">Length 0, negative, over the drain limit, or the stream ended inside the body.</exception>
    public static async Task<(FrameStatus Status, byte[]? Payload)> ReadBodyAsync(
        Stream stream, int length, int maxBytes, int maxDrainBytes, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (length <= 0)
        {
            throw new PipeProtocolException($"Invalid frame length {length}.");
        }

        if (length > maxBytes)
        {
            if (length > maxDrainBytes)
            {
                throw new PipeProtocolException($"The frame is {length} bytes; the limit is {maxBytes}.");
            }

            var scratch = new byte[8192];
            int left = length;
            while (left > 0)
            {
                int read = await stream.ReadAsync(scratch.AsMemory(0, Math.Min(scratch.Length, left)), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    throw new PipeProtocolException("The stream ended inside a frame.");
                }

                left -= read;
            }

            return (FrameStatus.TooLargeDrained, null);
        }

        var payload = new byte[length];
        if (await ReadAtMostAsync(stream, payload, cancellationToken).ConfigureAwait(false) != length)
        {
            throw new PipeProtocolException("The stream ended inside a frame.");
        }

        return (FrameStatus.Ok, payload);
    }

    /// <summary>Header + body in one call (the client side, which has no separate timeouts).</summary>
    public static async Task<(FrameStatus Status, byte[]? Payload)> ReadAsync(Stream stream, int maxBytes, CancellationToken cancellationToken)
    {
        if (await ReadHeaderAsync(stream, cancellationToken).ConfigureAwait(false) is not { } length)
        {
            return (FrameStatus.EndOfStream, null);
        }

        return await ReadBodyAsync(stream, length, maxBytes, maxBytes, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<int> ReadAtMostAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer[total..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total;
    }
}
