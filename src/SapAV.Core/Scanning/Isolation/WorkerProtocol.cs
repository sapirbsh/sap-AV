using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SapAV.Core.Scanning.Isolation;

/// <summary>A message from the other side of the worker pipe broke the protocol (framing, size, schema or content).</summary>
public sealed class WorkerProtocolException : Exception
{
    public WorkerProtocolException(string message)
        : base(message)
    {
    }

    public WorkerProtocolException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>Size and count caps of the broker/worker protocol (B5). Worker output above any cap is rejected.</summary>
public static class WorkerLimits
{
    /// <summary>Largest scan or probe request (engine to worker).</summary>
    public const int MaxRequestBytes = 16 * 1024;

    /// <summary>Largest rule package (rule files + blocklist, engine to worker). Only the engine sends these.</summary>
    public const int MaxRulesRequestBytes = 128 * 1024 * 1024;

    /// <summary>Largest response (worker to engine). The engine rejects anything bigger before parsing it.</summary>
    public const int MaxResponseBytes = 256 * 1024;

    /// <summary>JSON nesting limit for both directions.</summary>
    public const int MaxJsonDepth = 16;

    public const int MaxNotes = 32;
    public const int MaxNoteLength = 2048;
    public const int MaxDetections = 80;
    public const int MaxYaraMatches = 64;
    public const int MaxTags = 16;
    public const int MaxTagLength = 128;
    public const int MaxIdentifierLength = 256;
    public const int MaxChainLength = 16;
    public const int MaxFindings = 16;
    public const int MaxFindingScore = 1000;
    public const int MaxTextLength = 1024;
    public const int MaxPathLength = 2048;
    public const int MaxRuleErrors = 32;
    public const int MaxSecondaryTechniques = 16;
}

/// <summary>
/// Length-prefixed frames over the worker pipes: a 4-byte little-endian length, then that many bytes of UTF-8 JSON.
/// The length is checked against the reader's cap <b>before</b> anything is allocated or read.
/// </summary>
public static class WorkerFraming
{
    /// <summary>Writes one frame and flushes.</summary>
    /// <exception cref="WorkerProtocolException">The payload is empty or over <paramref name="maxBytes"/>.</exception>
    public static void Write(Stream stream, ReadOnlySpan<byte> payload, int maxBytes)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (payload.Length == 0 || payload.Length > maxBytes)
        {
            throw new WorkerProtocolException($"Frame of {payload.Length} bytes is outside 1..{maxBytes}.");
        }

        Span<byte> header = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
        stream.Write(header);
        stream.Write(payload);
        stream.Flush();
    }

    /// <summary>
    /// Reads one frame. Returns null if the pipe closed cleanly before a new frame started (the other side exited).
    /// </summary>
    /// <exception cref="WorkerProtocolException">A length of 0, over <paramref name="maxBytes"/>, or a frame cut short.</exception>
    public static byte[]? Read(Stream stream, int maxBytes)
    {
        ArgumentNullException.ThrowIfNull(stream);
        Span<byte> header = stackalloc byte[4];
        int got = ReadAtMost(stream, header);
        if (got == 0)
        {
            return null;
        }

        if (got < header.Length)
        {
            throw new WorkerProtocolException("The pipe closed inside a frame header.");
        }

        int length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > maxBytes)
        {
            throw new WorkerProtocolException($"Frame length {length} is outside 1..{maxBytes}.");
        }

        var payload = new byte[length];
        if (ReadAtMost(stream, payload) != length)
        {
            throw new WorkerProtocolException($"The pipe closed inside a {length}-byte frame.");
        }

        return payload;
    }

    private static int ReadAtMost(Stream stream, Span<byte> buffer)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = stream.Read(buffer[total..]);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total;
    }
}

/// <summary>The strict JSON rules of the worker protocol (same spirit as the pipe and quarantine models).</summary>
/// <remarks>
/// Unknown properties, duplicate properties, comments, trailing commas, numbers as strings and nesting past
/// <see cref="WorkerLimits.MaxJsonDepth"/> are errors. Every message property is <c>required</c> (it must be present,
/// even when null), non-nullable references must not be null, and enums are read strictly by name.
/// </remarks>
public static class WorkerJson
{
    public static JsonSerializerOptions Options { get; } = new()
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        AllowDuplicateProperties = false,
        RespectNullableAnnotations = true,
        RespectRequiredConstructorParameters = true,
        MaxDepth = WorkerLimits.MaxJsonDepth,
        AllowTrailingCommas = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        NumberHandling = JsonNumberHandling.Strict,
        PropertyNameCaseInsensitive = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    /// <summary>Serializes <paramref name="value"/>; fails if the result is over <paramref name="maxBytes"/>.</summary>
    /// <exception cref="WorkerProtocolException">Too large.</exception>
    public static byte[] Serialize<T>(T value, int maxBytes)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, Options);
        if (bytes.Length > maxBytes)
        {
            throw new WorkerProtocolException($"{typeof(T).Name} is {bytes.Length} bytes, over the {maxBytes}-byte cap.");
        }

        return bytes;
    }

    /// <summary>Deserializes strictly; every failure (schema, enum, null, model validation) is a protocol error.</summary>
    /// <exception cref="WorkerProtocolException">Not a valid <typeparamref name="T"/>.</exception>
    public static T Deserialize<T>(byte[] payload)
        where T : class
    {
        ArgumentNullException.ThrowIfNull(payload);
        try
        {
            return JsonSerializer.Deserialize<T>(payload, Options)
                ?? throw new WorkerProtocolException($"{typeof(T).Name} is JSON null.");
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException or InvalidOperationException or NotSupportedException or FormatException)
        {
            throw new WorkerProtocolException($"Invalid {typeof(T).Name}: {ex.GetType().Name}: {ex.Message}", ex);
        }
    }
}
