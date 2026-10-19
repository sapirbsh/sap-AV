using System.Collections.Frozen;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SapAV.Core.Serialization;

/// <summary>
/// JSON converter that reads and writes an enum strictly by name.
/// </summary>
/// <remarks>
/// Reading accepts only a JSON string that exactly matches (ordinal, case-sensitive) one of
/// <see cref="Enum.GetNames{TEnum}"/>. Numbers (bare or quoted), lowercase, padded or comma-combined
/// names, null and any other token throw <see cref="JsonException"/>. This keeps pipe and Event Log
/// payloads independent of numeric enum order and stops undefined values from getting in.
/// Writing an undefined value also throws <see cref="JsonException"/> instead of emitting a number.
/// </remarks>
public sealed class StrictEnumConverter<T> : JsonConverter<T>
    where T : struct, Enum
{
    private static readonly FrozenDictionary<string, T> ByName =
        Enum.GetValues<T>().ToFrozenDictionary(v => Enum.GetName(v)!, StringComparer.Ordinal);

    public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.String)
        {
            throw new JsonException($"Expected a {typeof(T).Name} name as a JSON string, got {reader.TokenType}.");
        }

        var name = reader.GetString();
        if (name is null || !ByName.TryGetValue(name, out var value))
        {
            throw new JsonException($"'{name}' is not a valid {typeof(T).Name} name.");
        }

        return value;
    }

    public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
    {
        var name = Enum.IsDefined(value) ? Enum.GetName(value) : null;
        if (name is null)
        {
            throw new JsonException($"Cannot serialize undefined {typeof(T).Name} value '{value}'.");
        }

        writer.WriteStringValue(name);
    }
}
