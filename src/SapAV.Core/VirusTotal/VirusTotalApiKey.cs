using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace SapAV.Core.VirusTotal;

/// <summary>
/// An opaque VirusTotal API key. The plaintext is readable only inside SapAV.Core (the client puts it in the
/// <c>x-apikey</c> header); <see cref="ToString"/>, JSON serialization and equality never expose it, so a key handle can be
/// passed around, logged by accident or put in a status object without leaking.
/// </summary>
/// <remarks>
/// Format: 16-128 ASCII letters, digits, <c>-</c> or <c>_</c> (real VT keys are 64 lowercase hex). Anything else (spaces, CR/LF,
/// other characters) is refused, so a key can't inject a second header.
/// </remarks>
[JsonConverter(typeof(RefuseJsonConverter))]
public sealed class VirusTotalApiKey
{
    public const int MinLength = 16;
    public const int MaxLength = 128;

    /// <summary>Environment variable for a development key (the end-user key lives in <see cref="VirusTotalKeyStore"/>).</summary>
    public const string EnvironmentVariable = "SAPAV_VIRUSTOTAL_APIKEY";

    private VirusTotalApiKey(string value)
    {
        Value = value;
        Fingerprint = Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes("sap-AV VT key id v1\0" + value)))[..16];
    }

    /// <summary>The plaintext (header only).</summary>
    internal string Value { get; }

    /// <summary>A short one-way ID of the key (to notice that the key changed); safe to show or compare.</summary>
    public string Fingerprint { get; }

    /// <summary>True if <paramref name="value"/> has the key format (see the remarks on the class).</summary>
    public static bool IsValidFormat([NotNullWhen(true)] string? value)
    {
        if (value is null || value.Length is < MinLength or > MaxLength)
        {
            return false;
        }

        foreach (char c in value)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>A key from <paramref name="value"/> (trimmed), or null if it doesn't have the key format. Never throws.</summary>
    public static VirusTotalApiKey? TryCreate(string? value)
    {
        string? trimmed = value?.Trim();
        return IsValidFormat(trimmed) ? new VirusTotalApiKey(trimmed) : null;
    }

    /// <summary>The development key from <see cref="EnvironmentVariable"/>, or null if unset or malformed.</summary>
    public static VirusTotalApiKey? FromEnvironment() => TryCreate(Environment.GetEnvironmentVariable(EnvironmentVariable));

    /// <summary>Never the key.</summary>
    public override string ToString() => $"VirusTotal API key (id {Fingerprint})";

    /// <summary>Refuses to write or read a key as JSON (keys never go over the pipe or into a file as JSON).</summary>
    private sealed class RefuseJsonConverter : JsonConverter<VirusTotalApiKey>
    {
        public override VirusTotalApiKey Read(ref System.Text.Json.Utf8JsonReader reader, Type typeToConvert, System.Text.Json.JsonSerializerOptions options) =>
            throw new System.Text.Json.JsonException("A VirusTotal API key is never deserialized.");

        public override void Write(System.Text.Json.Utf8JsonWriter writer, VirusTotalApiKey value, System.Text.Json.JsonSerializerOptions options) =>
            throw new System.Text.Json.JsonException("A VirusTotal API key is never serialized.");
    }
}
