using System.Text.Json;
using SapAV.Core.Text;

namespace SapAV.Core.VirusTotal;

/// <summary>
/// Strict parsing of a VirusTotal v3 <c>/files/{id}</c> body into <see cref="VirusTotalReport"/>. The body is untrusted:
/// depth-limited, no comments or trailing commas, wrong types are ignored field by field, counts are clamped, at most
/// <see cref="MaxResultEntries"/> engine entries are looked at, and every kept string is sanitized and capped.
/// </summary>
internal static class VirusTotalResponseParser
{
    /// <summary>Engine entries of <c>last_analysis_results</c> looked at (VirusTotal has ~75 engines).</summary>
    public const int MaxResultEntries = 256;

    private const int MaxDepth = 32;

    /// <summary>Plausible analysis dates: VirusTotal v3 data starts after 2004; anything past 2100 is junk.</summary>
    private static readonly DateTimeOffset EarliestDate = new(2004, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset LatestDate = new(2100, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static readonly JsonDocumentOptions Options = new()
    {
        MaxDepth = MaxDepth,
        CommentHandling = JsonCommentHandling.Disallow,
        AllowTrailingCommas = false,
        AllowDuplicateProperties = false, // a second "malicious" key must not be able to override the first
    };

    private static readonly string[] OtherStatsKeys = ["timeout", "confirmed-timeout", "type-unsupported", "failure"];

    /// <summary>The report, or null (with <paramref name="problem"/>) if the body isn't a file report for <paramref name="sha256"/>.</summary>
    public static VirusTotalReport? TryParseReport(ReadOnlyMemory<byte> body, string sha256, out string? problem)
    {
        try
        {
            using var document = JsonDocument.Parse(body, Options);
            return Map(document.RootElement, sha256, out problem);
        }
        catch (JsonException)
        {
            problem = "the response is not valid JSON";
            return null;
        }
    }

    /// <summary>The <c>error.code</c> of an error body if it is a plain identifier (e.g. "QuotaExceededError"), else null.</summary>
    public static string? TryGetErrorCode(ReadOnlyMemory<byte> body)
    {
        if (body.IsEmpty)
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(body, Options);
            if (document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object
                && error.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String)
            {
                string? value = code.GetString();
                return value is { Length: > 0 and <= 64 } && value.All(char.IsAsciiLetterOrDigit) ? value : null;
            }
        }
        catch (JsonException)
        {
        }

        return null;
    }

    private static VirusTotalReport? Map(JsonElement root, string sha256, out string? problem)
    {
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Object)
        {
            problem = "the response has no data object";
            return null;
        }

        // The id of a file object is its SHA-256: a report for another file (or one that doesn't say which file it is, review D3
        // L6) is refused, not cached under this hash.
        if (!data.TryGetProperty("id", out var id))
        {
            problem = "the response doesn't say which file it is for";
            return null;
        }

        if (id.ValueKind != JsonValueKind.String || !string.Equals(id.GetString(), sha256, StringComparison.OrdinalIgnoreCase))
        {
            problem = "the response is for a different file";
            return null;
        }

        if (data.TryGetProperty("type", out var type) && !(type.ValueKind == JsonValueKind.String && type.ValueEquals("file")))
        {
            problem = "the response is not a file object";
            return null;
        }

        if (!data.TryGetProperty("attributes", out var attributes) || attributes.ValueKind != JsonValueKind.Object)
        {
            problem = "the response has no attributes";
            return null;
        }

        int malicious = 0, suspicious = 0, undetected = 0, harmless = 0, other = 0;
        if (attributes.TryGetProperty("last_analysis_stats", out var stats) && stats.ValueKind == JsonValueKind.Object)
        {
            malicious = Count(stats, "malicious");
            suspicious = Count(stats, "suspicious");
            undetected = Count(stats, "undetected");
            harmless = Count(stats, "harmless");
            foreach (var key in OtherStatsKeys)
            {
                other += Count(stats, key);
            }
        }

        DateTimeOffset? date = null;
        if (attributes.TryGetProperty("last_analysis_date", out var dateValue) && dateValue.ValueKind == JsonValueKind.Number
            && dateValue.TryGetInt64(out long seconds)
            && seconds >= EarliestDate.ToUnixTimeSeconds() && seconds < LatestDate.ToUnixTimeSeconds())
        {
            date = DateTimeOffset.FromUnixTimeSeconds(seconds);
        }

        problem = null;
        return new VirusTotalReport(malicious, suspicious, undetected, harmless,
            malicious + suspicious + undetected + harmless + other, date, Labels(attributes), ThreatLabel(attributes));
    }

    private static int Count(JsonElement stats, string name) =>
        stats.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out int count)
            ? Math.Clamp(count, 0, VirusTotalReport.MaxCount)
            : 0;

    /// <summary>"Engine: result" for engines whose category is malicious (first), then suspicious; capped and sanitized.</summary>
    private static List<string> Labels(JsonElement attributes)
    {
        var labels = new List<string>(VirusTotalReport.MaxLabels);
        if (!attributes.TryGetProperty("last_analysis_results", out var results) || results.ValueKind != JsonValueKind.Object)
        {
            return labels;
        }

        foreach (var category in (ReadOnlySpan<string>)["malicious", "suspicious"])
        {
            int seen = 0;
            foreach (var entry in results.EnumerateObject())
            {
                if (labels.Count >= VirusTotalReport.MaxLabels || ++seen > MaxResultEntries)
                {
                    break;
                }

                var value = entry.Value;
                if (value.ValueKind != JsonValueKind.Object
                    || !value.TryGetProperty("category", out var c) || c.ValueKind != JsonValueKind.String || !c.ValueEquals(category))
                {
                    continue;
                }

                string engine = Clean(value.TryGetProperty("engine_name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString() : entry.Name,
                    VirusTotalReport.MaxEngineNameLength);
                if (engine.Length == 0)
                {
                    continue;
                }

                string result = Clean(value.TryGetProperty("result", out var r) && r.ValueKind == JsonValueKind.String ? r.GetString() : null,
                    VirusTotalReport.MaxResultLength);
                labels.Add(result.Length == 0 ? $"{engine}: {category}" : $"{engine}: {result}");
            }
        }

        return labels;
    }

    private static string? ThreatLabel(JsonElement attributes)
    {
        if (attributes.TryGetProperty("popular_threat_classification", out var classification)
            && classification.ValueKind == JsonValueKind.Object
            && classification.TryGetProperty("suggested_threat_label", out var label) && label.ValueKind == JsonValueKind.String)
        {
            string clean = Clean(label.GetString(), VirusTotalReport.MaxThreatLabelLength);
            return clean.Length == 0 ? null : clean;
        }

        return null;
    }

    /// <summary>Display-safe single line, capped. The raw string is cut first so a huge value isn't copied whole.</summary>
    private static string Clean(string? value, int maxLength)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        if (value.Length > maxLength * 4)
        {
            value = value[..(maxLength * 4)];
        }

        return SafeText.Display(value, maxLength);
    }
}
