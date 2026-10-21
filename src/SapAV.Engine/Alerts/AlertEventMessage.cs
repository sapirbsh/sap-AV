using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using SapAV.Core.Alerts;

namespace SapAV.Engine.Alerts;

/// <summary>
/// Formats an <see cref="Alert"/> as the Event Log message: one line of JSON with the alert's stable field names,
/// guaranteed to fit the Event Log's per-string limit.
/// </summary>
/// <remarks>
/// <para>
/// <b>Encoding.</b> <see cref="JavaScriptEncoder.Default"/> escapes every non-ASCII character (and <c>&lt;</c>,
/// <c>&gt;</c>, <c>&amp;</c>, quotes), so the message is pure ASCII: characters equal bytes, and bidi controls or
/// U+2028 in a file name show as <c>\u202E</c> / <c>\u2028</c> instead of reordering or breaking the text.
/// No enum converter is registered here: the models' own <c>StrictEnumConverter</c> attributes apply.
/// </para>
/// <para>
/// <b>Size cap.</b> A string written with ReportEvent may have at most 31,839 characters. If the full JSON is
/// longer than <see cref="MaxMessageChars"/>, it is shortened in this order, each step only as far as needed:
/// (1) reasons are dropped from the end, least severe first, always keeping the first (worst) one, so the message
/// still reads back as a valid alert (<c>"ReasonsOmitted": n</c>),
/// (2) secondary technique IDs are dropped from the end (<c>"SecondaryTechniqueIdsOmitted": n</c>),
/// (3) the source URL is dropped (<c>"SourceUrlOmitted": true</c>),
/// (4) only if the path alone still doesn't fit (a path near the 32,767-character limit, escaped up to 6 bytes per
/// character), its middle is replaced by an ellipsis, U+2026 (<c>"FilePathTruncated": true</c>).
/// The identifying fields (AlertId, Timestamp, Type, Verdict, Sha256, TechniqueId, Action, Trigger, EngineVersion)
/// are never changed, and a shortened message still reads back as a valid <see cref="Alert"/>.
/// </para>
/// </remarks>
public static class AlertEventMessage
{
    /// <summary>Default cap, with headroom below the 31,839-character Event Log limit.</summary>
    public const int MaxMessageChars = 30_000;

    /// <summary>
    /// Smallest cap accepted: enough for every bounded field, one reason (up to 1,024 characters, 6 bytes each when
    /// escaped) and a shortened path.
    /// </summary>
    public const int MinMessageChars = 16_384;

    private static readonly JsonSerializerOptions Options = new()
    {
        Encoder = JavaScriptEncoder.Default,
        WriteIndented = false,
    };

    /// <exception cref="ArgumentNullException"><paramref name="alert"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxChars"/> is below <see cref="MinMessageChars"/>.</exception>
    public static string Format(Alert alert, int maxChars = MaxMessageChars)
    {
        ArgumentNullException.ThrowIfNull(alert);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxChars, MinMessageChars);

        var json = JsonSerializer.Serialize(alert, Options);
        if (json.Length <= maxChars)
        {
            return json;
        }

        var node = JsonSerializer.SerializeToNode(alert, Options)!.AsObject();
        if (TrimList(node, nameof(Alert.Reasons), alert.Reasons, "ReasonsOmitted", minKeep: 1, maxChars)
            || TrimList(node, nameof(Alert.SecondaryTechniqueIds), alert.SecondaryTechniqueIds, "SecondaryTechniqueIdsOmitted", minKeep: 0, maxChars)
            || DropSourceUrl(node, alert, maxChars))
        {
            return node.ToJsonString(Options);
        }

        ShortenPath(node, alert.FilePath, maxChars);
        return node.ToJsonString(Options);
    }

    /// <summary>Keeps the longest prefix of <paramref name="items"/> that fits; true if the message now fits.</summary>
    private static bool TrimList(
        JsonObject node, string property, IReadOnlyList<string> items, string omittedProperty, int minKeep, int maxChars)
    {
        minKeep = Math.Min(minKeep, items.Count);
        if (items.Count == minKeep)
        {
            return Fits(node, maxChars);
        }

        int keep = LargestFitting(minKeep, items.Count, k => SetList(node, property, items, k, omittedProperty), node, maxChars);
        SetList(node, property, items, keep, omittedProperty);
        return Fits(node, maxChars);
    }

    private static void SetList(JsonObject node, string property, IReadOnlyList<string> items, int keep, string omittedProperty)
    {
        node[property] = new JsonArray(items.Take(keep).Select(i => (JsonNode?)JsonValue.Create(i)).ToArray());
        if (keep < items.Count)
        {
            node[omittedProperty] = items.Count - keep;
        }
        else
        {
            node.Remove(omittedProperty);
        }
    }

    private static bool DropSourceUrl(JsonObject node, Alert alert, int maxChars)
    {
        if (alert.SourceUrl is not null)
        {
            node[nameof(Alert.SourceUrl)] = null;
            node["SourceUrlOmitted"] = true;
        }

        return Fits(node, maxChars);
    }

    private static void ShortenPath(JsonObject node, string path, int maxChars)
    {
        node["FilePathTruncated"] = true;
        int keep = LargestFitting(0, path.Length, k => node[nameof(Alert.FilePath)] = Middle(path, k), node, maxChars);
        node[nameof(Alert.FilePath)] = Middle(path, keep);
    }

    /// <summary>Keeps <paramref name="keep"/> characters of <paramref name="path"/>: the start and end, "..." between.</summary>
    private static string Middle(string path, int keep)
    {
        int head = keep / 2;
        int tail = keep - head;
        if (head > 0 && char.IsHighSurrogate(path[head - 1]))
        {
            head--;
        }

        int tailStart = path.Length - tail;
        if (tail > 0 && char.IsLowSurrogate(path[tailStart]))
        {
            tailStart++;
        }

        return string.Concat(path.AsSpan(0, head), "\u2026", path.AsSpan(tailStart));
    }

    /// <summary>Binary search for the largest k in [min, max] for which the message fits after <paramref name="apply"/>(k).</summary>
    private static int LargestFitting(int min, int max, Action<int> apply, JsonObject node, int maxChars)
    {
        int lo = min, hi = max;
        while (lo < hi)
        {
            int mid = lo + ((hi - lo + 1) / 2);
            apply(mid);
            if (Fits(node, maxChars))
            {
                lo = mid;
            }
            else
            {
                hi = mid - 1;
            }
        }

        return lo;
    }

    private static bool Fits(JsonObject node, int maxChars) => node.ToJsonString(Options).Length <= maxChars;
}
