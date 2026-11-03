using System.Net;
using System.Text;
using SapAV.Core.VirusTotal;

namespace SapAV.Core.Tests.VirusTotal;

/// <summary>Test data for the VirusTotal tests. Keys are obviously fake; no test ever talks to the real API.</summary>
internal static class Vt
{
    /// <summary>An obviously fake key in the accepted format.</summary>
    public const string FakeKey = "FAKE-test-key-not-real-0123456789abcdef";

    public const string OtherFakeKey = "FAKE-other-test-key-not-real-9876543210";

    public static readonly string ShaA = new('a', 64);
    public static readonly string ShaB = new('b', 64);

    public static string Sha(int i) => i.ToString("x64");

    public static VirusTotalApiKey Key() => VirusTotalApiKey.TryCreate(FakeKey)!;

    /// <summary>A minimal, well-formed file report.</summary>
    public static string Report(string sha, int malicious = 3, int suspicious = 1, int undetected = 60, int harmless = 0,
        long date = 1_760_000_000, string results = """
            "EngineA": {"category": "malicious", "engine_name": "EngineA", "result": "Trojan.Fake"},
            "EngineB": {"category": "undetected", "engine_name": "EngineB", "result": null},
            "EngineC": {"category": "suspicious", "engine_name": "EngineC", "result": "Heur.Fake"},
            "EngineD": {"category": "malicious", "engine_name": "EngineD", "result": "Gen:Fake"}
            """) => $$"""
        {"data": {"id": "{{sha}}", "type": "file", "attributes": {
            "last_analysis_date": {{date}},
            "last_analysis_stats": {"malicious": {{malicious}}, "suspicious": {{suspicious}}, "undetected": {{undetected}},
                                    "harmless": {{harmless}}, "timeout": 2, "type-unsupported": 4},
            "last_analysis_results": { {{results}} },
            "popular_threat_classification": {"suggested_threat_label": "trojan.fake/test"}
        } } }
        """;

    public static HttpResponseMessage Json(HttpStatusCode code, string body) =>
        new(code) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    public static HttpResponseMessage Error(HttpStatusCode code, string errorCode) =>
        Json(code, $$"""{"error": {"code": "{{errorCode}}", "message": "fake message"} }""");
}

/// <summary>A scripted HTTP handler that records what was sent (headers copied before the request is disposed).</summary>
internal sealed class FakeVtHandler : HttpMessageHandler
{
    public sealed record Sent(HttpMethod Method, Uri? Uri, IReadOnlyDictionary<string, string> Headers, bool HasContent);

    private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _respond;
    private int _calls;

    public FakeVtHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) => _respond = respond;

    public FakeVtHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : this((r, _) => Task.FromResult(respond(r)))
    {
    }

    public List<Sent> Requests { get; } = [];

    public int Calls => Volatile.Read(ref _calls);

    /// <summary>Answers each request with a report for the hash in its URL.</summary>
    public static FakeVtHandler Reports() => new(r => Vt.Json(HttpStatusCode.OK, Vt.Report(r.RequestUri!.Segments[^1])));

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _calls);
        lock (Requests)
        {
            Requests.Add(new Sent(request.Method, request.RequestUri,
                request.Headers.ToDictionary(h => h.Key, h => string.Join(",", h.Value), StringComparer.OrdinalIgnoreCase),
                request.Content is not null));
        }

        return _respond(request, cancellationToken);
    }
}

/// <summary>A clock the test moves by hand (timers stay real).</summary>
internal sealed class FakeClock : TimeProvider
{
    public DateTimeOffset Now { get; set; } = new(2026, 11, 3, 12, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow() => Now;

    public void Advance(TimeSpan by) => Now += by;
}

/// <summary>A key source the test sets directly.</summary>
internal sealed class FakeKeySource(string? key) : IVirusTotalKeySource
{
    public VirusTotalApiKey? Key { get; set; } = VirusTotalApiKey.TryCreate(key);

    public VirusTotalApiKey? GetKey() => Key;
}

/// <summary>A non-seekable body that never ends, counting bytes handed out.</summary>
internal sealed class EndlessStream : Stream
{
    public long Served { get; private set; }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count)
    {
        buffer.AsSpan(offset, count).Fill((byte)' ');
        Served += count;
        return count;
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
