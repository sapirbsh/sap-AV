using System.Net;
using System.Text;
using System.Text.Json;
using SapAV.Core.Text;
using SapAV.Core.VirusTotal;

namespace SapAV.Core.Tests.VirusTotal;

public sealed class VirusTotalClientTests
{
    private static VirusTotalClient Client(FakeVtHandler handler, VirusTotalClientOptions? options = null) =>
        new(new HttpClient(handler) { BaseAddress = new Uri("https://evil.example/") }, options);

    [Fact]
    public async Task Request_IsAPlainGetOfTheLowercaseHash_WithTheKeyOnlyInXApiKey()
    {
        var handler = FakeVtHandler.Reports();
        var upper = new string('A', 64);

        var response = await Client(handler).LookupAsync(upper, Vt.Key());

        Assert.Equal(VirusTotalStatus.Found, response.Status);
        var sent = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, sent.Method);
        Assert.Equal($"https://www.virustotal.com/api/v3/files/{new string('a', 64)}", sent.Uri!.AbsoluteUri); // BaseAddress ignored, no query
        Assert.Equal(Vt.FakeKey, sent.Headers["x-apikey"]);
        Assert.False(sent.HasContent);
        Assert.DoesNotContain(sent.Headers, h => h.Key != "x-apikey" && h.Value.Contains(Vt.FakeKey, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")] // 63
    [InlineData("../../../users/me?x=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData(" aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public async Task InvalidHash_IsRefusedBeforeAnyRequest(string value)
    {
        var handler = FakeVtHandler.Reports();

        var ex = await Assert.ThrowsAsync<ArgumentException>(() => Client(handler).LookupAsync(value, Vt.Key()));

        Assert.Equal(0, handler.Calls);
        Assert.DoesNotContain(Vt.FakeKey, ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Report_IsMappedToTheSmallModel()
    {
        var handler = FakeVtHandler.Reports();

        var report = (await Client(handler).LookupAsync(Vt.ShaA, Vt.Key())).Report!;

        Assert.Equal((3, 1, 60, 0), (report.Malicious, report.Suspicious, report.Undetected, report.Harmless));
        Assert.Equal(70, report.TotalEngines); // + timeout 2 + type-unsupported 4
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_760_000_000), report.LastAnalysisDate);
        Assert.Equal(["EngineA: Trojan.Fake", "EngineD: Gen:Fake", "EngineC: Heur.Fake"], report.Labels); // malicious first
        Assert.Equal("trojan.fake/test", report.ThreatLabel);
        Assert.True(report.IsDetected);
    }

    [Fact]
    public async Task HostileReport_IsClampedCappedAndSanitized()
    {
        string hugeName = new('N', 100_000);
        var results = new StringBuilder();
        results.Append($$"""
            "x": {"category": "malicious", "engine_name": "Evil\r\nFAKE LOG LINE‮", "result": "{{hugeName}}"},
            "y": {"category": "malicious", "engine_name": 42, "result": ["not", "a", "string"]},
            "z": "not an object",
            """);
        for (int i = 0; i < 2000; i++)
        {
            results.Append($$"""
                "e{{i}}": {"category": "malicious", "engine_name": "E{{i}}", "result": "R"},
                """);
        }

        results.Append(""" "last": {"category": "malicious"} """);
        string body = Vt.Report(Vt.ShaA, malicious: 2_000_000_000, suspicious: -5, undetected: 0, date: 99_999_999_999, results: results.ToString())
            .Replace("\"harmless\": 0", "\"harmless\": \"lots\"", StringComparison.Ordinal);
        var handler = new FakeVtHandler(_ => Vt.Json(HttpStatusCode.OK, body));

        var report = (await Client(handler).LookupAsync(Vt.ShaA, Vt.Key())).Report!;

        Assert.Equal(VirusTotalReport.MaxCount, report.Malicious);
        Assert.Equal(0, report.Suspicious);
        Assert.Equal(0, report.Harmless); // wrong type ignored
        Assert.Null(report.LastAnalysisDate); // year ~5138 is implausible
        Assert.Equal(VirusTotalReport.MaxLabels, report.Labels.Count);
        Assert.All(report.Labels, label =>
        {
            Assert.True(label.Length <= VirusTotalReport.MaxEngineNameLength + 2 + VirusTotalReport.MaxResultLength);
            Assert.Equal(SafeText.Display(label, 1000), label); // already display-safe: no CR/LF, bidi or controls
        });
        Assert.StartsWith("Evil", report.Labels[0], StringComparison.Ordinal);
        Assert.Contains("FAKE LOG LINE�: NNN", report.Labels[0], StringComparison.Ordinal); // CR/LF became spaces, RLO became U+FFFD
        Assert.Equal("y: malicious", report.Labels[1]); // non-string name and result: the entry key and the category
        Assert.Equal("E0: R", report.Labels[2]);
    }

    public static TheoryData<string> MalformedBodies() =>
    [
        "not json at all",
        """[1, 2, 3]""",
        """{"error": null}""",
        """{"data": {"id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "type": "file", "attributes": {}}}""", // another file
        """{"data": {"type": "url", "attributes": {}}}""",
        """{"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}, "attributes": {"last_analysis_stats": {"malicious": 9}}}}""", // duplicate key
        """{"data": {"attributes": {} }, } """, // trailing comma
        """{"data": {"attributes": {"x": """ + new string('[', 5000) + new string(']', 5000) + "} } }", // too deep
    ];

    [Theory]
    [MemberData(nameof(MalformedBodies))]
    public async Task MalformedOrForeignReport_IsAnError_NotAFinding(string body)
    {
        var handler = new FakeVtHandler(_ => Vt.Json(HttpStatusCode.OK, body));

        var response = await Client(handler).LookupAsync(Vt.ShaA, Vt.Key());

        Assert.Equal(VirusTotalStatus.Error, response.Status);
        Assert.Null(response.Report);
    }

    [Fact]
    public async Task OversizedBody_IsRefused_WithoutReadingItAll()
    {
        var endless = new EndlessStream();
        var streaming = new FakeVtHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(endless) });
        var announced = new FakeVtHandler(_ =>
        {
            var response = Vt.Json(HttpStatusCode.OK, Vt.Report(Vt.ShaA));
            response.Content.Headers.ContentLength = 50L * 1024 * 1024 * 1024;
            return response;
        });
        var options = new VirusTotalClientOptions { MaxBodyBytes = 64 * 1024 };

        var first = await Client(streaming, options).LookupAsync(Vt.ShaA, Vt.Key());
        var second = await Client(announced, options).LookupAsync(Vt.ShaA, Vt.Key());

        Assert.Equal(VirusTotalStatus.Error, first.Status);
        Assert.InRange(endless.Served, 64 * 1024, 64 * 1024 + 128 * 1024); // stopped just past the cap
        Assert.Equal(VirusTotalStatus.Error, second.Status);
    }

    [Theory]
    [InlineData(404, null, VirusTotalStatus.NotFound)]
    [InlineData(401, "WrongCredentialsError", VirusTotalStatus.BadKey)]
    [InlineData(403, "ForbiddenError", VirusTotalStatus.BadKey)]
    [InlineData(429, "QuotaExceededError", VirusTotalStatus.QuotaExceeded)]
    [InlineData(403, "QuotaExceededError", VirusTotalStatus.QuotaExceeded)]
    [InlineData(500, null, VirusTotalStatus.Transient)]
    [InlineData(503, "TransientError", VirusTotalStatus.Transient)]
    [InlineData(302, null, VirusTotalStatus.Error)]
    [InlineData(400, "BadRequestError", VirusTotalStatus.Error)]
    public async Task StatusCodes_MapToOutcomes(int code, string? errorCode, VirusTotalStatus expected)
    {
        var handler = new FakeVtHandler(_ => errorCode is null
            ? new HttpResponseMessage((HttpStatusCode)code)
            : Vt.Error((HttpStatusCode)code, errorCode));

        var response = await Client(handler).LookupAsync(Vt.ShaA, Vt.Key());

        Assert.Equal(expected, response.Status);
        Assert.Null(response.Report);
        Assert.DoesNotContain(Vt.FakeKey, response.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("fake message", response.Detail, StringComparison.Ordinal); // server free text is not kept
    }

    [Fact]
    public async Task RetryAfter_IsReadAndCapped()
    {
        var shortWait = new FakeVtHandler(_ =>
        {
            var r = Vt.Error(HttpStatusCode.TooManyRequests, "QuotaExceededError");
            r.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(30));
            return r;
        });
        var hugeWait = new FakeVtHandler(_ =>
        {
            var r = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
            r.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromDays(400));
            return r;
        });

        Assert.Equal(TimeSpan.FromSeconds(30), (await Client(shortWait).LookupAsync(Vt.ShaA, Vt.Key())).RetryAfter);
        Assert.Equal(TimeSpan.FromDays(1), (await Client(hugeWait).LookupAsync(Vt.ShaA, Vt.Key())).RetryAfter);
    }

    [Fact]
    public async Task Timeout_And_NetworkError_AreTransient_ButCallerCancellationThrows()
    {
        var hang = new FakeVtHandler(async (_, token) =>
        {
            await Task.Delay(Timeout.Infinite, token);
            throw new InvalidOperationException("unreachable");
        });
        var offline = new FakeVtHandler((_, _) => throw new HttpRequestException(HttpRequestError.NameResolutionError, "No such host is known."));
        var options = new VirusTotalClientOptions { RequestTimeout = TimeSpan.FromMilliseconds(100) };

        var timedOut = await Client(hang, options).LookupAsync(Vt.ShaA, Vt.Key());
        var unreachable = await Client(offline).LookupAsync(Vt.ShaA, Vt.Key());
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        var slow = new VirusTotalClientOptions { RequestTimeout = TimeSpan.FromSeconds(30) };

        Assert.Equal(VirusTotalStatus.Transient, timedOut.Status);
        Assert.Equal(VirusTotalStatus.Transient, unreachable.Status);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Client(hang, slow).LookupAsync(Vt.ShaA, Vt.Key(), cancel.Token));
    }

    [Fact]
    public async Task ResponseFromAnotherHost_IsRefused()
    {
        // A handler that followed a redirect on its own: the final request URI is not VirusTotal.
        var handler = new FakeVtHandler(_ =>
        {
            var r = Vt.Json(HttpStatusCode.OK, Vt.Report(Vt.ShaA, malicious: 0, suspicious: 0));
            r.RequestMessage = new HttpRequestMessage(HttpMethod.Get, "https://attacker.example/api/v3/files/" + Vt.ShaA);
            return r;
        });

        var response = await Client(handler).LookupAsync(Vt.ShaA, Vt.Key());

        Assert.Equal(VirusTotalStatus.Error, response.Status);
        Assert.Null(response.Report);
    }

    [Fact]
    public void ApiKey_IsNeverExposed_ByToStringOrJson_AndRejectsHeaderInjection()
    {
        var key = Vt.Key();

        Assert.DoesNotContain(Vt.FakeKey, key.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain(Vt.FakeKey, key.Fingerprint, StringComparison.Ordinal);
        var ex = Assert.Throws<JsonException>(() => JsonSerializer.Serialize(new { Key = key }));
        Assert.DoesNotContain(Vt.FakeKey, ex.ToString(), StringComparison.Ordinal);
        Assert.Null(VirusTotalApiKey.TryCreate(Vt.FakeKey + "\r\nX-Evil: 1"));
        Assert.Null(VirusTotalApiKey.TryCreate("short"));
        Assert.Null(VirusTotalApiKey.TryCreate("has a space in it 0123456789"));
        Assert.Equal(key.Fingerprint, VirusTotalApiKey.TryCreate("  " + Vt.FakeKey + "  ")!.Fingerprint); // trimmed
    }
}
