using System.Net;
using System.Net.Http.Headers;
using SapAV.Core.Hashing;

namespace SapAV.Core.VirusTotal;

/// <summary>Limits of <see cref="VirusTotalClient"/>.</summary>
public sealed record VirusTotalClientOptions
{
    /// <summary>Whole request, headers and body (default 20 s). A timeout is <see cref="VirusTotalStatus.Transient"/>.</summary>
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(20);

    /// <summary>Largest 200 body read (default 4 MiB; a file report is usually 10-200 KB). Bigger is <see cref="VirusTotalStatus.Error"/>.</summary>
    public int MaxBodyBytes { get; init; } = 4 * 1024 * 1024;

    /// <summary>Largest error body read for its <c>error.code</c> (default 16 KiB; more is ignored, not an error).</summary>
    public int MaxErrorBodyBytes { get; init; } = 16 * 1024;

    /// <summary>Longest Retry-After honoured (default 1 day).</summary>
    public TimeSpan MaxRetryAfter { get; init; } = TimeSpan.FromDays(1);

    internal void Validate()
    {
        if (RequestTimeout <= TimeSpan.Zero || RequestTimeout > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentOutOfRangeException(nameof(RequestTimeout), RequestTimeout, "The request timeout must be between 0 and 5 minutes.");
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(MaxBodyBytes, 1024, nameof(MaxBodyBytes));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxErrorBodyBytes, 0, nameof(MaxErrorBodyBytes));
        ArgumentOutOfRangeException.ThrowIfLessThan(MaxRetryAfter, TimeSpan.Zero, nameof(MaxRetryAfter));
    }
}

/// <summary>
/// VirusTotal API v3 hash lookup (ROADMAP feature 3, D2): <c>GET https://www.virustotal.com/api/v3/files/{sha256}</c>
/// with the key in the <c>x-apikey</c> header and nothing else. No upload code exists here.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item><b>Privacy</b>: only the validated, lowercase SHA-256 leaves the machine. No body, no file name or path, no query string.</item>
/// <item><b>Transport</b>: HTTPS to <c>www.virustotal.com</c> only. The URL is absolute (a <c>BaseAddress</c> on the injected client
/// is ignored), redirects are refused (3xx is an error; use <see cref="CreateHttpClient"/>, which turns redirects off, and if an
/// injected handler follows one to another host the response is refused too).</item>
/// <item><b>Timeouts</b>: <see cref="VirusTotalClientOptions.RequestTimeout"/> per request, distinct from the caller's token: a timeout
/// or network error is <see cref="VirusTotalStatus.Transient"/>, only the caller's own cancellation throws (review M4).</item>
/// <item><b>Untrusted response</b>: the body is read with a byte cap, then parsed strictly (<see cref="VirusTotalResponseParser"/>).</item>
/// <item><b>Key</b>: never logged, never in <see cref="VirusTotalResponse.Detail"/>, never in an exception message.</item>
/// </list>
/// Thread-safe (HttpClient is). Never throws for network or server problems.
/// </remarks>
public sealed class VirusTotalClient
{
    public const string Host = "www.virustotal.com";
    public const string ApiKeyHeader = "x-apikey";
    private const string FilesPath = "/api/v3/files/";

    private readonly HttpClient _http;
    private readonly VirusTotalClientOptions _options;

    /// <param name="http">The HTTP client (tests inject a fake handler). Its own Timeout should be infinite or longer than ours.</param>
    /// <param name="options">Limits, or the defaults.</param>
    public VirusTotalClient(HttpClient http, VirusTotalClientOptions? options = null)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _options = options ?? new VirusTotalClientOptions();
        _options.Validate();
    }

    /// <summary>
    /// The production HTTP client: no redirects, no cookies, a connect timeout, the system proxy, no automatic decompression
    /// (so the body cap counts real bytes). The per-request timeout is the client's own (<see cref="HttpClient.Timeout"/> is infinite).
    /// </summary>
    public static HttpClient CreateHttpClient() =>
        new(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(10),
            PooledConnectionLifetime = TimeSpan.FromMinutes(10),
            MaxResponseHeadersLength = 64, // KiB
        })
        {
            Timeout = Timeout.InfiniteTimeSpan,
        };

    /// <summary>The request URI for a hash (already validated and lowercase).</summary>
    internal static Uri FileUri(string sha256) => new($"https://{Host}{FilesPath}{sha256}", UriKind.Absolute);

    /// <summary>Looks up one SHA-256.</summary>
    /// <exception cref="ArgumentException"><paramref name="sha256"/> is not 64 hex characters (nothing is sent).</exception>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is null.</exception>
    /// <exception cref="OperationCanceledException">Only when <paramref name="cancellationToken"/> was cancelled.</exception>
    public async Task<VirusTotalResponse> LookupAsync(string sha256, VirusTotalApiKey key, CancellationToken cancellationToken = default)
    {
        if (!Sha256Hex.TryNormalize(sha256, out var hash))
        {
            throw new ArgumentException("The value is not a SHA-256 (64 hex characters); nothing was sent.", nameof(sha256));
        }

        ArgumentNullException.ThrowIfNull(key);
        cancellationToken.ThrowIfCancellationRequested();

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.RequestTimeout);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, FileUri(hash));
            request.Version = HttpVersion.Version11;
            request.VersionPolicy = HttpVersionPolicy.RequestVersionOrHigher;
            request.Headers.Add(ApiKeyHeader, key.Value); // validated format: no CR/LF or spaces
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            return await HandleAsync(response, hash, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return new VirusTotalResponse(VirusTotalStatus.Transient, null, null, $"VirusTotal did not answer within {_options.RequestTimeout.TotalSeconds:0} s.");
        }
        catch (HttpRequestException ex)
        {
            // The message of an HttpRequestException can name the host, never the header; still, only the error kind is kept.
            return new VirusTotalResponse(VirusTotalStatus.Transient, null, null, $"VirusTotal could not be reached ({ex.HttpRequestError}).");
        }
        catch (IOException)
        {
            return new VirusTotalResponse(VirusTotalStatus.Transient, null, null, "The connection to VirusTotal broke off.");
        }
    }

    private async Task<VirusTotalResponse> HandleAsync(HttpResponseMessage response, string hash, CancellationToken token)
    {
        // A handler that follows redirects on its own must not have ended up anywhere but VirusTotal over HTTPS.
        var finalUri = response.RequestMessage?.RequestUri;
        if (finalUri is not null && !(finalUri.Scheme == Uri.UriSchemeHttps && string.Equals(finalUri.Host, Host, StringComparison.OrdinalIgnoreCase)))
        {
            return Error("The response came from a host other than VirusTotal; it was refused.");
        }

        int code = (int)response.StatusCode;
        TimeSpan? retryAfter = RetryAfter(response);
        if (code == 200)
        {
            var body = await ReadCappedAsync(response.Content, _options.MaxBodyBytes, token).ConfigureAwait(false);
            if (body is null)
            {
                return Error($"The VirusTotal response is larger than {_options.MaxBodyBytes} bytes; it was refused.");
            }

            var report = VirusTotalResponseParser.TryParseReport(body.Value, hash, out var problem);
            return report is null
                ? Error($"The VirusTotal response was refused: {problem}.")
                : new VirusTotalResponse(VirusTotalStatus.Found, report, null, $"VirusTotal: {report.DetectionRatio} engines flagged the file.");
        }

        string? errorCode = _options.MaxErrorBodyBytes == 0
            ? null
            : VirusTotalResponseParser.TryGetErrorCode(await ReadCappedAsync(response.Content, _options.MaxErrorBodyBytes, token).ConfigureAwait(false) ?? default);
        string detail = errorCode is null ? $"HTTP {code}" : $"HTTP {code}, {errorCode}";

        if (code == 429 || errorCode == "QuotaExceededError")
        {
            return new VirusTotalResponse(VirusTotalStatus.QuotaExceeded, null, retryAfter, $"VirusTotal quota exceeded ({detail}).");
        }

        return code switch
        {
            404 => new VirusTotalResponse(VirusTotalStatus.NotFound, null, null, "VirusTotal does not know this file."),
            401 or 403 => new VirusTotalResponse(VirusTotalStatus.BadKey, null, null, $"VirusTotal refused the API key ({detail})."),
            >= 500 and <= 599 => new VirusTotalResponse(VirusTotalStatus.Transient, null, retryAfter, $"VirusTotal server error ({detail})."),
            >= 300 and <= 399 => Error($"VirusTotal answered with a redirect ({detail}); it was not followed."),
            _ => Error($"Unexpected VirusTotal answer ({detail})."),
        };
    }

    private static VirusTotalResponse Error(string detail) => new(VirusTotalStatus.Error, null, null, detail);

    private TimeSpan? RetryAfter(HttpResponseMessage response)
    {
        var header = response.Headers.RetryAfter;
        TimeSpan? value = header?.Delta ?? (header?.Date is { } date ? date - DateTimeOffset.UtcNow : null);
        return value is { } v ? TimeSpan.FromTicks(Math.Clamp(v.Ticks, 0, _options.MaxRetryAfter.Ticks)) : null;
    }

    /// <summary>The body, or null if it is (or announces to be) longer than <paramref name="maxBytes"/>.</summary>
    private static async Task<ReadOnlyMemory<byte>?> ReadCappedAsync(HttpContent content, int maxBytes, CancellationToken token)
    {
        if (content.Headers.ContentLength is long announced && announced > maxBytes)
        {
            return null;
        }

        await using var stream = await content.ReadAsStreamAsync(token).ConfigureAwait(false);
        var buffer = new byte[Math.Min(maxBytes + 1, 64 * 1024)];
        int length = 0;
        while (true)
        {
            if (length == buffer.Length)
            {
                if (buffer.Length > maxBytes)
                {
                    return null; // one byte past the cap
                }

                Array.Resize(ref buffer, (int)Math.Min((long)buffer.Length * 2, maxBytes + 1L));
            }

            int read = await stream.ReadAsync(buffer.AsMemory(length), token).ConfigureAwait(false);
            if (read == 0)
            {
                return buffer.AsMemory(0, length);
            }

            length += read;
        }
    }
}
