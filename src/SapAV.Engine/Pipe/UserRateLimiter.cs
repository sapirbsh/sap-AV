using System.Security.Principal;

namespace SapAV.Engine.Pipe;

/// <summary>A token bucket per user SID, shared by all of that user's connections (B4 per-user request rate).</summary>
internal sealed class UserRateLimiter(TimeProvider time, double perSecond, int burst)
{
    private const int MaxTrackedUsers = 1024;

    private readonly Lock _lock = new();
    private readonly Dictionary<SecurityIdentifier, (double Tokens, long Stamp)> _buckets = [];

    public bool TryAcquire(SecurityIdentifier user)
    {
        ArgumentNullException.ThrowIfNull(user);
        long now = time.GetTimestamp();
        lock (_lock)
        {
            double tokens = burst;
            if (_buckets.TryGetValue(user, out var bucket))
            {
                double seconds = time.GetElapsedTime(bucket.Stamp, now).TotalSeconds;
                tokens = Math.Min(burst, bucket.Tokens + seconds * perSecond);
            }
            else if (_buckets.Count >= MaxTrackedUsers)
            {
                // Forget users whose bucket is full again (idle); only full buckets are dropped, so nobody gains tokens.
                foreach (var (sid, b) in _buckets.ToArray())
                {
                    if (b.Tokens + time.GetElapsedTime(b.Stamp, now).TotalSeconds * perSecond >= burst)
                    {
                        _buckets.Remove(sid);
                    }
                }
            }

            bool allowed = tokens >= 1;
            _buckets[user] = (allowed ? tokens - 1 : tokens, now);
            return allowed;
        }
    }
}
