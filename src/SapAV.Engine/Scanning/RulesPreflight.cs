using SapAV.Engine.Alerts;
using SapAV.Engine.Sandbox;

namespace SapAV.Engine.Scanning;

/// <summary>
/// Review A M5: zero loaded YARA rules, or rule files that failed, would still scan files "Clean". Before each job this
/// checks what the broker loaded (loading it now if nothing was loaded yet) and turns problems into a job-level warning
/// plus a <see cref="Core.Alerts.AlertType.ScanRulesDegraded"/> alert (9003; one per window). The alert names only counts:
/// rule-file error text comes from the worker and stays out of the Event Log (review X2/B3 M2).
/// </summary>
internal sealed class RulesPreflight(IScanBroker broker, IAlertDispatcher alerts, string rulesLocation, TimeProvider time) : IScanJobPreflight
{
    public async Task<IReadOnlyList<string>> CheckAsync(ScanJob job, CancellationToken cancellationToken)
    {
        var rules = broker.Status.Rules ?? await broker.ReloadRulesAsync(cancellationToken).ConfigureAwait(false);
        var (warning, alertText) = Judge(rules);
        if (warning is null)
        {
            return [];
        }

        alerts.Post(ScanAlerts.RulesDegraded(rulesLocation, alertText!, job.Request.Trigger, time.GetUtcNow()), health: true);
        return [warning];
    }

    /// <summary>The job warning (may name rule files) and the alert text (counts only), or nulls when the rules are fine.</summary>
    internal static (string? Warning, string? AlertText) Judge(RulesLoadSummary? rules)
    {
        if (rules is null)
        {
            const string text = "The scan rules could not be loaded into the scan worker; files are reported NotScanned until it recovers.";
            return (text, text);
        }

        if (rules.RuleCount == 0)
        {
            const string text = "No YARA rules are loaded: YARA can't detect anything; only the blocklist and heuristics run.";
            return (text, text);
        }

        if (rules.FileErrors.Count > 0)
        {
            return ($"{rules.FileErrors.Count} YARA rule file(s) failed to load ({string.Join("; ", rules.FileErrors.Take(3))}); " +
                    $"{rules.RuleCount} rules are active.",
                $"{rules.FileErrors.Count} YARA rule file(s) failed to load; {rules.RuleCount} rules are active. See the engine log.");
        }

        return (null, null);
    }
}
