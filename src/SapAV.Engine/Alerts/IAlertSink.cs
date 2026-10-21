using SapAV.Core.Alerts;

namespace SapAV.Engine.Alerts;

/// <summary>
/// Somewhere alerts are delivered (the Windows Event Log now; the GUI pipe later). Fake it in tests.
/// </summary>
public interface IAlertSink
{
    /// <summary>
    /// Delivers one alert. Delivery problems (sink unavailable, log full, access denied) are logged by the sink and
    /// never thrown: an alert that can't be delivered must not stop scanning or crash the service.
    /// </summary>
    /// <exception cref="ArgumentNullException"><paramref name="alert"/> is null.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was canceled.</exception>
    ValueTask WriteAsync(Alert alert, CancellationToken cancellationToken = default);
}
