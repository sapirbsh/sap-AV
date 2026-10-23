using System.Text.Json.Serialization;
using SapAV.Core.Serialization;

namespace SapAV.Core.Alerts;

/// <summary>What sap-AV did about an <see cref="Alert"/>. Serialized to JSON by name.</summary>
[JsonConverter(typeof(StrictEnumConverter<AlertAction>))]
public enum AlertAction
{
    /// <summary>Nothing was done (e.g. Suspicious: reported only, or the user still has to decide).</summary>
    None,

    /// <summary>The file was moved to quarantine (B2).</summary>
    Quarantined,

    /// <summary>Quarantine was attempted and failed; the file is still in place.</summary>
    QuarantineFailed,

    /// <summary>A persistence entry or process was blocked (D5 / E11).</summary>
    Blocked,

    /// <summary>The item was restored from quarantine (B2).</summary>
    Restored,

    /// <summary>
    /// Not quarantined automatically (protected location such as Windows or Program Files, a SYSTEM/TrustedInstaller-owned
    /// file, or the auto-quarantine rate limit): the user has to confirm the quarantine (B3).
    /// </summary>
    NeedsUserConfirmation,
}
