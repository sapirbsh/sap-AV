namespace SapAV.Core.Scanning;

/// <summary>
/// The version of the detection logic the scan worker runs (heuristics, verdict rules, categories). Raise it whenever a change
/// would judge an unchanged file differently, so verdicts cached under the old logic (the C5 scan cache) stop counting even in
/// builds whose engine version carries no git hash.
/// </summary>
public static class DetectionLogic
{
    /// <summary>
    /// 2: E1 (PotentiallyUnwanted, threat categories), E3 (infostealer / miner heuristics).
    /// 3: A5 follow-up (malformed-PE detection, image extensions, entropy read budget, trusted SFX names, bidi isolates).
    /// 4: E2 (third-party YARA rules: explicit verdict / category mapping enforced at load, YARA scan-time budget).
    /// </summary>
    public const int Version = 4;
}
