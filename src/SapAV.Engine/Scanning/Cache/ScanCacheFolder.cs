using SapAV.Engine.Quarantine;

namespace SapAV.Engine.Scanning.Cache;

/// <summary>
/// The cache's folder (C5): <c>%ProgramData%\sap-AV\Cache</c>, created atomically with the protected SYSTEM + Administrators
/// DACL (inherited by <c>scan.db</c>, its <c>-wal</c> / <c>-shm</c> files and the key file), inside the verified data root
/// (<see cref="EngineDataRoot"/>). A tampered database could make a file look Clean, so a folder that exists with another
/// owner, a wider DACL or as a reparse point is refused and the cache stays off (scans run uncached). The GUI never reads it.
/// Same rules as every engine data subfolder (<see cref="EngineDataSubfolder"/>).
/// </summary>
internal static class ScanCacheFolder
{
    /// <summary>Creates or verifies the folder; returns its full path.</summary>
    /// <param name="parentIsDataRoot">Verify / create the parent with <see cref="EngineDataRoot.Ensure"/> first (default: when it is the real data root).</param>
    /// <exception cref="QuarantineStoreException">The folder can't be used safely (the message says why).</exception>
    public static string Ensure(string folder, QuarantineAccessPolicy policy, bool? parentIsDataRoot = null) =>
        EngineDataSubfolder.Ensure(folder, policy, "scan cache", parentIsDataRoot);
}
