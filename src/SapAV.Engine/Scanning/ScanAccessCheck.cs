using Microsoft.Win32.SafeHandles;

namespace SapAV.Engine.Scanning;

/// <summary>
/// "Scan with the requester's access" (ROADMAP B4 / C1). The engine scans as SYSTEM, so a job a standard user asked for
/// must not reach folders or files that user can't read: otherwise the results would leak hashes and verdicts of other
/// users' files. A job with an access check consults it before listing every folder and before scanning every file
/// (on the scan's own handle, so the check is bound to the object that is scanned). Jobs without one (engine-initiated,
/// or requested by an administrator) scan everything.
/// </summary>
internal interface IScanAccessCheck
{
    /// <summary>May the requester list this folder (FILE_LIST_DIRECTORY)? False when it can't be determined.</summary>
    bool CanList(string directoryPath);

    /// <summary>May the requester read this open file (FILE_READ_DATA)? False when it can't be determined.</summary>
    bool CanRead(SafeFileHandle handle);
}
