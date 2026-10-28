using System.Text.Json.Serialization;
using SapAV.Core.Hashing;
using SapAV.Core.Heuristics;
using SapAV.Core.Serialization;

namespace SapAV.Core.Persistence;

/// <summary>
/// Where an autostart target lives, by path (ROADMAP C3). Only a name: who can write there is decided from the ACL
/// (<see cref="IPathWritability"/>). Serialized to JSON by name.
/// </summary>
[JsonConverter(typeof(StrictEnumConverter<TargetLocation>))]
public enum TargetLocation
{
    Other,

    /// <summary>Under <c>%SystemRoot%</c> (System32, SysWOW64, ...), except its Temp folders.</summary>
    Windows,

    /// <summary><c>Program Files</c> or <c>Program Files (x86)</c>.</summary>
    ProgramFiles,

    /// <summary><c>%ProgramData%</c> (its subfolders are often writable by users: the ACL decides).</summary>
    ProgramData,

    /// <summary>A user's profile, outside AppData / Downloads.</summary>
    UserProfile,

    /// <summary>A user's AppData (Roaming / Local / LocalLow, but not Local\Temp).</summary>
    AppData,

    /// <summary>A Temp folder (a user's, <c>%SystemRoot%\Temp</c>, <c>SystemTemp</c>).</summary>
    Temp,

    /// <summary>A user's Downloads folder.</summary>
    Downloads,

    /// <summary><c>C:\Users\Public</c> (writable by every user).</summary>
    Public,

    /// <summary>The Recycle Bin (<c>$Recycle.Bin</c>): nothing should ever run from there.</summary>
    RecycleBin,
}

/// <summary>Classifies target paths (no file I/O).</summary>
public static class TargetLocations
{
    /// <summary>Temp, Downloads, Public, Recycle Bin: places programs aren't installed to.</summary>
    public static bool IsHighRisk(TargetLocation location) =>
        location is TargetLocation.Temp or TargetLocation.Downloads or TargetLocation.Public or TargetLocation.RecycleBin;

    /// <param name="systemRoot">The Windows folder (e.g. <c>C:\Windows</c>); null = only a <c>\Windows\</c> segment counts.</param>
    public static TargetLocation Classify(string path, string? systemRoot)
    {
        ArgumentNullException.ThrowIfNull(path);
        string plain = ExactPath.StripPrefix(path);
        switch (FileNameRules.ClassifyFolder(plain))
        {
            case RiskyFolder.Temp:
                return TargetLocation.Temp;
            case RiskyFolder.Downloads:
                return TargetLocation.Downloads;
            case RiskyFolder.AppData:
                return TargetLocation.AppData;
        }

        var parts = plain.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3)
        {
            return TargetLocation.Other; // a file directly in a drive root
        }

        if (Is(parts[1], "$Recycle.Bin"))
        {
            return TargetLocation.RecycleBin;
        }

        if (Is(parts[1], "Users"))
        {
            return parts.Length >= 4 && Is(parts[2], "Public") ? TargetLocation.Public
                : parts.Length >= 4 ? TargetLocation.UserProfile
                : TargetLocation.Other;
        }

        if (IsUnder(plain, systemRoot) || (systemRoot is null && Is(parts[1], "Windows")))
        {
            return TargetLocation.Windows;
        }

        if (Is(parts[1], "Program Files") || Is(parts[1], "Program Files (x86)"))
        {
            return TargetLocation.ProgramFiles;
        }

        return Is(parts[1], "ProgramData") ? TargetLocation.ProgramData : TargetLocation.Other;
    }

    /// <summary>True if <paramref name="path"/> is inside <paramref name="folder"/> (case-insensitive, whole components).</summary>
    public static bool IsUnder(string path, string? folder)
    {
        if (string.IsNullOrEmpty(folder))
        {
            return false;
        }

        string root = ExactPath.StripPrefix(folder).TrimEnd('\\');
        string plain = ExactPath.StripPrefix(path);
        return root.Length >= 2 && plain.Length > root.Length + 1 && plain.StartsWith(root, StringComparison.OrdinalIgnoreCase)
            && plain[root.Length] == '\\';
    }

    private static bool Is(string a, string b) => a.Equals(b, StringComparison.OrdinalIgnoreCase);
}
