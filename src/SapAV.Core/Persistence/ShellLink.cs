using System.Buffers.Binary;
using System.Text;

namespace SapAV.Core.Persistence;

/// <summary>What a shell link (<c>.lnk</c>) file says about its target, as stored (nothing resolved or expanded).</summary>
/// <param name="IdListPath">The path built from the LinkTargetIDList (My Computer, a drive, file entries); null if absent or not a file-system path.</param>
/// <param name="IdListUnsupported">An ID list is there, but its items aren't a plain drive path (a special folder, a network place...).</param>
/// <param name="LinkInfoPath">LinkInfo LocalBasePath + CommonPathSuffix; null if absent or ignored (ForceNoLinkInfo).</param>
/// <param name="LinkInfoNetworkShare">LinkInfo's network share name (<c>\\server\share</c>), when the target is on a share.</param>
/// <param name="EnvironmentTarget">The EnvironmentVariableDataBlock target (e.g. <c>%windir%\notepad.exe</c>), unexpanded.</param>
public sealed record ShellLinkInfo(
    string? IdListPath,
    bool IdListUnsupported,
    string? LinkInfoPath,
    string? LinkInfoNetworkShare,
    string? EnvironmentTarget,
    string? RelativePath,
    string? WorkingDirectory,
    string? Arguments);

/// <summary>
/// A minimal, bounded parser of the shell link binary format ([MS-SHLLINK]) for the Startup folder collector (ROADMAP C2).
/// </summary>
/// <remarks>
/// Why a parser and not IShellLink: resolving a link through the shell as SYSTEM can activate shell extensions / COM
/// handlers chosen by whoever wrote the file, and IShellLink::Resolve may search the disk or contact a server (link
/// tracking, network paths). This parser reads only the bytes of a file the engine already opened without following
/// links: managed code, every offset and length checked against the buffer, input capped at <see cref="MaxSize"/>,
/// item / block / string counts capped, no recursion. Malformed input returns null with a reason; it never throws.
/// It reads the header, the LinkTargetIDList (root My Computer, drive, file-entry items with their long names), LinkInfo
/// (local base path + suffix, or a network share), StringData (relative path, working directory, arguments) and the
/// EnvironmentVariableDataBlock. ANSI strings are decoded as Latin-1 (the Unicode forms are preferred when present).
/// </remarks>
public static class ShellLinkParser
{
    public const int MaxSize = 256 * 1024;
    public const int MaxStringLength = 8192;

    private const int HeaderSize = 0x4C;
    private const uint HasLinkTargetIdList = 0x1;
    private const uint HasLinkInfo = 0x2;
    private const uint HasName = 0x4;
    private const uint HasRelativePath = 0x8;
    private const uint HasWorkingDir = 0x10;
    private const uint HasArguments = 0x20;
    private const uint HasIconLocation = 0x40;
    private const uint IsUnicode = 0x80;
    private const uint ForceNoLinkInfo = 0x100;
    private const uint EnvironmentBlockSignature = 0xA0000001;

    private static readonly Guid LinkClsid = new("00021401-0000-0000-C000-000000000046");
    private static readonly Guid MyComputer = new("20D04FE0-3AEA-1069-A2D8-08002B30309D");

    /// <summary>Parses a shell link; null (and <paramref name="error"/>) when it isn't a well-formed link.</summary>
    public static ShellLinkInfo? Parse(ReadOnlySpan<byte> data, out string? error)
    {
        try
        {
            return ParseCore(data, out error);
        }
        catch (Exception ex) when (ex is ArgumentException or IndexOutOfRangeException or DecoderFallbackException or OverflowException)
        {
            error = "The shortcut is malformed.";
            return null;
        }
    }

    private static ShellLinkInfo? ParseCore(ReadOnlySpan<byte> data, out string? error)
    {
        error = null;
        if (data.Length > MaxSize)
        {
            error = "The shortcut is larger than the size cap.";
            return null;
        }

        if (data.Length < HeaderSize || BinaryPrimitives.ReadUInt32LittleEndian(data) != HeaderSize
            || new Guid(data.Slice(4, 16)) != LinkClsid)
        {
            error = "Not a shell link (bad header).";
            return null;
        }

        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(data[20..]);
        int offset = HeaderSize;
        string? idListPath = null;
        bool idListUnsupported = false;
        if ((flags & HasLinkTargetIdList) != 0)
        {
            int size = U16(data, offset);
            offset += 2;
            if (!Fits(data, offset, size))
            {
                error = "The ID list runs past the end of the file.";
                return null;
            }

            idListPath = ParseIdList(data.Slice(offset, size), out idListUnsupported);
            offset += size;
        }

        string? linkInfoPath = null;
        string? share = null;
        if ((flags & HasLinkInfo) != 0)
        {
            int size = checked((int)U32(data, offset));
            if (size < 0x1C || !Fits(data, offset, size))
            {
                error = "The LinkInfo structure is malformed.";
                return null;
            }

            if ((flags & ForceNoLinkInfo) == 0)
            {
                (linkInfoPath, share) = ParseLinkInfo(data.Slice(offset, size));
            }

            offset += size;
        }

        bool unicode = (flags & IsUnicode) != 0;
        string? relative = null, workingDir = null, arguments = null;
        foreach (uint flag in new[] { HasName, HasRelativePath, HasWorkingDir, HasArguments, HasIconLocation })
        {
            if ((flags & flag) == 0)
            {
                continue;
            }

            int count = U16(data, offset);
            offset += 2;
            int bytes = count * (unicode ? 2 : 1);
            if (!Fits(data, offset, bytes))
            {
                error = "A shortcut string runs past the end of the file.";
                return null;
            }

            string value = Decode(data.Slice(offset, bytes), unicode);
            offset += bytes;
            switch (flag)
            {
                case HasRelativePath: relative = value; break;
                case HasWorkingDir: workingDir = value; break;
                case HasArguments: arguments = value; break;
            }
        }

        string? environment = ParseExtraData(data, offset);
        return new ShellLinkInfo(idListPath, idListUnsupported, linkInfoPath, share, environment, relative, workingDir, arguments);
    }

    /// <summary>Root My Computer (optional), a drive item, then file-entry items; anything else is unsupported (null).</summary>
    private static string? ParseIdList(ReadOnlySpan<byte> list, out bool unsupported)
    {
        unsupported = false;
        var parts = new List<string>();
        string? drive = null;
        int offset = 0;
        for (int items = 0; items < 64; items++)
        {
            if (offset + 2 > list.Length)
            {
                break;
            }

            int size = U16(list, offset);
            if (size == 0)
            {
                break;
            }

            if (size < 3 || !Fits(list, offset, size))
            {
                unsupported = true;
                return null;
            }

            var item = list.Slice(offset, size);
            byte type = item[2];
            if (type == 0x1F && size >= 20 && items == 0 && new Guid(item.Slice(4, 16)) == MyComputer)
            {
                // root: My Computer
            }
            else if ((type & 0x70) == 0x20 && drive is null && parts.Count == 0)
            {
                drive = NullTerminatedAscii(item[3..]);
                if (drive.Length < 2 || !char.IsAsciiLetter(drive[0]) || drive[1] != ':')
                {
                    unsupported = true;
                    return null;
                }

                drive = drive[..2] + "\\";
            }
            else if ((type & 0x70) == 0x30 && drive is not null && FileEntryName(item, type) is { } name)
            {
                parts.Add(name);
            }
            else
            {
                unsupported = true;
                return null;
            }

            offset += size;
        }

        if (drive is null)
        {
            unsupported = offset > 0;
            return null;
        }

        return drive + string.Join('\\', parts);
    }

    /// <summary>A file entry's long name (from its 0xBEEF0004 extension block), else its primary (short) name.</summary>
    private static string? FileEntryName(ReadOnlySpan<byte> item, byte type)
    {
        const int nameOffset = 14; // size(2) type(1) unknown(1) filesize(4) date(4) attributes(2)
        if (item.Length <= nameOffset)
        {
            return null;
        }

        bool unicodeName = (type & 0x04) != 0;
        string shortName;
        int end;
        if (unicodeName)
        {
            shortName = NullTerminatedUtf16(item[nameOffset..], out int chars);
            end = nameOffset + (chars + 1) * 2;
        }
        else
        {
            shortName = NullTerminatedAscii(item[nameOffset..]);
            end = nameOffset + shortName.Length + 1;
            end += end % 2; // padded to an even offset
        }

        if (item.Length >= 4 && LongName(item, end) is { } longName)
        {
            return longName;
        }

        return IsFileName(shortName) ? shortName : null;
    }

    private static string? LongName(ReadOnlySpan<byte> item, int searchFrom)
    {
        int extension = U16(item, item.Length - 2); // offset of the first extension block
        if (extension < searchFrom || extension + 8 > item.Length - 2)
        {
            extension = searchFrom; // older writers: the block follows the primary name
        }

        if (extension + 8 > item.Length || U32(item, extension + 4) != 0xBEEF0004)
        {
            return null;
        }

        int blockSize = U16(item, extension);
        int version = U16(item, extension + 2);
        int nameAt = version >= 9 ? 46 : version >= 8 ? 42 : version >= 7 ? 38 : version >= 3 ? 20 : -1;
        if (nameAt < 0 || blockSize > item.Length - extension || nameAt + 2 > blockSize)
        {
            return null;
        }

        var name = NullTerminatedUtf16(item.Slice(extension + nameAt, blockSize - nameAt), out _);
        return IsFileName(name) ? name : null;
    }

    private static (string? Path, string? Share) ParseLinkInfo(ReadOnlySpan<byte> info)
    {
        int headerSize = (int)U32(info, 4);
        uint linkFlags = U32(info, 8);
        string? suffix = null;
        string? basePath = null;
        if (headerSize >= 0x24)
        {
            int baseUnicode = (int)U32(info, 0x1C);
            int suffixUnicode = (int)U32(info, 0x20);
            if ((linkFlags & 1) != 0 && baseUnicode > 0 && baseUnicode < info.Length)
            {
                basePath = NullTerminatedUtf16(info[baseUnicode..], out _);
            }

            if (suffixUnicode > 0 && suffixUnicode < info.Length)
            {
                suffix = NullTerminatedUtf16(info[suffixUnicode..], out _);
            }
        }

        int baseAnsi = (int)U32(info, 0x10);
        int suffixAnsi = (int)U32(info, 0x18);
        if (basePath is null && (linkFlags & 1) != 0 && baseAnsi > 0 && baseAnsi < info.Length)
        {
            basePath = NullTerminatedAscii(info[baseAnsi..]);
        }

        if (suffix is null && suffixAnsi > 0 && suffixAnsi < info.Length)
        {
            suffix = NullTerminatedAscii(info[suffixAnsi..]);
        }

        string? share = null;
        int network = (int)U32(info, 0x14);
        if ((linkFlags & 2) != 0 && network > 0 && network + 0x14 <= info.Length)
        {
            int netNameOffset = (int)U32(info, network + 8);
            if (netNameOffset > 0 && network + netNameOffset < info.Length)
            {
                share = NullTerminatedAscii(info[(network + netNameOffset)..]);
            }
        }

        string? path = basePath is { Length: > 0 }
            ? (string.IsNullOrEmpty(suffix) ? basePath : basePath.TrimEnd('\\') + "\\" + suffix)
            : null;
        return (path, share is { Length: > 0 } ? (string.IsNullOrEmpty(suffix) ? share : share.TrimEnd('\\') + "\\" + suffix) : null);
    }

    private static string? ParseExtraData(ReadOnlySpan<byte> data, int offset)
    {
        for (int blocks = 0; blocks < 64 && offset + 8 <= data.Length; blocks++)
        {
            int size = (int)U32(data, offset);
            if (size < 8 || !Fits(data, offset, size))
            {
                return null; // the terminal block (size < 4) or a broken one
            }

            if (U32(data, offset + 4) == EnvironmentBlockSignature && size >= 8 + 260 + 520)
            {
                var unicode = NullTerminatedUtf16(data.Slice(offset + 8 + 260, 520), out _);
                return unicode.Length > 0 ? unicode : NullTerminatedAscii(data.Slice(offset + 8, 260));
            }

            offset += size;
        }

        return null;
    }

    private static bool IsFileName(string name) =>
        name.Length is > 0 and <= 255 && name.IndexOfAny(['\\', '/', ':', '*', '?', '"', '<', '>', '|']) < 0 && !name.Any(char.IsControl);

    private static bool Fits(ReadOnlySpan<byte> data, int offset, int length) =>
        offset >= 0 && length >= 0 && offset <= data.Length && length <= data.Length - offset;

    private static int U16(ReadOnlySpan<byte> data, int offset) =>
        Fits(data, offset, 2) ? BinaryPrimitives.ReadUInt16LittleEndian(data[offset..]) : throw new ArgumentException("Truncated.");

    private static uint U32(ReadOnlySpan<byte> data, int offset) =>
        Fits(data, offset, 4) ? BinaryPrimitives.ReadUInt32LittleEndian(data[offset..]) : throw new ArgumentException("Truncated.");

    private static string Decode(ReadOnlySpan<byte> bytes, bool unicode)
    {
        var text = unicode ? Encoding.Unicode.GetString(bytes[..(bytes.Length & ~1)]) : Encoding.Latin1.GetString(bytes);
        return text.Length > MaxStringLength ? text[..MaxStringLength] : text;
    }

    private static string NullTerminatedAscii(ReadOnlySpan<byte> bytes)
    {
        int end = bytes.IndexOf((byte)0);
        var slice = end < 0 ? bytes : bytes[..end];
        return Encoding.Latin1.GetString(slice[..Math.Min(slice.Length, MaxStringLength)]);
    }

    private static string NullTerminatedUtf16(ReadOnlySpan<byte> bytes, out int chars)
    {
        int count = bytes.Length / 2;
        chars = count;
        for (int i = 0; i < count; i++)
        {
            if (bytes[2 * i] == 0 && bytes[(2 * i) + 1] == 0)
            {
                chars = i;
                break;
            }
        }

        return Encoding.Unicode.GetString(bytes[..(Math.Min(chars, MaxStringLength) * 2)]);
    }
}

/// <summary>The target a shell link runs, chosen as the shell does, with the disagreement between its sources noted.</summary>
/// <param name="Path">The chosen target (unexpanded sources expanded), not yet normalized; null when there is none.</param>
/// <param name="Network">The target is on a network share (never resolved by the engine).</param>
/// <param name="Mismatch">The ID list, LinkInfo and environment block name different files.</param>
public sealed record ShellLinkTarget(string? Path, bool Network, bool Mismatch)
{
    /// <summary>
    /// Order: the environment block (the shell rebuilds the target from it when present), the ID list (what the shell
    /// opens), LinkInfo, then the relative path against <paramref name="linkFolder"/>.
    /// </summary>
    public static ShellLinkTarget Select(ShellLinkInfo info, EnvironmentBlock environment, string linkFolder)
    {
        ArgumentNullException.ThrowIfNull(info);
        ArgumentNullException.ThrowIfNull(environment);
        string? expanded = info.EnvironmentTarget is { Length: > 0 } env ? environment.Expand(env, out _) : null;
        var candidates = new[] { expanded, info.IdListPath, info.LinkInfoPath }.Where(c => !string.IsNullOrWhiteSpace(c)).ToList();
        bool mismatch = candidates.Select(c => c!.TrimEnd('\\').ToUpperInvariant()).Distinct().Count() > 1;
        if (candidates.Count > 0)
        {
            string chosen = candidates[0]!;
            return new ShellLinkTarget(chosen, chosen.StartsWith(@"\\", StringComparison.Ordinal), mismatch);
        }

        if (info.LinkInfoNetworkShare is { } share)
        {
            return new ShellLinkTarget(share, true, mismatch);
        }

        if (info.RelativePath is { Length: > 0 } relative && !relative.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return new ShellLinkTarget(System.IO.Path.Join(linkFolder, relative), false, mismatch);
        }

        return new ShellLinkTarget(null, false, mismatch);
    }
}
