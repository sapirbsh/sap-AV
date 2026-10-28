using System.Text;

namespace SapAV.Core.Tests.TestSupport;

/// <summary>
/// Builds synthetic shell link (<c>.lnk</c>) bytes at test time ([MS-SHLLINK]): an ID list (My Computer, a drive, file
/// entries with version-9 long names), LinkInfo (local or network), StringData and an EnvironmentVariableDataBlock.
/// Only the parts the parser reads; nothing here points at anything real.
/// </summary>
internal sealed class ShellLinkBuilder
{
    private static readonly Guid LinkClsid = new("00021401-0000-0000-C000-000000000046");
    private static readonly Guid MyComputer = new("20D04FE0-3AEA-1069-A2D8-08002B30309D");

    public string? IdListPath { get; init; }

    public string? LocalBasePath { get; init; }

    public string? NetworkShare { get; init; }

    public string? RelativePath { get; init; }

    public string? Arguments { get; init; }

    public string? EnvironmentTarget { get; init; }

    public byte[] Build()
    {
        uint flags = 0x80; // IsUnicode
        var body = new List<byte>();
        if (IdListPath is not null)
        {
            flags |= 0x1;
            var list = IdList(IdListPath);
            body.AddRange(BitConverter.GetBytes((ushort)list.Length));
            body.AddRange(list);
        }

        if (LocalBasePath is not null || NetworkShare is not null)
        {
            flags |= 0x2;
            body.AddRange(LinkInfo());
        }

        if (RelativePath is not null)
        {
            flags |= 0x8;
            body.AddRange(StringData(RelativePath));
        }

        if (Arguments is not null)
        {
            flags |= 0x20;
            body.AddRange(StringData(Arguments));
        }

        if (EnvironmentTarget is not null)
        {
            flags |= 0x200;
            var block = new byte[0x314];
            BitConverter.GetBytes(0x314u).CopyTo(block, 0);
            BitConverter.GetBytes(0xA0000001u).CopyTo(block, 4);
            Encoding.Latin1.GetBytes(EnvironmentTarget).CopyTo(block, 8);
            Encoding.Unicode.GetBytes(EnvironmentTarget).CopyTo(block, 8 + 260);
            body.AddRange(block);
        }

        body.AddRange(new byte[4]); // terminal extra-data block

        var header = new byte[0x4C];
        BitConverter.GetBytes(0x4Cu).CopyTo(header, 0);
        LinkClsid.ToByteArray().CopyTo(header, 4);
        BitConverter.GetBytes(flags).CopyTo(header, 20);
        return [.. header, .. body];
    }

    private static byte[] StringData(string value) => [.. BitConverter.GetBytes((ushort)value.Length), .. Encoding.Unicode.GetBytes(value)];

    private static byte[] IdList(string path)
    {
        var items = new List<byte>();
        var root = new byte[20];
        BitConverter.GetBytes((ushort)20).CopyTo(root, 0);
        root[2] = 0x1F;
        root[3] = 0x50;
        MyComputer.ToByteArray().CopyTo(root, 4);
        items.AddRange(root);

        var drive = new byte[25];
        BitConverter.GetBytes((ushort)25).CopyTo(drive, 0);
        drive[2] = 0x2F;
        Encoding.ASCII.GetBytes(path[..3]).CopyTo(drive, 3);
        items.AddRange(drive);

        var names = path[3..].Split('\\', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < names.Length; i++)
        {
            items.AddRange(FileEntry(names[i], directory: i < names.Length - 1));
        }

        items.AddRange(new byte[2]); // terminal ID
        return [.. items];
    }

    /// <summary>A file entry: an 8.3-style short name, then a version-9 0xBEEF0004 block with the long name.</summary>
    private static byte[] FileEntry(string name, bool directory)
    {
        var item = new List<byte> { 0, 0, (byte)(directory ? 0x31 : 0x32), 0 };
        item.AddRange(new byte[10]); // size, date, attributes
        string shortName = name.Length > 12 ? "LONGNA~1" : name.ToUpperInvariant();
        item.AddRange(Encoding.ASCII.GetBytes(shortName));
        item.Add(0);
        if (item.Count % 2 == 1)
        {
            item.Add(0);
        }

        int extensionOffset = item.Count;
        var block = new List<byte>(new byte[46]);
        block.AddRange(Encoding.Unicode.GetBytes(name));
        block.AddRange(new byte[2]);
        block.AddRange(BitConverter.GetBytes((ushort)extensionOffset));
        var blockArray = block.ToArray();
        BitConverter.GetBytes((ushort)blockArray.Length).CopyTo(blockArray, 0);
        BitConverter.GetBytes((ushort)9).CopyTo(blockArray, 2);
        BitConverter.GetBytes(0xBEEF0004u).CopyTo(blockArray, 4);
        item.AddRange(blockArray);
        var result = item.ToArray();
        BitConverter.GetBytes((ushort)result.Length).CopyTo(result, 0);
        return result;
    }

    private byte[] LinkInfo()
    {
        const int headerSize = 0x1C;
        var volume = new byte[0x11];
        BitConverter.GetBytes(0x11u).CopyTo(volume, 0);
        BitConverter.GetBytes(3u).CopyTo(volume, 4);
        BitConverter.GetBytes(0x10u).CopyTo(volume, 12);

        var tail = new List<byte>();
        uint linkFlags = 0;
        int volumeOffset = 0, baseOffset = 0, networkOffset = 0;
        if (LocalBasePath is not null)
        {
            linkFlags |= 1;
            volumeOffset = headerSize + tail.Count;
            tail.AddRange(volume);
            baseOffset = headerSize + tail.Count;
            tail.AddRange(Encoding.Latin1.GetBytes(LocalBasePath));
            tail.Add(0);
        }

        if (NetworkShare is not null)
        {
            linkFlags |= 2;
            networkOffset = headerSize + tail.Count;
            var network = new List<byte>();
            network.AddRange(BitConverter.GetBytes(0u)); // size, patched below
            network.AddRange(BitConverter.GetBytes(0u));
            network.AddRange(BitConverter.GetBytes(0x14u));
            network.AddRange(BitConverter.GetBytes(0u));
            network.AddRange(BitConverter.GetBytes(0u));
            network.AddRange(Encoding.Latin1.GetBytes(NetworkShare));
            network.Add(0);
            var bytes = network.ToArray();
            BitConverter.GetBytes((uint)bytes.Length).CopyTo(bytes, 0);
            tail.AddRange(bytes);
        }

        int suffixOffset = headerSize + tail.Count;
        tail.Add(0); // empty common path suffix

        var info = new byte[headerSize];
        BitConverter.GetBytes((uint)(headerSize + tail.Count)).CopyTo(info, 0);
        BitConverter.GetBytes((uint)headerSize).CopyTo(info, 4);
        BitConverter.GetBytes(linkFlags).CopyTo(info, 8);
        BitConverter.GetBytes((uint)volumeOffset).CopyTo(info, 12);
        BitConverter.GetBytes((uint)baseOffset).CopyTo(info, 16);
        BitConverter.GetBytes((uint)networkOffset).CopyTo(info, 20);
        BitConverter.GetBytes((uint)suffixOffset).CopyTo(info, 24);
        return [.. info, .. tail];
    }
}
