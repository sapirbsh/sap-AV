using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SapAV.Core.Tests.TestSupport;

/// <summary>
/// Creates a junction (mount-point reparse point) with an arbitrary NT target such as <c>\??\pipe\</c>,
/// which <c>mklink /J</c> refuses. Used to prove the hasher's guarantees don't depend on walking paths.
/// </summary>
internal static class RawJunction
{
    private const uint IoReparseTagMountPoint = 0xA0000003;
    private const uint FsctlSetReparsePoint = 0x000900A4;

    /// <summary>Creates empty directory <paramref name="dir"/> and makes it a junction to <paramref name="ntTarget"/>.</summary>
    /// <returns>Null on success, otherwise the reason it couldn't be created.</returns>
    public static string? TryCreate(string dir, string ntTarget)
    {
        Directory.CreateDirectory(dir);

        var substitute = Encoding.Unicode.GetBytes(ntTarget);
        var print = Array.Empty<byte>();
        int pathBufferBytes = substitute.Length + 2 + print.Length + 2;
        var buffer = new byte[8 + 8 + pathBufferBytes];
        var span = buffer.AsSpan();
        BinaryPrimitives.WriteUInt32LittleEndian(span, IoReparseTagMountPoint);
        BinaryPrimitives.WriteUInt16LittleEndian(span[4..], (ushort)(8 + pathBufferBytes)); // ReparseDataLength
        BinaryPrimitives.WriteUInt16LittleEndian(span[8..], 0);                               // SubstituteNameOffset
        BinaryPrimitives.WriteUInt16LittleEndian(span[10..], (ushort)substitute.Length);     // SubstituteNameLength
        BinaryPrimitives.WriteUInt16LittleEndian(span[12..], (ushort)(substitute.Length + 2)); // PrintNameOffset
        BinaryPrimitives.WriteUInt16LittleEndian(span[14..], (ushort)print.Length);          // PrintNameLength
        substitute.CopyTo(span[16..]);

        using var handle = CreateFileW(dir, 0x40000000 /* GENERIC_WRITE */, 0, IntPtr.Zero, 3 /* OPEN_EXISTING */,
            0x02000000 | 0x00200000 /* BACKUP_SEMANTICS | OPEN_REPARSE_POINT */, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            return $"open failed: {Marshal.GetPInvokeErrorMessage(Marshal.GetLastPInvokeError())}";
        }

        if (!DeviceIoControl(handle, FsctlSetReparsePoint, buffer, buffer.Length, IntPtr.Zero, 0, out _, IntPtr.Zero))
        {
            return $"FSCTL_SET_REPARSE_POINT failed: {Marshal.GetPInvokeErrorMessage(Marshal.GetLastPInvokeError())}";
        }

        return null;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice, uint dwIoControlCode, byte[] lpInBuffer, int nInBufferSize,
        IntPtr lpOutBuffer, int nOutBufferSize, out int lpBytesReturned, IntPtr lpOverlapped);
}
