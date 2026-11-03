using System.ComponentModel;
using System.Runtime.InteropServices;

namespace SapAV.Core.VirusTotal;

/// <summary>
/// Machine-scope DPAPI (<c>CryptProtectData</c> with <c>CRYPTPROTECT_LOCAL_MACHINE</c>), with caller entropy. P/Invoke rather
/// than <c>System.Security.Cryptography.ProtectedData</c>: that assembly ships only in the WindowsDesktop shared framework
/// (or as a NuGet package), not in Microsoft.NETCore.App. Same call as the quarantine's metadata key (B2).
/// </summary>
/// <remarks>
/// Machine scope binds the blob to this Windows installation; any process on the machine can unprotect it, so the
/// real protection on the machine is the folder ACL (SYSTEM + Administrators). The entropy keeps one purpose's blob
/// from being accepted for another.
/// </remarks>
internal static unsafe class MachineDpapi
{
    private const uint UiForbidden = 0x1;
    private const uint LocalMachine = 0x4;

    /// <exception cref="Win32Exception">DPAPI failed.</exception>
    public static byte[] Protect(byte[] data, byte[] entropy) => Run(data, entropy, protect: true);

    /// <exception cref="Win32Exception">The blob is corrupt, from another machine, or has other entropy.</exception>
    public static byte[] Unprotect(byte[] blob, byte[] entropy) => Run(blob, entropy, protect: false);

    private static byte[] Run(byte[] data, byte[] entropy, bool protect)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(entropy);
        fixed (byte* d = data)
        fixed (byte* e = entropy)
        {
            var input = new DataBlob { Size = (uint)data.Length, Data = (IntPtr)d };
            var extra = new DataBlob { Size = (uint)entropy.Length, Data = (IntPtr)e };
            DataBlob output = default;
            bool ok = protect
                ? CryptProtectData(&input, null, &extra, IntPtr.Zero, IntPtr.Zero, UiForbidden | LocalMachine, &output)
                : CryptUnprotectData(&input, IntPtr.Zero, &extra, IntPtr.Zero, IntPtr.Zero, UiForbidden, &output);
            if (!ok)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            }

            try
            {
                var result = new byte[output.Size];
                Marshal.Copy(output.Data, result, 0, result.Length);
                return result;
            }
            finally
            {
                if (output.Data != IntPtr.Zero)
                {
                    new Span<byte>((void*)output.Data, (int)output.Size).Clear();
                    LocalFree(output.Data);
                }
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public uint Size;
        public IntPtr Data;
    }

    [DllImport("crypt32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern bool CryptProtectData(DataBlob* dataIn, char* description, DataBlob* entropy, IntPtr reserved,
        IntPtr prompt, uint flags, DataBlob* dataOut);

    [DllImport("crypt32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern bool CryptUnprotectData(DataBlob* dataIn, IntPtr description, DataBlob* entropy, IntPtr reserved,
        IntPtr prompt, uint flags, DataBlob* dataOut);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr LocalFree(IntPtr memory);
}
