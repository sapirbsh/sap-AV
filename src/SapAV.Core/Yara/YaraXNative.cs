using System.Runtime.InteropServices;

namespace SapAV.Core.Yara;

/// <summary>
/// The YARA-X C API (<c>yara_x_capi.dll</c>, pinned version in <c>native/yara-x/YaraX.targets</c>), declared
/// from its <c>yara_x.h</c>. Only the functions sap-AV uses.
/// </summary>
/// <remarks>
/// Threading (from the header): one <c>YRX_RULES</c> may be shared by many scanners, each used from its own
/// thread; a scanner must be destroyed before its rules. sap-AV creates one scanner per scan.
/// Strings are NUL-terminated UTF-8; identifiers/namespaces returned by the API are pointer + length (not
/// NUL-terminated) and live as long as the rules. Callback pointers are only valid during the callback.
/// </remarks>
internal static unsafe class YaraXNative
{
    private const string Dll = "yara_x_capi";

    // YRX_RESULT
    public const int Success = 0;
    public const int SyntaxError = 1;
    public const int ScanTimeout = 4;

    // yrx_compiler_create flags
    public const uint DisableIncludes = 32;

    // YRX_METADATA_TYPE
    public const int MetaI64 = 0;
    public const int MetaF64 = 1;
    public const int MetaBoolean = 2;
    public const int MetaString = 3;
    public const int MetaBytes = 4;

    [StructLayout(LayoutKind.Sequential)]
    public struct YrxBuffer
    {
        public byte* Data;
        public nuint Length;
    }

    /// <summary><c>YRX_METADATA { const char* identifier; enum value_type; union value }</c> (value at offset 16 on x64).</summary>
    [StructLayout(LayoutKind.Explicit)]
    public struct YrxMetadata
    {
        [FieldOffset(0)] public byte* Identifier;
        [FieldOffset(8)] public int ValueType;
        [FieldOffset(16)] public long I64;
        [FieldOffset(16)] public double F64;
        [FieldOffset(16)] public byte Boolean;
        [FieldOffset(16)] public byte* String;
        [FieldOffset(16)] public nuint BytesLength;
        [FieldOffset(24)] public byte* BytesData;
    }

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern byte* yrx_last_error();

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void yrx_buffer_destroy(YrxBuffer* buffer);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yrx_compiler_create(uint flags, out IntPtr compiler);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void yrx_compiler_destroy(IntPtr compiler);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yrx_compiler_add_source_with_origin(IntPtr compiler, byte* source, byte* origin);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yrx_compiler_new_namespace(IntPtr compiler, byte* ns);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yrx_compiler_errors_json(IntPtr compiler, out YrxBuffer* buffer);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yrx_compiler_warnings_json(IntPtr compiler, out YrxBuffer* buffer);

    /// <summary>Builds the added sources (never null per the API) and resets the compiler.</summary>
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern IntPtr yrx_compiler_build(IntPtr compiler);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void yrx_rules_destroy(IntPtr rules);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yrx_rules_iter(IntPtr rules, delegate* unmanaged[Cdecl]<IntPtr, IntPtr, void> callback, IntPtr userData);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yrx_rules_iter_imports(IntPtr rules, delegate* unmanaged[Cdecl]<byte*, IntPtr, void> callback, IntPtr userData);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yrx_rule_identifier(IntPtr rule, out byte* identifier, out nuint length);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yrx_rule_namespace(IntPtr rule, out byte* ns, out nuint length);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yrx_rule_iter_metadata(IntPtr rule, delegate* unmanaged[Cdecl]<YrxMetadata*, IntPtr, void> callback, IntPtr userData);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yrx_rule_iter_tags(IntPtr rule, delegate* unmanaged[Cdecl]<byte*, IntPtr, void> callback, IntPtr userData);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yrx_scanner_create(IntPtr rules, out IntPtr scanner);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void yrx_scanner_destroy(IntPtr scanner);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yrx_scanner_set_timeout(IntPtr scanner, ulong timeoutSeconds);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yrx_scanner_fast_scan(IntPtr scanner, [MarshalAs(UnmanagedType.U1)] bool yes);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yrx_scanner_on_matching_rule(IntPtr scanner, delegate* unmanaged[Cdecl]<IntPtr, IntPtr, void> callback, IntPtr userData);

    /// <summary><paramref name="data"/> may be null when <paramref name="length"/> is 0 (empty data).</summary>
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yrx_scanner_scan(IntPtr scanner, byte* data, nuint length);

    /// <summary>UTF-8 text from pointer + length (not NUL-terminated).</summary>
    public static string Utf8(byte* data, nuint length) =>
        data is null ? string.Empty : System.Text.Encoding.UTF8.GetString(data, checked((int)length));

    /// <summary>NUL-terminated UTF-8 text, or null for a null pointer.</summary>
    public static string? Utf8(byte* text) => text is null ? null : Marshal.PtrToStringUTF8((IntPtr)text);

    /// <summary>The calling thread's last YARA-X error message.</summary>
    public static string LastError() => Utf8(yrx_last_error()) ?? "unknown error";

    /// <summary>Copies a YRX_BUFFER's content as UTF-8 and destroys the buffer.</summary>
    public static string TakeBuffer(YrxBuffer* buffer)
    {
        if (buffer is null)
        {
            return string.Empty;
        }

        try
        {
            return Utf8(buffer->Data, buffer->Length);
        }
        finally
        {
            yrx_buffer_destroy(buffer);
        }
    }

    /// <summary>NUL-terminated UTF-8 bytes for passing a string.</summary>
    public static byte[] ToUtf8z(string value)
    {
        var bytes = new byte[System.Text.Encoding.UTF8.GetByteCount(value) + 1];
        System.Text.Encoding.UTF8.GetBytes(value, bytes);
        return bytes;
    }

    public static void EnsureAvailable()
    {
        if (!Environment.Is64BitProcess)
        {
            throw new PlatformNotSupportedException("The bundled yara_x_capi.dll is x64 only.");
        }
    }
}
