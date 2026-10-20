using System.Runtime.InteropServices;

namespace SapAV.Core.Yara;

/// <summary>
/// The few libyara functions sap-AV calls, declared directly against the native <c>libyara.dll</c> that
/// dnYara.NativePack ships (YARA 4.1.1, x64). dnYara's own wrappers are not used for compiling or scanning:
/// its <c>AddRuleString</c> marshals rule text as ANSI (mangling UTF-8 text strings), and its scan methods
/// either re-open the file by path or need the whole file in a managed <c>byte[]</c>.
/// </summary>
/// <remarks>
/// Struct layouts are YARA 4.1.1's on x64, where every <c>DECLARE_REFERENCE</c> is an 8-byte union:
/// <c>YR_RULES { arena; rules_table; ... }</c>, <c>YR_RULE { int32 flags; int32 num_atoms; identifier; tags;
/// metas; strings; ns }</c> (48 bytes), <c>YR_META { identifier; string; int64 integer; int32 type; int32 flags }</c>
/// (32 bytes), <c>YR_NAMESPACE { name; ... }</c>. They are only read, never written.
/// </remarks>
internal static unsafe class LibYara
{
    private const string Dll = "libyara";

    public const int ErrorSuccess = 0;
    public const int ErrorInsufficientMemory = 1;
    public const int ErrorCouldNotMapFile = 4;
    public const int ErrorScanTimeout = 26;
    public const int ErrorCallbackError = 28;
    public const int ErrorTooManyMatches = 30;

    public const int CallbackContinue = 0;
    public const int CallbackError = 2;

    public const int CallbackMsgRuleMatching = 1;

    public const int ScanFlagsFastMode = 0x01;
    public const int ScanFlagsReportRulesMatching = 0x08;

    public const int RuleFlagsPrivate = 0x01;
    public const int RuleFlagsNull = 0x04;

    public const int MetaTypeInteger = 1;
    public const int MetaTypeString = 2;
    public const int MetaTypeBoolean = 3;
    public const int MetaFlagsLastInRule = 0x01;

    public const int CompilerErrorLevelError = 0;
    public const int CompilerErrorLevelWarning = 1;

    [StructLayout(LayoutKind.Sequential)]
    public struct YrRules
    {
        public IntPtr Arena;
        public YrRule* RulesTable;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct YrRule
    {
        public int Flags;
        public int NumAtoms;
        public byte* Identifier;
        public byte* Tags;
        public YrMeta* Metas;
        public IntPtr Strings;
        public YrNamespace* Namespace;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct YrMeta
    {
        public byte* Identifier;
        public byte* String;
        public long Integer;
        public int Type;
        public int Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct YrNamespace
    {
        public byte* Name;
    }

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yr_initialize();

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yr_compiler_create(out IntPtr compiler);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void yr_compiler_destroy(IntPtr compiler);

    /// <summary>
    /// <c>void callback(int error_level, const char* file_name, int line_number, const YR_RULE* rule,
    /// const char* message, void* user_data)</c>.
    /// </summary>
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void yr_compiler_set_callback(
        IntPtr compiler,
        delegate* unmanaged[Cdecl]<int, byte*, int, YrRule*, byte*, IntPtr, void> callback,
        IntPtr userData);

    /// <summary>Passing null callbacks disables <c>include</c> ("includes are disabled" compile error).</summary>
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void yr_compiler_set_include_callback(
        IntPtr compiler, IntPtr includeCallback, IntPtr includeFree, IntPtr userData);

    /// <summary>Both strings are NUL-terminated UTF-8. Returns the number of errors.</summary>
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yr_compiler_add_string(IntPtr compiler, byte* rulesString, byte* namespaceName);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yr_compiler_get_rules(IntPtr compiler, out IntPtr rules);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yr_rules_destroy(IntPtr rules);

    /// <summary>
    /// <c>int callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)</c>;
    /// <paramref name="timeoutSeconds"/> 0 means no timeout.
    /// </summary>
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern int yr_rules_scan_mem(
        IntPtr rules,
        byte* buffer,
        nuint bufferSize,
        int flags,
        delegate* unmanaged[Cdecl]<IntPtr, int, IntPtr, IntPtr, int> callback,
        IntPtr userData,
        int timeoutSeconds);

    /// <summary>Reads a NUL-terminated UTF-8 string from native memory (null pointer gives null).</summary>
    public static string? Utf8(byte* text) => text is null ? null : Marshal.PtrToStringUTF8((IntPtr)text);

    private static readonly Lazy<int> Initialized = new(() =>
    {
        if (!Environment.Is64BitProcess)
        {
            throw new PlatformNotSupportedException("The bundled libyara.dll is x64 only.");
        }

        return yr_initialize();
    }, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>
    /// Calls <c>yr_initialize</c> once per process. It is never finalized: compiled rule sets may be in use
    /// until the process exits, and libyara's init is reference-counted anyway.
    /// </summary>
    /// <exception cref="DllNotFoundException">libyara.dll is not next to the application.</exception>
    /// <exception cref="InvalidOperationException">libyara failed to initialize.</exception>
    public static void EnsureInitialized()
    {
        int error = Initialized.Value;
        if (error != ErrorSuccess)
        {
            throw new InvalidOperationException($"yr_initialize failed (YARA error {error}).");
        }
    }
}
