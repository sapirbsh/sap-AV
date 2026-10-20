using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using SapAV.Core.Hashing;
using SapAV.Core.Tests.TestSupport;
using Xunit.Abstractions;

namespace SapAV.Core.Tests.Hashing;

/// <summary>
/// Path forms around the device-namespace check: GLOBALROOT, raw volumes, the <c>\\?\UNC\</c> form,
/// UNC paths that reach a local pipe over SMB loopback, drive letters aliased to a device, and Windows 11
/// legacy names inside a folder (<c>dir\CON</c> is an ordinary file, <c>dir\NUL</c> still is not).
/// </summary>
public sealed class Sha256HasherDevicePathGapTests(ITestOutputHelper output) : IDisposable
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
    private readonly TempDirectory _dir = new();

    public void Dispose() => _dir.Dispose();

    private static async Task<HashResult> WithTimeout(Task<HashResult> task)
    {
        var finished = await Task.WhenAny(task, Task.Delay(Timeout));
        Assert.True(ReferenceEquals(task, finished), "Hashing did not finish in time");
        return await task;
    }

    private static byte[] Data(int n)
    {
        var b = new byte[n];
        new Random(11).NextBytes(b);
        return b;
    }

    private static string Sha(byte[] data) => Convert.ToHexStringLower(SHA256.HashData(data));

    private static void AssertRejectedBeforeOpen(HashResult result)
    {
        Assert.True(result.FailureReason == HashFailureReason.NotRegularFile, $"{result.FailureReason}: {result.ErrorMessage}");
        Assert.True(
            result.ErrorMessage!.Contains("Device-namespace path") || result.ErrorMessage.Contains("resolves to a device"),
            $"expected the pre-open check, got: {result.ErrorMessage}");
    }

    // --- GLOBALROOT ---

    [Fact]
    public async Task GlobalRoot_ToARealFile_IsRejectedBeforeOpen()
    {
        // Documents current behavior: every \\?\GLOBALROOT\ path is treated as a device path, even one that
        // names a real file on a disk volume (conservative: GLOBALROOT reaches any NT device).
        var data = Data(64);
        var path = _dir.WriteFile("gr.bin", data);
        var drive = Path.GetPathRoot(path)!.TrimEnd('\\'); // "C:"
        var nt = QueryDosDevice(drive);
        Assert.NotNull(nt);
        var globalRoot = @"\\?\GLOBALROOT" + nt + path[drive.Length..];
        Assert.True((await new Sha256Hasher().HashFileAsync(@"\\?\" + path)).IsHashed); // control: the file is hashable

        var result = await WithTimeout(new Sha256Hasher().HashFileAsync(globalRoot));
        output.WriteLine($"{globalRoot} -> {result.FailureReason}: {result.ErrorMessage}");

        AssertRejectedBeforeOpen(result);
    }

    [Theory]
    [InlineData(@"\\?\GLOBALROOT\Device\NamedPipe\")]
    [InlineData(@"\\.\GLOBALROOT\Device\NamedPipe\")]
    [InlineData(@"\\?\GLOBALROOT\??\pipe\")]
    public async Task GlobalRoot_ToNamedPipe_IsNeverOpened(string prefix)
    {
        await using var probe = new PipeProbe();

        var result = await WithTimeout(new Sha256Hasher().HashFileAsync(prefix + probe.Name));

        AssertRejectedBeforeOpen(result);
        Assert.False(await probe.WasConnectedAsync());
    }

    // --- Raw volumes and disks ---

    [Theory]
    [InlineData(@"\\.\C:")]
    [InlineData(@"\\?\C:")]
    [InlineData(@"//./C:")]
    [InlineData(@"\\.\c:")]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData(@"\\.\HarddiskVolume1")]
    public async Task RawVolumeOrDisk_IsRejectedBeforeOpen(string path)
    {
        var result = await WithTimeout(new Sha256Hasher().HashFileAsync(path));

        AssertRejectedBeforeOpen(result);
        Assert.Null(result.Length);
    }

    [Fact]
    public async Task VolumeGuidWithoutTrailingSeparator_IsRawVolume_RejectedBeforeOpen()
    {
        var guidRoot = GetVolumeGuidPath(Path.GetPathRoot(_dir.Path)!); // \\?\Volume{...}\
        Assert.NotNull(guidRoot);

        var result = await WithTimeout(new Sha256Hasher().HashFileAsync(guidRoot!.TrimEnd('\\')));

        AssertRejectedBeforeOpen(result);
    }

    [Fact]
    public async Task VolumeGuidPathToAFile_IsHashed()
    {
        var data = Data(99);
        var path = _dir.WriteFile("vol.bin", data);
        var root = Path.GetPathRoot(path)!;
        var guidRoot = GetVolumeGuidPath(root);
        Assert.NotNull(guidRoot);

        var result = await new Sha256Hasher().HashFileAsync(guidRoot + path[root.Length..]);

        Assert.True(result.IsHashed, $"{result.FailureReason}: {result.ErrorMessage}");
        Assert.Equal(Sha(data), result.Sha256);
    }

    [Theory]
    [InlineData(@"\\.\C:\")]
    [InlineData(@"\\?\C:\")]
    public async Task DriveRootInDeviceForm_IsDirectory_NotRawVolume(string path)
    {
        var result = await WithTimeout(new Sha256Hasher().HashFileAsync(path));

        Assert.Equal(HashFailureReason.Directory, result.FailureReason);
    }

    // --- \\?\UNC\ and plain UNC ---

    [RequiresFact(Requires.AdminShare)]
    public async Task LongUncForm_ToALocalAdminShare_IsAllowedAndHashed()
    {
        // \\?\UNC\server\share\file is treated as a regular file path (allowed), like \\server\share\file.
        var data = Data(128);
        var path = _dir.WriteFile("unc.bin", data);
        var share = $@"localhost\{path[0]}$" + path[2..];

        foreach (var candidate in new[] { @"\\" + share, @"\\?\UNC\" + share })
        {
            var result = await WithTimeout(new Sha256Hasher().HashFileAsync(candidate));
            output.WriteLine($"{candidate} -> {result.FailureReason}: {result.ErrorMessage}");
            Assert.True(result.IsHashed, $"{candidate}: {result.FailureReason}: {result.ErrorMessage}");
            Assert.Equal(Sha(data), result.Sha256);
        }
    }

    public static TheoryData<string> UncPipePrefixes => new()
    {
        @"\\localhost\pipe\",
        @"\\127.0.0.1\pipe\",
        @"\\?\UNC\localhost\pipe\",
        @"\\.\UNC\localhost\pipe\",
        @"//localhost/pipe/",
    };

    [Theory]
    [MemberData(nameof(UncPipePrefixes))]
    public async Task UncPathToALocalPipe_IsNotRegularFile_WithoutIo(string prefix)
    {
        // These pass the string check (UNC is a file form). If the SMB loopback reaches the pipe, the
        // open-time GetFileType check must still reject it without reading or writing.
        await using var probe = new PipeProbe(acceptRemoteClients: true);
        int reads = 0;
        var hasher = new Sha256Hasher { BeforeReadHook = _ => { reads++; return Task.CompletedTask; } };

        var result = await WithTimeout(hasher.HashFileAsync(prefix + probe.Name));
        bool connected = await probe.WasConnectedAsync();
        output.WriteLine($"{prefix}<name> -> {result.FailureReason}: {result.ErrorMessage}; server saw a connect: {connected}");

        Assert.False(result.IsHashed);
        Assert.Equal(0, reads);
        Assert.Equal(0, await probe.BytesWrittenByClientAsync());
        if (connected)
        {
            Assert.True(result.FailureReason == HashFailureReason.NotRegularFile, $"{result.FailureReason}: {result.ErrorMessage}");
        }
    }

    [RequiresTheory(Requires.SmbLoopbackPipe)]
    [InlineData(@"\\localhost\pipe\")]
    [InlineData(@"\\?\UNC\localhost\pipe\")]
    public async Task UncPathToALocalPipe_WithHashingFlags_CannotBeImpersonated(string prefix)
    {
        // Same as HashingFlags_GiveThePipeServerOnlyAnonymousImpersonation, but over SMB loopback, where the
        // impersonation level travels in the SMB CREATE request.
        await using var probe = new PipeProbe(acceptRemoteClients: true);
        using (var handle = PipeProbe.OpenClient(prefix + probe.Name, NativeFile.HashingFlags))
        {
            await using var client = new FileStream(handle, FileAccess.ReadWrite, 0, isAsync: true);
            await client.WriteAsync(new byte[] { 1 }).AsTask().WaitAsync(Timeout);

            var identity = await probe.ClientIdentityAfterOneByteAsync().WaitAsync(Timeout);
            output.WriteLine($"identity seen by server: {identity ?? "(impersonation failed)"}");

            Assert.True(identity is null || identity.Contains("ANONYMOUS", StringComparison.OrdinalIgnoreCase),
                $"pipe server impersonated the client as '{identity}'");
        }
    }

    // --- Drive letter aliased to the pipe device (per-session DOS device, no admin needed) ---

    [Fact]
    public async Task DriveLetterAliasedToThePipeDevice_IsNotRegularFile_WithoutIo()
    {
        await using var probe = new PipeProbe();
        var letter = FreeDriveLetter();
        if (letter is null)
        {
            output.WriteLine("SKIPPED at runtime (no assertions; not checkable at discovery): no free drive letter right now.");
            return;
        }

        const uint RawTargetPath = 0x1, RemoveDefinition = 0x2, ExactMatchOnRemove = 0x4;
        const string target = @"\Device\NamedPipe";
        if (!DefineDosDeviceW(RawTargetPath, letter, target))
        {
            output.WriteLine($"SKIPPED at runtime (no assertions; not checkable at discovery): DefineDosDevice failed, Win32 error {Marshal.GetLastPInvokeError()}");
            return;
        }

        try
        {
            int reads = 0;
            var hasher = new Sha256Hasher { BeforeReadHook = _ => { reads++; return Task.CompletedTask; } };

            var result = await WithTimeout(hasher.HashFileAsync($@"{letter}\{probe.Name}"));
            output.WriteLine($"{letter}\\<name> -> {result.FailureReason}: {result.ErrorMessage}; connected: {await probe.WasConnectedAsync()}");

            Assert.True(result.FailureReason == HashFailureReason.NotRegularFile, $"{result.FailureReason}: {result.ErrorMessage}");
            Assert.Equal(0, reads);
            Assert.Equal(0, await probe.BytesWrittenByClientAsync());
        }
        finally
        {
            Assert.True(DefineDosDeviceW(RawTargetPath | RemoveDefinition | ExactMatchOnRemove, letter, target),
                $"could not remove test drive alias {letter}: {Marshal.GetLastPInvokeError()}");
        }
    }

    // --- Windows 11: legacy device names inside a folder ---

    [RequiresTheory(Requires.Windows11)]
    [InlineData("CON")]
    [InlineData("con")]
    [InlineData("COM1")]
    [InlineData("LPT1")]
    [InlineData("AUX")]
    [InlineData("CON.txt")]
    [InlineData("nul.txt")]
    public async Task LegacyNameInsideAFolder_OnWindows11_IsAnOrdinaryFile_AndIsHashed(string name)
    {
        // Before Windows 11 these names map to devices in any folder (see the requirement).
        var data = Data(42);
        var path = _dir.File(name);
        File.WriteAllBytes(@"\\?\" + path, data); // the \\?\ form creates the file whatever the name
        try
        {
            output.WriteLine($"GetFullPath({path}) = {Path.GetFullPath(path)}");

            var result = await WithTimeout(new Sha256Hasher().HashFileAsync(path));

            Assert.True(result.IsHashed, $"{result.FailureReason}: {result.ErrorMessage}");
            Assert.Equal(Sha(data), result.Sha256);
        }
        finally
        {
            File.Delete(@"\\?\" + path);
        }
    }

    [Fact]
    public async Task FileNamedNul_IsOnlyHashableInTheExtendedForm()
    {
        // Documents a limit (not a hasher bug): Windows 11 still maps dir\NUL to \\.\NUL, so a real file
        // named NUL is NotRegularFile by its normal path and is only hashable as \\?\dir\NUL. Callers
        // (the engine) that hand over normal paths will not hash such a file.
        var data = Data(42);
        var path = _dir.File("NUL");
        var extended = @"\\?\" + path;
        File.WriteAllBytes(extended, data);
        try
        {
            var normal = await WithTimeout(new Sha256Hasher().HashFileAsync(path));
            var viaExtended = await WithTimeout(new Sha256Hasher().HashFileAsync(extended));
            output.WriteLine($"normal path -> {normal.FailureReason}: {normal.ErrorMessage}");

            Assert.Equal(HashFailureReason.NotRegularFile, normal.FailureReason);
            Assert.True(viaExtended.IsHashed, $"{viaExtended.FailureReason}: {viaExtended.ErrorMessage}");
            Assert.Equal(Sha(data), viaExtended.Sha256);
        }
        finally
        {
            File.Delete(extended);
        }
    }

    // --- Native helpers ---

    private static string? QueryDosDevice(string drive)
    {
        var buffer = new char[1024];
        int n = QueryDosDeviceW(drive, buffer, buffer.Length);
        return n == 0 ? null : new string(buffer, 0, Array.IndexOf(buffer, '\0'));
    }

    private static string? GetVolumeGuidPath(string root)
    {
        var sb = new StringBuilder(64);
        return GetVolumeNameForVolumeMountPointW(root, sb, sb.Capacity) ? sb.ToString() : null;
    }

    private static string? FreeDriveLetter()
    {
        for (char c = 'Z'; c >= 'M'; c--)
        {
            var d = c + ":";
            if (QueryDosDevice(d) is null && !Directory.Exists(d + @"\"))
            {
                return d;
            }
        }

        return null;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern int QueryDosDeviceW(string lpDeviceName, [Out] char[] lpTargetPath, int ucchMax);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DefineDosDeviceW(uint dwFlags, string lpDeviceName, string lpTargetPath);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeNameForVolumeMountPointW(string lpszVolumeMountPoint, StringBuilder lpszVolumeName, int cchBufferLength);
}
