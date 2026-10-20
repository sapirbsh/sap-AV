using System.Security.Cryptography;
using SapAV.Core.Hashing;
using SapAV.Core.Models;
using SapAV.Core.Tests.TestSupport;

namespace SapAV.Core.Tests.Hashing;

/// <summary>
/// Non-regular targets (devices, pipes, symlinks to pipes, directories), offline/cloud files, handle
/// metadata, and detection of files that change while being hashed.
/// </summary>
public sealed class Sha256HasherSpecialTargetTests : IDisposable
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
    private readonly TempDirectory _dir = new();

    /// <summary>Creates a file symlink. Callers are gated by [RequiresFact(Requires.Symlinks)], so failure is a real failure.</summary>
    private static void CreateSymlink(string link, string target) => File.CreateSymbolicLink(link, target);

    public void Dispose() => _dir.Dispose();

    private static byte[] RandomBytes(int count)
    {
        var bytes = new byte[count];
        new Random(99).NextBytes(bytes);
        return bytes;
    }

    /// <summary>Fails instead of hanging if the hasher blocks on a device or pipe.</summary>
    private static async Task<HashResult> WithTimeout(Task<HashResult> task)
    {
        var finished = await Task.WhenAny(task, Task.Delay(Timeout));
        Assert.True(ReferenceEquals(task, finished), "Hashing did not finish in time (blocked on a non-regular target?)");
        return await task;
    }

    // --- Devices and pipes ---

    [Theory]
    [InlineData(@"\\.\NUL")]
    [InlineData("NUL")]
    [InlineData(@"C:\NUL")]
    public async Task NulDevice_IsNotRegularFile(string path)
    {
        var result = await WithTimeout(new Sha256Hasher().HashFileAsync(path));

        Assert.Equal(ScanStatus.Error, result.Status);
        Assert.Equal(HashFailureReason.NotRegularFile, result.FailureReason);
        Assert.Null(result.Sha256);
    }

    [Fact]
    public async Task ConsoleDevice_IsNotRegularFile_OrFailsCleanly()
    {
        // With no console attached, opening CON can fail; either way it must not be hashed or throw.
        var result = await WithTimeout(new Sha256Hasher().HashFileAsync("CON"));

        Assert.False(result.IsHashed);
        Assert.Equal(ScanStatus.Error, result.Status);
    }

    [Fact]
    public async Task NamedPipe_IsNotRegularFile_AndIsNeverOpened()
    {
        await using var probe = new PipeProbe(); // actively waits, so a connect would be seen

        var result = await WithTimeout(new Sha256Hasher().HashFileAsync(probe.Path));

        Assert.Equal(ScanStatus.Error, result.Status);
        Assert.True(result.FailureReason == HashFailureReason.NotRegularFile, $"{result.FailureReason}: {result.ErrorMessage}");
        Assert.False(await probe.WasConnectedAsync());
    }

    [Theory]
    [InlineData("CON")]
    [InlineData("CONIN$")]
    [InlineData("CONOUT$")]
    [InlineData("NUL")]
    [InlineData("COM1")]
    [InlineData("LPT1")]
    [InlineData("AUX")]
    [InlineData("PRN")]
    public void LegacyDeviceNames_ResolveToTheDeviceNamespace(string name)
    {
        // The hasher checks GetFullPath(path) too, so these are rejected before any open.
        Assert.True(Sha256Hasher.IsDeviceNamespacePath(Path.GetFullPath(name)), Path.GetFullPath(name));
    }

    [Theory]
    [InlineData("CON")]
    [InlineData("CONIN$")]
    [InlineData("COM1")]
    [InlineData("LPT1")]
    [InlineData("NUL")]
    public async Task LegacyDeviceNames_AreRejectedBeforeOpening(string name)
    {
        var result = await WithTimeout(new Sha256Hasher().HashFileAsync(name));

        Assert.Equal(HashFailureReason.NotRegularFile, result.FailureReason);
        Assert.Contains("resolves to a device", result.ErrorMessage); // the pre-open check, not the open
    }

    [Theory]
    [InlineData(@"\\.\pipe\x", true)]
    [InlineData(@"\\?\pipe\x", true)]
    [InlineData(@"//./pipe/x", true)]
    [InlineData(@"\\.\NUL", true)]
    [InlineData(@"\\.\PhysicalDrive0", true)]
    [InlineData(@"\\.\C:", true)]           // raw volume
    [InlineData(@"\\?\C:", true)]
    [InlineData(@"\\?\GLOBALROOT\Device\Null", true)]
    [InlineData(@"\??\pipe\x", true)]       // NT form, as stored in symlink targets
    [InlineData(@"\??\C:\x.bin", false)]
    [InlineData(@"\?\pipe\x", false)]       // not a device prefix
    [InlineData(@"\\x\pipe", false)]        // plain UNC server "x"
    [InlineData(@"\\?\C:\Windows\notepad.exe", false)]
    [InlineData(@"\\.\C:\Windows\notepad.exe", false)]
    [InlineData(@"\\?\UNC\server\share\f.bin", false)]
    [InlineData(@"\\?\Volume{12345678-1234-1234-1234-123456789abc}\f.bin", false)]
    [InlineData(@"C:\Windows\notepad.exe", false)]
    [InlineData(@"\\server\share\f.bin", false)]
    [InlineData("NUL", false)] // legacy DOS name: caught via GetFullPath (see LegacyDeviceNames_*)
    public void DeviceNamespacePaths_AreRecognized(string path, bool expected)
    {
        Assert.Equal(expected, Sha256Hasher.IsDeviceNamespacePath(path));
    }

    [Fact]
    public async Task ExtendedLengthPathToRegularFile_IsHashed()
    {
        var data = RandomBytes(64);
        var path = _dir.WriteFile("long-form.bin", data);

        var result = await new Sha256Hasher().HashFileAsync(@"\\?\" + path);

        Assert.True(result.IsHashed, result.ErrorMessage);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(data)), result.Sha256);
    }

    [RequiresFact(Requires.Symlinks)]
    public async Task SymlinkToNamedPipe_IsNotRegularFile_WithNothingWritten()
    {
        // Through a link the pipe may be opened (anonymously); the guarantee is rejection before any I/O.
        // Fuller coverage (chains, junctions, impersonation) is in Sha256HasherLinkTests.
        await using var probe = new PipeProbe();
        var link = _dir.File("looks-like-a-file.bin");
        CreateSymlink(link, probe.Path);

        var result = await WithTimeout(new Sha256Hasher().HashFileAsync(link));

        Assert.False(result.IsHashed);
        Assert.Equal(ScanStatus.Error, result.Status);
        Assert.True(result.FailureReason == HashFailureReason.NotRegularFile, $"{result.FailureReason}: {result.ErrorMessage}");
        Assert.Equal(0, await probe.BytesWrittenByClientAsync());
    }

    [RequiresFact(Requires.Symlinks)]
    public async Task SymlinkChainToNamedPipe_IsNotRegularFile_WithNothingWritten()
    {
        await using var probe = new PipeProbe();
        var inner = _dir.File("inner.bin");
        var outer = _dir.File("outer.bin");
        CreateSymlink(inner, probe.Path);
        CreateSymlink(outer, "inner.bin"); // relative hop

        var result = await WithTimeout(new Sha256Hasher().HashFileAsync(outer));

        Assert.True(result.FailureReason == HashFailureReason.NotRegularFile, $"{result.FailureReason}: {result.ErrorMessage}");
        Assert.Equal(0, await probe.BytesWrittenByClientAsync());
    }

    [RequiresFact(Requires.Symlinks)]
    public async Task SymlinkToRegularFile_IsHashedAsTarget()
    {
        var data = RandomBytes(100);
        var target = _dir.WriteFile("target.bin", data);
        var link = _dir.File("link.bin");
        CreateSymlink(link, target);

        var result = await new Sha256Hasher().HashFileAsync(link);

        Assert.True(result.IsHashed, result.ErrorMessage);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(data)), result.Sha256);
    }

    [Fact]
    public async Task Directory_IsDirectoryError_NotAccessDenied()
    {
        var result = await new Sha256Hasher().HashFileAsync(_dir.Path);

        Assert.Equal(ScanStatus.Error, result.Status);
        Assert.Equal(HashFailureReason.Directory, result.FailureReason);
        Assert.True(result.Attributes?.HasFlag(FileAttributes.Directory));
    }

    [Fact]
    public async Task DirectoryWithTrailingSeparator_IsDirectoryError()
    {
        var result = await new Sha256Hasher().HashFileAsync(_dir.Path + Path.DirectorySeparatorChar);

        Assert.Equal(HashFailureReason.Directory, result.FailureReason);
    }

    // --- Offline / cloud placeholders ---

    [Fact]
    public async Task OfflineFile_IsSkippedOffline_WithoutHashing()
    {
        var path = _dir.WriteFile("offline.bin", RandomBytes(50));
        File.SetAttributes(path, FileAttributes.Offline);
        try
        {
            var result = await new Sha256Hasher().HashFileAsync(path);

            Assert.Equal(ScanStatus.SkippedOffline, result.Status);
            Assert.Equal(HashFailureReason.Offline, result.FailureReason);
            Assert.Null(result.Sha256);
            Assert.True(result.Attributes?.HasFlag(FileAttributes.Offline));

            var scan = result.ToNotScannedResult(new ScanItem(path, ScanTrigger.FullScan), DateTimeOffset.UnixEpoch);
            Assert.Equal(ScanStatus.SkippedOffline, scan.Status);
            Assert.Null(scan.Verdict);
        }
        finally
        {
            File.SetAttributes(path, FileAttributes.Normal);
        }
    }

    [Theory]
    [InlineData(0x00001000, true)]  // FILE_ATTRIBUTE_OFFLINE
    [InlineData(0x00040000, true)]  // FILE_ATTRIBUTE_RECALL_ON_OPEN
    [InlineData(0x00400000, true)]  // FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    [InlineData(0x00400000 | 0x00000020, true)]
    [InlineData(0x00000020, false)] // Archive
    [InlineData(0x00000080, false)] // Normal
    [InlineData(0x00000400, false)] // ReparsePoint alone (e.g. a plain symlink)
    [InlineData(0x00080000, false)] // FILE_ATTRIBUTE_PINNED (content is local)
    public void PlaceholderAttributes_AreDetected(int attributes, bool expected)
    {
        Assert.Equal(expected, Sha256Hasher.IsOfflineOrPlaceholder((FileAttributes)attributes));
    }

    // --- Metadata from the handle ---

    [Fact]
    public async Task HashedFile_CarriesLastWriteAndAttributesFromHandle()
    {
        var path = _dir.WriteFile("meta.bin", RandomBytes(10));
        var lastWrite = new DateTime(2025, 1, 2, 3, 4, 5, DateTimeKind.Utc);
        File.SetLastWriteTimeUtc(path, lastWrite);

        var result = await new Sha256Hasher().HashFileAsync(path);

        Assert.True(result.IsHashed);
        Assert.Equal(lastWrite, result.LastWriteTimeUtc);
        Assert.Equal(DateTimeKind.Utc, result.LastWriteTimeUtc!.Value.Kind);
        Assert.Equal(File.GetAttributes(path), result.Attributes);
        Assert.Equal(10, result.Length);
    }

    [Fact]
    public async Task OversizeFile_StillCarriesMetadata_ForTheCache()
    {
        var path = _dir.WriteFile("big.bin", RandomBytes(200));

        var result = await new Sha256Hasher(maxSizeBytes: 100).HashFileAsync(path);

        Assert.Equal(HashFailureReason.TooLarge, result.FailureReason);
        Assert.Equal(200, result.Length);
        Assert.Equal(File.GetLastWriteTimeUtc(path), result.LastWriteTimeUtc);
        Assert.NotNull(result.Attributes);
    }

    [Fact]
    public async Task StreamHashing_HasNoFileMetadata()
    {
        var result = await new Sha256Hasher().HashStreamAsync(new MemoryStream([1, 2, 3]));

        Assert.Null(result.LastWriteTimeUtc);
        Assert.Null(result.Attributes);
    }

    // --- Changes during hashing ---

    [Fact]
    public async Task FileModifiedDuringHashing_IsChangedDuringHashing_NotHashed()
    {
        var path = _dir.WriteFile("changing.bin", RandomBytes(1000));
        var hasher = new Sha256Hasher(bufferSize: 100)
        {
            BeforeReadHook = async bytesSoFar =>
            {
                if (bytesSoFar == 300)
                {
                    await using var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                    writer.Write(new byte[10]); // same size, different content
                    await writer.FlushAsync();
                    File.SetLastWriteTimeUtc(writer.SafeFileHandle, DateTime.UtcNow.AddMinutes(1));
                }
            },
        };

        var result = await hasher.HashFileAsync(path);

        Assert.Equal(ScanStatus.Error, result.Status);
        Assert.Equal(HashFailureReason.ChangedDuringHashing, result.FailureReason);
        Assert.Null(result.Sha256);
        Assert.False(string.IsNullOrEmpty(result.ErrorMessage));
    }

    [Fact]
    public async Task FileTruncatedDuringHashing_IsChangedDuringHashing()
    {
        var path = _dir.WriteFile("shrinking.bin", RandomBytes(1000));
        var hasher = new Sha256Hasher(bufferSize: 100)
        {
            BeforeReadHook = bytesSoFar =>
            {
                if (bytesSoFar == 200)
                {
                    using var writer = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                    writer.SetLength(500);
                }

                return Task.CompletedTask;
            },
        };

        var result = await hasher.HashFileAsync(path);

        Assert.Equal(HashFailureReason.ChangedDuringHashing, result.FailureReason);
    }

    [Fact]
    public async Task FileGrowingUnderLimitDuringHashing_IsChangedDuringHashing()
    {
        var path = _dir.WriteFile("growing.bin", RandomBytes(300));
        var hasher = new Sha256Hasher(maxSizeBytes: 10_000, bufferSize: 100)
        {
            BeforeReadHook = bytesSoFar =>
            {
                if (bytesSoFar == 100)
                {
                    using var writer = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                    writer.Write(new byte[200]);
                }

                return Task.CompletedTask;
            },
        };

        var result = await hasher.HashFileAsync(path);

        Assert.Equal(HashFailureReason.ChangedDuringHashing, result.FailureReason);
    }

    [Fact]
    public async Task FileGrowingPastLimitDuringHashing_IsTooLarge_NotReadOn()
    {
        var path = _dir.WriteFile("growing-big.bin", RandomBytes(50));
        var hasher = new Sha256Hasher(maxSizeBytes: 100, bufferSize: 10)
        {
            BeforeReadHook = bytesSoFar =>
            {
                if (bytesSoFar == 20)
                {
                    using var writer = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
                    writer.Write(new byte[100_000]);
                }

                return Task.CompletedTask;
            },
        };

        var result = await hasher.HashFileAsync(path);

        Assert.Equal(HashFailureReason.TooLarge, result.FailureReason);
        Assert.Equal(101, result.Length);
    }

    [Fact]
    public async Task UnchangedFile_WithHook_IsHashed()
    {
        var data = RandomBytes(1000);
        var path = _dir.WriteFile("steady.bin", data);
        int calls = 0;
        var hasher = new Sha256Hasher(bufferSize: 100) { BeforeReadHook = _ => { calls++; return Task.CompletedTask; } };

        var result = await hasher.HashFileAsync(path);

        Assert.True(result.IsHashed, result.ErrorMessage);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(data)), result.Sha256);
        Assert.True(calls >= 10);
    }

    // --- HRESULT mapping (exact values) ---

    public static TheoryData<int, HashFailureReason> HResults => new()
    {
        { unchecked((int)0x80070020), HashFailureReason.Locked },             // ERROR_SHARING_VIOLATION
        { unchecked((int)0x80070021), HashFailureReason.Locked },             // ERROR_LOCK_VIOLATION
        { unchecked((int)0x800700E1), HashFailureReason.BlockedByAntivirus }, // ERROR_VIRUS_INFECTED
        { unchecked((int)0x800700E2), HashFailureReason.BlockedByAntivirus }, // ERROR_VIRUS_DELETED
        { unchecked((int)0x8007007B), HashFailureReason.InvalidPath },        // ERROR_INVALID_NAME
        { 0x00000020, HashFailureReason.IoError },                            // bare Win32 code, not an HRESULT
        { unchecked((int)0x80040020), HashFailureReason.IoError },            // same low word, other facility
        { unchecked((int)0x80000021), HashFailureReason.IoError },
        { 0x000000E1, HashFailureReason.IoError },
        { unchecked((int)0x80070005), HashFailureReason.IoError },            // E_ACCESSDENIED as plain IOException
        { unchecked((int)0x80004005), HashFailureReason.IoError },            // E_FAIL
    };

    [Theory]
    [MemberData(nameof(HResults))]
    public async Task IOExceptionHResult_IsMappedExactly(int hresult, HashFailureReason expected)
    {
        var stream = new ScriptedStream(RandomBytes(100)) { FailWith = new IOException("x", hresult) };

        var result = await new Sha256Hasher().HashStreamAsync(stream);

        Assert.Equal(expected, result.FailureReason);
        Assert.Equal(HashResult.StatusFor(expected), result.Status);
    }

    [Fact]
    public async Task BlockedByAntivirus_HasDistinctReason_AndErrorStatus()
    {
        var stream = new ScriptedStream(RandomBytes(100))
        {
            FailWith = new IOException("Operation did not complete successfully because the file contains a virus.",
                unchecked((int)0x800700E1)),
        };

        var result = await new Sha256Hasher().HashStreamAsync(stream);

        Assert.Equal(HashFailureReason.BlockedByAntivirus, result.FailureReason);
        Assert.Equal(ScanStatus.Error, result.Status);
        Assert.Contains("virus", result.ErrorMessage);
    }

    [Theory]
    [InlineData(2, HashFailureReason.NotFound)]          // ERROR_FILE_NOT_FOUND
    [InlineData(3, HashFailureReason.NotFound)]          // ERROR_PATH_NOT_FOUND
    [InlineData(15, HashFailureReason.NotFound)]         // ERROR_INVALID_DRIVE
    [InlineData(53, HashFailureReason.NotFound)]         // ERROR_BAD_NETPATH
    [InlineData(67, HashFailureReason.NotFound)]         // ERROR_BAD_NET_NAME
    [InlineData(5, HashFailureReason.AccessDenied)]      // ERROR_ACCESS_DENIED
    [InlineData(32, HashFailureReason.Locked)]           // ERROR_SHARING_VIOLATION
    [InlineData(33, HashFailureReason.Locked)]           // ERROR_LOCK_VIOLATION
    [InlineData(225, HashFailureReason.BlockedByAntivirus)] // ERROR_VIRUS_INFECTED
    [InlineData(226, HashFailureReason.BlockedByAntivirus)] // ERROR_VIRUS_DELETED
    [InlineData(123, HashFailureReason.InvalidPath)]     // ERROR_INVALID_NAME
    [InlineData(161, HashFailureReason.InvalidPath)]     // ERROR_BAD_PATHNAME
    [InlineData(206, HashFailureReason.InvalidPath)]     // ERROR_FILENAME_EXCED_RANGE
    [InlineData(1921, HashFailureReason.InvalidPath)]    // ERROR_CANT_RESOLVE_FILENAME (link loop)
    [InlineData(231, HashFailureReason.NotRegularFile)]  // ERROR_PIPE_BUSY
    [InlineData(1920, HashFailureReason.IoError)]        // ERROR_CANT_ACCESS_FILE
    [InlineData(31, HashFailureReason.IoError)]          // ERROR_GEN_FAILURE
    [InlineData(0x20 + 0x10000, HashFailureReason.IoError)] // not a Win32 code we know: no masking
    public void CreateFileErrors_AreMappedExactly(int win32Error, HashFailureReason expected)
    {
        Assert.Equal(expected, Sha256Hasher.MapWin32Error(win32Error));
    }

    [Fact]
    public void HashingFlags_AreExplicit()
    {
        const uint overlapped = 0x40000000, sequential = 0x08000000, backup = 0x02000000, noRecallAndSqos = 0x00100000;

        Assert.Equal(overlapped | sequential | backup | noRecallAndSqos, NativeFile.HashingFlags);
        Assert.Equal(0u, NativeFile.HashingFlags & 0x00030000); // SQOS level bits = SecurityAnonymous (0)
        Assert.Equal(0u, NativeFile.HashingFlags & 0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT not set: links are followed
    }

    [Theory]
    [InlineData(typeof(FileNotFoundException), HashFailureReason.NotFound)]
    [InlineData(typeof(DirectoryNotFoundException), HashFailureReason.NotFound)]
    [InlineData(typeof(DriveNotFoundException), HashFailureReason.NotFound)]
    [InlineData(typeof(PathTooLongException), HashFailureReason.InvalidPath)]
    [InlineData(typeof(UnauthorizedAccessException), HashFailureReason.AccessDenied)]
    [InlineData(typeof(EndOfStreamException), HashFailureReason.IoError)]
    public void ExceptionTypes_AreClassified(Type type, HashFailureReason expected)
    {
        var ex = (Exception)Activator.CreateInstance(type)!;

        Assert.True(Sha256Hasher.TryClassify(ex, out var reason));
        Assert.Equal(expected, reason);
    }

    [Theory]
    [InlineData(typeof(OperationCanceledException))]
    [InlineData(typeof(TaskCanceledException))]
    [InlineData(typeof(ArgumentException))]
    [InlineData(typeof(NotSupportedException))]
    [InlineData(typeof(InvalidOperationException))]
    public void NonIoExceptions_AreNotClassified(Type type)
    {
        Assert.False(Sha256Hasher.TryClassify((Exception)Activator.CreateInstance(type)!, out _));
    }

    // --- Buffer sizing ---

    [Fact]
    public void DefaultBuffer_IsPowerOfTwo_SoThePoolReturnsExactlyThatSize()
    {
        Assert.Equal(128 * 1024, Sha256Hasher.DefaultBufferSize);
        Assert.True(System.Numerics.BitOperations.IsPow2(Sha256Hasher.DefaultBufferSize));

        var rented = System.Buffers.ArrayPool<byte>.Shared.Rent(Sha256Hasher.DefaultBufferSize);
        try
        {
            Assert.Equal(Sha256Hasher.DefaultBufferSize, rented.Length);
        }
        finally
        {
            System.Buffers.ArrayPool<byte>.Shared.Return(rented);
        }
    }

    [Fact]
    public async Task ReadsNeverExceedConfiguredBufferSize_EvenIfPoolReturnsMore()
    {
        // 1000 is not a power of two: the pool hands out 1024, but each read must ask for at most 1000.
        var stream = new ScriptedStream(RandomBytes(10_000));

        var result = await new Sha256Hasher(bufferSize: 1000).HashStreamAsync(stream);

        Assert.True(result.IsHashed);
        Assert.Equal(10, stream.ReadCount - 1); // 10 full reads + the final 0-byte read
    }
}
