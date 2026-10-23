using SapAV.Core.Blocklist;
using SapAV.Core.Scanning.Isolation;
using SapAV.Core.Yara;

namespace SapAV.Engine.Sandbox;

/// <summary>Supplies the rule package (YARA rule files + blocklist) the workers load. Fake it in tests.</summary>
public interface IScanRulesSource
{
    /// <summary>Reads the current rule files and blocklist. Never compiles or parses them (the worker does).</summary>
    Task<WorkerLoadRules> LoadAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Reads <see cref="SandboxOptions.RulesDirectory"/> (<c>*.yar</c>, same files as <see cref="YaraRuleSet.LoadDirectory"/>)
/// and <see cref="SandboxOptions.BlocklistPath"/> as raw bytes, with the usual size caps. A missing directory or file is
/// an empty package plus a read error, so the engine still starts and warns (B3 M5). The files are opened by path, which
/// is acceptable only once D3 keeps them in the ACL-protected <c>%ProgramData%\sap-AV</c> folder.
/// </summary>
public sealed class DirectoryScanRulesSource(SandboxOptions options) : IScanRulesSource
{
    public async Task<WorkerLoadRules> LoadAsync(CancellationToken cancellationToken = default)
    {
        var readErrors = new List<string>();
        IReadOnlyList<YaraRuleFile> files = [];
        string directory = options.ResolvedRulesDirectory;
        try
        {
            files = YaraRuleSet.ReadDirectoryFiles(directory, out var errors, cancellationToken);
            readErrors.AddRange(errors.Select(e => e.ToString()));
        }
        catch (DirectoryNotFoundException)
        {
            readErrors.Add($"The rules directory {directory} doesn't exist.");
        }

        byte[] blocklist = [];
        string blocklistPath = options.ResolvedBlocklistPath;
        try
        {
            blocklist = await ReadCappedAsync(blocklistPath, HashBlocklist.DefaultMaxSizeBytes, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            readErrors.Add($"The blocklist {blocklistPath} could not be read: {ex.Message}");
        }

        return new WorkerLoadRules
        {
            RuleFiles = files.Select(f => new WorkerRuleFile { Name = f.Name, Content = f.Content }).ToArray(),
            ReadErrors = readErrors.Take(WorkerLimits.MaxRuleErrors).ToArray(),
            Blocklist = blocklist,
        };
    }

    private static async Task<byte[]> ReadCappedAsync(string path, long maxBytes, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, useAsync: true);
        if (stream.Length > maxBytes)
        {
            throw new InvalidDataException($"The file is {stream.Length} bytes, over the {maxBytes}-byte limit.");
        }

        var buffer = new byte[stream.Length];
        await stream.ReadExactlyAsync(buffer, cancellationToken).ConfigureAwait(false);
        return buffer;
    }
}
