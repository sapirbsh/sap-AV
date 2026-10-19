namespace SapAV.Core.Tests.TestSupport;

/// <summary>A unique temp folder for one test, deleted (best effort) on dispose.</summary>
internal sealed class TempDirectory : IDisposable
{
    public TempDirectory()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sapav-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public string File(string name) => System.IO.Path.Combine(Path, name);

    public string WriteFile(string name, byte[] content)
    {
        var path = File(name);
        System.IO.File.WriteAllBytes(path, content);
        return path;
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
            // Best effort: never fail a test because cleanup raced with another process.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
