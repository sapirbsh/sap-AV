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
        // A few short retries: removing a junction (e.g. to the pipe namespace) or a file another process
        // (indexer, Defender) still has open leaves it delete-pending for a moment, so the folder isn't empty yet.
        for (int attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                if (Directory.Exists(Path))
                {
                    Directory.Delete(Path, recursive: true);
                }

                return;
            }
            catch (IOException)
            {
                // Best effort: never fail a test because cleanup raced with another process.
            }
            catch (UnauthorizedAccessException)
            {
            }

            Thread.Sleep(20 * (attempt + 1));
        }
    }
}
