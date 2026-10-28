using SapAV.Core.Persistence;
using SapAV.Core.Tests.TestSupport;

namespace SapAV.Core.Tests.Persistence;

/// <summary>The bounded .lnk parser (ROADMAP C2) on synthetic links built at test time.</summary>
public class ShellLinkParserTests
{
    private static readonly EnvironmentBlock Environment = new(new Dictionary<string, string> { ["windir"] = @"C:\Windows" });

    [Fact]
    public void IdList_GivesTheLongNamePath_AndArguments()
    {
        var bytes = new ShellLinkBuilder { IdListPath = @"C:\Program Files\Vendor Tools\updater.exe", Arguments = "--quiet --tray" }.Build();

        var info = ShellLinkParser.Parse(bytes, out var error);

        Assert.Null(error);
        Assert.Equal(@"C:\Program Files\Vendor Tools\updater.exe", info!.IdListPath);
        Assert.Equal("--quiet --tray", info.Arguments);
        var target = ShellLinkTarget.Select(info, Environment, @"C:\Startup");
        Assert.Equal(@"C:\Program Files\Vendor Tools\updater.exe", target.Path);
        Assert.False(target.Mismatch);
    }

    [Fact]
    public void LinkInfoOnly_AndRelativePathOnly_AreUsed()
    {
        var linkInfo = ShellLinkParser.Parse(new ShellLinkBuilder { LocalBasePath = @"C:\Tools\a.exe" }.Build(), out _)!;
        var relative = ShellLinkParser.Parse(new ShellLinkBuilder { RelativePath = @"..\b.exe" }.Build(), out _)!;

        Assert.Equal(@"C:\Tools\a.exe", ShellLinkTarget.Select(linkInfo, Environment, @"C:\Startup").Path);
        Assert.Equal(@"C:\Startup\..\b.exe", ShellLinkTarget.Select(relative, Environment, @"C:\Startup").Path);
    }

    [Fact]
    public void EnvironmentBlock_WinsAndIsExpanded_DisagreementIsFlagged()
    {
        var bytes = new ShellLinkBuilder
        {
            EnvironmentTarget = @"%windir%\notepad.exe",
            IdListPath = @"C:\Users\Public\evil.exe",
            LocalBasePath = @"C:\Windows\notepad.exe",
        }.Build();

        var target = ShellLinkTarget.Select(ShellLinkParser.Parse(bytes, out _)!, Environment, @"C:\Startup");

        Assert.Equal(@"C:\Windows\notepad.exe", target.Path);
        Assert.True(target.Mismatch);
    }

    [Fact]
    public void NetworkShare_IsReportedAsNetwork()
    {
        var info = ShellLinkParser.Parse(new ShellLinkBuilder { NetworkShare = @"\\server\share" }.Build(), out _)!;

        var target = ShellLinkTarget.Select(info, Environment, @"C:\Startup");

        Assert.True(target.Network);
        Assert.Equal(@"\\server\share", target.Path);
    }

    [Fact]
    public void MalformedTruncatedAndOversized_ReturnNull_NeverThrow()
    {
        var good = new ShellLinkBuilder { IdListPath = @"C:\a\b.exe", Arguments = "x", LocalBasePath = @"C:\a\b.exe" }.Build();

        Assert.Null(ShellLinkParser.Parse(new byte[10], out var shortError));
        Assert.NotNull(shortError);
        Assert.Null(ShellLinkParser.Parse(new byte[ShellLinkParser.MaxSize + 1], out _));
        for (int length = 0; length < good.Length; length += 7)
        {
            ShellLinkParser.Parse(good.AsSpan(0, length), out _); // truncated anywhere: no exception
        }

        var random = new Random(42);
        for (int i = 0; i < 3000; i++)
        {
            var mutated = (byte[])good.Clone();
            for (int j = 0; j < 4; j++)
            {
                mutated[random.Next(0x14, mutated.Length)] = (byte)random.Next(256);
            }

            ShellLinkParser.Parse(mutated, out _);
        }
    }
}
