using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using SapAV.Core.Pipe;

namespace SapAV.Core.Tests.Pipe;

public sealed class PipeJsonTests
{
    private static PipeRequest Parse(string json) => JsonSerializer.Deserialize<PipeRequest>(json, PipeJson.Options)!;

    [Fact]
    public void Request_RoundTrips_WithTypedBody()
    {
        var request = new PipeRequest(7, PipeRequestKind.ScanCreate, PipeJson.ToElement(new ScanCreateRequest([@"C:\x"])));
        var back = Parse(Encoding.UTF8.GetString(PipeJson.Serialize(request, PipeProtocol.MaxRequestBytes)));

        Assert.Equal(7, back.Id);
        Assert.Equal(PipeRequestKind.ScanCreate, back.Kind);
        Assert.Equal([@"C:\x"], PipeJson.Body<ScanCreateRequest>(back.Body).Paths);
    }

    [Theory]
    [InlineData("""{"Id":1,"Kind":"Hello","Kind":"ScanList"}""")]                 // duplicate key
    [InlineData("""{"Id":1,"Kind":"Hello","Extra":1}""")]                          // unknown member
    [InlineData("""{"Id":1,"Kind":"hello"}""")]                                    // wrong case
    [InlineData("""{"Id":1,"Kind":0}""")]                                          // enum as number
    [InlineData("""{"Id":1,"Kind":"0"}""")]                                        // quoted number
    [InlineData("""{"Kind":"Hello"}""")]                                           // missing required Id
    [InlineData("""{"Id":"1","Kind":"Hello"}""")]                                  // number as string
    [InlineData("""{"Id":1,"Kind":"Hello",}""")]                                   // trailing comma
    [InlineData("""{"Id":1,/*c*/"Kind":"Hello"}""")]                               // comment
    public void Envelope_RejectsLooseJson(string json)
    {
        Assert.ThrowsAny<JsonException>(() => Parse(json));
    }

    [Fact]
    public void Envelope_RejectsNonPositiveId_AsArgumentException()
    {
        Assert.ThrowsAny<ArgumentException>(() => Parse("""{"Id":0,"Kind":"Hello"}"""));
    }

    [Fact]
    public void Body_RejectsDuplicateKeysUnknownMembersAndNulls()
    {
        // A duplicate inside the body is refused while the envelope is parsed (the JsonElement honours the option).
        Assert.ThrowsAny<JsonException>(() => Parse(
            """{"Id":1,"Kind":"ScanStart","Body":{"JobId":"00000000-0000-0000-0000-000000000001","JobId":"00000000-0000-0000-0000-000000000002"}}"""));
        var unknown = Parse("""{"Id":1,"Kind":"ScanStart","Body":{"JobId":"00000000-0000-0000-0000-000000000001","X":1}}""");
        var nullPaths = Parse("""{"Id":1,"Kind":"ScanCreate","Body":{"Paths":null}}""");

        Assert.ThrowsAny<JsonException>(() => PipeJson.Body<JobRequest>(unknown.Body));
        Assert.ThrowsAny<JsonException>(() => PipeJson.Body<ScanCreateRequest>(nullPaths.Body));
        Assert.ThrowsAny<JsonException>(() => PipeJson.Body<JobRequest>(null));
    }

    [Fact]
    public void Body_ModelValidation_ThrowsArgumentException()
    {
        var bad = Parse("""{"Id":1,"Kind":"ScanGet","Body":{"JobId":"00000000-0000-0000-0000-000000000001","ResultsLimit":100000}}""");
        Assert.ThrowsAny<ArgumentException>(() => PipeJson.Body<ScanGetRequest>(bad.Body));
    }

    [Fact]
    public void Envelope_RejectsDepthOver16()
    {
        string deep = string.Concat(Enumerable.Repeat("{\"a\":", 20)) + "1" + new string('}', 20);
        Assert.ThrowsAny<JsonException>(() => Parse($$"""{"Id":1,"Kind":"Hello","Body":{{deep}}}"""));
    }

    [Fact]
    public void WirePath_FlagsHiddenCharacters_KeepsBidiAsEvidence()
    {
        var path = WirePath.From("C:\\x\\inv\u202Efdp.exe\r");
        Assert.True(path.HasHiddenCharacters);
        Assert.Equal("C:\\x\\inv\u202Efdp.exe\uFFFD", path.Value);
        Assert.False(WirePath.From(@"C:\x\y.txt").HasHiddenCharacters);
    }

    [Fact]
    public async Task Framing_RoundTrips_AndDrainsOversizedFrames()
    {
        using var stream = new MemoryStream();
        await PipeFraming.WriteAsync(stream, new byte[] { 1, 2, 3 }, 10, default);
        await WriteRawAsync(stream, 50, new byte[50]);       // over the cap of 10, drainable
        await PipeFraming.WriteAsync(stream, new byte[] { 9 }, 10, default);
        stream.Position = 0;

        var first = await PipeFraming.ReadAsync(stream, 10, default);
        int length = (await PipeFraming.ReadHeaderAsync(stream, default))!.Value;
        var drained = await PipeFraming.ReadBodyAsync(stream, length, 10, 100, default);
        var third = await PipeFraming.ReadAsync(stream, 10, default);
        var end = await PipeFraming.ReadAsync(stream, 10, default);

        Assert.Equal(new byte[] { 1, 2, 3 }, first.Payload);
        Assert.Equal(PipeFraming.FrameStatus.TooLargeDrained, drained.Status);
        Assert.Equal(new byte[] { 9 }, third.Payload);
        Assert.Equal(PipeFraming.FrameStatus.EndOfStream, end.Status);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MaxValue)]
    public async Task Framing_RefusesBadLengths_BeforeAllocating(int length)
    {
        using var stream = new MemoryStream();
        await WriteRawAsync(stream, length, []);
        stream.Position = 0;
        int header = (await PipeFraming.ReadHeaderAsync(stream, default))!.Value;

        await Assert.ThrowsAsync<PipeProtocolException>(() => PipeFraming.ReadBodyAsync(stream, header, 10, 100, default));
    }

    [Fact]
    public async Task Framing_TruncatedFrame_Throws()
    {
        using var stream = new MemoryStream();
        await WriteRawAsync(stream, 8, new byte[3]);
        stream.Position = 0;
        await Assert.ThrowsAsync<PipeProtocolException>(() => PipeFraming.ReadAsync(stream, 10, default));
    }

    private static async Task WriteRawAsync(Stream stream, int length, byte[] body)
    {
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, length);
        await stream.WriteAsync(header);
        await stream.WriteAsync(body);
    }
}
