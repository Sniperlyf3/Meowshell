using Meowshell;

namespace Meowshell.Tests;

public sealed class MeowshellAgentProtocolTests
{
    // Regression test for the ReadFrameAsync refactor: it used to read the
    // whole frame body (header + payload) into one buffer, then copy the
    // payload portion out into a second, separately-allocated buffer -- at
    // the 64MiB frame limit, two ~64MiB allocations live at once for a
    // single incoming frame. It now reads the header and payload directly
    // into their final buffers. This proves the refactor still produces the
    // exact same (Type, ChannelId, Payload) for a hand-written frame.
    [Fact]
    public async Task ReadFrameAsyncRoundTripsTypeChannelIdAndPayload()
    {
        var payload = System.Text.Encoding.UTF8.GetBytes("{\"msg\":\"connected\"}");
        using var stream = new MemoryStream();
        await MeowshellAgentProtocol.WriteFrameAsync(
            stream,
            new MeowshellAgentProtocol.AgentFrame(MeowshellAgentProtocol.FrameTypeControl, 7, payload),
            CancellationToken.None);
        stream.Position = 0;

        var frame = await MeowshellAgentProtocol.ReadFrameAsync(stream, CancellationToken.None);

        Assert.NotNull(frame);
        Assert.Equal(MeowshellAgentProtocol.FrameTypeControl, frame!.Value.Type);
        Assert.Equal(7u, frame.Value.ChannelId);
        Assert.Equal(payload, frame.Value.Payload);
    }

    [Fact]
    public async Task ReadFrameAsyncRoundTripsAnEmptyPayload()
    {
        using var stream = new MemoryStream();
        await MeowshellAgentProtocol.WriteFrameAsync(
            stream,
            new MeowshellAgentProtocol.AgentFrame(MeowshellAgentProtocol.FrameTypeData, 42, []),
            CancellationToken.None);
        stream.Position = 0;

        var frame = await MeowshellAgentProtocol.ReadFrameAsync(stream, CancellationToken.None);

        Assert.NotNull(frame);
        Assert.Equal(MeowshellAgentProtocol.FrameTypeData, frame!.Value.Type);
        Assert.Equal(42u, frame.Value.ChannelId);
        Assert.Empty(frame.Value.Payload);
    }

    [Fact]
    public async Task ReadFrameAsyncReturnsNullOnCleanEof()
    {
        using var stream = new MemoryStream();
        var frame = await MeowshellAgentProtocol.ReadFrameAsync(stream, CancellationToken.None);
        Assert.Null(frame);
    }

    [Fact]
    public async Task ReadFrameAsyncThrowsOnAnOverlongFrame()
    {
        var lenBuf = new byte[4];
        // One past MaxFrameLength (64MiB) plus the 5-byte header, as the
        // wire encodes it (header + payload length, not payload alone).
        uint tooLong = (64 << 20) + 1;
        lenBuf[0] = (byte)(tooLong >> 24);
        lenBuf[1] = (byte)(tooLong >> 16);
        lenBuf[2] = (byte)(tooLong >> 8);
        lenBuf[3] = (byte)tooLong;
        using var stream = new MemoryStream(lenBuf);

        var ex = await Assert.ThrowsAsync<TailcatException>(
            () => MeowshellAgentProtocol.ReadFrameAsync(stream, CancellationToken.None));
        Assert.Contains("exceeds", ex.Message);
    }

    [Fact]
    public async Task ReadFrameAsyncThrowsOnConnectionClosedMidFrame()
    {
        using var stream = new MemoryStream();
        await MeowshellAgentProtocol.WriteFrameAsync(
            stream,
            new MeowshellAgentProtocol.AgentFrame(MeowshellAgentProtocol.FrameTypeControl, 1, "hello"u8.ToArray()),
            CancellationToken.None);
        // Truncate: keep the 4-byte length prefix but drop the last byte of
        // the frame body it promises.
        var truncated = stream.ToArray()[..^1];
        using var truncatedStream = new MemoryStream(truncated);

        await Assert.ThrowsAsync<TailcatException>(
            () => MeowshellAgentProtocol.ReadFrameAsync(truncatedStream, CancellationToken.None));
    }
}
