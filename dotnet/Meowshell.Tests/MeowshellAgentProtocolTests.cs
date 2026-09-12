using System.Diagnostics;
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

file sealed class ThrowingControlSink : IAgentChannelSink
{
    public Exception? Faulted;
    public Task OnDataAsync(byte stream, ReadOnlyMemory<byte> data) => Task.CompletedTask;
    public Task OnControlAsync(AgentMessage msg) => throw new InvalidOperationException("boom from OnControlAsync");
    public void OnFault(Exception ex) => Faulted = ex;
}

public sealed class AgentChannelDataPumpTests
{
    // Regression test: AgentChannelDataPump's background pump task is
    // fire-and-forget (Task.Run, never awaited or observed). Its read loop
    // already swallowed exceptions from OnDataAsync on purpose, but an
    // exception from OnControlAsync had nothing catching it at all -- it
    // just unobserved-faulted the pump task and silently killed the loop,
    // leaving whatever this channel's sink represents (an upload, a
    // download, a shell) hung forever waiting for a completion signal that
    // would now never arrive.
    [Fact]
    public async Task ControlHandlerExceptionReachesOnFaultInsteadOfVanishing()
    {
        var inner = new ThrowingControlSink();
        var pump = new AgentChannelDataPump(inner);

        await pump.OnControlAsync(new AgentMessage { Msg = "exit_status" });

        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(2);
        while (inner.Faulted is null && DateTime.UtcNow < deadline)
            await Task.Delay(10);

        Assert.NotNull(inner.Faulted);
        Assert.IsType<InvalidOperationException>(inner.Faulted);
    }

    // Regression test for N1: OnDataAsync used to await its internal bounded
    // channel's own WriteAsync directly, which blocks once the channel's
    // 32-item capacity fills and stays blocked for as long as this
    // channel's own consumer (RunAsync's pump loop, stuck awaiting the
    // stalled inner sink here) never drains it. That awaited call ran
    // synchronously inside MeowshellAgentConnection's single shared
    // RunReadLoopAsync (via HandleDataAsync), so one stalled channel froze
    // frame delivery for every other multiplexed channel on the same
    // connection -- not just this one. Feeds far more data than the queue's
    // capacity through a pump whose inner sink never returns from
    // OnDataAsync, and asserts every single call still returns essentially
    // immediately (the old behavior would have hung the call indefinitely,
    // since nothing ever frees a slot) and that this channel alone ends up
    // faulted once its capacity is actually exceeded.
    [Fact]
    public async Task OnDataAsyncNeverBlocksEvenWhenTheInnerSinkStalls()
    {
        var sink = new StallingSink();
        var pump = new AgentChannelDataPump(sink);

        const int attempts = 200;
        var maxCallDuration = TimeSpan.Zero;
        for (var i = 0; i < attempts; i++)
        {
            var sw = Stopwatch.StartNew();
            await pump.OnDataAsync(0, new byte[] { 1, 2, 3 }).WaitAsync(TimeSpan.FromSeconds(2));
            sw.Stop();
            if (sw.Elapsed > maxCallDuration) maxCallDuration = sw.Elapsed;
        }

        Assert.True(maxCallDuration < TimeSpan.FromSeconds(1),
            $"a single OnDataAsync call took {maxCallDuration}, want it to never block on the stalled inner sink");

        // The bounded queue (32 items) can only ever absorb so much while
        // its one consumer is permanently stuck on the first item -- well
        // under the 200 fed above, so backpressure must have kicked in and
        // failed this channel by now.
        Assert.NotNull(sink.Faulted);
        Assert.Contains("not being consumed fast enough", sink.Faulted!.Message);
    }

    // Same property for OnControlAsync, which used to await the same
    // WriteAsync for a control message (e.g. a delayed exit_status arriving
    // right as the channel's data queue is already saturated).
    [Fact]
    public async Task OnControlAsyncNeverBlocksEvenWhenTheInnerSinkStalls()
    {
        var sink = new StallingSink();
        var pump = new AgentChannelDataPump(sink);

        // Saturate the queue with data first, the same way the data-only
        // test does, so a subsequent control message actually lands on a
        // full queue instead of just sailing through.
        for (var i = 0; i < 64; i++)
        {
            await pump.OnDataAsync(0, new byte[] { 1 }).WaitAsync(TimeSpan.FromSeconds(2));
        }

        await pump.OnControlAsync(new AgentMessage { Msg = "exit_status" }).WaitAsync(TimeSpan.FromSeconds(2));

        Assert.NotNull(sink.Faulted);
    }

    // A channel whose own consumer keeps up must behave exactly as before:
    // this is the independence half of the property -- no false-positive
    // faulting or dropped data just because backpressure handling now
    // exists. Waits for each item to actually reach the inner sink before
    // sending the next, so the queue never has a real chance to fill up
    // regardless of how the background pump happens to get scheduled --
    // deliberately not racing thread-pool timing, since the property this
    // checks (a consumer that isn't stuck sees no faults or drops) doesn't
    // depend on how fast the writes themselves come in.
    [Fact]
    public async Task OnDataAsyncDeliversNormallyWhenTheInnerSinkKeepsUp()
    {
        var received = new List<byte[]>();
        Exception? faulted = null;
        var sink = new DelegatingSink(
            onData: (stream, data) => { received.Add(data.ToArray()); return Task.CompletedTask; },
            onFault: ex => faulted = ex);
        var pump = new AgentChannelDataPump(sink);

        const int total = 50;
        for (var i = 0; i < total; i++)
        {
            await pump.OnDataAsync(0, new byte[] { (byte)i }).WaitAsync(TimeSpan.FromSeconds(2));

            var expected = i + 1;
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(2);
            while (received.Count < expected && DateTime.UtcNow < deadline)
            {
                await Task.Delay(1);
            }
        }

        Assert.Equal(total, received.Count);
        Assert.Null(faulted);
    }
}

// A sink whose OnDataAsync never completes on its own -- stands in for any
// real downstream consumer that stops making progress: a forward whose peer
// stops reading, a download whose destination stalls on disk I/O, anything
// past IAgentChannelSink.OnDataAsync.
file sealed class StallingSink : IAgentChannelSink
{
    private readonly TaskCompletionSource _gate = new();
    public volatile Exception? Faulted;

    public Task OnDataAsync(byte stream, ReadOnlyMemory<byte> data) => _gate.Task;
    public Task OnControlAsync(AgentMessage msg) => Task.CompletedTask;
    public void OnFault(Exception ex) => Faulted = ex;
}

file sealed class DelegatingSink(Func<byte, ReadOnlyMemory<byte>, Task> onData, Action<Exception> onFault) : IAgentChannelSink
{
    public Task OnDataAsync(byte stream, ReadOnlyMemory<byte> data) => onData(stream, data);
    public Task OnControlAsync(AgentMessage msg) => Task.CompletedTask;
    public void OnFault(Exception ex) => onFault(ex);
}
