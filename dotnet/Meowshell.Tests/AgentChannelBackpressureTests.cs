using System.IO.Pipelines;
using Meowshell;

namespace Meowshell.Tests;

public sealed class AgentChannelBackpressureTests
{
    private sealed class BufferedPipeSink : IAgentChannelSink
    {
        private readonly Pipe _pipe = AgentPipeFactory.CreateOutputPipe();
        public Stream Output => _pipe.Reader.AsStream();

        public async Task OnDataAsync(byte stream, ReadOnlyMemory<byte> data)
        {
            await _pipe.Writer.WriteAsync(data);
        }

        public Task OnControlAsync(AgentMessage msg) => Task.CompletedTask;
        public void OnFault(Exception ex) => _pipe.Writer.Complete(ex);
    }

    [Fact]
    public async Task TinyFrameBurstDoesNotFalsePositiveWhileOutputHasBoundedHeadroom()
    {
        var sink = new BufferedPipeSink();
        var backpressure = 0;
        var pump = new AgentChannelDataPump(sink, () => Interlocked.Increment(ref backpressure));
        var frame = new byte[1024];

        // 128 KiB is deliberately above System.IO.Pipelines' default ~64 KiB pause threshold.
        // The old shell/download pipes would stop their pump there; another 32 tiny frames then
        // overflowed AgentChannelDataPump even though this is a small, legitimate SSH burst.
        for (var i = 0; i < 128; i++)
        {
            await pump.OnDataAsync(0, frame);
            await Task.Delay(1);
        }

        Assert.Equal(0, Volatile.Read(ref backpressure));

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var received = 0;
        var buffer = new byte[8192];
        while (received < 128 * 1024)
        {
            var n = await sink.Output.ReadAsync(buffer, timeout.Token);
            Assert.True(n > 0);
            received += n;
        }
        Assert.Equal(128 * 1024, received);
        Assert.Equal(0, Volatile.Read(ref backpressure));
    }
}
