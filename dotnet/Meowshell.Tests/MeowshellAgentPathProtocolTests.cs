using System.Text.Json;
using Meowshell;

namespace Meowshell.Tests;

public sealed class MeowshellAgentPathProtocolTests
{
    [Fact]
    public void Relayed_path_round_trips_false_via_and_counters()
    {
        var original = new AgentMessage
        {
            Msg = "path",
            Direct = false,
            Via = "derp-eu.meowssh.dev",
            RelayedBytesSent = 182400,
            RelayedBytesRecv = 906112,
        };

        var json = JsonSerializer.Serialize(original, MeowshellAgentProtocol.JsonOptions);
        Assert.Contains("\"direct\":false", json, StringComparison.Ordinal);
        Assert.Contains("\"via\":\"derp-eu.meowssh.dev\"", json, StringComparison.Ordinal);
        Assert.Contains("\"relayed_bytes_sent\":182400", json, StringComparison.Ordinal);
        Assert.Contains("\"relayed_bytes_recv\":906112", json, StringComparison.Ordinal);

        var decoded = JsonSerializer.Deserialize<AgentMessage>(json, MeowshellAgentProtocol.JsonOptions)!;
        Assert.False(decoded.Direct);
        Assert.Equal(original.Via, decoded.Via);
        Assert.Equal(original.RelayedBytesSent, decoded.RelayedBytesSent);
        Assert.Equal(original.RelayedBytesRecv, decoded.RelayedBytesRecv);
    }

    [Fact]
    public void Missing_direct_field_remains_unknown_for_backward_compatibility()
    {
        var decoded = JsonSerializer.Deserialize<AgentMessage>(
            "{\"msg\":\"path\"}",
            MeowshellAgentProtocol.JsonOptions)!;

        Assert.Null(decoded.Direct);
        Assert.Null(decoded.Via);
        Assert.Equal(0UL, decoded.RelayedBytesSent);
        Assert.Equal(0UL, decoded.RelayedBytesRecv);
    }
}
