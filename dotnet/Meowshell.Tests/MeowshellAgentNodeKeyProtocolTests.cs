using System.Text.Json;
using Meowshell;

namespace Meowshell.Tests;

public sealed class MeowshellAgentNodeKeyProtocolTests
{
    [Fact]
    public void ConnectedFrameDeserializesPublicNodeKey()
    {
        const string expected = "nodekey:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        var message = JsonSerializer.Deserialize<AgentMessage>(
            $"{{\"msg\":\"connected\",\"node_key\":\"{expected}\"}}",
            MeowshellAgentProtocol.JsonOptions);

        Assert.NotNull(message);
        Assert.Equal("connected", message.Msg);
        Assert.Equal(expected, message.NodeKey);
    }

    [Fact]
    public void LegacyConnectedFrameLeavesNodeKeyNull()
    {
        var message = JsonSerializer.Deserialize<AgentMessage>(
            "{\"msg\":\"connected\"}",
            MeowshellAgentProtocol.JsonOptions);

        Assert.NotNull(message);
        Assert.Null(message.NodeKey);
    }
}
