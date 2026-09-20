using System.Text.Json;
using Meowshell;

namespace Meowshell.Tests;

public sealed class MeowshellAgentRelayHealthProtocolTests
{
    [Fact]
    public void Relay_problem_round_trips()
    {
        var original = new AgentMessage
        {
            Msg = "relay_health",
            RelayProblem = "MeowSSH managed relay: monthly usage allowance exceeded",
        };

        var json = JsonSerializer.Serialize(original, MeowshellAgentProtocol.JsonOptions);
        Assert.Contains("\"relay_problem\":\"MeowSSH managed relay: monthly usage allowance exceeded\"", json, StringComparison.Ordinal);

        var decoded = JsonSerializer.Deserialize<AgentMessage>(json, MeowshellAgentProtocol.JsonOptions)!;
        Assert.Equal(original.RelayProblem, decoded.RelayProblem);
    }

    [Fact]
    public void Missing_relay_problem_field_means_healthy()
    {
        var decoded = JsonSerializer.Deserialize<AgentMessage>(
            "{\"msg\":\"relay_health\"}",
            MeowshellAgentProtocol.JsonOptions)!;

        Assert.Null(decoded.RelayProblem);
    }

    [Fact]
    public void Explicit_empty_relay_problem_deserializes_the_same_as_a_missing_field()
    {
        // The Go agent's omitempty drops relay_problem entirely for a
        // "healthy" report (see protocol.go), so a real agent never actually
        // sends an explicit "". But MeowshellAgentConnection's dispatch
        // (HandleControlAsync's "relay_health" case) treats both the same
        // way on purpose -- via string.IsNullOrEmpty, not a null check --
        // precisely so it doesn't depend on that Go-side wire detail.
        var decoded = JsonSerializer.Deserialize<AgentMessage>(
            "{\"msg\":\"relay_health\",\"relay_problem\":\"\"}",
            MeowshellAgentProtocol.JsonOptions)!;

        Assert.Equal(string.Empty, decoded.RelayProblem);
    }
}
