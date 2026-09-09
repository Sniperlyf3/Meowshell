#nullable enable
using System.Text.RegularExpressions;

namespace Meowshell;

/// <summary>One successful pong, parsed from a "pong in ... via ..." line.</summary>
/// <param name="Latency">Round-trip latency.</param>
/// <param name="Direct">Whether the pong arrived over a direct path rather than relayed through DERP.</param>
/// <param name="Via">The direct endpoint (e.g. "1.2.3.4:5678") when <see cref="Direct"/>, else the DERP region code or ID.</param>
public sealed record TailcatPong(TimeSpan Latency, bool Direct, string Via);

/// <summary>
/// The result of <see cref="TailcatClient.PingAsync"/>. <see cref="Pong"/>
/// is populated from the last "pong in ... via ..." line tailcat printed,
/// if any -- present even when <see cref="Success"/> is false, since
/// <c>--until-direct</c> can print several relayed pongs before giving up
/// on ever going direct.
/// </summary>
/// <param name="Result">The raw process result: exit code and full stdout/stderr.</param>
/// <param name="Pong">The most recent parsed pong, or null if tailcat printed none.</param>
public sealed record TailcatPingResult(TailcatResult Result, TailcatPong? Pong)
{
    /// <summary><see cref="Result"/>'s exit code is 0.</summary>
    public bool Success => Result.Success;

    private static readonly Regex PongLine = new(
        @"^pong in (?<latency>\S+) via (?<via>.+)$", RegexOptions.Compiled | RegexOptions.Multiline);

    internal static TailcatPingResult From(TailcatResult result)
    {
        TailcatPong? pong = null;
        foreach (Match m in PongLine.Matches(result.Stdout))
        {
            if (!GoDuration.TryParse(m.Groups["latency"].Value, out var latency)) continue;
            var via = m.Groups["via"].Value;
            pong = via.StartsWith("DERP(", StringComparison.Ordinal) && via.EndsWith(')')
                ? new TailcatPong(latency, Direct: false, Via: via[5..^1])
                : new TailcatPong(latency, Direct: true, Via: via);
        }
        return new TailcatPingResult(result, pong);
    }
}
