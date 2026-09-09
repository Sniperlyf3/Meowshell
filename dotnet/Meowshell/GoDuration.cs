#nullable enable
using System.Globalization;
using System.Text.RegularExpressions;

namespace Meowshell;

/// <summary>
/// Parses Go's <c>time.Duration.String()</c> format: an optional sign,
/// then either one fractional unit for a sub-second duration (e.g.
/// "580&#181;s", "12.3ms") or hours/minutes/seconds run together (e.g.
/// "1h2m3s", "2m0.5s") -- the format tailcat itself prints latencies in
/// (see <c>tailcat ping</c>'s output). Every unit's value is summed, so
/// this parses any string in the format regardless of which units Go
/// chose to include, without reproducing Go's own formatting rules.
/// </summary>
internal static class GoDuration
{
    private static readonly Regex Token = new(
        @"\G(?<num>\d+(?:\.\d+)?)(?<unit>ns|µs|us|ms|s|m|h)", RegexOptions.Compiled);

    public static bool TryParse(string s, out TimeSpan result)
    {
        result = TimeSpan.Zero;
        var trimmed = s.Trim();
        if (trimmed.Length == 0) return false;

        var negative = trimmed.StartsWith('-');
        if (negative || trimmed.StartsWith('+')) trimmed = trimmed[1..];
        if (trimmed.Length == 0) return false;

        double totalSeconds = 0;
        var pos = 0;
        var matchedAny = false;
        while (pos < trimmed.Length)
        {
            var m = Token.Match(trimmed, pos);
            if (!m.Success || m.Index != pos) return false; // a gap is not a clean duration string
            matchedAny = true;
            pos = m.Index + m.Length;
            var value = double.Parse(m.Groups["num"].Value, CultureInfo.InvariantCulture);
            totalSeconds += m.Groups["unit"].Value switch
            {
                "ns" => value / 1_000_000_000,
                "µs" or "us" => value / 1_000_000,
                "ms" => value / 1_000,
                "s" => value,
                "m" => value * 60,
                "h" => value * 3600,
                _ => 0,
            };
        }
        if (!matchedAny) return false;

        result = TimeSpan.FromSeconds(negative ? -totalSeconds : totalSeconds);
        return true;
    }
}
