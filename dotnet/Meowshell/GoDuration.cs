#nullable enable
using System.Globalization;
using System.Text.RegularExpressions;

namespace Meowshell;

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
            if (!m.Success || m.Index != pos) return false;
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
