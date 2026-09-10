#nullable enable
using System.Text.RegularExpressions;

namespace Meowshell;

/// <summary>
/// meowshell's own resolved environment for a session -- the shell/home/user/path/term/lang
/// it would hand a real session, and where it found the tailcat binary. Mirrors <c>meowshell env</c>,
/// useful for diagnosing a broken environment (an app sandbox, <c>adb shell</c>, a stripped-down
/// container) before starting a real session rather than after one fails mysteriously.
/// </summary>
/// <param name="Shell">The resolved login shell (fixed up on Android/adb shell, where <c>$SHELL</c> is often wrong or missing).</param>
/// <param name="Home">The resolved home directory.</param>
/// <param name="User">The resolved username.</param>
/// <param name="Path">The resolved <c>PATH</c>.</param>
/// <param name="Term">The resolved <c>TERM</c>.</param>
/// <param name="Lang">The resolved <c>LANG</c>.</param>
/// <param name="TailcatBinaryPath">Where meowshell found the tailcat binary, or null if it couldn't (see <see cref="Warnings"/> and the thrown exception's diagnostics for why, when this is null).</param>
/// <param name="Warnings">Resolver warnings, e.g. about a shell that doesn't exist or a broken environment variable.</param>
public sealed record TailcatEnvironment(
    string Shell, string Home, string User, string Path, string Term, string Lang,
    string? TailcatBinaryPath, IReadOnlyList<string> Warnings)
{
    private static readonly Regex LineRe = new(@"^(\S+)\s+(.*)$", RegexOptions.Compiled);

    internal static TailcatEnvironment Parse(string stdout)
    {
        string shell = "", home = "", user = "", path = "", term = "", lang = "";
        string? tailcatBin = null;
        var warnings = new List<string>();

        foreach (var rawLine in stdout.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            var m = LineRe.Match(line);
            if (!m.Success) continue;
            var value = m.Groups[2].Value;
            switch (m.Groups[1].Value)
            {
                case "shell": shell = value; break;
                case "home": home = value; break;
                case "user": user = value; break;
                case "path": path = value; break;
                case "term": term = value; break;
                case "lang": lang = value; break;
                case "tailcat": tailcatBin = value.StartsWith("NOT FOUND", StringComparison.Ordinal) ? null : value; break;
                case "warning:": warnings.Add(value); break;
            }
        }

        return new TailcatEnvironment(shell, home, user, path, term, lang, tailcatBin, warnings);
    }
}
