#nullable enable
using System.Globalization;
using System.Text.RegularExpressions;

namespace Meowshell;

/// <summary>
/// One entry from <c>tailcat ls</c>. <see cref="Mode"/>, <see cref="Size"/>,
/// <see cref="ModifiedRaw"/> and <see cref="ModifiedAt"/> are only present
/// for a long listing (<c>longListing: true</c>); a short listing carries
/// only the name.
/// </summary>
/// <param name="Name">The entry's name, without a trailing slash even for a directory.</param>
/// <param name="IsDirectory">Whether the entry is a directory.</param>
/// <param name="Mode">The raw permission string, e.g. "-rw-r--r--" or "drwxr-xr-x".</param>
/// <param name="Size">The size in bytes.</param>
/// <param name="ModifiedRaw">
/// The modification time exactly as tailcat printed it: "Mon _2 15:04" for
/// a file modified within the last 180 days, else "Mon _2  2006" -- the
/// same ambiguous, locale-independent format classic Unix <c>ls -l</c>
/// uses, carrying either a time-of-day or a year but never both.
/// </param>
/// <param name="ModifiedAt">
/// A best-effort reconstruction of <see cref="ModifiedRaw"/>: when it
/// carries a year, midnight on that date; when it carries a time of day,
/// that time on the most recent matching date not in the future. Treat
/// this as informational, not a precise instant -- the missing half
/// (time-of-day or year) is a guess, and tailcat's clock may be in any
/// time zone, which nothing here reveals.
/// </param>
public sealed record TailcatFileEntry(
    string Name,
    bool IsDirectory,
    string? Mode,
    long? Size,
    string? ModifiedRaw,
    DateTime? ModifiedAt)
{
    // "<mode> <size> <Mon> <day> <time-or-year> <name>", matching
    // printEntry's "%s %12d %s %s\n" in tailcat's own ls.go, where the
    // third %s is itself "Mon _2 15:04" or "Mon _2  2006" -- three
    // whitespace-separated tokens. Matched by runs of non-whitespace and
    // whitespace rather than fixed column widths, since %12d only
    // guarantees a *minimum* width.
    private static readonly Regex LongFormat = new(
        @"^(?<mode>\S+)\s+(?<size>\d+)\s+(?<month>[A-Za-z]{3})\s+(?<day>\d{1,2})\s+(?<timeOrYear>\d{1,2}:\d{2}|\d{4})\s+(?<name>.+)$",
        RegexOptions.Compiled);

    /// <summary>
    /// Parses <c>tailcat ls</c>'s stdout. <paramref name="longListing"/>
    /// must match whether <c>-l</c> was passed: a short listing's lines
    /// are only ever a bare name (a file name can itself contain
    /// whitespace, so a short line is never tokenized), while a long
    /// listing's lines are tokenized to separate the fixed fields from a
    /// name that may still contain spaces.
    /// </summary>
    /// <exception cref="TailcatException">A line didn't match the expected long-listing shape.</exception>
    internal static IReadOnlyList<TailcatFileEntry> ParseAll(string stdout, bool longListing)
    {
        var lines = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var entries = new List<TailcatFileEntry>(lines.Length);
        foreach (var rawLine in lines)
        {
            var line = rawLine.TrimEnd('\r');
            if (line.Length == 0) continue;
            entries.Add(longListing ? ParseLong(line) : ParseShort(line));
        }
        return entries;
    }

    private static TailcatFileEntry ParseShort(string line)
    {
        var (name, isDir) = SplitTrailingSlash(line);
        return new TailcatFileEntry(name, isDir, Mode: null, Size: null, ModifiedRaw: null, ModifiedAt: null);
    }

    private static TailcatFileEntry ParseLong(string line)
    {
        var m = LongFormat.Match(line);
        if (!m.Success)
        {
            throw new TailcatException(
                "unexpected output from tailcat ls -l", exitCode: 0,
                $"line didn't match the expected \"<mode> <size> <date> <name>\" shape: {line}");
        }
        var (name, isDir) = SplitTrailingSlash(m.Groups["name"].Value);
        var modifiedRaw = $"{m.Groups["month"].Value} {m.Groups["day"].Value} {m.Groups["timeOrYear"].Value}";
        return new TailcatFileEntry(
            name, isDir,
            Mode: m.Groups["mode"].Value,
            Size: long.Parse(m.Groups["size"].Value, CultureInfo.InvariantCulture),
            ModifiedRaw: modifiedRaw,
            ModifiedAt: TryParseModified(m.Groups["month"].Value, m.Groups["day"].Value, m.Groups["timeOrYear"].Value));
    }

    private static (string Name, bool IsDirectory) SplitTrailingSlash(string name) =>
        name.EndsWith('/') ? (name[..^1], true) : (name, false);

    private static DateTime? TryParseModified(string month, string day, string timeOrYear)
    {
        if (!DateTime.TryParseExact(month, "MMM", CultureInfo.InvariantCulture, DateTimeStyles.None, out var monthDate))
            return null;
        if (!int.TryParse(day, NumberStyles.Integer, CultureInfo.InvariantCulture, out var dayNum))
            return null;

        if (timeOrYear.Contains(':'))
        {
            if (!TimeOnly.TryParseExact(timeOrYear, "HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out var time))
                return null;
            // No year given: assume the most recent one that isn't in the
            // future, mirroring classic "ls -l" parsing.
            var now = DateTime.UtcNow;
            for (var year = now.Year; year >= now.Year - 1; year--)
            {
                if (!TryMakeDate(year, monthDate.Month, dayNum, out var candidateDate)) continue;
                var candidate = candidateDate.Add(time.ToTimeSpan());
                if (candidate <= now.AddDays(1)) return candidate;
            }
            return null;
        }

        if (!int.TryParse(timeOrYear, NumberStyles.Integer, CultureInfo.InvariantCulture, out var year2))
            return null;
        return TryMakeDate(year2, monthDate.Month, dayNum, out var dateOnly) ? dateOnly : null;
    }

    private static bool TryMakeDate(int year, int month, int day, out DateTime date)
    {
        try
        {
            date = new DateTime(year, month, day, 0, 0, 0, DateTimeKind.Unspecified);
            return true;
        }
        catch (ArgumentOutOfRangeException)
        {
            date = default;
            return false;
        }
    }
}
