#nullable enable

namespace Meowshell;

/// <summary>
/// Locating and preparing the meowshell and tailcat binaries, shared by
/// every wrapper that spawns one of them.
/// </summary>
internal static class MeowshellBinaries
{
    /// <summary>
    /// Resolves the meowshell and tailcat binary paths and makes sure both
    /// are executable.
    /// </summary>
    /// <exception cref="FileNotFoundException">No binaries were found, or one of the two is missing from the resolved directory.</exception>
    public static (string Meowshell, string Tailcat) Locate(string? binaryDirectory, BinaryNaming naming)
    {
        var binaries = binaryDirectory ?? BinaryLocator.Locate(naming);
        if (binaries is null)
        {
            var tried = string.Join(", ", BinaryLocator.SearchPath(AppContext.BaseDirectory));
            throw new FileNotFoundException(
                $"no meowshell and tailcat for {BinaryLocator.RuntimeIdentifier} (looked in {tried}). " +
                $"Reference a Meowshell.Runtime.* package, set BinaryDirectory, " +
                $"or point {BinaryLocator.DirectoryVariable} at them.");
        }

        var meowshell = Path.Combine(binaries, naming.FileName("meowshell"));
        var tailcat = Path.Combine(binaries, naming.FileName("tailcat"));
        foreach (var path in new[] { meowshell, tailcat })
        {
            if (!File.Exists(path))
                throw new FileNotFoundException($"missing native binary: {path}", path);
            EnsureExecutable(path);
        }
        return (meowshell, tailcat);
    }

    /// <summary>
    /// Makes sure a binary can be executed. NuGet restore does not reliably
    /// carry the executable bit onto Unix filesystems, so a package-delivered
    /// binary can arrive unrunnable; Android unpacks its own and needs
    /// nothing. Failures here are ignored: if the bit really cannot be set,
    /// starting the process reports it far better than guessing would.
    /// </summary>
    private static void EnsureExecutable(string path)
    {
        if (OperatingSystem.IsWindows()) return;
        try
        {
            var mode = File.GetUnixFileMode(path);
            const UnixFileMode exec =
                UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute;
            if ((mode & UnixFileMode.UserExecute) == 0)
            {
                File.SetUnixFileMode(path, mode | exec);
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            // Left to the process start to report.
        }
    }
}
