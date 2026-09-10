#nullable enable

namespace Meowshell;

internal static class MeowshellBinaries
{
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
        }
    }
}
