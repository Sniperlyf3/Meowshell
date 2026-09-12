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

        var info = new FileInfo(path);
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException($"refusing native binary symlink/reparse point: {path}");

        var mode = File.GetUnixFileMode(path);
        const UnixFileMode writeByOthers =
            UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;
        if ((mode & writeByOthers) != 0)
        {
            throw new IOException(
                $"refusing native binary writable by group/other: {path} ({Convert.ToString((int)mode, 8)})");
        }

        if ((mode & UnixFileMode.UserExecute) == 0)
        {
            // The runtime packages can lose the executable bit when unpacked
            // through tooling that does not preserve Unix metadata. Restore
            // only the owner's execute bit; making a private binary executable
            // by group/other broadens access for no functional reason.
            File.SetUnixFileMode(path, mode | UnixFileMode.UserExecute);
        }
    }
}
