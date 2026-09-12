#nullable enable

namespace Meowshell;

/// <summary>
/// Resolves the private, per-user directory <see cref="MeowshellOptions.Create"/> uses for
/// <see cref="TailcatOptions.HomeDirectory"/>/<see cref="MeowshellOptions.WorkDirectory"/> outside Android.
/// </summary>
internal static class MeowshellHomeDirectory
{
    // Owner read/write/execute only -- nothing for group or other. Used as
    // both the mode this creates the directory with and the ceiling a
    // pre-existing one must not exceed.
    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    /// <summary>
    /// A "meowshell" directory under the platform's local-application-data location (e.g.
    /// <c>%LOCALAPPDATA%</c> on Windows, <c>$XDG_DATA_HOME</c> or <c>~/.local/share</c> on Linux) -- not the
    /// previous <c>Path.Combine(Path.GetTempPath(), "meowshell")</c>, a fixed, predictable name inside a
    /// directory every local user can write to. Anyone who got there first could have planted a symlink
    /// at that exact path (redirecting the session key material and known_hosts this becomes HOME for
    /// wherever they chose) or simply left the directory readable/writable by others. Verified secure
    /// (or created that way) before being handed back; see <see cref="EnsureSecure"/>.
    /// </summary>
    public static string ResolveDefault()
    {
        var baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.Create);
        var dir = Path.Combine(baseDir, "meowshell");
        EnsureSecure(dir);
        return dir;
    }

    /// <summary>Creates <paramref name="dir"/> restricted to the owner if it doesn't exist, or verifies a
    /// pre-existing one actually is: not a symlink/reparse point, and not accessible by anyone else.</summary>
    /// <exception cref="IOException">
    /// <paramref name="dir"/> is a symlink/reparse point, a pre-existing directory's permissions allow
    /// group/other access, or it isn't actually accessible as the current user despite its permissions
    /// (a stronger signal than the mode bits alone, and the closest a P/Invoke-free, cross-platform check
    /// gets to a real owner-UID comparison: nothing short of being the owner or root can read a directory
    /// whose mode is verified to already exclude group and other entirely).
    /// </exception>
    internal static void EnsureSecure(string dir)
    {
        var info = new DirectoryInfo(dir);
        if (!info.Exists)
        {
            if (File.Exists(dir))
                throw new IOException($"{dir} already exists as a file, not a directory");
            Directory.CreateDirectory(dir);
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(dir, OwnerOnly);
            return;
        }

        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException(
                $"refusing to use {dir}: it is a symlink/reparse point, not a real directory " +
                "(it may not lead where it appears to)");
        }

        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var mode = File.GetUnixFileMode(dir);
        if ((mode & ~OwnerOnly) != 0)
        {
            throw new IOException(
                $"refusing to use {dir}: permissions {ToOctal(mode)} allow group/other access " +
                "(a pre-existing directory here that isn't exclusively yours could let another local user read or tamper with session data)");
        }
        try
        {
            using var enumerator = Directory.EnumerateFileSystemEntries(dir).GetEnumerator();
            enumerator.MoveNext();
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new IOException($"refusing to use {dir}: not accessible as the current user", ex);
        }
    }

    private static string ToOctal(UnixFileMode mode) => Convert.ToString((int)mode, 8).PadLeft(3, '0');
}
