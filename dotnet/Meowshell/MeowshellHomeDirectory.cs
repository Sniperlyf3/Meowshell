#nullable enable
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

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

            if (OperatingSystem.IsWindows())
                Directory.CreateDirectory(dir);
            else
                Directory.CreateDirectory(dir, OwnerOnly);

            // Re-read after creation instead of trusting what we intended to
            // create: another actor able to mutate an unsafe parent could
            // have raced the path. The checks below reject a reparse point or
            // broadened Unix mode rather than returning it as trusted HOME.
            info.Refresh();
        }

        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException(
                $"refusing to use {dir}: it is a symlink/reparse point, not a real directory " +
                "(it may not lead where it appears to)");
        }

        if (OperatingSystem.IsWindows())
        {
            ValidateWindowsSecurity(info);
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

    [SupportedOSPlatform("windows")]
    private static void ValidateWindowsSecurity(DirectoryInfo info)
    {
        var security = info.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier
            ?? throw new IOException($"refusing to use {info.FullName}: Windows ACL has no owner SID");

        using var identity = WindowsIdentity.GetCurrent();
        var current = identity.User
            ?? throw new IOException($"refusing to use {info.FullName}: current Windows identity has no user SID");
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

        bool Trusted(IdentityReference sid) =>
            sid.Equals(current) || sid.Equals(admins) || sid.Equals(system);

        if (!Trusted(owner))
            throw new IOException(
                $"refusing to use {info.FullName}: directory is not owned by the current user, Administrators, or SYSTEM");

        // HOME can contain saved Tailcat client keys and other private
        // session state, so confidentiality matters as much as integrity.
        // Unix enforces this with mode 0700; Windows must likewise reject
        // untrusted principals that can read/list/traverse the directory,
        // not only principals that can modify it.
        const FileSystemRights sensitiveAccess =
            FileSystemRights.Read |
            FileSystemRights.ReadAndExecute |
            FileSystemRights.ListDirectory |
            FileSystemRights.Traverse |
            FileSystemRights.Write |
            FileSystemRights.Modify |
            FileSystemRights.FullControl |
            FileSystemRights.ChangePermissions |
            FileSystemRights.TakeOwnership |
            FileSystemRights.Delete |
            FileSystemRights.DeleteSubdirectoriesAndFiles |
            FileSystemRights.CreateFiles |
            FileSystemRights.CreateDirectories |
            FileSystemRights.AppendData |
            FileSystemRights.WriteAttributes |
            FileSystemRights.WriteExtendedAttributes;

        var rules = security.GetAccessRules(
            includeExplicit: true, includeInherited: true, targetType: typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType != AccessControlType.Allow)
                continue;
            if ((rule.FileSystemRights & sensitiveAccess) == 0)
                continue;
            if (Trusted(rule.IdentityReference))
                continue;
            throw new IOException(
                $"refusing to use {info.FullName}: grants read/write access to {rule.IdentityReference.Value}");
        }
    }

    private static string ToOctal(UnixFileMode mode) => Convert.ToString((int)mode, 8).PadLeft(3, '0');
}
