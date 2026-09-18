using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

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
        var info = new FileInfo(path);
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException($"refusing native binary symlink/reparse point: {path}");

        var directory = info.Directory
            ?? throw new IOException($"native binary has no containing directory: {path}");
        if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException($"refusing native binary directory symlink/reparse point: {directory.FullName}");

        if (OperatingSystem.IsWindows())
        {
            ValidateWindowsDirectory(directory);
            ValidateWindowsExecutable(info);
            return;
        }

        var directoryMode = File.GetUnixFileMode(directory.FullName);
        const UnixFileMode writeDirectoryByOthers =
            UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;
        if ((directoryMode & writeDirectoryByOthers) != 0)
            throw new IOException($"refusing native binary directory writable by group/other: {directory.FullName}");

        if (!OperatingSystem.IsAndroid())
            ValidateUnixAncestorDirectories(directory);

        var mode = File.GetUnixFileMode(path);
        const UnixFileMode writeByOthers =
            UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;
        if ((mode & writeByOthers) != 0)
        {
            throw new IOException(
                $"refusing native binary writable by group/other: {path} ({Convert.ToString((int)mode, 8)})");
        }

        // Already executable by this process? Don't assume the USER bit is
        // the one that matters: on Android the binaries live under
        // ApplicationInfo.NativeLibraryDir, owned by `system` and read-only to
        // the app, so this process is not the owner and runs them through the
        // OTHER-execute bit instead (the OS extracts native libraries at
        // 0755, so this is normally already true). If either bit already
        // grants execution, there is nothing to repair -- and, on Android,
        // attempting one anyway is doomed: SetUnixFileMode on a file we don't
        // own throws UnauthorizedAccessException (home-directory-upgrade
        // spec, Finding 3).
        if ((mode & (UnixFileMode.UserExecute | UnixFileMode.OtherExecute)) == 0)
        {
            // The runtime packages can lose the executable bit when unpacked
            // through tooling that does not preserve Unix metadata. Restore
            // only the owner's execute bit; making a private binary executable
            // by group/other broadens access for no functional reason.
            try
            {
                File.SetUnixFileMode(path, mode | UnixFileMode.UserExecute);
            }
            catch (UnauthorizedAccessException ex)
            {
                // Latent until now: this process does not own the file (e.g. a
                // read-only, system-owned NativeLibraryDir on Android) and
                // cannot make it executable. Fail with a clear message instead
                // of letting an undocumented UnauthorizedAccessException escape.
                throw new IOException(
                    $"native binary is not executable and cannot be made so: {path}", ex);
            }
        }
    }

    [UnsupportedOSPlatform("windows")]
    private static void ValidateUnixAncestorDirectories(DirectoryInfo directory)
    {
        for (DirectoryInfo? current = directory.Parent; current is not null; current = current.Parent)
        {
            current.Refresh();
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException($"refusing native binary path through symlink/reparse point: {current.FullName}");

            var mode = File.GetUnixFileMode(current.FullName);
            const UnixFileMode writeByOthers = UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;
            if ((mode & writeByOthers) != 0 && (mode & UnixFileMode.StickyBit) == 0)
            {
                throw new IOException(
                    $"refusing native binary path: ancestor directory writable by group/other without sticky bit: {current.FullName}");
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static void ValidateWindowsDirectory(DirectoryInfo info)
    {
        var security = info.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier
            ?? throw new IOException($"refusing native binary directory {info.FullName}: Windows ACL has no owner SID");

        using var identity = WindowsIdentity.GetCurrent();
        var current = identity.User
            ?? throw new IOException($"refusing native binary directory {info.FullName}: current Windows identity has no user SID");
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

        bool Trusted(IdentityReference sid) =>
            sid.Equals(current) || sid.Equals(admins) || sid.Equals(system);

        if (!Trusted(owner))
            throw new IOException(
                $"refusing native binary directory {info.FullName}: not owned by the current user, Administrators, or SYSTEM");

        const FileSystemRights writeCapable =
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
            if ((rule.FileSystemRights & writeCapable) == 0)
                continue;
            if (Trusted(rule.IdentityReference))
                continue;
            throw new IOException(
                $"refusing native binary directory {info.FullName}: grants write-capable access to {rule.IdentityReference.Value}");
        }
    }

    [SupportedOSPlatform("windows")]
    private static void ValidateWindowsExecutable(FileInfo info)
    {
        var security = info.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier
            ?? throw new IOException($"refusing native binary {info.FullName}: Windows ACL has no owner SID");

        using var identity = WindowsIdentity.GetCurrent();
        var current = identity.User
            ?? throw new IOException($"refusing native binary {info.FullName}: current Windows identity has no user SID");
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);

        bool Trusted(IdentityReference sid) =>
            sid.Equals(current) || sid.Equals(admins) || sid.Equals(system);

        if (!Trusted(owner))
            throw new IOException(
                $"refusing native binary {info.FullName}: not owned by the current user, Administrators, or SYSTEM");

        const FileSystemRights writeCapable =
            FileSystemRights.Write |
            FileSystemRights.Modify |
            FileSystemRights.FullControl |
            FileSystemRights.ChangePermissions |
            FileSystemRights.TakeOwnership |
            FileSystemRights.Delete |
            FileSystemRights.AppendData |
            FileSystemRights.WriteAttributes |
            FileSystemRights.WriteExtendedAttributes;

        var rules = security.GetAccessRules(
            includeExplicit: true, includeInherited: true, targetType: typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType != AccessControlType.Allow)
                continue;
            if ((rule.FileSystemRights & writeCapable) == 0)
                continue;
            if (Trusted(rule.IdentityReference))
                continue;
            throw new IOException(
                $"refusing native binary {info.FullName}: grants write-capable access to {rule.IdentityReference.Value}");
        }
    }

}
