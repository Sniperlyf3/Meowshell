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

        if (OperatingSystem.IsWindows())
        {
            ValidateWindowsExecutable(info);
            return;
        }

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
