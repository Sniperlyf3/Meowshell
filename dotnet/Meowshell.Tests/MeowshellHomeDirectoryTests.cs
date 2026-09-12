using Meowshell;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Meowshell.Tests;

public sealed class MeowshellHomeDirectoryTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("meowshell-homedir-test-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    // Regression test for N3: MeowshellOptions.Create's default HomeDirectory
    // used to be Path.Combine(Path.GetTempPath(), "meowshell") -- a fixed,
    // predictable name inside a directory every local user can write to.
    [Fact]
    public void EnsureSecureCreatesAnOwnerOnlyDirectoryWhenNoneExists()
    {
        var target = Path.Combine(_dir, "meowshell");
        MeowshellHomeDirectory.EnsureSecure(target);

        Assert.True(Directory.Exists(target));
        if (!OperatingSystem.IsWindows())
        {
            var mode = File.GetUnixFileMode(target);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, mode);
        }
    }

    [Fact]
    public void EnsureSecureAcceptsAPreExistingOwnerOnlyDirectory()
    {
        if (OperatingSystem.IsWindows()) return;
        var target = Path.Combine(_dir, "meowshell");
        Directory.CreateDirectory(target);
        File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        MeowshellHomeDirectory.EnsureSecure(target); // must not throw
    }

    [Fact]
    public void EnsureSecureRejectsAPreExistingDirectoryReadableByOthers()
    {
        if (OperatingSystem.IsWindows()) return;
        var target = Path.Combine(_dir, "meowshell");
        Directory.CreateDirectory(target);
        File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);

        var ex = Assert.Throws<IOException>(() => MeowshellHomeDirectory.EnsureSecure(target));
        Assert.Contains("group/other", ex.Message);
    }

    [Fact]
    public void EnsureSecureRejectsAPreExistingDirectoryWritableByGroup()
    {
        if (OperatingSystem.IsWindows()) return;
        var target = Path.Combine(_dir, "meowshell");
        Directory.CreateDirectory(target);
        File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.GroupWrite);

        Assert.Throws<IOException>(() => MeowshellHomeDirectory.EnsureSecure(target));
    }

    [Fact]
    public void EnsureSecureRejectsASymlink()
    {
        if (OperatingSystem.IsWindows()) return;
        var real = Path.Combine(_dir, "elsewhere");
        Directory.CreateDirectory(real);
        var target = Path.Combine(_dir, "meowshell");
        Directory.CreateSymbolicLink(target, real);

        var ex = Assert.Throws<IOException>(() => MeowshellHomeDirectory.EnsureSecure(target));
        Assert.Contains("symlink", ex.Message);
    }

    [Fact]
    public void EnsureSecureRejectsAPathThatIsAlreadyAFile()
    {
        var target = Path.Combine(_dir, "meowshell");
        File.WriteAllText(target, "not a directory");

        Assert.Throws<IOException>(() => MeowshellHomeDirectory.EnsureSecure(target));
    }

    [Fact]
    public void ResolveDefaultReturnsAUsableDirectoryUnderLocalApplicationData()
    {
        var baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var dir = MeowshellHomeDirectory.ResolveDefault();

        Assert.StartsWith(baseDir, dir);
        Assert.True(Directory.Exists(dir));
        // Idempotent: calling it again against the directory it just
        // created and verified must not throw.
        Assert.Equal(dir, MeowshellHomeDirectory.ResolveDefault());
    }

    [Fact]
    public void EnsureSecureRejectsWindowsHomeReadableByBuiltinUsers()
    {
        if (!OperatingSystem.IsWindows()) return;

        var target = Path.Combine(_dir, "windows-readable-home");
        Directory.CreateDirectory(target);

        var info = new DirectoryInfo(target);
        var security = info.GetAccessControl();
        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        security.AddAccessRule(new FileSystemAccessRule(
            users,
            FileSystemRights.ReadAndExecute | FileSystemRights.ListDirectory,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Allow));
        info.SetAccessControl(security);

        var ex = Assert.Throws<IOException>(() => MeowshellHomeDirectory.EnsureSecure(target));
        Assert.Contains("read/write access", ex.Message);
    }

}
