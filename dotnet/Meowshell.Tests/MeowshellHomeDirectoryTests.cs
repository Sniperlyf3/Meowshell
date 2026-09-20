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
    public void EnsureSecureAcceptsOwnerOnlyDirectoryWithSetGroupBit()
    {
        if (OperatingSystem.IsWindows()) return;
        var target = Path.Combine(_dir, "meowshell-setgid");
        Directory.CreateDirectory(target);
        File.SetUnixFileMode(target,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
            UnixFileMode.SetGroup);

        MeowshellHomeDirectory.EnsureSecure(target); // Android commonly yields 2700.
    }

    // Regression test for the home-directory-upgrade spec's Finding 1: a
    // directory an OLDER version of this library (or a plain
    // Directory.CreateDirectory + umask) left at 0755 must be narrowed in
    // place on upgrade, not rejected forever -- EnsureSecure owns it (the test
    // process created it), so the chmod succeeds and no exception is thrown.
    // This test used to assert the opposite (that 0755 was rejected); the
    // spec calls that out explicitly as the case that must change, not be
    // deleted -- see EnsureSecureRejectsADirectoryItDoesNotOwnAndCannotNarrow
    // below for the case that must still throw.
    [Fact]
    public void EnsureSecureNarrowsAPreExistingDirectoryReadableByOthers()
    {
        if (OperatingSystem.IsWindows()) return;
        var target = Path.Combine(_dir, "meowshell");
        Directory.CreateDirectory(target);
        File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);

        MeowshellHomeDirectory.EnsureSecure(target); // must not throw -- narrowed instead

        var mode = File.GetUnixFileMode(target);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, mode);
    }

    [Fact]
    public void EnsureSecureNarrowsAPreExistingDirectoryWritableByGroup()
    {
        if (OperatingSystem.IsWindows()) return;
        var target = Path.Combine(_dir, "meowshell");
        Directory.CreateDirectory(target);
        File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.GroupWrite);

        MeowshellHomeDirectory.EnsureSecure(target); // must not throw -- narrowed instead

        var mode = File.GetUnixFileMode(target);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, mode);
    }

    // The case narrowing must NOT paper over: a directory this process does
    // not own (simulated here with chattr +i, which makes chmod fail with
    // UnauthorizedAccessException the same way owning-someone-else's-directory
    // would) is still refused, exactly as before Finding 1's fix.
    [Fact]
    public void EnsureSecureRejectsADirectoryItDoesNotOwnAndCannotNarrow()
    {
        if (OperatingSystem.IsWindows()) return;
        var target = Path.Combine(_dir, "meowshell");
        Directory.CreateDirectory(target);
        File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);

        if (!TrySetImmutable(target, true))
            return; // sandbox/filesystem doesn't support simulating an unnarrowable directory this way

        try
        {
            var ex = Assert.Throws<IOException>(() => MeowshellHomeDirectory.EnsureSecure(target));
            Assert.Contains("group/other", ex.Message);
        }
        finally
        {
            TrySetImmutable(target, false); // otherwise Dispose()'s recursive delete fails
        }
    }

    // Returns false (rather than throwing) when chattr isn't available or the
    // underlying filesystem doesn't support the immutable attribute, so the
    // test above can skip itself instead of failing on an unrelated sandbox
    // limitation.
    private static bool TrySetImmutable(string path, bool immutable)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("chattr", $"{(immutable ? "+i" : "-i")} {path}")
            {
                UseShellExecute = false,
                RedirectStandardError = true,
            };
            using var process = System.Diagnostics.Process.Start(psi);
            if (process is null) return false;
            process.WaitForExit();
            return process.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    [Fact]
    public void EnsureSecureRejectsASymlink()
    {
        if (OperatingSystem.IsWindows()) return;
        var real = Path.Combine(_dir, "elsewhere");
        Directory.CreateDirectory(real);
        File.SetUnixFileMode(real, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherExecute); // 0755, same shape as Finding 1
        var target = Path.Combine(_dir, "meowshell");
        Directory.CreateSymbolicLink(target, real);

        var ex = Assert.Throws<IOException>(() => MeowshellHomeDirectory.EnsureSecure(target));
        Assert.Contains("symlink", ex.Message);

        // The repair in EnsureSecure must never follow a symlink: it checks
        // for a reparse point before it ever looks at mode bits, so the link
        // target's own permissions are left exactly as this test set them.
        var realMode = File.GetUnixFileMode(real);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherExecute, realMode);
    }

    [Fact]
    public void EnsureSecureRejectsAPathThatIsAlreadyAFile()
    {
        var target = Path.Combine(_dir, "meowshell");
        File.WriteAllText(target, "not a directory");

        Assert.Throws<IOException>(() => MeowshellHomeDirectory.EnsureSecure(target));
    }

    // Fix 3 (home-directory-upgrade spec, "the exception type is outside the
    // documented model"): every process-launching entry point calls
    // EnsureSecureForEntryPoint, not EnsureSecure directly, specifically so a
    // bad home/working directory surfaces as the one documented failure type
    // (TailcatException) instead of an undocumented raw IOException that a
    // caller following ConnectAsync's own <exception> doc would never catch.
    [Fact]
    public void EnsureSecureForEntryPointWrapsTheIOExceptionInATailcatException()
    {
        if (OperatingSystem.IsWindows()) return;
        var real = Path.Combine(_dir, "elsewhere");
        Directory.CreateDirectory(real);
        var target = Path.Combine(_dir, "meowshell");
        Directory.CreateSymbolicLink(target, real); // deterministic, ownership-independent way to hit EnsureSecure's IOException

        var ex = Assert.Throws<TailcatException>(() => MeowshellHomeDirectory.EnsureSecureForEntryPoint(target));
        Assert.Equal(MeowshellErrorCode.HomeDirectoryUnsafe, ex.Code);
        Assert.Contains("symlink", ex.Message);
    }

    [Fact]
    public void EnsureSecureForEntryPointStillAcceptsAPrivateDirectory()
    {
        var target = Path.Combine(_dir, "meowshell");
        MeowshellHomeDirectory.EnsureSecureForEntryPoint(target); // must not throw

        Assert.True(Directory.Exists(target));
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
