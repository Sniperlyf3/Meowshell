using Meowshell;

namespace Meowshell.Tests;

// Fix 2 (home-directory-upgrade spec, "make the helper public"): a consumer
// that manages its own storage layout previously had to re-implement
// MeowshellHomeDirectory's symlink rejection, race-safe re-read, Windows ACL
// check and narrowing logic itself, because that type is internal. These
// tests exercise the new public MeowshellHome.Prepare() entry point directly,
// the way such a consumer would, rather than the internal type.
public sealed class MeowshellHomeTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("meowshell-home-test-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void PrepareCreatesAnOwnerOnlyDirectoryWhenNoneExistsAndReturnsThePath()
    {
        var target = Path.Combine(_dir, "app-storage");

        var returned = MeowshellHome.Prepare(target);

        Assert.Equal(target, returned);
        Assert.True(Directory.Exists(target));
        if (!OperatingSystem.IsWindows())
        {
            var mode = File.GetUnixFileMode(target);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, mode);
        }
    }

    [Fact]
    public void PrepareNarrowsAPreExistingOverPermissiveDirectory()
    {
        if (OperatingSystem.IsWindows()) return;
        var target = Path.Combine(_dir, "app-storage");
        Directory.CreateDirectory(target);
        File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherExecute); // 0755, e.g. Directory.CreateDirectory under a 022 umask

        MeowshellHome.Prepare(target); // must not throw -- narrowed instead

        var mode = File.GetUnixFileMode(target);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, mode);
    }

    [Fact]
    public void PrepareRejectsASymlink()
    {
        if (OperatingSystem.IsWindows()) return;
        var real = Path.Combine(_dir, "elsewhere");
        Directory.CreateDirectory(real);
        var target = Path.Combine(_dir, "app-storage");
        Directory.CreateSymbolicLink(target, real);

        var ex = Assert.Throws<IOException>(() => MeowshellHome.Prepare(target));
        Assert.Contains("symlink", ex.Message);
    }

    [Fact]
    public void PrepareIsIdempotent()
    {
        var target = Path.Combine(_dir, "app-storage");
        MeowshellHome.Prepare(target);

        MeowshellHome.Prepare(target); // must not throw the second time either
    }
}
