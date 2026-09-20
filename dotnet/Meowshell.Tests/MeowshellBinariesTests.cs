using Meowshell;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Meowshell.Tests;

public sealed class MeowshellBinariesTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("meowshell-binaries-test-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void LocateRejectsWindowsBinaryWritableByBuiltinUsers()
    {
        if (!OperatingSystem.IsWindows()) return;

        var naming = BinaryNaming.ForCurrentPlatform();
        foreach (var name in new[] { naming.FileName("meowshell"), naming.FileName("tailcat") })
            File.WriteAllText(Path.Combine(_dir, name), "placeholder");

        var target = new FileInfo(Path.Combine(_dir, naming.FileName("tailcat")));
        var security = target.GetAccessControl();
        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        security.AddAccessRule(new FileSystemAccessRule(
            users,
            FileSystemRights.Write,
            AccessControlType.Allow));
        target.SetAccessControl(security);

        var ex = Assert.Throws<IOException>(() => MeowshellBinaries.Locate(_dir, naming));
        Assert.Contains("write-capable access", ex.Message);
    }

    [Fact]
    public void LocateRejectsUnixBinaryBelowWritableAncestor()
    {
        if (OperatingSystem.IsWindows() || OperatingSystem.IsAndroid()) return;

        var ancestor = Path.Combine(_dir, "replaceable");
        var binaries = Path.Combine(ancestor, "private");
        Directory.CreateDirectory(binaries);
        File.SetUnixFileMode(ancestor,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
            UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
            UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute);
        File.SetUnixFileMode(binaries,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        var naming = BinaryNaming.ForCurrentPlatform();
        foreach (var name in new[] { naming.FileName("meowshell"), naming.FileName("tailcat") })
            File.WriteAllText(Path.Combine(binaries, name), "placeholder");

        var ex = Assert.Throws<IOException>(() => MeowshellBinaries.Locate(binaries, naming));
        Assert.Contains("ancestor directory writable", ex.Message);
    }

    // Finding 3 (home-directory-upgrade spec, latent): EnsureExecutable used
    // to check only UnixFileMode.UserExecute before deciding whether to
    // chmod. On Android the app is not the owner of a binary under
    // ApplicationInfo.NativeLibraryDir -- it runs it through the
    // OTHER-execute bit -- so a file that's already executable that way, but
    // whose containing directory the app cannot write to, used to trigger a
    // doomed chmod attempt anyway (fine while the OS always sets the owner
    // bit too, at 0755, but a raw UnauthorizedAccessException the moment a
    // library lacked it). Simulate the read-only directory with chattr +i so
    // the chmod really would fail if the pre-check regressed and attempted it.
    [Fact]
    public void LocateDoesNotThrowWhenABinaryIsAlreadyExecutableByOtherAndItsDirectoryIsReadOnly()
    {
        if (OperatingSystem.IsWindows() || OperatingSystem.IsAndroid()) return;

        var bin = Path.Combine(_dir, "android-like-bin");
        Directory.CreateDirectory(bin);
        var naming = BinaryNaming.ForCurrentPlatform();
        var paths = new[] { naming.FileName("meowshell"), naming.FileName("tailcat") }
            .Select(name => Path.Combine(bin, name)).ToArray();
        foreach (var path in paths)
        {
            File.WriteAllText(path, "stub");
            // No UserExecute (this process, as the file's owner in the test,
            // would otherwise get the repair branch); OtherExecute present,
            // the bit that actually matters when this process is not the
            // owner, as on Android.
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherExecute);
        }

        // Immutable on the FILES themselves (not just the directory): chmod
        // acts on the inode, so a read-only directory alone would not stop
        // it. If the pre-check regressed and attempted a chmod anyway, this
        // makes that attempt really fail instead of silently succeeding as
        // it would as the file's owner.
        if (!paths.All(p => TrySetImmutable(p, true)))
        {
            foreach (var p in paths) TrySetImmutable(p, false);
            return; // sandbox/filesystem doesn't support simulating this
        }

        try
        {
            var located = MeowshellBinaries.Locate(bin, naming); // must not throw
            Assert.Equal(Path.Combine(bin, naming.FileName("meowshell")), located.Meowshell);
        }
        finally
        {
            foreach (var p in paths) TrySetImmutable(p, false); // otherwise Dispose()'s recursive delete fails
        }
    }

    // The guard side of the same fix: when a binary genuinely isn't
    // executable by this process and the repair chmod fails (simulated the
    // same way), Locate must fail with a clear IOException naming the binary
    // instead of an undocumented UnauthorizedAccessException.
    [Fact]
    public void LocateFailsWithAnIOExceptionWhenAnUnexecutableBinaryCannotBeRepaired()
    {
        if (OperatingSystem.IsWindows()) return;

        var bin = Path.Combine(_dir, "unrepairable-bin");
        Directory.CreateDirectory(bin);
        var naming = BinaryNaming.ForCurrentPlatform();
        var target = Path.Combine(bin, naming.FileName("tailcat"));
        File.WriteAllText(target, "stub");
        File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite); // no execute bit anywhere
        File.WriteAllText(Path.Combine(bin, naming.FileName("meowshell")), "stub");
        File.SetUnixFileMode(Path.Combine(bin, naming.FileName("meowshell")),
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        if (!TrySetImmutable(target, true))
            return; // sandbox/filesystem doesn't support simulating an unrepairable binary this way

        try
        {
            var ex = Assert.Throws<IOException>(() => MeowshellBinaries.Locate(bin, naming));
            Assert.Contains("not executable and cannot be made so", ex.Message);
            Assert.Contains(target, ex.Message);
        }
        finally
        {
            TrySetImmutable(target, false); // otherwise Dispose()'s recursive delete fails
        }
    }

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
    public void LocateAllowsUnixBinaryBelowStickyWritableAncestor()
    {
        if (OperatingSystem.IsWindows() || OperatingSystem.IsAndroid()) return;

        var ancestor = Path.Combine(_dir, "sticky");
        var binaries = Path.Combine(ancestor, "private");
        Directory.CreateDirectory(binaries);
        File.SetUnixFileMode(ancestor,
            UnixFileMode.StickyBit |
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
            UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
            UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute);
        File.SetUnixFileMode(binaries,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        var naming = BinaryNaming.ForCurrentPlatform();
        foreach (var name in new[] { naming.FileName("meowshell"), naming.FileName("tailcat") })
            File.WriteAllText(Path.Combine(binaries, name), "placeholder");

        var located = MeowshellBinaries.Locate(binaries, naming);
        Assert.Equal(Path.Combine(binaries, naming.FileName("meowshell")), located.Meowshell);
        Assert.Equal(Path.Combine(binaries, naming.FileName("tailcat")), located.Tailcat);
    }
}
