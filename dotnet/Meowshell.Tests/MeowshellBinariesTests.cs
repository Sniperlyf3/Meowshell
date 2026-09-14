using Meowshell;
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
