using System.Diagnostics;
using Meowshell;

namespace Meowshell.Tests;

/// <summary>
/// Runs <see cref="MeowshellSocksProxy"/> and <see cref="MeowshellPortForward"/>
/// against the real tailcat and meowshell binaries built by build.sh -- the
/// .NET counterpart to <see cref="MeowshellServerE2ETests"/> for the two
/// other long-lived listeners meowshell wraps.
///
/// Skipped (each test returns immediately) when the real binaries are not
/// available, e.g. a local "dotnet test" run without a "dist" build.
/// </summary>
public sealed class MeowshellListenersE2ETests : IDisposable
{
    private const string TailcatEnvVar = "DOTNET_E2E_TAILCAT_BIN";
    private const string MeowshellEnvVar = "DOTNET_E2E_MEOWSHELL_BIN";

    private readonly string _dir = Directory.CreateTempSubdirectory("meowshell-listeners-e2e-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    /// <summary>Same layout as MeowshellServerE2ETests.RealBinaries(): copies the
    /// real binaries into a directory named per the current platform's
    /// convention, executable. Returns null (skip) if either is unavailable.</summary>
    private (string binDir, string tailcatPath)? RealBinaries()
    {
        var tailcatSrc = Environment.GetEnvironmentVariable(TailcatEnvVar);
        var meowshellSrc = Environment.GetEnvironmentVariable(MeowshellEnvVar);
        if (string.IsNullOrEmpty(tailcatSrc) || string.IsNullOrEmpty(meowshellSrc)
            || !File.Exists(tailcatSrc) || !File.Exists(meowshellSrc))
        {
            return null;
        }

        var bin = Path.Combine(_dir, "bin");
        Directory.CreateDirectory(bin);
        var naming = BinaryNaming.ForCurrentPlatform();
        var tailcatDst = Path.Combine(bin, naming.FileName("tailcat"));
        var meowshellDst = Path.Combine(bin, naming.FileName("meowshell"));
        File.Copy(tailcatSrc, tailcatDst);
        File.Copy(meowshellSrc, meowshellDst);
        if (!OperatingSystem.IsWindows())
        {
            const UnixFileMode exec =
                UnixFileMode.UserRead | UnixFileMode.UserExecute | UnixFileMode.UserWrite;
            File.SetUnixFileMode(tailcatDst, exec);
            File.SetUnixFileMode(meowshellDst, exec);
        }
        return (bin, tailcatDst);
    }

    [Fact]
    public async Task ASocksProxyStaysUpUntilStopped()
    {
        var real = RealBinaries();
        if (real is null) return; // see RealBinaries()
        var (bin, _) = real.Value;

        await using var proxy = await MeowshellSocksProxy.StartAsync(new MeowshellSocksOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "home"),
        });

        await Task.Delay(500);
        Assert.False(proxy.Completed.IsCompleted, "the proxy exited on its own instead of staying up as a listener");

        await proxy.StopAsync();
        Assert.True(proxy.Completed.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task APortForwardStartsItsLocalListenerAndStopsCleanly()
    {
        var real = RealBinaries();
        if (real is null) return; // see RealBinaries()
        var (bin, tailcatPath) = real.Value;

        // forward validates its <tc-addr> argument up front, so it needs a
        // syntactically real address -- nothing has to be listening at the
        // target for the local listener itself to come up.
        var configDir = Path.Combine(_dir, "keyconfig");
        Directory.CreateDirectory(configDir);
        var genkeyPsi = new ProcessStartInfo(tailcatPath)
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        genkeyPsi.ArgumentList.Add("genkey");
        genkeyPsi.ArgumentList.Add("--key=forward-e2e");
        genkeyPsi.Environment["XDG_CONFIG_HOME"] = configDir;
        using var genkey = Process.Start(genkeyPsi)!;
        var address = (await genkey.StandardOutput.ReadToEndAsync()).Trim();
        var exited = await Task.Run(() => genkey.WaitForExit(30_000));
        Assert.True(exited, "tailcat genkey did not exit in time");
        Assert.NotEmpty(address);

        await using var forward = await MeowshellPortForward.StartAsync(new MeowshellPortForwardOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "home2"),
            Address = address,
            Mappings = ["0:80"],
        });

        await Task.Delay(500);
        Assert.False(forward.Completed.IsCompleted, "forward exited on its own instead of staying up as a listener");

        await forward.StopAsync();
        Assert.True(forward.Completed.IsCompletedSuccessfully);
    }
}
