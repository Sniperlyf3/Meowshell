using System.Diagnostics;
using System.Text.RegularExpressions;
using Meowshell;

namespace Meowshell.Tests;

/// <summary>
/// Runs MeowshellServer against the real tailcat and meowshell binaries
/// built by build.sh, with a real tailcat client on the other end -- the one
/// thing the fake-binary tests in <see cref="MeowshellServerTests"/> cannot
/// cover, and the .NET counterpart to e2e/host-e2e.sh.
///
/// Skipped (each test returns immediately) when the real binaries are not
/// available, e.g. a local "dotnet test" run without a "dist" build. The CI
/// "dotnet" job always sets <see cref="TailcatEnvVar"/> and
/// <see cref="MeowshellEnvVar"/>, so there these tests actually run.
/// </summary>
public sealed class MeowshellServerE2ETests : IDisposable
{
    private const string TailcatEnvVar = "DOTNET_E2E_TAILCAT_BIN";
    private const string MeowshellEnvVar = "DOTNET_E2E_MEOWSHELL_BIN";

    private readonly string _dir = Directory.CreateTempSubdirectory("meowshell-e2e-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    /// <summary>
    /// Copies the real binaries named by <see cref="TailcatEnvVar"/> and
    /// <see cref="MeowshellEnvVar"/> into a directory laid out the way
    /// MeowshellServer expects: named per the current platform's convention,
    /// executable. Returns null if either variable is unset or names a
    /// missing file, which the caller treats as "nothing to test against".
    /// </summary>
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

    private static async Task<(int exitCode, string stdout, string stderr)> RunAsync(
        string exe, params string[] args)
    {
        var psi = new ProcessStartInfo(exe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        using var p = Process.Start(psi)!;
        var stdoutTask = p.StandardOutput.ReadToEndAsync();
        var stderrTask = p.StandardError.ReadToEndAsync();
        var exited = await Task.Run(() => p.WaitForExit(30_000));
        if (!exited)
        {
            p.Kill(entireProcessTree: true);
            throw new TimeoutException($"{exe} {string.Join(' ', args)} did not exit in time");
        }
        return (p.ExitCode, (await stdoutTask).Trim(), (await stderrTask).Trim());
    }

    /// <summary>
    /// The node key an address carries, the same way e2e/host-e2e.sh
    /// compares identities: a server picks a DERP region at startup and
    /// embeds it, so the address it publishes is not byte-identical to the
    /// one genkey printed.
    /// </summary>
    private static async Task<string> IdentityAsync(string tailcatPath, string address)
    {
        var (exitCode, stdout, _) = await RunAsync(tailcatPath, "parse", address);
        Assert.Equal(0, exitCode);
        var match = Regex.Match(stdout, "\"ServerPublic\":\\s*\"([^\"]+)\"");
        Assert.True(match.Success, $"no ServerPublic in: {stdout}");
        return match.Groups[1].Value;
    }

    [Fact]
    public async Task ARealClientCanRunACommandOverTheAddress()
    {
        var real = RealBinaries();
        if (real is null) return; // see RealBinaries()
        var (bin, tailcatPath) = real.Value;

        // Construct MeowshellOptions directly rather than through Create():
        // this test needs a specific directory of real downloaded binaries,
        // not the auto-discovery a real consumer gets for free.
        var options = new MeowshellOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "home"),
            WorkDirectory = Path.Combine(_dir, "work"),
            InsecureNoAuth = true,
            Lifetime = TimeSpan.FromMinutes(2),
            StartTimeout = TimeSpan.FromSeconds(30),
        };

        var logs = new List<string>();
        await using var server = await MeowshellServer.StartAsync(options);
        server.Log += line => { lock (logs) logs.Add(line); };

        Assert.False(string.IsNullOrWhiteSpace(server.Address));

        var marker = $"dotnet-e2e-{Guid.NewGuid():N}";
        var (exitCode, stdout, stderr) = await RunAsync(tailcatPath, "ssh", server.Address, $"echo {marker}");

        Assert.True(exitCode == 0, $"tailcat ssh failed (exit {exitCode}): {stderr}\n---server log---\n{string.Join('\n', logs)}");
        Assert.Contains(marker, stdout);

        await server.StopAsync();
        Assert.True(server.Completed.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task APrivateKeyDeliveredAtRuntimeCarriesTheProvisionedIdentity()
    {
        var real = RealBinaries();
        if (real is null) return; // see RealBinaries()
        var (bin, tailcatPath) = real.Value;

        // Provision a key on the host, exactly as a backend handing out a
        // per-session key would -- with its own config directory, entirely
        // separate from wherever MeowshellServer runs the session.
        var configDir = Path.Combine(_dir, "keyconfig");
        Directory.CreateDirectory(configDir);
        var genkeyPsi = new ProcessStartInfo(tailcatPath)
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        genkeyPsi.ArgumentList.Add("genkey");
        genkeyPsi.ArgumentList.Add("--key=dotnet-e2e");
        genkeyPsi.Environment["XDG_CONFIG_HOME"] = configDir;
        using (var genkey = Process.Start(genkeyPsi)!)
        {
            var provisioned = (await genkey.StandardOutput.ReadToEndAsync()).Trim();
            var exited = await Task.Run(() => genkey.WaitForExit(30_000));
            Assert.True(exited, "tailcat genkey did not exit in time");
            Assert.Equal(0, genkey.ExitCode);
            Assert.NotEmpty(provisioned);

            var keyPath = Path.Combine(configDir, "tailcat", "keys", "dotnet-e2e.private.json");
            Assert.True(File.Exists(keyPath), $"genkey did not write {keyPath}");
            var keyJson = await File.ReadAllTextAsync(keyPath);

            var options = new MeowshellOptions
            {
                BinaryDirectory = bin,
                HomeDirectory = Path.Combine(_dir, "home"),
                WorkDirectory = Path.Combine(_dir, "work"),
                InsecureNoAuth = true,
                Lifetime = TimeSpan.FromMinutes(2),
                PrivateKeyJson = keyJson,
                StartTimeout = TimeSpan.FromSeconds(30),
            };

            await using var server = await MeowshellServer.StartAsync(options);

            var provisionedIdentity = await IdentityAsync(tailcatPath, provisioned);
            var publishedIdentity = await IdentityAsync(tailcatPath, server.Address);
            Assert.Equal(provisionedIdentity, publishedIdentity);

            await server.StopAsync();
        }
    }
}
