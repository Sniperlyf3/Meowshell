using Meowshell;

namespace Meowshell.Tests;

/// <summary>
/// Exercises MeowshellSocksProxy against a stand-in for meowshell, the same
/// way <see cref="MeowshellServerTests"/> does for MeowshellServer.
/// </summary>
public sealed class MeowshellSocksProxyTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("meowshell-socks-test-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    /// <summary>Writes stand-in binaries whose "meowshell" records its own argv, one element per line, then stays up.</summary>
    private (MeowshellSocksOptions options, string argsFile) Fake()
    {
        var bin = Path.Combine(_dir, "bin");
        Directory.CreateDirectory(bin);
        var argsFile = Path.Combine(_dir, "args-" + Guid.NewGuid().ToString("N"));
        var shell = Path.Combine(bin, "libmeowshell.so");
        File.WriteAllText(shell, $"#!/bin/bash\nprintf '%s\\n' \"$@\" > {argsFile}\nexec sleep 300\n");
        File.SetUnixFileMode(shell, UnixFileMode.UserRead | UnixFileMode.UserExecute | UnixFileMode.UserWrite);
        var cat = Path.Combine(bin, "libtailcat.so");
        File.WriteAllText(cat, "#!/bin/bash\ntrue\n");
        File.SetUnixFileMode(cat, UnixFileMode.UserRead | UnixFileMode.UserExecute | UnixFileMode.UserWrite);

        return (new MeowshellSocksOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "home"),
            Naming = BinaryNaming.Android,
            GracePeriod = TimeSpan.FromSeconds(2),
        }, argsFile);
    }

    [Fact]
    public async Task AllFlagsArePassedThrough()
    {
        var (options, argsFile) = Fake();
        await using var proxy = await MeowshellSocksProxy.StartAsync(options with
        {
            Listen = "127.0.0.1:1080",
            ClientKey = "client-default",
            DerpMapUrl = "https://derp.example/map.json",
            Verbose = true,
        });

        // StartAsync returns as soon as the process is created, with no
        // handoff file to wait on the way MeowshellServer has -- give the
        // fake's own write a moment to land.
        for (var i = 0; i < 100 && !File.Exists(argsFile); i++)
            await Task.Delay(50);

        var args = File.ReadAllLines(argsFile);
        Assert.Contains("socks", args);
        Assert.Contains("--listen=127.0.0.1:1080", args);
        Assert.Contains("--key=client-default", args);
        Assert.Contains("--derpmap-url=https://derp.example/map.json", args);
        Assert.Contains("--verbose", args);
    }

    [Fact]
    public async Task StaysUpUntilStoppedAndIsIdempotent()
    {
        var (options, _) = Fake();
        var proxy = await MeowshellSocksProxy.StartAsync(options);

        Assert.False(proxy.Completed.IsCompleted, "the proxy exited on its own instead of staying up as a listener");

        await proxy.StopAsync();
        await proxy.StopAsync(); // must not throw
        Assert.True(proxy.Completed.IsCompletedSuccessfully);
        await proxy.DisposeAsync();
    }

    [Fact]
    public async Task ReportsMissingBinaries()
    {
        var (options, _) = Fake();
        var missing = options with { BinaryDirectory = Path.Combine(_dir, "nope") };
        await Assert.ThrowsAsync<FileNotFoundException>(() => MeowshellSocksProxy.StartAsync(missing));
    }
}
