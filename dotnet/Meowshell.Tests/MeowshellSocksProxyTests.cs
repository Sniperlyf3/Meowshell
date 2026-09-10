using Meowshell;

namespace Meowshell.Tests;

public sealed class MeowshellSocksProxyTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("meowshell-socks-test-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private (MeowshellSocksOptions options, string argsFile) Fake(string script = "exec sleep 300\n")
    {
        var bin = Path.Combine(_dir, "bin");
        Directory.CreateDirectory(bin);
        var argsFile = Path.Combine(_dir, "args-" + Guid.NewGuid().ToString("N"));
        var shell = Path.Combine(bin, "libmeowshell.so");
        File.WriteAllText(shell, $"#!/bin/bash\nprintf '%s\\n' \"$@\" > {argsFile}\n" + script);
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
        await proxy.StopAsync();
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

    [Fact]
    public async Task CompletedFaultsWhenTheProxyCrashesOnItsOwn()
    {
        var (options, _) = Fake("sleep 0.2\necho 'listen: address already in use' >&2\nexit 1\n");
        await using var proxy = await MeowshellSocksProxy.StartAsync(options);

        var ex = await Assert.ThrowsAsync<TailcatException>(() => proxy.Completed);
        Assert.Equal(1, ex.ExitCode);
        Assert.Contains("address already in use", ex.Diagnostics);
    }
}
