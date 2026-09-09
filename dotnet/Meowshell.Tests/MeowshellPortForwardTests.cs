using Meowshell;

namespace Meowshell.Tests;

/// <summary>
/// Exercises MeowshellPortForward against a stand-in for meowshell, the
/// same way <see cref="MeowshellServerTests"/> does for MeowshellServer.
/// </summary>
public sealed class MeowshellPortForwardTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("meowshell-forward-test-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    /// <summary>Writes stand-in binaries whose "meowshell" records its own argv, one element per line, then stays up.</summary>
    private (MeowshellPortForwardOptions options, string argsFile) Fake()
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

        return (new MeowshellPortForwardOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "home"),
            Naming = BinaryNaming.Android,
            Address = "tcTESTADDRESS000000000000",
            Mappings = ["8080"],
            GracePeriod = TimeSpan.FromSeconds(2),
        }, argsFile);
    }

    [Fact]
    public async Task AllFlagsAndMappingsArePassedThrough()
    {
        var (options, argsFile) = Fake();
        await using var forward = await MeowshellPortForward.StartAsync(options with
        {
            Mappings = ["8080", "0:9090"],
            Bind = "0.0.0.0",
            ClientKey = "client-default",
            DerpMapUrl = "https://derp.example/map.json",
            Verbose = true,
        });

        for (var i = 0; i < 100 && !File.Exists(argsFile); i++)
            await Task.Delay(50);

        var args = File.ReadAllLines(argsFile);
        Assert.Contains("forward", args);
        Assert.Contains("--bind=0.0.0.0", args);
        Assert.Contains("--key=client-default", args);
        Assert.Contains("--derpmap-url=https://derp.example/map.json", args);
        Assert.Contains("--verbose", args);
        Assert.Contains(options.Address, args);
        Assert.Contains("8080", args);
        Assert.Contains("0:9090", args);
    }

    [Fact]
    public async Task RequiresAtLeastOneMapping()
    {
        var (options, _) = Fake();
        var empty = options with { Mappings = [] };
        await Assert.ThrowsAsync<ArgumentException>(() => MeowshellPortForward.StartAsync(empty));
    }

    [Fact]
    public async Task StaysUpUntilStoppedAndIsIdempotent()
    {
        var (options, _) = Fake();
        var forward = await MeowshellPortForward.StartAsync(options);

        Assert.False(forward.Completed.IsCompleted, "forward exited on its own instead of staying up as a listener");

        await forward.StopAsync();
        await forward.StopAsync(); // must not throw
        Assert.True(forward.Completed.IsCompletedSuccessfully);
        await forward.DisposeAsync();
    }

    [Fact]
    public async Task ReportsMissingBinaries()
    {
        var (options, _) = Fake();
        var missing = options with { BinaryDirectory = Path.Combine(_dir, "nope") };
        await Assert.ThrowsAsync<FileNotFoundException>(() => MeowshellPortForward.StartAsync(missing));
    }
}
