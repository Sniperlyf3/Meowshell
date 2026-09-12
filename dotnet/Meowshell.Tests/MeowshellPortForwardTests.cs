using Meowshell;

namespace Meowshell.Tests;

public sealed class MeowshellPortForwardTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("meowshell-forward-test-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private (MeowshellPortForwardOptions options, string argsFile) Fake(string script = "exec sleep 300\n")
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

        // Waiting on File.Exists alone races the fake shell script's own
        // "printf ... > argsFile" line: the shell's stdout redirection
        // creates (and truncates) the file before printf actually runs, so
        // a poll landing in that gap can observe an existing but still-empty
        // file and read back no args at all.
        for (var i = 0; i < 100 && (!File.Exists(argsFile) || new FileInfo(argsFile).Length == 0); i++)
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

    // Regression test: StartAsync used to discard MeowshellBinaries.Locate's
    // resolved tailcat path (var (meowshell, _) = ...), so the spawned
    // "meowshell forward" process resolved tailcat on its own -- via an
    // inherited TAILCAT_BIN, a sibling binary, or $PATH -- silently
    // overriding whatever BinaryDirectory the caller explicitly selected.
    // Sets a bogus inherited TAILCAT_BIN before starting and asserts the
    // child still sees the BinaryDirectory-resolved path.
    [Fact]
    public async Task ResolvedTailcatBinaryOverridesInheritedTailcatBinEnvironmentVariable()
    {
        var bin = Path.Combine(_dir, "bin");
        Directory.CreateDirectory(bin);
        var envFile = Path.Combine(_dir, "env-" + Guid.NewGuid().ToString("N"));
        var shell = Path.Combine(bin, "libmeowshell.so");
        File.WriteAllText(shell, $"#!/bin/bash\necho \"TAILCAT_BIN=$TAILCAT_BIN\" > {envFile}\nexec sleep 300\n");
        File.SetUnixFileMode(shell, UnixFileMode.UserRead | UnixFileMode.UserExecute | UnixFileMode.UserWrite);
        var cat = Path.Combine(bin, "libtailcat.so");
        File.WriteAllText(cat, "#!/bin/bash\ntrue\n");
        File.SetUnixFileMode(cat, UnixFileMode.UserRead | UnixFileMode.UserExecute | UnixFileMode.UserWrite);

        var options = new MeowshellPortForwardOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "home"),
            Naming = BinaryNaming.Android,
            Address = "tcTESTADDRESS000000000000",
            Mappings = ["8080"],
            GracePeriod = TimeSpan.FromSeconds(2),
        };

        Environment.SetEnvironmentVariable("TAILCAT_BIN", "/bogus/attacker/tailcat");
        try
        {
            await using var forward = await MeowshellPortForward.StartAsync(options);

            for (var i = 0; i < 100 && (!File.Exists(envFile) || new FileInfo(envFile).Length == 0); i++)
                await Task.Delay(50);

            Assert.Equal($"TAILCAT_BIN={cat}", File.ReadAllText(envFile).Trim());
        }
        finally
        {
            Environment.SetEnvironmentVariable("TAILCAT_BIN", null);
        }
    }

    [Fact]
    public async Task RequiresAtLeastOneMapping()
    {
        var (options, _) = Fake();
        var empty = options with { Mappings = [] };
        await Assert.ThrowsAsync<ArgumentException>(() => MeowshellPortForward.StartAsync(empty));
    }

    // Regression test for N13: GracePeriod used to reach TailcatListener
    // unvalidated and only actually get used much later, inside StopAsync's
    // own CancellationTokenSource -- so an invalid value (a caller mistake, a
    // TimeSpan built from bad arithmetic) would not surface until shutdown,
    // by which point the process was already running. The redirection line
    // at the top of the fake shell script always creates argsFile as soon as
    // the process actually starts, regardless of arguments, so its absence
    // here proves the process was never spawned.
    [Fact]
    public async Task StartAsync_RejectsAnInvalidGracePeriodWithoutStartingTheProcess()
    {
        var (options, argsFile) = Fake();
        var bad = options with { GracePeriod = TimeSpan.FromSeconds(-1) };
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => MeowshellPortForward.StartAsync(bad));
        Assert.False(File.Exists(argsFile), "the forward process was started despite an invalid GracePeriod");
    }

    [Fact]
    public async Task StaysUpUntilStoppedAndIsIdempotent()
    {
        var (options, _) = Fake();
        var forward = await MeowshellPortForward.StartAsync(options);

        Assert.False(forward.Completed.IsCompleted, "forward exited on its own instead of staying up as a listener");

        await forward.StopAsync();
        await forward.StopAsync();
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

    [Fact]
    public async Task CompletedFaultsWhenForwardingCrashesOnItsOwn()
    {
        var (options, _) = Fake("sleep 0.2\necho 'listen: address already in use' >&2\nexit 1\n");
        await using var forward = await MeowshellPortForward.StartAsync(options);

        var ex = await Assert.ThrowsAsync<TailcatException>(() => forward.Completed);
        Assert.Equal(1, ex.ExitCode);
        Assert.Contains("address already in use", ex.Diagnostics);
    }
}
