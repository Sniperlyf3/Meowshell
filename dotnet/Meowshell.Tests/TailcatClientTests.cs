using Meowshell;

namespace Meowshell.Tests;

/// <summary>
/// Exercises TailcatClient against a stand-in for the bare tailcat binary --
/// unlike MeowshellServer/MeowshellSocksProxy/MeowshellPortForward, these
/// calls never go through meowshell, so the fake here plays "tailcat"
/// directly. The PlatformNotSupportedException SshAsync/CpAsync raise on
/// Android isn't covered here: OperatingSystem.IsAndroid() reflects the
/// real runtime, not something this net8.0 test process can fake.
/// </summary>
public sealed class TailcatClientTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("tailcat-client-test-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    /// <summary>Writes a stand-in "tailcat" running <paramref name="script"/>, recording its own argv, one element per line, plus a trivial "meowshell" (unused, but MeowshellBinaries.Locate requires both to exist).</summary>
    private (TailcatClientOptions options, string argsFile) Fake(string script)
    {
        var bin = Path.Combine(_dir, "bin");
        Directory.CreateDirectory(bin);
        var argsFile = Path.Combine(_dir, "args-" + Guid.NewGuid().ToString("N"));
        var naming = BinaryNaming.ForCurrentPlatform();
        var tailcat = Path.Combine(bin, naming.FileName("tailcat"));
        File.WriteAllText(tailcat, $"#!/bin/bash\nprintf '%s\\n' \"$@\" > {argsFile}\n" + script);
        var meowshell = Path.Combine(bin, naming.FileName("meowshell"));
        File.WriteAllText(meowshell, "#!/bin/bash\ntrue\n");
        if (!OperatingSystem.IsWindows())
        {
            const UnixFileMode exec = UnixFileMode.UserRead | UnixFileMode.UserExecute | UnixFileMode.UserWrite;
            File.SetUnixFileMode(tailcat, exec);
            File.SetUnixFileMode(meowshell, exec);
        }

        return (new TailcatClientOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "home"),
            Naming = naming,
            Timeout = TimeSpan.FromSeconds(10),
        }, argsFile);
    }

    [Fact]
    public async Task GenerateKeyReturnsTheLastLineOfOutput()
    {
        var (options, argsFile) = Fake("echo '# wrote file to somewhere'\necho tcTHEADDRESS000000000000\n");
        var address = await TailcatClient.GenerateKeyAsync(options, new TailcatKeyOptions
        {
            Name = "test-key",
            Force = true,
            Region = "derp1.example.com",
            Psk = false,
        });

        Assert.Equal("tcTHEADDRESS000000000000", address);
        var args = File.ReadAllLines(argsFile);
        Assert.Equal(["genkey", "--key=test-key", "--force", "--region=derp1.example.com", "--psk=false"], args);
    }

    [Fact]
    public async Task GenerateKeyThrowsOnFailure()
    {
        var (options, _) = Fake("echo 'name already exists' >&2\nexit 1\n");
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            TailcatClient.GenerateKeyAsync(options, new TailcatKeyOptions { Name = "dup" }));
        Assert.Contains("name already exists", ex.Message);
    }

    [Fact]
    public async Task DeleteKeyRunsGenkeyDelete()
    {
        var (options, argsFile) = Fake("");
        await TailcatClient.DeleteKeyAsync(options, "old-key");
        Assert.Equal(["genkey", "--key=old-key", "--delete"], File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task ListKeysSplitsOutputIntoLines()
    {
        var (options, argsFile) = Fake("printf 'default\\nclient-default\\n'\n");
        var keys = await TailcatClient.ListKeysAsync(options);
        Assert.Equal(["default", "client-default"], keys);
        Assert.Equal(["genkey", "--list"], File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task ParseReturnsRawJson()
    {
        var (options, argsFile) = Fake("""echo '{"RegionID":1}'""" + "\n");
        var json = await TailcatClient.ParseAsync(options, "tcSOMEADDR");
        Assert.Equal("""{"RegionID":1}""", json);
        Assert.Equal(["parse", "tcSOMEADDR"], File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task ResolveReturnsTheExpandedAddress()
    {
        var (options, argsFile) = Fake("echo tcEXPANDED\n");
        var expanded = await TailcatClient.ResolveAsync(options, "tcSHORT");
        Assert.Equal("tcEXPANDED", expanded);
        Assert.Equal(["resolve", "tcSHORT"], File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task PrintPubPassesTheClientKeyBeforeTheSubcommand()
    {
        var (options, argsFile) = Fake("echo nodekey:abc\n");
        var pub = await TailcatClient.PrintPubAsync(options, "my-client");
        Assert.Equal("nodekey:abc", pub);
        Assert.Equal(["--key=my-client", "printpub"], File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task PingDoesNotThrowOnANonZeroExit()
    {
        // --until-direct timing out is a meaningful, non-exceptional result.
        var (options, argsFile) = Fake("echo 'pong in 42ms via DERP(sfo)'\nexit 1\n");
        var result = await TailcatClient.PingAsync(options, "tcADDR", untilDirect: true, timeout: TimeSpan.FromSeconds(5));

        Assert.False(result.Success);
        Assert.Equal(1, result.ExitCode);
        Assert.Contains("pong in 42ms", result.Stdout);
        Assert.Equal(["ping", "--until-direct", "--timeout=5s", "tcADDR"], File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task ListFilesThrowsOnFailure()
    {
        var (options, argsFile) = Fake("echo 'no such file' >&2\nexit 1\n");
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => TailcatClient.ListFilesAsync(options, "tcADDR:missing", longListing: true));
        Assert.Contains("no such file", ex.Message);
        Assert.Equal(["ls", "-l", "tcADDR:missing"], File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task TimesOutAndKillsAHungCommand()
    {
        var (options, _) = Fake("exec sleep 300\n");
        var timed = options with { Timeout = TimeSpan.FromMilliseconds(500) };
        await Assert.ThrowsAsync<TimeoutException>(() => TailcatClient.ResolveAsync(timed, "tcADDR"));
    }

    [Fact]
    public async Task DerpMapUrlAndVerboseArePassedBeforeTheSubcommand()
    {
        var (options, argsFile) = Fake("echo tcADDR\n");
        await TailcatClient.ResolveAsync(
            options with { DerpMapUrl = "https://derp.example/map.json", Verbose = true }, "tcADDR");
        Assert.Equal(
            ["--derpmap-url=https://derp.example/map.json", "--verbose", "resolve", "tcADDR"],
            File.ReadAllLines(argsFile));
    }
}
