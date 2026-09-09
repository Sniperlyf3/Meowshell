using Meowshell;

namespace Meowshell.Tests;

/// <summary>
/// Exercises TailcatClient against a stand-in for the bare tailcat binary --
/// unlike MeowshellServer/MeowshellSocksProxy/MeowshellPortForward, these
/// calls never go through meowshell, so the fake here plays "tailcat"
/// directly. The PlatformNotSupportedException SshAsync/CpAsync raise on
/// Android isn't covered here: OperatingSystem.IsAndroid() reflects the
/// real runtime, not something this net8.0 test process can fake.
///
/// The parsing tests below feed real output captured from the actual
/// tailcat binary (built from tailscale/tailcat, run against a hermetic
/// local DERP+STUN server -- see tailscale.com/tstest/integration), not
/// guessed strings, so a future tailcat release changing its output shape
/// fails these loudly rather than silently producing wrong typed results.
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
    public async Task GenerateKeyReturnsAPublicKeyForAClientKey()
    {
        var (options, _) = Fake("echo '# wrote file to somewhere' >&2\necho nodekey:abc123\n");
        var pub = await TailcatClient.GenerateKeyAsync(options, new TailcatKeyOptions { Name = "client-key", Client = true });
        Assert.Equal("nodekey:abc123", pub);
    }

    [Fact]
    public async Task GenerateKeyThrowsOnFailure()
    {
        var (options, _) = Fake("echo 'name already exists' >&2\nexit 1\n");
        var ex = await Assert.ThrowsAsync<TailcatException>(() =>
            TailcatClient.GenerateKeyAsync(options, new TailcatKeyOptions { Name = "dup" }));
        Assert.Equal(1, ex.ExitCode);
        Assert.Contains("name already exists", ex.Message);
    }

    [Fact]
    public async Task GenerateKeyThrowsOnUnexpectedOutputShape()
    {
        // A zero exit but output that isn't a tailcat address at all --
        // this should never happen against a real binary, but must not be
        // silently trusted if it does.
        var (options, _) = Fake("echo not-an-address\n");
        var ex = await Assert.ThrowsAsync<TailcatException>(() =>
            TailcatClient.GenerateKeyAsync(options, new TailcatKeyOptions { Name = "key" }));
        Assert.Equal(0, ex.ExitCode);
        Assert.Contains("not-an-address", ex.Message);
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

    // Captured from `tailcat parse <addr>` for a short address with no
    // embedded region (just a RegionID reference).
    private const string ParseJsonShort = """
        {
            "ServerPublic": "nodekey:8d927fef23cb84f285a936d650be0d73820f5a613062ed2ffe1922bfe77cf55d",
            "ServerDiscoPublic": "discokey:843c6d2f4e9d30b21f39b7f64d0d1ed9467c3197076ace8cbb5cc26774d03867",
            "PresharedKey": "psk:0d271a03cc077f6ba3ccaf099b46468e33dab0cd643d95fa66435a0601b16a35",
            "RegionID": 1
        }
        """;

    // Captured from `tailcat parse <resolved-addr>`, where <resolved-addr>
    // came from `tailcat resolve` -- a "full address" embedding its DERP
    // node directly instead of referencing a region by ID.
    private const string ParseJsonEmbeddedRegion = """
        {
            "ServerPublic": "nodekey:2aeee97e7151c4189254361d2d1ba08553c99b8993881e9375e2f1adb9de7f59",
            "ServerDiscoPublic": "discokey:5cc360ec1d79a2f43c02793f990bebb281c945a3de571f5d3dece89d65af0739",
            "PresharedKey": "psk:5328503ade7212f5cebfb8fa6053892a0ead06c86db42022d48f004a2baff687",
            "Region": [
                {
                    "Nodes": [
                        {
                            "HostName": "127.0.0.1",
                            "IPv4": "127.0.0.1",
                            "IPv6": "none",
                            "STUNPort": 43597,
                            "DERPPort": 44885,
                            "InsecureForTests": true
                        }
                    ]
                }
            ]
        }
        """;

    [Fact]
    public async Task ParseReturnsTypedFieldsForAShortAddress()
    {
        var (options, argsFile) = Fake($"cat <<'EOF'\n{ParseJsonShort}\nEOF\n");
        var parsed = await TailcatClient.ParseAsync(options, new TailcatAddress("tcSOMEADDR"));

        Assert.Equal("nodekey:8d927fef23cb84f285a936d650be0d73820f5a613062ed2ffe1922bfe77cf55d", parsed.ServerPublic);
        Assert.Equal("discokey:843c6d2f4e9d30b21f39b7f64d0d1ed9467c3197076ace8cbb5cc26774d03867", parsed.ServerDiscoPublic);
        Assert.Equal("psk:0d271a03cc077f6ba3ccaf099b46468e33dab0cd643d95fa66435a0601b16a35", parsed.PresharedKey);
        Assert.Equal(1, parsed.RegionId);
        Assert.Null(parsed.Region);
        Assert.Equal(["parse", "tcSOMEADDR"], File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task ParseReturnsTypedFieldsForAFullAddressWithAnEmbeddedRegion()
    {
        var (options, _) = Fake($"cat <<'EOF'\n{ParseJsonEmbeddedRegion}\nEOF\n");
        var parsed = await TailcatClient.ParseAsync(options, new TailcatAddress("tcRESOLVED"));

        Assert.Equal(0, parsed.RegionId);
        Assert.NotNull(parsed.Region);
        var region = Assert.Single(parsed.Region);
        Assert.Null(region.RegionCode);
        var node = Assert.Single(region.Nodes!);
        Assert.Equal("127.0.0.1", node.HostName);
        Assert.Equal("127.0.0.1", node.IPv4);
        Assert.Equal(43597, node.StunPort);
        Assert.Equal(44885, node.DerpPort);
        Assert.True(node.InsecureForTests);
    }

    [Fact]
    public async Task ParseThrowsOnMalformedJson()
    {
        var (options, _) = Fake("echo 'not json at all'\n");
        var ex = await Assert.ThrowsAsync<TailcatException>(
            () => TailcatClient.ParseAsync(options, new TailcatAddress("tcADDR")));
        Assert.Equal(0, ex.ExitCode);
    }

    [Fact]
    public async Task ParseThrowsOnFailure()
    {
        var (options, _) = Fake("echo 'tailcat address doesn'\"'\"'t start with \"tc\"' >&2\nexit 1\n");
        var ex = await Assert.ThrowsAsync<TailcatException>(
            () => TailcatClient.ParseAsync(options, new TailcatAddress("tcADDR")));
        Assert.Equal(1, ex.ExitCode);
    }

    [Fact]
    public async Task ResolveReturnsTheExpandedAddress()
    {
        var (options, argsFile) = Fake("echo tcEXPANDED\n");
        var expanded = await TailcatClient.ResolveAsync(options, "tcSHORT");
        Assert.Equal("tcEXPANDED", expanded.ToString());
        Assert.Equal(["resolve", "tcSHORT"], File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task ResolveThrowsOnUnexpectedOutputShape()
    {
        var (options, _) = Fake("echo not-an-address\n");
        var ex = await Assert.ThrowsAsync<TailcatException>(() => TailcatClient.ResolveAsync(options, "tcSHORT"));
        Assert.Equal(0, ex.ExitCode);
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
    public async Task PrintPubThrowsOnUnexpectedOutputShape()
    {
        var (options, _) = Fake("echo oops\n");
        var ex = await Assert.ThrowsAsync<TailcatException>(() => TailcatClient.PrintPubAsync(options));
        Assert.Equal(0, ex.ExitCode);
    }

    [Fact]
    public async Task PingParsesADirectPong()
    {
        // Captured from `tailcat ping <addr>` against a hermetic local server.
        var (options, argsFile) = Fake("printf 'pong in 580µs via 127.0.0.1:45437\\n'\n");
        var result = await TailcatClient.PingAsync(options, "tcADDR");

        Assert.True(result.Success);
        Assert.NotNull(result.Pong);
        Assert.Equal(TimeSpan.FromMicroseconds(580), result.Pong!.Latency);
        Assert.True(result.Pong.Direct);
        Assert.Equal("127.0.0.1:45437", result.Pong.Via);
        Assert.Equal(["ping", "tcADDR"], File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task PingParsesADerpRelayedPong()
    {
        // Captured from `tailcat ping <addr>` when the connection fell back to DERP.
        var (options, _) = Fake("printf 'pong in 680µs via DERP(test)\\n'\n");
        var result = await TailcatClient.PingAsync(options, "tcADDR");

        Assert.True(result.Success);
        Assert.NotNull(result.Pong);
        Assert.Equal(TimeSpan.FromMicroseconds(680), result.Pong!.Latency);
        Assert.False(result.Pong.Direct);
        Assert.Equal("test", result.Pong.Via);
    }

    [Theory]
    [InlineData("1.5s", 1500)]
    [InlineData("2m0.5s", 120_500)]
    [InlineData("1h2m3s", 3_723_000)]
    [InlineData("0s", 0)]
    public async Task PingParsesCompoundGoDurations(string duration, int expectedMilliseconds)
    {
        var (options, _) = Fake($"printf 'pong in {duration} via 127.0.0.1:1\\n'\n");
        var result = await TailcatClient.PingAsync(options, "tcADDR");
        Assert.Equal(TimeSpan.FromMilliseconds(expectedMilliseconds), result.Pong!.Latency);
    }

    [Fact]
    public async Task PingDoesNotThrowOnANonZeroExit()
    {
        // --until-direct timing out is a meaningful, non-exceptional result,
        // and can still have printed relayed pongs before giving up.
        var (options, argsFile) = Fake("echo 'pong in 42ms via DERP(sfo)'\nexit 1\n");
        var result = await TailcatClient.PingAsync(options, "tcADDR", untilDirect: true, timeout: TimeSpan.FromSeconds(5));

        Assert.False(result.Success);
        Assert.Equal(1, result.Result.ExitCode);
        Assert.NotNull(result.Pong);
        Assert.Equal(TimeSpan.FromMilliseconds(42), result.Pong!.Latency);
        Assert.False(result.Pong.Direct);
        Assert.Equal(["ping", "--until-direct", "--timeout=5s", "tcADDR"], File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task PingLeavesPongNullWhenNothingMatched()
    {
        var (options, _) = Fake("echo 'ping: no route to host' >&2\nexit 1\n");
        var result = await TailcatClient.PingAsync(options, "tcADDR");
        Assert.False(result.Success);
        Assert.Null(result.Pong);
    }

    [Fact]
    public async Task ListFilesParsesAShortListing()
    {
        // Captured from `tailcat ls <addr>` against a directory containing
        // one file and one subdirectory.
        var (options, argsFile) = Fake("printf 'hello.txt\\nsubdir/\\n'\n");
        var entries = await TailcatClient.ListFilesAsync(options, "tcADDR", longListing: false);

        Assert.Equal(2, entries.Count);
        Assert.Equal("hello.txt", entries[0].Name);
        Assert.False(entries[0].IsDirectory);
        Assert.Null(entries[0].Mode);
        Assert.Equal("subdir", entries[1].Name);
        Assert.True(entries[1].IsDirectory);
        Assert.Equal(["ls", "tcADDR"], File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task ListFilesParsesALongListing()
    {
        // Captured from `tailcat ls -l <addr>` against the same directory.
        var (options, argsFile) = Fake(
            "printf -- '-rw-r--r--            3 Sep  9 10:56 hello.txt\\ndrwxr-xr-x         4096 Sep  9 10:56 subdir/\\n'\n");
        var entries = await TailcatClient.ListFilesAsync(options, "tcADDR", longListing: true);

        Assert.Equal(2, entries.Count);

        var file = entries[0];
        Assert.Equal("hello.txt", file.Name);
        Assert.False(file.IsDirectory);
        Assert.Equal("-rw-r--r--", file.Mode);
        Assert.Equal(3, file.Size);
        Assert.Equal("Sep 9 10:56", file.ModifiedRaw);
        Assert.NotNull(file.ModifiedAt);
        Assert.Equal(9, file.ModifiedAt!.Value.Month);
        Assert.Equal(9, file.ModifiedAt.Value.Day);
        Assert.Equal(10, file.ModifiedAt.Value.Hour);
        Assert.Equal(56, file.ModifiedAt.Value.Minute);
        Assert.True(file.ModifiedAt.Value <= DateTime.UtcNow.AddDays(1));

        var dir = entries[1];
        Assert.Equal("subdir", dir.Name);
        Assert.True(dir.IsDirectory);
        Assert.Equal("drwxr-xr-x", dir.Mode);
        Assert.Equal(4096, dir.Size);

        Assert.Equal(["ls", "-l", "tcADDR"], File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task ListFilesParsesALongListingOfASingleFileTarget()
    {
        // Captured from `tailcat ls -l <addr>:hello.txt` (a file, not a
        // directory): one entry, no directory traversal.
        var (options, _) = Fake("printf -- '-rw-r--r--            3 Sep  9 10:56 hello.txt\\n'\n");
        var entries = await TailcatClient.ListFilesAsync(options, "tcADDR:hello.txt", longListing: true);
        var entry = Assert.Single(entries);
        Assert.Equal("hello.txt", entry.Name);
        Assert.False(entry.IsDirectory);
    }

    [Fact]
    public async Task ListFilesParsesAnOlderEntryWithAYearInsteadOfATime()
    {
        // tailcat prints a year instead of a time of day for anything
        // modified more than 180 days ago -- not reachable from a fresh
        // hermetic test server, so this line is built from the verified
        // "%s %12d %s %s" format (tailcat's ls.go) rather than captured live.
        var (options, _) = Fake("printf -- '-rw-r--r--          512 Jan 15  2019 old.txt\\n'\n");
        var entries = await TailcatClient.ListFilesAsync(options, "tcADDR", longListing: true);
        var entry = Assert.Single(entries);

        Assert.Equal("old.txt", entry.Name);
        Assert.Equal("Jan 15 2019", entry.ModifiedRaw);
        Assert.Equal(new DateTime(2019, 1, 15, 0, 0, 0, DateTimeKind.Unspecified), entry.ModifiedAt);
    }

    [Fact]
    public async Task ListFilesThrowsOnFailure()
    {
        var (options, argsFile) = Fake("echo 'no such file' >&2\nexit 1\n");
        var ex = await Assert.ThrowsAsync<TailcatException>(
            () => TailcatClient.ListFilesAsync(options, "tcADDR:missing", longListing: true));
        Assert.Equal(1, ex.ExitCode);
        Assert.Contains("no such file", ex.Message);
        Assert.Equal(["ls", "-l", "tcADDR:missing"], File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task ListFilesThrowsOnAnUnparseableLongListingLine()
    {
        var (options, _) = Fake("echo 'not a valid ls -l line at all'\n");
        var ex = await Assert.ThrowsAsync<TailcatException>(
            () => TailcatClient.ListFilesAsync(options, "tcADDR", longListing: true));
        Assert.Equal(0, ex.ExitCode);
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
