using Meowshell;

namespace Meowshell.Tests;

public sealed class TailcatClientTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("tailcat-client-test-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

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

    private TailcatClientOptions FakeMeowshell(string script)
    {
        var bin = Path.Combine(_dir, "bin");
        Directory.CreateDirectory(bin);
        var naming = BinaryNaming.ForCurrentPlatform();
        var meowshell = Path.Combine(bin, naming.FileName("meowshell"));
        File.WriteAllText(meowshell, "#!/bin/bash\n" + script);
        var tailcat = Path.Combine(bin, naming.FileName("tailcat"));
        File.WriteAllText(tailcat, "#!/bin/bash\ntrue\n");
        if (!OperatingSystem.IsWindows())
        {
            const UnixFileMode exec = UnixFileMode.UserRead | UnixFileMode.UserExecute | UnixFileMode.UserWrite;
            File.SetUnixFileMode(meowshell, exec);
            File.SetUnixFileMode(tailcat, exec);
        }

        return new TailcatClientOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "home"),
            Naming = naming,
            Timeout = TimeSpan.FromSeconds(10),
        };
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

    private const string ParseJsonShort = """
        {
            "ServerPublic": "nodekey:8d927fef23cb84f285a936d650be0d73820f5a613062ed2ffe1922bfe77cf55d",
            "ServerDiscoPublic": "discokey:843c6d2f4e9d30b21f39b7f64d0d1ed9467c3197076ace8cbb5cc26774d03867",
            "PresharedKey": "psk:0d271a03cc077f6ba3ccaf099b46468e33dab0cd643d95fa66435a0601b16a35",
            "RegionID": 1
        }
        """;

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

        var (options, _) = Fake("printf -- '-rw-r--r--            3 Sep  9 10:56 hello.txt\\n'\n");
        var entries = await TailcatClient.ListFilesAsync(options, "tcADDR:hello.txt", longListing: true);
        var entry = Assert.Single(entries);
        Assert.Equal("hello.txt", entry.Name);
        Assert.False(entry.IsDirectory);
    }

    [Fact]
    public async Task ListFilesParsesAnOlderEntryWithAYearInsteadOfATime()
    {

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
    public async Task ListFilesAcceptsATypedRemotePath()
    {
        var (options, argsFile) = Fake("printf 'hello.txt\\n'\n");
        var address = new TailcatAddress("tcADDR");
        await TailcatClient.ListFilesAsync(options, TailcatPath.Remote(address, "subdir"));
        Assert.Equal(["ls", "tcADDR:subdir"], File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task ListFilesRejectsALocalTypedPath()
    {
        var (options, _) = Fake("");
        await Assert.ThrowsAsync<ArgumentException>(
            () => TailcatClient.ListFilesAsync(options, TailcatPath.Local("not-remote")));
    }

    [Fact]
    public void TailcatPathFormatsALocalPathAsIs()
    {
        TailcatPath path = "local/file.txt";
        Assert.False(path.IsRemote);
        Assert.Equal("local/file.txt", path.ToString());
    }

    [Fact]
    public void TailcatPathFormatsARemoteAddressWithAPath()
    {
        var path = TailcatPath.Remote(new TailcatAddress("tcADDR"), "sub/dir.txt");
        Assert.True(path.IsRemote);
        Assert.Equal("tcADDR:sub/dir.txt", path.ToString());
    }

    [Fact]
    public void TailcatPathFormatsARemoteAddressWithNoPathAsATrailingColon()
    {
        var path = TailcatPath.Remote(new TailcatAddress("tcADDR"));
        Assert.Equal("tcADDR:", path.ToString());
    }

    [Fact]
    public void TailcatPathFormatsARemoteHost()
    {
        var path = TailcatPath.RemoteHost("device.example.com", "file.txt");
        Assert.True(path.IsRemote);
        Assert.Equal("device.example.com:file.txt", path.ToString());
    }

    [Fact]
    public async Task CpUploadsALocalSourceToARemoteTarget()
    {
        var (options, argsFile) = Fake("");
        var address = new TailcatAddress("tcADDR");
        await TailcatClient.CpAsync(options, TailcatPath.Local("photo.jpg"), TailcatPath.Remote(address, "photos/photo.jpg"));
        Assert.Equal(["cp", "photo.jpg", "tcADDR:photos/photo.jpg"], File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task CpDownloadsARemoteSourceToALocalTarget()
    {
        var (options, argsFile) = Fake("");
        var address = new TailcatAddress("tcADDR");
        await TailcatClient.CpAsync(
            options, TailcatPath.Remote(address, "report.txt"), "local-copy.txt",
            recursive: true, preserve: true, port: "2222");
        Assert.Equal(["cp", "-r", "-p", "-P", "2222", "tcADDR:report.txt", "local-copy.txt"], File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task CpCopiesMultipleSourcesToOneRemoteTarget()
    {
        var (options, argsFile) = Fake("");
        var address = new TailcatAddress("tcADDR");
        await TailcatClient.CpAsync(
            options, [TailcatPath.Local("a.txt"), TailcatPath.Local("b.txt")], TailcatPath.Remote(address, "dir/"));
        Assert.Equal(["cp", "a.txt", "b.txt", "tcADDR:dir/"], File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task CpThrowsWithNoRemotePath()
    {
        var (options, _) = Fake("");
        var ex = await Assert.ThrowsAsync<ArgumentException>(
            () => TailcatClient.CpAsync(options, TailcatPath.Local("a.txt"), TailcatPath.Local("b.txt")));
        Assert.Contains("must be remote", ex.Message);
    }

    [Fact]
    public async Task CpThrowsWhenRemotePathsNameDifferentServers()
    {
        var (options, _) = Fake("");
        var ex = await Assert.ThrowsAsync<ArgumentException>(() => TailcatClient.CpAsync(
            options,
            [TailcatPath.Remote(new TailcatAddress("tcAAA"), "a.txt")],
            TailcatPath.Remote(new TailcatAddress("tcBBB"), "b.txt")));
        Assert.Contains("must name the same server", ex.Message);
    }

    [Fact]
    public async Task CpThrowsWithNoSources()
    {
        var (options, _) = Fake("");
        await Assert.ThrowsAsync<ArgumentException>(
            () => TailcatClient.CpAsync(options, [], TailcatPath.Remote(new TailcatAddress("tcADDR"))));
    }

    [Fact]
    public async Task CpDoesNotThrowOnANonZeroExit()
    {

        var (options, _) = Fake("echo 'scp: no such file or directory' >&2\nexit 1\n");
        var result = await TailcatClient.CpAsync(
            options, TailcatPath.Local("missing.txt"), TailcatPath.Remote(new TailcatAddress("tcADDR")));
        Assert.False(result.Success);
        Assert.Equal(1, result.ExitCode);
        Assert.Contains("no such file", result.Stderr);
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

    [Fact]
    public async Task GetEnvironmentParsesAFullMeowshellEnvReport()
    {

        var options = FakeMeowshell(
            "printf 'shell /bin/bash\\nhome  /home/e2e\\nuser  e2e\\npath  /usr/bin:/bin\\nterm  xterm-256color\\nlang  en_US.UTF-8\\ntailcat /opt/bin/tailcat\\n'\n");

        var env = await TailcatClient.GetEnvironmentAsync(options);

        Assert.Equal("/bin/bash", env.Shell);
        Assert.Equal("/home/e2e", env.Home);
        Assert.Equal("e2e", env.User);
        Assert.Equal("/usr/bin:/bin", env.Path);
        Assert.Equal("xterm-256color", env.Term);
        Assert.Equal("en_US.UTF-8", env.Lang);
        Assert.Equal("/opt/bin/tailcat", env.TailcatBinaryPath);
        Assert.Empty(env.Warnings);
    }

    [Fact]
    public async Task GetEnvironmentSurfacesWarningsAndAMissingTailcatBinary()
    {
        var options = FakeMeowshell(
            "printf 'shell /bin/sh\\nhome  /home/e2e\\nuser  e2e\\npath  /usr/bin\\nterm  \\nlang  \\ntailcat NOT FOUND (exec: \"tailcat\": executable file not found in $PATH)\\nwarning: $SHELL not set, falling back to /bin/sh\\n'\n");

        var env = await TailcatClient.GetEnvironmentAsync(options);

        Assert.Null(env.TailcatBinaryPath);
        Assert.Equal(["$SHELL not set, falling back to /bin/sh"], env.Warnings);
    }

    [Fact]
    public async Task GetEnvironmentThrowsOnFailure()
    {
        var options = FakeMeowshell("echo 'boom' >&2\nexit 1\n");
        var ex = await Assert.ThrowsAsync<TailcatException>(() => TailcatClient.GetEnvironmentAsync(options));
        Assert.Equal(1, ex.ExitCode);
    }
}
