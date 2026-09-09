using System.Diagnostics;
using Meowshell;

namespace Meowshell.Tests;

/// <summary>
/// Exercises the lifecycle against a stand-in for meowshell, so the process
/// handling, address handoff and shutdown are covered without an Android
/// device in the loop.
/// </summary>
public sealed class MeowshellServerTests : IDisposable
{
    private const string FakeAddress = "tcTESTADDRESS000000000000";
    private readonly string _dir = Directory.CreateTempSubdirectory("meowshell-test-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    /// <summary>Writes stand-in binaries; the script body decides what "meowshell" does.</summary>
    private MeowshellOptions Fake(string script, TimeSpan? lifetime = null)
    {
        var bin = Path.Combine(_dir, "bin");
        Directory.CreateDirectory(bin);
        var shell = Path.Combine(bin, "libmeowshell.so");
        File.WriteAllText(shell, "#!/bin/bash\n" + script);
        File.SetUnixFileMode(shell, UnixFileMode.UserRead | UnixFileMode.UserExecute | UnixFileMode.UserWrite);
        var cat = Path.Combine(bin, "libtailcat.so");
        File.WriteAllText(cat, "#!/bin/bash\ntrue\n");
        File.SetUnixFileMode(cat, UnixFileMode.UserRead | UnixFileMode.UserExecute | UnixFileMode.UserWrite);

        return new MeowshellOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "home"),
            WorkDirectory = Path.Combine(_dir, "work"),
            InsecureNoAuth = true,
            Naming = BinaryNaming.Android,   // the stand-ins are named lib*.so
            Lifetime = lifetime ?? TimeSpan.FromMinutes(5),
            StartTimeout = TimeSpan.FromSeconds(10),
            GracePeriod = TimeSpan.FromSeconds(2),
        };
    }

    private const string PublishesAddress =
        $"printf '%s' '{FakeAddress}' > \"$TAILCAT_ADDR_FILE\"\nexec sleep 300\n";

    /// <summary>A fake that records its own argv, one element per line, before publishing an address.</summary>
    private (MeowshellOptions options, string argsFile) FakeCapturingArgv()
    {
        var argsFile = Path.Combine(_dir, "args-" + Guid.NewGuid().ToString("N"));
        var script =
            $"printf '%s\\n' \"$@\" > {argsFile}\n" +
            $"printf '%s' '{FakeAddress}' > \"$TAILCAT_ADDR_FILE\"\n" +
            "exec sleep 300\n";
        return (Fake(script), argsFile);
    }

    [Fact]
    public async Task StartAsync_ReturnsTheAddressTheServerPublished()
    {
        await using var server = await MeowshellServer.StartAsync(Fake(PublishesAddress));
        Assert.Equal(FakeAddress, server.Address);
    }

    [Fact]
    public async Task StartAsync_RequiresSomethingToServe()
    {
        var nothing = Fake(PublishesAddress) with { InsecureNoAuth = false };
        await Assert.ThrowsAsync<ArgumentException>(() => MeowshellServer.StartAsync(nothing));
    }

    [Fact]
    public async Task StartAsync_RejectsBothAuthenticationModesTogether()
    {
        var both = Fake(PublishesAddress) with { AuthorizedKeys = "alice@github" };
        await Assert.ThrowsAsync<ArgumentException>(() => MeowshellServer.StartAsync(both));
    }

    [Fact]
    public async Task StartAsync_ReportsMissingBinaries()
    {
        var missing = Fake(PublishesAddress) with { BinaryDirectory = Path.Combine(_dir, "nope") };
        await Assert.ThrowsAsync<FileNotFoundException>(() => MeowshellServer.StartAsync(missing));
    }

    [Fact]
    public async Task StartAsync_FailsWhenTheServerExitsWithoutAnAddress()
    {
        var ex = await Assert.ThrowsAsync<TailcatException>(
            () => MeowshellServer.StartAsync(Fake("echo 'derpmap fetch: boom' >&2\nexit 3\n")));
        Assert.Equal(3, ex.ExitCode);
        Assert.Contains("derpmap fetch: boom", ex.Diagnostics);
        Assert.Contains("derpmap fetch: boom", ex.Message);
    }

    [Fact]
    public async Task StartAsync_TimesOutWhenNoAddressAppears()
    {
        var slow = Fake("exec sleep 300\n") with { StartTimeout = TimeSpan.FromSeconds(2) };
        await Assert.ThrowsAsync<TimeoutException>(() => MeowshellServer.StartAsync(slow));
    }

    [Fact]
    public async Task StopAsync_TerminatesTheServerAndIsIdempotent()
    {
        var server = await MeowshellServer.StartAsync(Fake(PublishesAddress));
        await server.StopAsync();
        await server.StopAsync();          // must not throw
        Assert.True(server.Completed.IsCompleted);
        await server.DisposeAsync();
    }

    [Fact]
    public async Task CompletedFaultsWhenTheServerCrashesOnItsOwn()
    {
        var script =
            $"printf '%s' '{FakeAddress}' > \"$TAILCAT_ADDR_FILE\"\n" +
            "sleep 0.2\n" +
            "echo 'panic: something broke' >&2\n" +
            "exit 2\n";
        await using var server = await MeowshellServer.StartAsync(Fake(script));

        var ex = await Assert.ThrowsAsync<TailcatException>(() => server.Completed);
        Assert.Equal(2, ex.ExitCode);
        Assert.Contains("something broke", ex.Diagnostics);
    }

    [Fact]
    public async Task CompletedSucceedsWhenStopAsyncInitiatedTheExit()
    {
        var server = await MeowshellServer.StartAsync(Fake(PublishesAddress));
        await server.StopAsync();
        await server.Completed; // must not throw
        await server.DisposeAsync();
    }

    [Fact]
    public async Task TheDeadlineShutsTheServerDownOnItsOwn()
    {
        await using var server = await MeowshellServer.StartAsync(
            Fake(PublishesAddress, lifetime: TimeSpan.FromSeconds(2)));

        await server.Completed.WaitAsync(TimeSpan.FromSeconds(20));
        Assert.True(server.Completed.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task AGracefulStopIsAttemptedBeforeKilling()
    {
        // The stand-in traps SIGTERM and records it, so a SIGKILL-only stop
        // would leave the marker absent.
        var marker = Path.Combine(_dir, "sigterm");
        var script =
            $"trap 'printf caught > {marker}; exit 0' TERM\n" +
            $"printf '%s' '{FakeAddress}' > \"$TAILCAT_ADDR_FILE\"\n" +
            "while true; do sleep 0.1; done\n";

        var server = await MeowshellServer.StartAsync(Fake(script));
        await server.StopAsync();
        Assert.True(File.Exists(marker), "the server was killed without being asked to stop first");
    }

    [Fact]
    public async Task APrivateKeyIsPipedInOnStdin()
    {
        // The key must reach the process without being written anywhere.
        var seen = Path.Combine(_dir, "stdin-key");
        var script =
            $"cat > {seen}\n" +
            $"printf '%s' '{FakeAddress}' > \"$TAILCAT_ADDR_FILE\"\n" +
            "exec sleep 300\n";

        const string key = """{"Private":"privkey:deadbeef","Public":{}}""";
        await using var server = await MeowshellServer.StartAsync(
            Fake(script) with { PrivateKeyJson = key });

        Assert.Equal(key, File.ReadAllText(seen));
    }

    [Fact]
    public async Task TheServerIsToldWhereTailcatIs()
    {
        // meowshell looks for a sibling named "tailcat"; under an Android
        // native library directory everything is lib*.so, so the path has to
        // be passed explicitly.
        var seen = Path.Combine(_dir, "env");
        var script =
            $"printf '%s\\n' \"$TAILCAT_BIN\" \"$HOME\" > {seen}\n" +
            $"printf '%s' '{FakeAddress}' > \"$TAILCAT_ADDR_FILE\"\n" +
            "exec sleep 300\n";

        var options = Fake(script);
        await using var server = await MeowshellServer.StartAsync(options);

        var lines = File.ReadAllLines(seen);
        Assert.Equal(Path.Combine(options.BinaryDirectory, "libtailcat.so"), lines[0]);
        Assert.Equal(options.HomeDirectory, lines[1]);
    }

    [Fact]
    public async Task DerpMapUrlIsPassedThrough()
    {
        var (options, argsFile) = FakeCapturingArgv();
        await using var server = await MeowshellServer.StartAsync(
            options with { DerpMapUrl = "https://derp.example/map.json" });
        Assert.Contains("--derpmap-url=https://derp.example/map.json", File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task VerboseIsPassedThrough()
    {
        var (options, argsFile) = FakeCapturingArgv();
        await using var server = await MeowshellServer.StartAsync(options with { Verbose = true });
        Assert.Contains("--verbose", File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task FullAddressIsPassedThrough()
    {
        var (options, argsFile) = FakeCapturingArgv();
        await using var server = await MeowshellServer.StartAsync(options with { FullAddress = true });
        Assert.Contains("--full-address", File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task DisablingPskIsPassedThrough()
    {
        var (options, argsFile) = FakeCapturingArgv();
        await using var server = await MeowshellServer.StartAsync(options with { Psk = false });
        Assert.Contains("--psk=false", File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task PskLeftAtItsDefaultTrueIsNotPassedThrough()
    {
        var (options, argsFile) = FakeCapturingArgv();
        await using var server = await MeowshellServer.StartAsync(options);
        Assert.DoesNotContain("--psk=false", File.ReadAllLines(argsFile));
    }

    [Fact]
    public async Task ForcedCommandIsPassedThroughAfterADoubleDash()
    {
        var (options, argsFile) = FakeCapturingArgv();
        await using var server = await MeowshellServer.StartAsync(
            options with { ForcedCommand = ["echo", "hi there"] });

        var args = File.ReadAllLines(argsFile);
        var separator = Array.IndexOf(args, "--");
        Assert.True(separator >= 0, "no -- separator found in: " + string.Join(' ', args));
        Assert.Equal(["echo", "hi there"], args[(separator + 1)..]);
    }

    [Fact]
    public async Task FilesAloneRequiresNoAuthenticationMode()
    {
        var (options, argsFile) = FakeCapturingArgv();
        await using var server = await MeowshellServer.StartAsync(
            options with { InsecureNoAuth = false, Files = "/srv/drop" });

        var args = File.ReadAllLines(argsFile);
        Assert.Contains("--files=/srv/drop", args);
        Assert.DoesNotContain("--insecure-no-auth", args);
    }

    [Fact]
    public async Task FilesCombinedWithNoAuthSshServesBoth()
    {
        var (options, argsFile) = FakeCapturingArgv();
        await using var server = await MeowshellServer.StartAsync(options with { Files = "/srv/drop:rw" });

        var args = File.ReadAllLines(argsFile);
        Assert.Contains("--insecure-no-auth", args);
        Assert.Contains("--files=/srv/drop:rw", args);
    }

    [Fact]
    public async Task FilesWithForcedCommandOnSshThrows()
    {
        var opts = Fake(PublishesAddress) with { Files = "/srv/drop", ForcedCommand = ["echo", "hi"] };
        await Assert.ThrowsAsync<ArgumentException>(() => MeowshellServer.StartAsync(opts));
    }

    [Fact]
    public async Task ForcedCommandAloneRequiresNoAuthenticationMode()
    {
        var (options, argsFile) = FakeCapturingArgv();
        await using var server = await MeowshellServer.StartAsync(
            options with { InsecureNoAuth = false, ForcedCommand = ["echo", "hi"] });

        var args = File.ReadAllLines(argsFile);
        Assert.DoesNotContain("--insecure-no-auth", args);
        var separator = Array.IndexOf(args, "--");
        Assert.True(separator >= 0, "no -- separator found in: " + string.Join(' ', args));
        Assert.Equal(["echo", "hi"], args[(separator + 1)..]);
    }

    [Fact]
    public void BinaryNamingFollowsThePlatformConvention()
    {
        // Android only unpacks lib*.so into the native library directory,
        // which is the one place an app may execute from.
        Assert.Equal("libtailcat.so", BinaryNaming.Android.FileName("tailcat"));
        Assert.Equal("tailcat.exe", BinaryNaming.Windows.FileName("tailcat"));
        Assert.Equal("tailcat", BinaryNaming.Plain.FileName("tailcat"));
    }

    [Fact]
    public void CreateLeavesBinaryDiscoveryToBinaryLocatorOnNonAndroidPlatforms()
    {
        // Create's Android branch is compiled into Meowshell only for
        // the android target framework (see the #if ANDROID in
        // MeowshellServer.cs), which this plain net8.0 test assembly does
        // not build; that branch is exercised only by the on-device probe
        // in Meowshell.AndroidProbe. This covers the other one: no
        // BinaryDirectory set, so StartAsync falls back to BinaryLocator,
        // exactly as a real desktop or server consumer gets for free.
        var host = MeowshellOptions.Create(TimeSpan.FromMinutes(1));
        Assert.Null(host.BinaryDirectory);
        Assert.Equal(BinaryNaming.ForCurrentPlatform(), host.Naming);
        Assert.Equal(TimeSpan.FromMinutes(1), host.Lifetime);
    }

    [Fact]
    public async Task MissingBinariesAreReportedByTheirPlatformName()
    {
        var opts = Fake(PublishesAddress) with
        {
            BinaryDirectory = Path.Combine(_dir, "empty"),
            Naming = BinaryNaming.Windows,
        };
        Directory.CreateDirectory(opts.BinaryDirectory);
        var ex = await Assert.ThrowsAsync<FileNotFoundException>(
            () => MeowshellServer.StartAsync(opts));
        Assert.Contains("meowshell.exe", ex.Message);
    }

    [Fact]
    public void TheRuntimeIdentifierNamesAnOsAndArchitecture()
    {
        Assert.Matches(@"^(linux|win|osx|android)-(x64|x86|arm64|arm)$", BinaryLocator.RuntimeIdentifier);
    }

    [Fact]
    public void TheSearchPathCoversBothPublishLayouts()
    {
        var path = BinaryLocator.SearchPath("/app").ToList();
        // A RID-specific publish flattens native assets beside the assembly;
        // a RID-agnostic build keeps the package's runtimes/ layout.
        Assert.Contains("/app", path);
        Assert.Contains(Path.Combine("/app", "runtimes", BinaryLocator.RuntimeIdentifier, "native"), path);
    }

    [Fact]
    public void LocateFindsBinariesInThePackageLayout()
    {
        var rid = BinaryLocator.RuntimeIdentifier;
        var native = Path.Combine(_dir, "app", "runtimes", rid, "native");
        Directory.CreateDirectory(native);
        var naming = BinaryNaming.ForCurrentPlatform();
        File.WriteAllText(Path.Combine(native, naming.FileName("tailcat")), "");
        File.WriteAllText(Path.Combine(native, naming.FileName("meowshell")), "");

        Assert.Equal(native, BinaryLocator.Locate(naming, Path.Combine(_dir, "app")));
    }

    [Fact]
    public void LocateIgnoresAnIncompleteDirectory()
    {
        // Only one of the pair present must not count: the failure would
        // otherwise surface much later, as a missing-file error at start.
        var app = Path.Combine(_dir, "half");
        Directory.CreateDirectory(app);
        var naming = BinaryNaming.ForCurrentPlatform();
        File.WriteAllText(Path.Combine(app, naming.FileName("tailcat")), "");

        Assert.Null(BinaryLocator.Locate(naming, app));
    }

    [Fact]
    public async Task ABinaryWithoutTheExecutableBitIsMadeRunnable()
    {
        // NuGet restore does not reliably carry the executable bit, so a
        // package-delivered binary can arrive unrunnable.
        if (OperatingSystem.IsWindows()) return;
        var opts = Fake(PublishesAddress);
        var shell = Path.Combine(opts.BinaryDirectory!, opts.Naming.FileName("meowshell"));
        File.SetUnixFileMode(shell, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        await using var server = await MeowshellServer.StartAsync(opts);
        Assert.Equal(FakeAddress, server.Address);
    }
}
