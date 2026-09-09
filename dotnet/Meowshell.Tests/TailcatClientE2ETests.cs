using System.Diagnostics;
using System.Text.RegularExpressions;
using Meowshell;

namespace Meowshell.Tests;

/// <summary>
/// Runs <see cref="TailcatClient"/> against the real tailcat binary built by
/// build.sh, feeding its actual output through this library's real parsing
/// code -- the check that a future tailcat release changing its output
/// shape breaks this suite, not just the recorded fixtures in
/// <see cref="TailcatClientTests"/>. Genkey/parse/printpub need no network
/// (a numeric --region skips the DERP map fetch); resolve/ping/ls need a
/// live server and real network, so they also cover the same ground as
/// <see cref="MeowshellServerE2ETests"/> from the client side.
///
/// Skipped (each test returns immediately) when the real binaries are not
/// available, e.g. a local "dotnet test" run without a "dist" build.
/// </summary>
public sealed class TailcatClientE2ETests : IDisposable
{
    // Same reasoning as MeowshellServerE2ETests: a tailcat address is a live
    // credential, so it must never reach a CI log verbatim.
    private static readonly Regex AddressPattern = new(@"\btc[A-Za-z0-9_-]{10,}", RegexOptions.Compiled);
    private static string Redact(string text) => AddressPattern.Replace(text, "tc<redacted>");
    private static void Mask(string value)
    {
        if (!string.IsNullOrEmpty(value)) Console.WriteLine("::add-mask::" + value);
    }

    private const string TailcatEnvVar = "DOTNET_E2E_TAILCAT_BIN";
    private const string MeowshellEnvVar = "DOTNET_E2E_MEOWSHELL_BIN";

    private readonly string _dir = Directory.CreateTempSubdirectory("tailcat-client-e2e-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    /// <summary>Same layout as MeowshellServerE2ETests.RealBinaries(). Returns null (skip) if either binary is unavailable.</summary>
    private (string binDir, string tailcatPath)? FindRealBinaries()
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

    private TailcatClientOptions ClientOptions(string bin) => new()
    {
        BinaryDirectory = bin,
        HomeDirectory = Path.Combine(_dir, "home"),
        Timeout = TimeSpan.FromSeconds(30),
    };

    [Fact]
    public async Task GenerateKeyAndParseRoundTripAgainstTheRealBinary()
    {
        var real = FindRealBinaries();
        if (real is null) return; // see FindRealBinaries()
        var (bin, _) = real.Value;
        var options = ClientOptions(bin);

        // A numeric region needs no DERP map fetch, so this needs no network.
        var address = await TailcatClient.GenerateKeyAsync(options, new TailcatKeyOptions
        {
            Name = "e2e-server-key",
            Region = "1",
        });
        Assert.StartsWith("tc", address);
        Mask(address);

        var parsed = await TailcatClient.ParseAsync(options, new TailcatAddress(address));
        Assert.StartsWith("nodekey:", parsed.ServerPublic);
        Assert.NotNull(parsed.ServerDiscoPublic);
        Assert.StartsWith("discokey:", parsed.ServerDiscoPublic);
        Assert.NotNull(parsed.PresharedKey);
        Assert.StartsWith("psk:", parsed.PresharedKey);
        Assert.Equal(1, parsed.RegionId);
        Assert.Null(parsed.Region);
    }

    [Fact]
    public async Task GenerateKeyForAClientReturnsAPublicKey()
    {
        var real = FindRealBinaries();
        if (real is null) return; // see FindRealBinaries()
        var (bin, _) = real.Value;

        var pub = await TailcatClient.GenerateKeyAsync(ClientOptions(bin), new TailcatKeyOptions
        {
            Name = "e2e-client-key",
            Client = true,
        });
        Assert.StartsWith("nodekey:", pub);
    }

    [Fact]
    public async Task PrintPubReturnsAPublicKeyWithNoSavedKey()
    {
        var real = FindRealBinaries();
        if (real is null) return; // see FindRealBinaries()
        var (bin, _) = real.Value;

        var pub = await TailcatClient.PrintPubAsync(ClientOptions(bin));
        Assert.StartsWith("nodekey:", pub);
    }

    [Fact]
    public async Task ParseThrowsOnAGenuinelyInvalidAddress()
    {
        var real = FindRealBinaries();
        if (real is null) return; // see FindRealBinaries()
        var (bin, _) = real.Value;

        var ex = await Assert.ThrowsAsync<TailcatException>(
            () => TailcatClient.ParseAsync(ClientOptions(bin), new TailcatAddress("tcnotarealaddress")));
        Assert.NotEqual(0, ex.ExitCode);
    }

    /// <summary>
    /// Starts a real server (real binaries, real network -- the default
    /// tailcat.dev DERP map) and exercises resolve/ping/ls against it
    /// through TailcatClient, the client-side counterpart to
    /// MeowshellServerE2ETests. Needs real network the same way that class
    /// does: skips no differently than the other tests here when the
    /// binaries are missing, but will fail rather than skip if network
    /// access to tailcat.dev is blocked (as in this sandbox; CI has it).
    /// </summary>
    [Fact]
    public async Task ResolvePingAndLsAgainstARealRunningServer()
    {
        var real = FindRealBinaries();
        if (real is null) return; // see FindRealBinaries()
        var (bin, _) = real.Value;

        var served = Path.Combine(_dir, "served");
        Directory.CreateDirectory(Path.Combine(served, "subdir"));
        await File.WriteAllTextAsync(Path.Combine(served, "hello.txt"), "hi\n");

        var serverOptions = new MeowshellOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "server-home"),
            WorkDirectory = Path.Combine(_dir, "server-work"),
            InsecureNoAuth = true,
            Files = served,
            Lifetime = TimeSpan.FromMinutes(2),
            StartTimeout = TimeSpan.FromSeconds(30),
        };
        await using var server = await MeowshellServer.StartAsync(serverOptions);
        Mask(server.Address);
        var clientOptions = ClientOptions(bin);

        var resolved = await TailcatClient.ResolveAsync(clientOptions, server.Address);
        Assert.StartsWith("tc", resolved.ToString());

        var resolvedParsed = await TailcatClient.ParseAsync(clientOptions, resolved);
        Assert.NotNull(resolvedParsed.Region);
        Assert.NotEmpty(resolvedParsed.Region!);

        var ping = await TailcatClient.PingAsync(clientOptions, server.Address);
        Assert.True(ping.Success, Redact(ping.Result.Stderr));
        Assert.NotNull(ping.Pong);
        Assert.True(ping.Pong!.Latency > TimeSpan.Zero);

        var shortListing = await TailcatClient.ListFilesAsync(clientOptions, server.Address, longListing: false);
        Assert.Contains(shortListing, e => e.Name == "hello.txt" && !e.IsDirectory);
        Assert.Contains(shortListing, e => e.Name == "subdir" && e.IsDirectory);

        var longListing = await TailcatClient.ListFilesAsync(clientOptions, server.Address, longListing: true);
        var helloEntry = Assert.Single(longListing, e => e.Name == "hello.txt");
        Assert.Equal(3, helloEntry.Size);
        Assert.NotNull(helloEntry.Mode);
        Assert.NotNull(helloEntry.ModifiedAt);

        await server.StopAsync();
    }
}
