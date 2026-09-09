using System.Diagnostics;
using System.Text;
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
    /// A malformed address fails address parsing before any network call,
    /// so unlike most tests here this needs no live server or DERP access
    /// -- and it's the case ConnectAsync's fail-fast timeout race exists
    /// for: the failure has to surface as a thrown exception from
    /// ConnectAsync itself, not just an eventually-faulted Completed the
    /// caller happened to never await.
    /// </summary>
    [Fact]
    public async Task SshSessionConnectAsyncThrowsOnAGenuinelyInvalidAddress()
    {
        var real = FindRealBinaries();
        if (real is null) return; // see FindRealBinaries()
        var (bin, _) = real.Value;

        var ex = await Assert.ThrowsAsync<TailcatException>(
            () => TailcatSshSession.ConnectAsync(ClientOptions(bin), "tcnotarealaddress"));
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

    /// <summary>
    /// Uploads a file to a real server's writable "files" share, confirms
    /// it landed via ListFilesAsync, then downloads it back to a different
    /// local path and checks the bytes round-tripped exactly -- CpAsync and
    /// TailcatPath exercised against the real system scp, not a stand-in.
    /// Needs real network the same way <see cref="ResolvePingAndLsAgainstARealRunningServer"/> does.
    /// </summary>
    [Fact]
    public async Task CpUploadsAndDownloadsAFileAgainstARealServer()
    {
        var real = FindRealBinaries();
        if (real is null) return; // see FindRealBinaries()
        var (bin, _) = real.Value;

        var served = Path.Combine(_dir, "served-rw");
        Directory.CreateDirectory(served);

        var serverOptions = new MeowshellOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "cp-server-home"),
            WorkDirectory = Path.Combine(_dir, "cp-server-work"),
            Files = served + ":rw",
            Lifetime = TimeSpan.FromMinutes(2),
            StartTimeout = TimeSpan.FromSeconds(30),
        };
        await using var server = await MeowshellServer.StartAsync(serverOptions);
        Mask(server.Address);
        var clientOptions = ClientOptions(bin);
        var address = new TailcatAddress(server.Address);

        var localSource = Path.Combine(_dir, "upload-source.txt");
        var content = $"hello from a real scp round trip {Guid.NewGuid():N}\n";
        await File.WriteAllTextAsync(localSource, content);

        var uploadResult = await TailcatClient.CpAsync(
            clientOptions, TailcatPath.Local(localSource), TailcatPath.Remote(address, "uploaded.txt"));
        Assert.True(uploadResult.Success, Redact(uploadResult.Stderr));

        var entries = await TailcatClient.ListFilesAsync(clientOptions, TailcatPath.Remote(address));
        Assert.Contains(entries, e => e.Name == "uploaded.txt" && !e.IsDirectory);

        var localDest = Path.Combine(_dir, "downloaded.txt");
        var downloadResult = await TailcatClient.CpAsync(
            clientOptions, TailcatPath.Remote(address, "uploaded.txt"), TailcatPath.Local(localDest));
        Assert.True(downloadResult.Success, Redact(downloadResult.Stderr));

        Assert.Equal(content, await File.ReadAllTextAsync(localDest));

        await server.StopAsync();
    }

    /// <summary>
    /// Opens an interactive pseudo-terminal session against a real server
    /// and drives it entirely through TailcatSshSession's Output/WriteAsync
    /// -- the same shape an Android app with no real console would use --
    /// confirming a real shell prompt appears, a command's output comes
    /// back, and exiting ends the session cleanly. Needs real network the
    /// same way <see cref="ResolvePingAndLsAgainstARealRunningServer"/> does.
    /// </summary>
    [Fact]
    public async Task SshSessionRunsAnInteractiveShellAgainstARealServer()
    {
        var real = FindRealBinaries();
        if (real is null) return; // see FindRealBinaries()
        var (bin, _) = real.Value;

        var serverOptions = new MeowshellOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "ssh-server-home"),
            WorkDirectory = Path.Combine(_dir, "ssh-server-work"),
            InsecureNoAuth = true,
            Lifetime = TimeSpan.FromMinutes(2),
            StartTimeout = TimeSpan.FromSeconds(30),
        };
        await using var server = await MeowshellServer.StartAsync(serverOptions);
        Mask(server.Address);
        var clientOptions = ClientOptions(bin);

        await using var session = await TailcatSshSession.ConnectAsync(clientOptions, server.Address);

        var marker = $"sshsession-e2e-{Guid.NewGuid():N}";
        await session.WriteAsync(Encoding.UTF8.GetBytes($"echo {marker}\n"));
        await session.WriteAsync(Encoding.UTF8.GetBytes("exit\n"));

        var output = await ReadUntilAsync(session.Output, marker, TimeSpan.FromSeconds(30));
        Assert.Contains(marker, output);

        await session.Completed;
    }

    /// <summary>Reads from stream until <paramref name="marker"/> has appeared or <paramref name="timeout"/> elapses, returning everything read so far either way.</summary>
    private static async Task<string> ReadUntilAsync(Stream stream, string marker, TimeSpan timeout)
    {
        var buffer = new byte[4096];
        var text = new StringBuilder();
        using var cts = new CancellationTokenSource(timeout);
        while (!text.ToString().Contains(marker))
        {
            var read = await stream.ReadAsync(buffer, cts.Token);
            if (read == 0) break;
            text.Append(Encoding.UTF8.GetString(buffer, 0, read));
        }
        return text.ToString();
    }
}
