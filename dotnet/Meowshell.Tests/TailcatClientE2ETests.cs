using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using Meowshell;

namespace Meowshell.Tests;

[Collection(RelayE2ECollection.Name)]
public sealed class TailcatClientE2ETests : IDisposable
{
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
        if (real is null) return;
        var (bin, _) = real.Value;
        var options = ClientOptions(bin);

        var address = await TailcatClient.GenerateKeyAsync(options, new TailcatKeyOptions
        {
            Name = "e2e-server-key-" + Guid.NewGuid().ToString("N"),
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
        if (real is null) return;
        var (bin, _) = real.Value;

        var pub = await TailcatClient.GenerateKeyAsync(ClientOptions(bin), new TailcatKeyOptions
        {
            Name = "e2e-client-key-" + Guid.NewGuid().ToString("N"),
            Client = true,
        });
        Assert.StartsWith("nodekey:", pub);
    }

    [Fact]
    public async Task PrintPubReturnsAPublicKeyWithNoSavedKey()
    {
        var real = FindRealBinaries();
        if (real is null) return;
        var (bin, _) = real.Value;

        var pub = await TailcatClient.PrintPubAsync(ClientOptions(bin));
        Assert.StartsWith("nodekey:", pub);
    }

    [Fact]
    public async Task ParseThrowsOnAGenuinelyInvalidAddress()
    {
        var real = FindRealBinaries();
        if (real is null) return;
        var (bin, _) = real.Value;

        var ex = await Assert.ThrowsAsync<TailcatException>(
            () => TailcatClient.ParseAsync(ClientOptions(bin), new TailcatAddress("tcnotarealaddress")));
        Assert.NotEqual(0, ex.ExitCode);
    }

    [Fact]
    public async Task SshSessionConnectAsyncThrowsOnAGenuinelyInvalidAddress()
    {
        var real = FindRealBinaries();
        if (real is null) return;
        var (bin, _) = real.Value;

        var ex = await Assert.ThrowsAsync<TailcatException>(
            () => TailcatSshSession.ConnectAsync(ClientOptions(bin), "tcnotarealaddress"));
        Assert.NotEqual(MeowshellErrorCode.None, ex.Code);
    }

    [Fact]
    public async Task ResolvePingAndLsAgainstARealRunningServer()
    {
        var real = FindRealBinaries();
        if (real is null) return;
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
        await using var server = await RelayE2E.StartServerAsync(serverOptions);
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

    [Fact]
    public async Task CpUploadsAndDownloadsAFileAgainstARealServer()
    {
        var real = FindRealBinaries();
        if (real is null) return;
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
        await using var server = await RelayE2E.StartServerAsync(serverOptions);
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

    [Fact]
    public async Task SshSessionRunsAnInteractiveShellAgainstARealServer()
    {
        var real = FindRealBinaries();
        if (real is null) return;
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
        await using var server = await RelayE2E.StartServerAsync(serverOptions);
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
