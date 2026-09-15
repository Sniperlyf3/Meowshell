using Meowshell;

namespace Meowshell.Tests;

[Collection(RelayE2ECollection.Name)]
public sealed class MeowshellAgentExecutionE2ETests : IDisposable
{
    private const string TailcatEnvVar = "DOTNET_E2E_TAILCAT_BIN";
    private const string MeowshellEnvVar = "DOTNET_E2E_MEOWSHELL_BIN";

    private readonly string _dir = Directory.CreateTempSubdirectory("agent-execution-e2e-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public async Task RunCommandCapturesStdoutStderrAndExitCode()
    {
        var bin = FindRealBinaries();
        if (bin is null) return;

        await using var server = await StartServerAsync(bin);
        await using var connection = await MeowshellAgentConnection.ConnectAsync(ClientOptions(bin), server.Address);

        var result = await connection.RunCommandAsync("printf stdout-marker; printf stderr-marker >&2; exit 7");

        Assert.Equal(7, result.ExitCode);
        Assert.False(result.Succeeded);
        Assert.Contains("stdout-marker", result.StandardOutput);
        Assert.Contains("stderr-marker", result.StandardError);
    }

    [Fact]
    public async Task TimeoutClosesOnlyTheExecChannelAndConnectionRemainsUsable()
    {
        var bin = FindRealBinaries();
        if (bin is null) return;

        await using var server = await StartServerAsync(bin);
        await using var connection = await MeowshellAgentConnection.ConnectAsync(ClientOptions(bin), server.Address);

        var ex = await Assert.ThrowsAsync<TailcatException>(() =>
            connection.RunCommandAsync("sleep 10", TimeSpan.FromMilliseconds(150)));
        Assert.Equal(MeowshellErrorCode.Timeout, ex.Code);

        var after = await connection.RunCommandAsync("printf still-alive", TimeSpan.FromSeconds(5));
        Assert.Equal(0, after.ExitCode);
        Assert.Contains("still-alive", after.StandardOutput);
    }

    [Fact]
    public async Task CallerCancellationClosesOnlyTheExecChannel()
    {
        var bin = FindRealBinaries();
        if (bin is null) return;

        await using var server = await StartServerAsync(bin);
        await using var connection = await MeowshellAgentConnection.ConnectAsync(ClientOptions(bin), server.Address);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            connection.RunCommandAsync("sleep 10", cancellationToken: cts.Token));

        var after = await connection.RunCommandAsync("printf after-cancel", TimeSpan.FromSeconds(5));
        Assert.Equal(0, after.ExitCode);
        Assert.Contains("after-cancel", after.StandardOutput);
    }

    private string? FindRealBinaries()
    {
        var tailcatSrc = Environment.GetEnvironmentVariable(TailcatEnvVar);
        var meowshellSrc = Environment.GetEnvironmentVariable(MeowshellEnvVar);
        if (string.IsNullOrEmpty(tailcatSrc) || string.IsNullOrEmpty(meowshellSrc)
            || !File.Exists(tailcatSrc) || !File.Exists(meowshellSrc))
            return null;

        var bin = Path.Combine(_dir, "bin");
        Directory.CreateDirectory(bin);
        var naming = BinaryNaming.ForCurrentPlatform();
        var tailcatDst = Path.Combine(bin, naming.FileName("tailcat"));
        var meowshellDst = Path.Combine(bin, naming.FileName("meowshell"));
        File.Copy(tailcatSrc, tailcatDst);
        File.Copy(meowshellSrc, meowshellDst);
        if (!OperatingSystem.IsWindows())
        {
            const UnixFileMode exec = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
            File.SetUnixFileMode(tailcatDst, exec);
            File.SetUnixFileMode(meowshellDst, exec);
        }
        return bin;
    }

    private TailcatClientOptions ClientOptions(string bin) => new()
    {
        BinaryDirectory = bin,
        HomeDirectory = Path.Combine(_dir, "client-home"),
        Timeout = TimeSpan.FromSeconds(30),
    };

    private async Task<MeowshellServer> StartServerAsync(string bin)
    {
        var server = await RelayE2E.StartServerAsync(new MeowshellOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "server-home"),
            WorkDirectory = Path.Combine(_dir, "server-work"),
            InsecureNoAuth = true,
            Lifetime = TimeSpan.FromMinutes(2),
            StartTimeout = TimeSpan.FromSeconds(30),
        });
        Console.WriteLine("::add-mask::" + server.Address);
        return server;
    }
}
