using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Meowshell;

namespace Meowshell.Tests;

[Collection(RelayE2ECollection.Name)]
public sealed class MeowshellListenersE2ETests : IDisposable
{
    private const string TailcatEnvVar = "DOTNET_E2E_TAILCAT_BIN";
    private const string MeowshellEnvVar = "DOTNET_E2E_MEOWSHELL_BIN";

    private readonly string _dir = Directory.CreateTempSubdirectory("meowshell-listeners-e2e-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private (string binDir, string tailcatPath)? RealBinaries()
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

    [Fact]
    public async Task ASocksProxyStaysUpUntilStopped()
    {
        var real = RealBinaries();
        if (real is null) return;
        var (bin, _) = real.Value;

        await using var proxy = await MeowshellSocksProxy.StartAsync(new MeowshellSocksOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "home"),
        });

        await Task.Delay(500);
        Assert.False(proxy.Completed.IsCompleted, "the proxy exited on its own instead of staying up as a listener");

        await proxy.StopAsync();
        Assert.True(proxy.Completed.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task APortForwardStartsItsLocalListenerAndStopsCleanly()
    {
        var real = RealBinaries();
        if (real is null) return;
        var (bin, tailcatPath) = real.Value;

        var configDir = Path.Combine(_dir, "keyconfig");
        Directory.CreateDirectory(configDir);
        var genkeyPsi = new ProcessStartInfo(tailcatPath)
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };
        genkeyPsi.ArgumentList.Add("genkey");
        genkeyPsi.ArgumentList.Add("--key=forward-e2e");
        genkeyPsi.Environment["XDG_CONFIG_HOME"] = configDir;
        using var genkey = Process.Start(genkeyPsi)!;
        var address = (await genkey.StandardOutput.ReadToEndAsync()).Trim();
        var exited = await Task.Run(() => genkey.WaitForExit(30_000));
        Assert.True(exited, "tailcat genkey did not exit in time");
        Assert.NotEmpty(address);

        await using var forward = await MeowshellPortForward.StartAsync(new MeowshellPortForwardOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "home2"),
            Address = address,
            Mappings = ["0:80"],
        });

        await Task.Delay(500);
        Assert.False(forward.Completed.IsCompleted, "forward exited on its own instead of staying up as a listener");

        await forward.StopAsync();
        Assert.True(forward.Completed.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task APortForwardWithAllowExitNodeReachesAnArbitraryBackend()
    {
        var real = RealBinaries();
        if (real is null) return;
        var (bin, _) = real.Value;

        using var backend = new TcpListener(IPAddress.Loopback, 0);
        backend.Start();
        const string backendReply = "hello from the exit-node-forwarded backend";
        _ = Task.Run(async () =>
        {
            while (true)
            {
                TcpClient client;
                try { client = await backend.AcceptTcpClientAsync(); }
                catch { return; }
                _ = Task.Run(async () =>
                {
                    using (client)
                    {
                        var bytes = System.Text.Encoding.UTF8.GetBytes(backendReply);
                        await client.GetStream().WriteAsync(bytes);
                    }
                });
            }
        });
        var backendPort = ((IPEndPoint)backend.LocalEndpoint).Port;

        var serverLogs = new System.Collections.Concurrent.ConcurrentQueue<string>();
        await using var server = await MeowshellServer.StartAsync(new MeowshellOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "server-home"),
            WorkDirectory = Path.Combine(_dir, "server-work"),
            InsecureNoAuth = true,
            AllowExitNode = true,
            Lifetime = TimeSpan.FromMinutes(2),
            StartTimeout = TimeSpan.FromSeconds(30),
        }, onLog: serverLogs.Enqueue);

        // Register the startup log callback before the forward process starts.
        // Subscribing through forward.Log after StartAsync returns has its own
        // race: tailcat can bind and print the one-shot "forwarding ..." line
        // before the caller gets the returned wrapper.
        var forwardLogs = new System.Collections.Concurrent.ConcurrentQueue<string>();
        var boundAddressFound = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        void OnForwardLog(string line)
        {
            forwardLogs.Enqueue(line);
            var marker = "forwarding ";
            var at = line.IndexOf(marker, StringComparison.Ordinal);
            if (at < 0) return;
            var rest = line[(at + marker.Length)..];
            var end = rest.IndexOf(' ');
            if (end > 0) boundAddressFound.TrySetResult(rest[..end]);
        }

        await using var forward = await MeowshellPortForward.StartAsync(new MeowshellPortForwardOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "forward-home"),
            Address = server.Address,
            Mappings = [$"0:{backendPort}"],
        }, OnForwardLog);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var registration = cts.Token.Register(() => boundAddressFound.TrySetCanceled());
        var boundAddress = await boundAddressFound.Task;

        // "forwarding <addr> -> ..." means only that tailcat's local listener
        // is bound.  The client-side tailcat connection is lazy: the first
        // accepted TCP connection is what brings the DERP/WireGuard path up.
        // Under load that first attempt can legitimately lose the race and
        // close with EOF before the exit-node route is ready (upstream
        // tailcat's analogous exit-node-forward test documents the same
        // transient reset).  Treat this as readiness probing, not as the one
        // and only assertion attempt.  A real regression still fails after
        // the bounded overall deadline.
        var endpoint = IPEndPoint.Parse(boundAddress);
        var attempts = new List<string>();
        string? got = null;
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(20);
        while (DateTime.UtcNow < deadline && got != backendReply)
        {
            try
            {
                using var socket = new TcpClient();
                using var attemptCts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                await socket.ConnectAsync(endpoint, attemptCts.Token);

                var buffer = new byte[256];
                var total = 0;
                while (total < buffer.Length)
                {
                    var n = await socket.GetStream().ReadAsync(buffer.AsMemory(total), attemptCts.Token);
                    if (n == 0) break;
                    total += n;
                    if (total >= System.Text.Encoding.UTF8.GetByteCount(backendReply)) break;
                }
                got = System.Text.Encoding.UTF8.GetString(buffer, 0, total);
                attempts.Add($"received {total} bytes: {got ?? "<null>"}");
            }
            catch (Exception ex) when (ex is SocketException or IOException or OperationCanceledException)
            {
                attempts.Add($"{ex.GetType().Name}: {ex.Message}");
            }

            if (got != backendReply)
                await Task.Delay(200);
        }

        Assert.True(
            got == backendReply,
            "exit-node forward never became end-to-end ready; " +
            $"last={got ?? "<null>"}; attempts: {string.Join(" | ", attempts)}; " +
            $"forward logs: {string.Join(" || ", forwardLogs)}; " +
            $"server logs: {string.Join(" || ", serverLogs)}");
    }
}
