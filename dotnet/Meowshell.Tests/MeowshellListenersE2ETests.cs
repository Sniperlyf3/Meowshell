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
        var (bin, _) = real.Value;

        // tailcat forward now pings the remote peer before announcing
        // readiness (it no longer trusts a bound local listener alone --
        // the first accepted connection used to be what actually brought
        // the DERP/WireGuard path up, which could lose that race). A bare
        // genkey'd address with nothing listening behind it can no longer
        // stand in for "a forward target"; this needs a real, reachable
        // server the same way every other real-binary E2E here does.
        await using var server = await RelayE2E.StartServerAsync(new MeowshellOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "server-home"),
            WorkDirectory = Path.Combine(_dir, "server-work"),
            InsecureNoAuth = true,
            Lifetime = TimeSpan.FromMinutes(2),
            StartTimeout = TimeSpan.FromSeconds(30),
        });

        await using var forward = await MeowshellPortForward.StartAsync(new MeowshellPortForwardOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "home2"),
            Address = server.Address,
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
        await using var server = await RelayE2E.StartServerAsync(new MeowshellOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "server-home"),
            WorkDirectory = Path.Combine(_dir, "server-work"),
            InsecureNoAuth = true,
            AllowExitNode = true,
            Lifetime = TimeSpan.FromMinutes(2),
            StartTimeout = TimeSpan.FromSeconds(30),
        }, onLog: serverLogs.Enqueue);

        // StartAsync now has a production readiness contract: it returns
        // only after tailcat has bound every requested local listener, and
        // exposes the actual OS-assigned address directly. Applications no
        // longer need to parse diagnostic logs or race listener startup.
        var forwardLogs = new System.Collections.Concurrent.ConcurrentQueue<string>();
        await using var forward = await MeowshellPortForward.StartAsync(new MeowshellPortForwardOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "forward-home"),
            Address = server.Address,
            Mappings = [$"0:{backendPort}"],
            StartTimeout = TimeSpan.FromSeconds(30),
        }, forwardLogs.Enqueue);
        var boundAddress = Assert.Single(forward.BoundAddresses);

        // "forwarding <addr> -> ..." means only that tailcat's local listener
        // is bound.  The client-side tailcat connection is lazy: the first
        // accepted TCP connection is what brings the DERP/WireGuard path up.
        // Under load that first attempt can legitimately lose the race and
        // close with EOF before the exit-node route is ready (upstream
        // tailcat's analogous exit-node-forward test documents the same
        // transient reset).  Treat this as readiness probing, not as the one
        // and only assertion attempt.  A real regression still fails after
        // the bounded overall deadline.
        // StartAsync now waits for the forward listener to bind, and the
        // patched tailcat forward preflights the Tailcat peer before it ever
        // publishes that readiness. The first application connection must
        // therefore work immediately; retrying here would hide a real runtime
        // readiness regression that programmatic callers would still hit.
        var endpoint = IPEndPoint.Parse(boundAddress);
        using var socket = new TcpClient();
        using var attemptCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
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
        var got = System.Text.Encoding.UTF8.GetString(buffer, 0, total);

        Assert.True(
            got == backendReply,
            "first connection after StartAsync was not ready; " +
            $"received={got}; forward logs: {string.Join(" || ", forwardLogs)}; " +
            $"server logs: {string.Join(" || ", serverLogs)}");
    }
}
