using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using Meowshell;

namespace Meowshell.Tests;

/// <summary>
/// Runs <see cref="MeowshellAgentConnection"/> against a real "meowshell
/// agent" subprocess and a real tailcat server -- the check that the C#
/// wire client actually speaks the same framed protocol the Go side
/// (cmd/meowshell/agent.go, proven independently by its own Go-level E2E
/// tests) implements, not just that both sides individually parse their
/// own fixtures correctly.
///
/// Skipped (each test returns immediately) when the real binaries are not
/// available, e.g. a local "dotnet test" run without a "dist" build. Needs
/// real network unless TS_DEBUG_TAILCAT_LOCAL_DERP=1 is set in the test
/// process's own environment (inherited by every child process this
/// spawns) for the hermetic local-DERP mode tailcat itself provides.
/// </summary>
public sealed class MeowshellAgentConnectionE2ETests : IDisposable
{
    private static readonly Regex AddressPattern = new(@"\btc[A-Za-z0-9_-]{10,}", RegexOptions.Compiled);
    private static string Redact(string text) => AddressPattern.Replace(text, "tc<redacted>");
    private static void Mask(string value)
    {
        if (!string.IsNullOrEmpty(value)) Console.WriteLine("::add-mask::" + value);
    }

    private const string TailcatEnvVar = "DOTNET_E2E_TAILCAT_BIN";
    private const string MeowshellEnvVar = "DOTNET_E2E_MEOWSHELL_BIN";

    private readonly string _dir = Directory.CreateTempSubdirectory("agent-connection-e2e-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    /// <summary>Same layout as TailcatClientE2ETests.FindRealBinaries(). Returns null (skip) if either binary is unavailable.</summary>
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
    public async Task ExecChannelRunsACommandAndReportsARealExitCode()
    {
        var real = FindRealBinaries();
        if (real is null) return; // see FindRealBinaries()
        var (bin, _) = real.Value;

        await using var server = await MeowshellServer.StartAsync(new MeowshellOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "server-home"),
            WorkDirectory = Path.Combine(_dir, "server-work"),
            InsecureNoAuth = true,
            Lifetime = TimeSpan.FromMinutes(2),
            StartTimeout = TimeSpan.FromSeconds(30),
        });
        Mask(server.Address);

        await using var connection = await MeowshellAgentConnection.ConnectAsync(ClientOptions(bin), server.Address);

        var marker = $"agent-exec-e2e-{Guid.NewGuid():N}";
        await using (var ok = await connection.OpenExecAsync(["echo", marker]))
        {
            var output = await new StreamReader(ok.Output).ReadToEndAsync();
            Assert.Contains(marker, output);
            Assert.Equal(0, await ok.Completed);
        }

        await using var failing = await connection.OpenExecAsync(["sh", "-c", "'exit 42'"]);
        Assert.Equal(42, await failing.Completed);
    }

    [Fact]
    public async Task ShellChannelAcceptsInputAndResizesLive()
    {
        var real = FindRealBinaries();
        if (real is null) return; // see FindRealBinaries()
        var (bin, _) = real.Value;

        await using var server = await MeowshellServer.StartAsync(new MeowshellOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "server-home"),
            WorkDirectory = Path.Combine(_dir, "server-work"),
            InsecureNoAuth = true,
            Lifetime = TimeSpan.FromMinutes(2),
            StartTimeout = TimeSpan.FromSeconds(30),
        });
        Mask(server.Address);

        await using var connection = await MeowshellAgentConnection.ConnectAsync(ClientOptions(bin), server.Address);
        await using var shell = await connection.OpenShellAsync(columns: 80, rows: 24);

        await shell.ResizeAsync(120, 40);

        var marker = $"agent-shell-e2e-{Guid.NewGuid():N}";
        await shell.WriteAsync(Encoding.UTF8.GetBytes($"echo {marker}\n"));
        await shell.WriteAsync(Encoding.UTF8.GetBytes("exit\n"));

        var output = await ReadUntilAsync(shell.Output, marker, TimeSpan.FromSeconds(30));
        Assert.Contains(marker, output);
        await shell.Completed;
    }

    [Fact]
    public async Task SftpVerbsAndTransfersRoundTrip()
    {
        var real = FindRealBinaries();
        if (real is null) return; // see FindRealBinaries()
        var (bin, _) = real.Value;

        var served = Path.Combine(_dir, "served");
        Directory.CreateDirectory(served);
        await using var server = await MeowshellServer.StartAsync(new MeowshellOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "server-home"),
            WorkDirectory = Path.Combine(_dir, "server-work"),
            InsecureNoAuth = true,
            Files = served + ":rw",
            Lifetime = TimeSpan.FromMinutes(2),
            StartTimeout = TimeSpan.FromSeconds(30),
        });
        Mask(server.Address);

        await using var connection = await MeowshellAgentConnection.ConnectAsync(ClientOptions(bin), server.Address);

        await connection.MkdirAsync("uploads");
        var entries = await connection.ListFilesAsync(".");
        Assert.Contains(entries, e => e.Name == "uploads" && e.IsDirectory);

        var localUpload = Path.Combine(_dir, "upload.txt");
        var content = $"agent-sftp-e2e-{Guid.NewGuid():N}";
        await File.WriteAllTextAsync(localUpload, content);

        var progressReports = new List<long>();
        await connection.UploadAsync(localUpload, "uploads/file.txt", progress: new Progress<long>(progressReports.Add));
        Assert.NotEmpty(progressReports);

        var stat = await connection.StatAsync("uploads/file.txt");
        Assert.Equal(content.Length, stat.Size);

        var localDownload = Path.Combine(_dir, "downloaded.txt");
        await connection.DownloadAsync("uploads/file.txt", localDownload);
        Assert.Equal(content, await File.ReadAllTextAsync(localDownload));

        await connection.RenameAsync("uploads/file.txt", "uploads/renamed.txt");
        await connection.RemoveAsync("uploads/renamed.txt");
        await connection.RemoveDirectoryAsync("uploads");

        Assert.False(Directory.Exists(Path.Combine(served, "uploads")));
    }

    /// <summary>
    /// -L/-D forwarding against a tailcat destination: forwardClient
    /// (tailcatdial.go) dials through a native tailcat.Client instead of
    /// an SSH direct-tcpip channel there, since tailcat's own embedded SSH
    /// service never implements the latter (see forwarding.go's doc
    /// comment) -- the same mechanism tailcat's own "forward"/"socks"
    /// subcommands use. That dial is still gated by the destination
    /// server's own tailcat.Server.OnTCP: without <see cref="MeowshellOptions.AllowExitNode"/>
    /// it refuses anything but the server's own already-served ports, so
    /// this starts the server with it set and checks actual bytes cross
    /// the forward to an arbitrary backend -- not just that the listener
    /// opens (a real Go-level daemon test already proves the underlying
    /// feature: cmd/meowshell/agent_tailcat_forward_e2e_test.go).
    /// </summary>
    [Fact]
    public async Task LocalForwardReachesAnArbitraryBackendOnAnExitNodeServer()
    {
        var real = FindRealBinaries();
        if (real is null) return; // see FindRealBinaries()
        var (bin, _) = real.Value;

        await using var server = await MeowshellServer.StartAsync(new MeowshellOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "server-home"),
            WorkDirectory = Path.Combine(_dir, "server-work"),
            InsecureNoAuth = true,
            AllowExitNode = true,
            Lifetime = TimeSpan.FromMinutes(2),
            StartTimeout = TimeSpan.FromSeconds(30),
        });
        Mask(server.Address);

        await using var connection = await MeowshellAgentConnection.ConnectAsync(ClientOptions(bin), server.Address);

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
                        await client.GetStream().WriteAsync(Encoding.UTF8.GetBytes(backendReply));
                });
            }
        });

        await using var forward = await connection.OpenLocalForwardAsync(
            "127.0.0.1:0", $"127.0.0.1:{((IPEndPoint)backend.LocalEndpoint).Port}");
        Assert.NotEmpty(forward.BoundAddress);

        var boundEndpoint = IPEndPoint.Parse(forward.BoundAddress);
        using var socket = new TcpClient();
        await socket.ConnectAsync(boundEndpoint);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var buffer = new byte[256];
        var total = 0;
        int n;
        while (total < buffer.Length && (n = await socket.GetStream().ReadAsync(buffer.AsMemory(total), cts.Token)) > 0)
            total += n;
        Assert.Equal(backendReply, Encoding.UTF8.GetString(buffer, 0, total));
    }

    /// <summary>
    /// The Go-side loopback-default restriction (resolveLocalListener in
    /// forwarding.go): binding anything other than loopback fails outright
    /// unless explicitly opted into. Checked here at the C# call site --
    /// listenAddress reaches the agent process and is rejected before any
    /// SSH channel is even attempted, so this doesn't depend on tailcat's
    /// own (nonexistent) forwarding support.
    /// </summary>
    [Fact]
    public async Task LocalForwardRejectsNonLoopbackBindUnlessAllowed()
    {
        var real = FindRealBinaries();
        if (real is null) return; // see FindRealBinaries()
        var (bin, _) = real.Value;

        await using var server = await MeowshellServer.StartAsync(new MeowshellOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "server-home"),
            WorkDirectory = Path.Combine(_dir, "server-work"),
            InsecureNoAuth = true,
            Lifetime = TimeSpan.FromMinutes(2),
            StartTimeout = TimeSpan.FromSeconds(30),
        });
        Mask(server.Address);

        await using var connection = await MeowshellAgentConnection.ConnectAsync(ClientOptions(bin), server.Address);

        var ex = await Assert.ThrowsAsync<TailcatException>(() =>
            connection.OpenLocalForwardAsync("0.0.0.0:0", "127.0.0.1:1"));
        Assert.Contains("loopback", ex.Message, StringComparison.OrdinalIgnoreCase);

        // The opt-in makes the identical bind succeed (the listener opens;
        // whether tailcat itself would ever accept a forwarded connection
        // is the separate, already-covered concern above).
        await using var forward = await connection.OpenLocalForwardAsync("0.0.0.0:0", "127.0.0.1:1", allowNonLoopbackBind: true);
        Assert.NotEmpty(forward.BoundAddress);
    }

    /// <summary>
    /// A Unix-domain-socket forward: the recommended local endpoint over a
    /// TCP loopback socket, since filesystem permissions on the socket
    /// path -- not merely "which port" -- are what restrict access.
    /// </summary>
    [Fact]
    public async Task LocalForwardOnUnixSocketCreatesA0600Socket()
    {
        if (OperatingSystem.IsWindows()) return; // no AF_UNIX story to check here
        var real = FindRealBinaries();
        if (real is null) return; // see FindRealBinaries()
        var (bin, _) = real.Value;

        await using var server = await MeowshellServer.StartAsync(new MeowshellOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "server-home"),
            WorkDirectory = Path.Combine(_dir, "server-work"),
            InsecureNoAuth = true,
            Lifetime = TimeSpan.FromMinutes(2),
            StartTimeout = TimeSpan.FromSeconds(30),
        });
        Mask(server.Address);

        await using var connection = await MeowshellAgentConnection.ConnectAsync(ClientOptions(bin), server.Address);

        var socketPath = Path.Combine(_dir, "forward.sock");
        await using var forward = await connection.OpenLocalForwardOnUnixSocketAsync(socketPath, "127.0.0.1:1");
        Assert.Equal(socketPath, forward.BoundAddress);
        Assert.True(File.Exists(socketPath));
        var mode = File.GetUnixFileMode(socketPath);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode & (UnixFileMode)0b111_111_111);
    }

    /// <summary>
    /// forward_socks with auth: by default OpenSocksForwardAsync generates
    /// a random SOCKS5 username/password and the proxy enforces it via
    /// RFC 1929 subnegotiation -- proven here entirely at the SOCKS
    /// handshake layer (no CONNECT is ever attempted), so it doesn't
    /// depend on tailcat's own forwarding support either.
    /// </summary>
    [Fact]
    public async Task SocksForwardEnforcesAutoGeneratedToken()
    {
        var real = FindRealBinaries();
        if (real is null) return; // see FindRealBinaries()
        var (bin, _) = real.Value;

        await using var server = await MeowshellServer.StartAsync(new MeowshellOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "server-home"),
            WorkDirectory = Path.Combine(_dir, "server-work"),
            InsecureNoAuth = true,
            Lifetime = TimeSpan.FromMinutes(2),
            StartTimeout = TimeSpan.FromSeconds(30),
        });
        Mask(server.Address);

        await using var connection = await MeowshellAgentConnection.ConnectAsync(ClientOptions(bin), server.Address);

        await using var forward = await connection.OpenSocksForwardAsync("127.0.0.1:0");
        Assert.False(string.IsNullOrEmpty(forward.SocksUsername));
        Assert.False(string.IsNullOrEmpty(forward.SocksPassword));

        var boundEndpoint = IPEndPoint.Parse(forward.BoundAddress);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        using (var noAuthClient = new Socket(SocketType.Stream, ProtocolType.Tcp))
        {
            await noAuthClient.ConnectAsync(boundEndpoint, cts.Token);
            var method = await Socks5GreetAsync(noAuthClient, [0x00], cts.Token); // only offers "no auth"
            Assert.Equal(0xFF, method); // server requires auth: no acceptable method
        }

        using (var wrongCreds = new Socket(SocketType.Stream, ProtocolType.Tcp))
        {
            await wrongCreds.ConnectAsync(boundEndpoint, cts.Token);
            Assert.Equal(0x02, await Socks5GreetAsync(wrongCreds, [0x02], cts.Token));
            var status = await Socks5AuthAsync(wrongCreds, forward.SocksUsername!, "not-the-right-password", cts.Token);
            Assert.NotEqual(0x00, status);
        }

        using (var rightCreds = new Socket(SocketType.Stream, ProtocolType.Tcp))
        {
            await rightCreds.ConnectAsync(boundEndpoint, cts.Token);
            Assert.Equal(0x02, await Socks5GreetAsync(rightCreds, [0x02], cts.Token));
            var status = await Socks5AuthAsync(rightCreds, forward.SocksUsername!, forward.SocksPassword!, cts.Token);
            Assert.Equal(0x00, status);
        }
    }

    /// <summary>
    /// Fix 4's real target: HandleData used to fire-and-forget into each
    /// channel's sink (`_ = sink.OnDataAsync(...)`), which under
    /// backpressure could leave two overlapping WriteAsync calls in
    /// flight on the same Pipe -- undefined behavior. A remote command
    /// producing several times the Pipe's default 64KiB threshold in one
    /// channel is exactly the condition that used to be able to trigger
    /// it; this checks the bytes come through complete and byte-for-byte
    /// correct rather than merely "didn't throw" (the exception, when it
    /// happened at all, was itself an intermittent Pipe invariant
    /// violation, not a reliable repro on its own).
    /// </summary>
    [Fact]
    public async Task ExecChannelDeliversLargeOutputIntactUnderBackpressure()
    {
        var real = FindRealBinaries();
        if (real is null) return; // see FindRealBinaries()
        var (bin, _) = real.Value;

        await using var server = await MeowshellServer.StartAsync(new MeowshellOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "server-home"),
            WorkDirectory = Path.Combine(_dir, "server-work"),
            InsecureNoAuth = true,
            Lifetime = TimeSpan.FromMinutes(2),
            StartTimeout = TimeSpan.FromSeconds(30),
        });
        Mask(server.Address);

        await using var connection = await MeowshellAgentConnection.ConnectAsync(ClientOptions(bin), server.Address);

        const int totalBytes = 512 * 1024; // several multiples of the Pipe's 64KiB PauseWriterThreshold
        // One array element, not ["sh", "-c", ...]: OpenExecAsync joins
        // elements with spaces and the exec request already runs through
        // the remote's own shell (see agent.go's session.Start), so an
        // explicit "sh -c" prefix here double-wraps it -- the inner "sh -c"
        // then only takes "head" as its script and the rest as positional
        // params, leaving a bare `head` blocked forever reading this
        // channel's own (never-written, never-closed) stdin.
        await using var exec = await connection.OpenExecAsync([$"head -c {totalBytes} /dev/zero | tr '\\0' 'A'"]);

        using var ms = new MemoryStream();
        await exec.Output.CopyToAsync(ms);
        Assert.Equal(0, await exec.Completed);

        var received = ms.ToArray();
        Assert.Equal(totalBytes, received.Length);
        Assert.All(received, b => Assert.Equal((byte)'A', b));
    }

    private static async Task<byte> Socks5GreetAsync(Socket socket, byte[] methods, CancellationToken cancellationToken)
    {
        var greeting = new byte[2 + methods.Length];
        greeting[0] = 0x05;
        greeting[1] = (byte)methods.Length;
        methods.CopyTo(greeting, 2);
        await socket.SendAsync(greeting, cancellationToken);
        var resp = new byte[2];
        await ReadExactAsync(socket, resp, cancellationToken);
        Assert.Equal(0x05, resp[0]);
        return resp[1];
    }

    private static async Task<byte> Socks5AuthAsync(Socket socket, string username, string password, CancellationToken cancellationToken)
    {
        var userBytes = Encoding.UTF8.GetBytes(username);
        var passBytes = Encoding.UTF8.GetBytes(password);
        var req = new byte[3 + userBytes.Length + passBytes.Length];
        req[0] = 0x01;
        req[1] = (byte)userBytes.Length;
        userBytes.CopyTo(req, 2);
        req[2 + userBytes.Length] = (byte)passBytes.Length;
        passBytes.CopyTo(req, 3 + userBytes.Length);
        await socket.SendAsync(req, cancellationToken);
        var resp = new byte[2];
        await ReadExactAsync(socket, resp, cancellationToken);
        return resp[1];
    }

    private static async Task ReadExactAsync(Socket socket, byte[] buffer, CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var n = await socket.ReceiveAsync(buffer.AsMemory(total), cancellationToken);
            if (n == 0) throw new IOException("socket closed before the expected reply arrived");
            total += n;
        }
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
