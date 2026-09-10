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
    /// -L/-D forwarding (see forwarding.go's doc comment) only works
    /// against a general SSH host: tailcat's own embedded SSH server never
    /// registers a "direct-tcpip" channel handler, so it always refuses
    /// the channel a forward's Dial opens -- confirmed here rather than
    /// left as an assumption, since a real Go-level fake-SSH-server test
    /// already proves the *feature* works where the peer supports it (see
    /// cmd/meowshell/agent_forward_e2e_test.go); what this checks instead
    /// is that the C# client's own open/close plumbing behaves sanely
    /// against a peer that can't: the listener still opens successfully
    /// (BoundAddress comes back), and a forwarded connection is simply
    /// closed rather than hanging or crashing anything.
    /// </summary>
    [Fact]
    public async Task LocalForwardOpensAgainstTailcatButEachConnectionIsRefused()
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

        using var backend = new TcpListener(IPAddress.Loopback, 0);
        backend.Start();

        await using var forward = await connection.OpenLocalForwardAsync(
            "127.0.0.1:0", $"127.0.0.1:{((IPEndPoint)backend.LocalEndpoint).Port}");
        Assert.NotEmpty(forward.BoundAddress);

        var boundEndpoint = IPEndPoint.Parse(forward.BoundAddress);
        using var socket = new TcpClient();
        await socket.ConnectAsync(boundEndpoint);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var buffer = new byte[256];
        var n = await socket.GetStream().ReadAsync(buffer, cts.Token);
        Assert.Equal(0, n); // closed, not hung and not carrying any bytes -- tailcat never accepted the forwarded channel
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
