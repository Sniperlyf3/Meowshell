#nullable enable
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipelines;

namespace Meowshell;

/// <summary>Auth material and options for the connection's mandatory "configure" message. Leave everything unset for a connection that only ever needs the local ssh-agent or no auth at all.</summary>
public sealed record MeowshellAgentConfigureOptions
{
    /// <summary>Skip the local ssh-agent even if one is running.</summary>
    public bool DisableLocalAgent { get; init; }

    /// <summary>Private key blobs (any format golang.org/x/crypto/ssh's ParsePrivateKey accepts) to offer, never written to disk by the agent process.</summary>
    public IReadOnlyList<byte[]>? PrivateKeys { get; init; }

    /// <summary>OpenSSH certificate public keys, index-paired with <see cref="PrivateKeys"/>, to sign with instead of the bare key at the same index.</summary>
    public IReadOnlyList<byte[]>? Certificates { get; init; }

    /// <summary>Key IDs for Keystore-backed keys that never leave the caller -- see <see cref="MeowshellAgentConnection.SignRequested"/>.</summary>
    public IReadOnlyList<string>? KeystoreKeyIds { get; init; }

    /// <summary>Public keys, index-paired with <see cref="KeystoreKeyIds"/>.</summary>
    public IReadOnlyList<byte[]>? KeystorePublicKeys { get; init; }

    /// <summary>Forward the local ssh-agent (if any) to the remote, once connected.</summary>
    public bool ForwardLocalAgent { get; init; }

    /// <summary>Let a Keystore-backed RSA key (<see cref="KeystoreKeyIds"/>) fall back to the ssh-rsa (SHA-1) signature format for a server that predates RFC 8332 and rejects the SHA-2 RSA formats offered by default. Leave unset unless a specific server is known to need it: OpenSSH itself has refused ssh-rsa by default since 8.8.</summary>
    public bool AllowLegacyKeyAlgorithms { get; init; }
}

/// <summary>A host-key prompt: an unrecognized key on a TCP-transport connection, needing a trust-on-first-use decision.</summary>
/// <param name="Remote">The remote host being connected to.</param>
/// <param name="Fingerprint">The host key's fingerprint.</param>
public sealed record MeowshellHostKeyPrompt(string Remote, string Fingerprint);

/// <summary>A keyboard-interactive challenge, RFC 4256 style: zero or more questions, each independently maskable.</summary>
/// <param name="Name">The challenge's name.</param>
/// <param name="Instruction">Free-text instructions to show the user.</param>
/// <param name="Questions">The questions to ask, in order.</param>
/// <param name="Echos">Whether each corresponding question's answer should be shown as typed.</param>
public sealed record MeowshellKeyboardInteractivePrompt(string Name, string Instruction, IReadOnlyList<string> Questions, IReadOnlyList<bool> Echos);

/// <summary>A request to sign with a Keystore-backed key -- see <see cref="MeowshellAgentConfigureOptions.KeystoreKeyIds"/>.</summary>
/// <param name="KeyId">Which key to sign with.</param>
/// <param name="Algorithm">
/// The signature algorithm the SSH handshake negotiated -- "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa",
/// "ecdsa-sha2-nistp256" or "ssh-ed25519" -- which for an RSA key is not the same as the key's type, and
/// decides which digest to sign under (SHA-512, SHA-256 or SHA-1 respectively). Sign under this, not under
/// a fixed algorithm: the mismatch surfaces only as a failed handshake. See the README for the exact bytes
/// each algorithm expects back, including the DER-to-mpint conversion an ECDSA signature needs.
/// </param>
/// <param name="Data">The bytes to sign.</param>
public sealed record MeowshellSignRequest(string KeyId, string Algorithm, byte[] Data);

/// <summary>One directory entry or a single file's metadata, from an SFTP ls/stat/lstat.</summary>
/// <param name="Name">The entry's name.</param>
/// <param name="Size">The size in bytes.</param>
/// <param name="Mode">The raw permission bits.</param>
/// <param name="ModifiedAt">The modification time.</param>
/// <param name="IsDirectory">Whether the entry is a directory.</param>
public sealed record MeowshellSftpEntry(string Name, long Size, uint Mode, DateTimeOffset ModifiedAt, bool IsDirectory);

/// <summary>A persistent, multiplexed connection to a tailcat address or a general SSH host, driving "meowshell agent" as a long-lived subprocess. Open a shell, run a command, browse files, and forward a port all over the same login.</summary>
public sealed class MeowshellAgentConnection : IAsyncDisposable
{
    private readonly Process _process;
    private readonly JobObject? _job;
    private readonly Stream _stdin;
    private readonly Stream _stdout;
    private readonly TailcatDiagnostics _diagnostics = new();
    private readonly TaskCompletionSource _connected = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Task _readLoop;
    private readonly ConcurrentDictionary<uint, IAgentChannelSink> _channels = new();

    /// <summary>Test-only: how many channels are currently tracked. Not a public API -- a finished channel not being usable is the real, externally observable contract; this just lets a test also assert it isn't still referenced internally.</summary>
    internal int ChannelCountForTests => _channels.Count;
    private readonly ConcurrentDictionary<string, TaskCompletionSource<AgentMessage>> _pendingRequests = new();
    private readonly ConcurrentDictionary<string, PendingOpen> _pendingOpens = new();
    private readonly ConcurrentDictionary<uint, TaskCompletionSource> _pendingCloses = new();
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly SemaphoreSlim _stopLock = new(1, 1);
    private readonly CancellationTokenSource _lifetimeCts = new();
    private readonly ConcurrentDictionary<Task, byte> _promptTasks = new();
    private long _nextRequestId;
    private bool _stopped;

    /// <summary>Diagnostic output from meowshell/tailcat (connection setup, errors). Raised on a background thread.</summary>
    public event Action<string>? Log;

    /// <summary>An unrecognized host key on a TCP-transport connection. No handler (or the handler throwing) rejects the key.</summary>
    public event Func<MeowshellHostKeyPrompt, CancellationToken, Task<bool>>? HostKeyPromptRequested;

    /// <summary>A password is needed. No handler cancels the auth attempt.</summary>
    public event Func<string, CancellationToken, Task<string>>? PasswordRequested;

    /// <summary>An encrypted supplied private key needs its passphrase. No handler cancels the auth attempt.</summary>
    public event Func<CancellationToken, Task<string>>? PassphraseRequested;

    /// <summary>A keyboard-interactive (OTP/PAM) challenge. May fire more than once per connection attempt. No handler cancels the auth attempt.</summary>
    public event Func<MeowshellKeyboardInteractivePrompt, CancellationToken, Task<string[]>>? KeyboardInteractiveRequested;

    /// <summary>A Keystore-backed key needs to sign something, under the algorithm in <see cref="MeowshellSignRequest.Algorithm"/>. No handler refuses the signature.</summary>
    public event Func<MeowshellSignRequest, CancellationToken, Task<byte[]>>? SignRequested;

    private MeowshellAgentConnection(Process process, JobObject? job)
    {
        _process = process;
        _job = job;
        _stdin = process.StandardInput.BaseStream;
        _stdout = process.StandardOutput.BaseStream;
        _readLoop = Task.Run(RunReadLoopAsync);
    }

    /// <summary>Dials <paramref name="destination"/> -- a tailcat address, or a "[user@]host[:port]" TCP address -- and completes the SSH handshake, including any host-key/auth prompts along the way.</summary>
    /// <param name="options">Where the binaries live and how to reach the destination.</param>
    /// <param name="destination">A tailcat address, or a "[user@]host[:port]" TCP address.</param>
    /// <param name="configure">Auth material and options; omit for local-ssh-agent-or-nothing.</param>
    /// <param name="port">The destination's SSH service port, when it isn't 22.</param>
    /// <param name="jumpHosts">Intermediate TCP SSH hosts to tunnel through first, closest-to-here first.</param>
    /// <param name="knownHostsPath">known_hosts file for TCP-transport host-key verification (default: $HOME/.meowshell/known_hosts).</param>
    /// <param name="proxyUrl">A SOCKS5 or HTTP CONNECT proxy to reach the first TCP hop through.</param>
    /// <param name="cancellationToken">Cancels waiting for the connection to settle; does not cancel or stop the connection itself once returned.</param>
    /// <exception cref="TailcatException">The connection failed to establish within <see cref="TailcatClientOptions.Timeout"/>; <see cref="TailcatException.Code"/> names why when the agent reported a typed reason.</exception>
    public static async Task<MeowshellAgentConnection> ConnectAsync(
        TailcatClientOptions options, string destination, MeowshellAgentConfigureOptions? configure = null,
        string? port = null, IReadOnlyList<string>? jumpHosts = null, string? knownHostsPath = null, string? proxyUrl = null,
        CancellationToken cancellationToken = default)
    {
        var (meowshell, tailcat) = MeowshellBinaries.Locate(options.BinaryDirectory, options.Naming);
        MeowshellHomeDirectory.EnsureSecure(options.HomeDirectory);
        var psi = new ProcessStartInfo(meowshell)
        {
            WorkingDirectory = options.HomeDirectory,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("agent");
        if (!string.IsNullOrEmpty(port)) psi.ArgumentList.Add($"-p={port}");
        if (!string.IsNullOrEmpty(options.DerpMapUrl)) psi.ArgumentList.Add($"--derpmap-url={options.DerpMapUrl}");
        if (options.Verbose) psi.ArgumentList.Add("--verbose");
        if (!string.IsNullOrEmpty(knownHostsPath)) psi.ArgumentList.Add($"--known-hosts={knownHostsPath}");
        if (jumpHosts is not null)
            foreach (var hop in jumpHosts) psi.ArgumentList.Add($"--jump={hop}");
        psi.ArgumentList.Add(destination);

        psi.Environment["TAILCAT_BIN"] = tailcat;
        TailcatProcessEnvironment.ApplyHome(psi, options.HomeDirectory);

        var process = new Process { StartInfo = psi, EnableRaisingEvents = true };
        var job = MeowshellProcessControl.Start(process);
        var connection = new MeowshellAgentConnection(process, job);
        try
        {
            process.ErrorDataReceived += (_, e) =>
            {
                if (e.Data is null) return;
                connection._diagnostics.Add(e.Data);
                // Raised on a framework-owned thread with nothing else
                // watching it: an exception from a Log subscriber must not
                // be allowed to escape and take the process down over a
                // logging failure.
                try { connection.Log?.Invoke(e.Data); } catch { }
            };
            process.BeginErrorReadLine();

            await connection.SendConfigureAsync(configure ?? new MeowshellAgentConfigureOptions(), proxyUrl, cancellationToken).ConfigureAwait(false);

            var settled = await Task.WhenAny(connection._connected.Task, Task.Delay(options.Timeout, cancellationToken)).ConfigureAwait(false);
            if (settled != connection._connected.Task)
            {
                cancellationToken.ThrowIfCancellationRequested();
                throw new TailcatException("meowshell agent did not connect in time", 0, connection._diagnostics.Tail(), MeowshellErrorCode.Timeout);
            }
            await connection._connected.Task.ConfigureAwait(false);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private Task SendConfigureAsync(MeowshellAgentConfigureOptions configure, string? proxyUrl, CancellationToken cancellationToken) =>
        WriteControlAsync(0, new AgentMessage
        {
            Msg = "configure",
            DisableAgent = configure.DisableLocalAgent,
            Keys = ToJagged(configure.PrivateKeys),
            Certificates = ToJagged(configure.Certificates),
            KeystoreKeyIds = configure.KeystoreKeyIds?.ToArray(),
            KeystorePublicKeys = ToJagged(configure.KeystorePublicKeys),
            AgentForwarding = configure.ForwardLocalAgent,
            AllowLegacyKeyAlgorithms = configure.AllowLegacyKeyAlgorithms,
            ProxyUrl = proxyUrl,
        }, cancellationToken);

    private static byte[][]? ToJagged(IReadOnlyList<byte[]>? list) => list is null ? null : list.ToArray();

    /// <summary>Opens an interactive shell, with a pseudo-terminal unless <paramref name="pty"/> is set false.</summary>
    public Task<MeowshellAgentShellChannel> OpenShellAsync(int columns = 80, int rows = 24, string? term = null, bool? pty = null, CancellationToken cancellationToken = default) =>
        OpenShellChannelAsync(new AgentMessage { Msg = "open_channel", Kind = "shell", Pty = pty, Cols = columns, Rows = rows, Term = term }, cancellationToken);

    /// <summary>Runs <paramref name="command"/> non-interactively (or with a pseudo-terminal if <paramref name="pty"/> is true). Elements are joined with plain spaces -- no quoting is added.</summary>
    public Task<MeowshellAgentShellChannel> OpenExecAsync(IReadOnlyList<string> command, bool? pty = null, int columns = 80, int rows = 24, string? term = null, CancellationToken cancellationToken = default) =>
        OpenShellChannelAsync(new AgentMessage { Msg = "open_channel", Kind = "exec", Command = command.ToArray(), Pty = pty, Cols = columns, Rows = rows, Term = term }, cancellationToken);

    private Task<MeowshellAgentShellChannel> OpenShellChannelAsync(AgentMessage request, CancellationToken cancellationToken) =>
        OpenChannelAsync(request, (id, _) =>
        {
            var channel = new MeowshellAgentShellChannel(this, id);
            return (channel, (IAgentChannelSink)channel);
        }, cancellationToken);

    /// <summary>Lists a directory's entries.</summary>
    public async Task<IReadOnlyList<MeowshellSftpEntry>> ListFilesAsync(string path, CancellationToken cancellationToken = default)
    {
        var resp = await SftpRequestAsync(new AgentMessage { Op = "ls", Path = path }, cancellationToken).ConfigureAwait(false);
        return (resp.Entries ?? []).Select(ToSftpEntry).ToArray();
    }

    /// <summary>Stats a path, following a symlink (or not, with <paramref name="followSymlink"/> false).</summary>
    public async Task<MeowshellSftpEntry> StatAsync(string path, bool followSymlink = true, CancellationToken cancellationToken = default)
    {
        var resp = await SftpRequestAsync(new AgentMessage { Op = followSymlink ? "stat" : "lstat", Path = path }, cancellationToken).ConfigureAwait(false);
        return ToSftpEntry(resp.Entries![0]);
    }

    private static MeowshellSftpEntry ToSftpEntry(AgentSftpEntry e) =>
        new(e.Name, e.Size, e.Mode, DateTimeOffset.FromUnixTimeSeconds(e.ModTime), e.IsDir);

    /// <summary>Creates a directory. <paramref name="recursive"/> creates parents as needed (and does not error if it already exists).</summary>
    public Task MkdirAsync(string path, bool recursive = false, CancellationToken cancellationToken = default) =>
        SftpRequestAsync(new AgentMessage { Op = recursive ? "mkdir_all" : "mkdir", Path = path }, cancellationToken);

    /// <summary>Removes an empty directory.</summary>
    public Task RemoveDirectoryAsync(string path, CancellationToken cancellationToken = default) =>
        SftpRequestAsync(new AgentMessage { Op = "rmdir", Path = path }, cancellationToken);

    /// <summary>Removes a file.</summary>
    public Task RemoveAsync(string path, CancellationToken cancellationToken = default) =>
        SftpRequestAsync(new AgentMessage { Op = "remove", Path = path }, cancellationToken);

    /// <summary>Renames or moves a file or directory.</summary>
    public Task RenameAsync(string path, string newPath, CancellationToken cancellationToken = default) =>
        SftpRequestAsync(new AgentMessage { Op = "rename", Path = path, NewPath = newPath }, cancellationToken);

    /// <summary>Changes a path's permission bits.</summary>
    public Task ChmodAsync(string path, uint mode, CancellationToken cancellationToken = default) =>
        SftpRequestAsync(new AgentMessage { Op = "chmod", Path = path, Mode = mode }, cancellationToken);

    /// <summary>Changes a path's owning user/group IDs.</summary>
    public Task ChownAsync(string path, int uid, int gid, CancellationToken cancellationToken = default) =>
        SftpRequestAsync(new AgentMessage { Op = "chown", Path = path, Uid = uid, Gid = gid }, cancellationToken);

    /// <summary>Creates a symlink at <paramref name="path"/> pointing to <paramref name="target"/>.</summary>
    public Task SymlinkAsync(string path, string target, CancellationToken cancellationToken = default) =>
        SftpRequestAsync(new AgentMessage { Op = "symlink", Path = path, Target = target }, cancellationToken);

    /// <summary>Reads a symlink's target.</summary>
    public async Task<string> ReadLinkAsync(string path, CancellationToken cancellationToken = default) =>
        (await SftpRequestAsync(new AgentMessage { Op = "readlink", Path = path }, cancellationToken).ConfigureAwait(false)).Target!;

    /// <summary>Truncates (or extends) a remote file to an exact size.</summary>
    public Task TruncateAsync(string path, long size, CancellationToken cancellationToken = default) =>
        SftpRequestAsync(new AgentMessage { Op = "truncate", Path = path, Size = size }, cancellationToken);

    /// <summary>Resolves a path to its absolute form on the server.</summary>
    public async Task<string> RealPathAsync(string path, CancellationToken cancellationToken = default) =>
        (await SftpRequestAsync(new AgentMessage { Op = "realpath", Path = path }, cancellationToken).ConfigureAwait(false)).Path!;

    private async Task<AgentMessage> SftpRequestAsync(AgentMessage request, CancellationToken cancellationToken)
    {
        request.Msg = "sftp_op";
        var requestId = NextRequestId();
        request.RequestId = requestId;
        var tcs = new TaskCompletionSource<AgentMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingRequests[requestId] = tcs;
        try
        {
            await WriteControlAsync(0, request, cancellationToken).ConfigureAwait(false);
            using var registration = cancellationToken.Register(() => tcs.TrySetCanceled(cancellationToken));
            var response = await tcs.Task.ConfigureAwait(false);
            if (response.Msg == "error")
                throw AgentError(response, $"sftp {request.Op} {request.Path}");
            return response;
        }
        finally
        {
            _pendingRequests.TryRemove(requestId, out _);
        }
    }

    /// <summary>Uploads a local file, optionally reporting progress and preserving its mode/mtime remotely.</summary>
    public async Task UploadAsync(string localPath, string remotePath, bool preserve = false, IProgress<long>? progress = null, CancellationToken cancellationToken = default)
    {
        var info = new FileInfo(localPath);
        var request = new AgentMessage { Msg = "open_channel", Kind = "sftp_upload", Path = remotePath, Preserve = preserve };
        if (preserve)
        {
            request.Mode = (uint)GetUnixMode(localPath);
            request.ModTime = new DateTimeOffset(info.LastWriteTimeUtc).ToUnixTimeSeconds();
        }
        var completion = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        var id = await OpenChannelAsync(request,
            (chId, _) => (chId, (IAgentChannelSink)new AgentRequestResponseSink(completion)), cancellationToken).ConfigureAwait(false);
        var normalCloseSent = false;
        try
        {
            await using var file = File.OpenRead(localPath);
            var buffer = new byte[64 * 1024];
            long sent = 0;
            int n;
            while ((n = await file.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
            {
                await SendDataAsync(id, buffer.AsMemory(0, n), cancellationToken).ConfigureAwait(false);
                sent += n;
                progress?.Report(sent);
            }
            await WriteControlAsync(id, new AgentMessage { Msg = "close_channel" }, cancellationToken).ConfigureAwait(false);
            normalCloseSent = true;
            await completion.Task.ConfigureAwait(false);
        }
        finally
        {
            // Cancellation (or any failure) before the close_channel above
            // must still tell the agent to stop: otherwise it keeps the
            // remote file and SFTP channel open for the rest of the
            // connection's life. Safe to send twice -- a second
            // close_channel for an already-closed id is a no-op on the
            // agent side.
            if (!normalCloseSent)
            {
                try { await WriteControlAsync(id, new AgentMessage { Msg = "close_channel", Cancelled = true }, CancellationToken.None).ConfigureAwait(false); } catch { }
            }
            _channels.TryRemove(id, out _);
        }
    }

    private const int DefaultUnixFileMode = 0b110_100_100;

    private static int GetUnixMode(string path)
    {
        if (OperatingSystem.IsWindows()) return DefaultUnixFileMode;
        try { return (int)File.GetUnixFileMode(path); } catch (PlatformNotSupportedException) { return DefaultUnixFileMode; }
    }

    /// <summary>Downloads a remote file to a local path, optionally reporting (bytesDone, totalBytes) progress and preserving mode/mtime.</summary>
    public async Task DownloadAsync(string remotePath, string localPath, bool preserve = false, IProgress<(long Done, long Total)>? progress = null, CancellationToken cancellationToken = default)
    {
        var sink = new AgentDownloadSink();
        var id = await OpenChannelAsync(new AgentMessage { Msg = "open_channel", Kind = "sftp_download", Path = remotePath },
            (chId, opened) => { sink.TotalBytes = opened.Size; return (chId, (IAgentChannelSink)sink); }, cancellationToken).ConfigureAwait(false);

        var finalPath = Path.GetFullPath(localPath);
        var tempPath = finalPath + ".meowshell-download-" + Guid.NewGuid().ToString("N");
        var committed = false;
        try
        {
            var total = sink.TotalBytes;
            await using (var file = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, useAsync: true))
            {
                var stream = sink.Content;
                var buffer = new byte[64 * 1024];
                long done = 0;
                int n;
                while ((n = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
                {
                    await file.WriteAsync(buffer.AsMemory(0, n), cancellationToken).ConfigureAwait(false);
                    done += n;
                    progress?.Report((done, total));
                }
                await sink.Completed.ConfigureAwait(false);
                await file.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            if (preserve)
            {
                var stat = await StatAsync(remotePath, cancellationToken: cancellationToken).ConfigureAwait(false);
                File.SetLastWriteTimeUtc(tempPath, stat.ModifiedAt.UtcDateTime);
                if (!OperatingSystem.IsWindows())
                {
                    try { File.SetUnixFileMode(tempPath, (UnixFileMode)(stat.Mode & 0x1FF)); } catch (PlatformNotSupportedException) { }
                }
            }

            File.Move(tempPath, finalPath, overwrite: true);
            committed = true;
        }
        finally
        {
            // On the happy path the agent already closed its side once it
            // hit EOF, so this is a no-op there. On cancellation (or any
            // other failure) before that, it stops the agent from reading
            // and sending the rest of a possibly huge remote file that
            // nothing here is listening for anymore -- cancelling this call
            // must actually cancel the transfer, not just stop consuming it.
            try { await WriteControlAsync(id, new AgentMessage { Msg = "close_channel" }, CancellationToken.None).ConfigureAwait(false); } catch { }
            _channels.TryRemove(id, out _);
            if (!committed)
            {
                try { File.Delete(tempPath); } catch { }
            }
        }
    }

    /// <summary>"-L": listens locally, forwarding each connection to <paramref name="remoteAddress"/> through the SSH client. A ":0" port in <paramref name="listenAddress"/> gets an OS-assigned one. Refuses to bind anything other than loopback unless <paramref name="allowNonLoopbackBind"/> is true.</summary>
    /// <param name="listenAddress">Local <c>[address]:port</c> to listen on.</param>
    /// <param name="remoteAddress">Destination <c>host:port</c> reached through the SSH client.</param>
    /// <param name="allowNonLoopbackBind">Allow binding somewhere other than loopback.</param>
    /// <param name="maxConnections">Caps how many connections this forward services at once; further connections queue in the listen backlog (or get refused once that fills) instead of piling up unbounded goroutines and file descriptors on the agent. Zero (the default) means unlimited.</param>
    /// <param name="cancellationToken">Cancels the open request.</param>
    public Task<MeowshellForward> OpenLocalForwardAsync(string listenAddress, string remoteAddress, bool allowNonLoopbackBind = false, int maxConnections = 0, CancellationToken cancellationToken = default) =>
        OpenForwardAsync("forward_local", listenAddress, remoteAddress, listenNetwork: null, allowNonLoopbackBind, socksUsername: null, socksPassword: null, maxConnections, cancellationToken);

    /// <summary>"-L" over a Unix domain socket at <paramref name="socketPath"/> instead of a TCP port -- the recommended local endpoint whenever the caller can hand the path to whatever will connect to it.</summary>
    /// <param name="socketPath">Local Unix domain socket path to listen on.</param>
    /// <param name="remoteAddress">Destination <c>host:port</c> reached through the SSH client.</param>
    /// <param name="maxConnections">See <see cref="OpenLocalForwardAsync"/>.</param>
    /// <param name="cancellationToken">Cancels the open request.</param>
    public Task<MeowshellForward> OpenLocalForwardOnUnixSocketAsync(string socketPath, string remoteAddress, int maxConnections = 0, CancellationToken cancellationToken = default) =>
        OpenForwardAsync("forward_local", socketPath, remoteAddress, listenNetwork: "unix", allowNonLoopbackBind: false, socksUsername: null, socksPassword: null, maxConnections, cancellationToken);

    /// <summary>"-R": asks the remote to listen on <paramref name="listenAddress"/>, forwarding each connection it accepts to <paramref name="localAddress"/> on this machine.</summary>
    /// <param name="listenAddress">Remote <c>[address]:port</c> for the server to listen on.</param>
    /// <param name="localAddress">Local destination <c>host:port</c> to forward accepted connections to.</param>
    /// <param name="maxConnections">See <see cref="OpenLocalForwardAsync"/>.</param>
    /// <param name="cancellationToken">Cancels the open request.</param>
    public Task<MeowshellForward> OpenRemoteForwardAsync(string listenAddress, string localAddress, int maxConnections = 0, CancellationToken cancellationToken = default) =>
        OpenForwardAsync("forward_remote", listenAddress, localAddress, listenNetwork: null, allowNonLoopbackBind: false, socksUsername: null, socksPassword: null, maxConnections, cancellationToken);

    /// <summary>"-D": runs a local SOCKS5 proxy on <paramref name="listenAddress"/>. By default requires RFC 1929 SOCKS5 auth with a random token -- read it back from <see cref="MeowshellForward.SocksUsername"/>/<see cref="MeowshellForward.SocksPassword"/>.</summary>
    /// <param name="listenAddress">Local <c>[address]:port</c> to listen on.</param>
    /// <param name="requireAuth">Require SOCKS5 username/password auth.</param>
    /// <param name="socksUsername">Fixed SOCKS5 username, instead of a generated one.</param>
    /// <param name="socksPassword">Fixed SOCKS5 password, instead of a generated one.</param>
    /// <param name="allowNonLoopbackBind">Allow binding somewhere other than loopback.</param>
    /// <param name="maxConnections">See <see cref="OpenLocalForwardAsync"/>.</param>
    /// <param name="cancellationToken">Cancels the open request.</param>
    public Task<MeowshellForward> OpenSocksForwardAsync(string listenAddress, bool requireAuth = true, string? socksUsername = null, string? socksPassword = null, bool allowNonLoopbackBind = false, int maxConnections = 0, CancellationToken cancellationToken = default)
    {
        (socksUsername, socksPassword) = ResolveSocksAuth(requireAuth, socksUsername, socksPassword);
        return OpenForwardAsync("forward_socks", listenAddress, remoteAddress: null, listenNetwork: null, allowNonLoopbackBind, socksUsername, socksPassword, maxConnections, cancellationToken);
    }

    /// <summary>"-D" over a Unix domain socket at <paramref name="socketPath"/> instead of a TCP port. <paramref name="requireAuth"/> defaults to false here, unlike the TCP overload.</summary>
    /// <param name="socketPath">Local Unix domain socket path to listen on.</param>
    /// <param name="requireAuth">Require SOCKS5 username/password auth.</param>
    /// <param name="socksUsername">Fixed SOCKS5 username, instead of a generated one.</param>
    /// <param name="socksPassword">Fixed SOCKS5 password, instead of a generated one.</param>
    /// <param name="maxConnections">See <see cref="OpenLocalForwardAsync"/>.</param>
    /// <param name="cancellationToken">Cancels the open request.</param>
    public Task<MeowshellForward> OpenSocksForwardOnUnixSocketAsync(string socketPath, bool requireAuth = false, string? socksUsername = null, string? socksPassword = null, int maxConnections = 0, CancellationToken cancellationToken = default)
    {
        (socksUsername, socksPassword) = ResolveSocksAuth(requireAuth, socksUsername, socksPassword);
        return OpenForwardAsync("forward_socks", socketPath, remoteAddress: null, listenNetwork: "unix", allowNonLoopbackBind: false, socksUsername, socksPassword, maxConnections, cancellationToken);
    }

    private static (string? Username, string? Password) ResolveSocksAuth(bool requireAuth, string? username, string? password)
    {
        if (!requireAuth) return (null, null);
        if (username is not null && password is not null) return (username, password);
        return GenerateSocksToken();
    }

    private static (string Username, string Password) GenerateSocksToken() =>
        (Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(9)),
         Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(18)));

    private Task<MeowshellForward> OpenForwardAsync(string kind, string listenAddress, string? remoteAddress, string? listenNetwork, bool allowNonLoopbackBind, string? socksUsername, string? socksPassword, int maxConnections, CancellationToken cancellationToken)
    {
        if (maxConnections < 0)
            throw new ArgumentOutOfRangeException(nameof(maxConnections), maxConnections, "maxConnections must not be negative (0 means unlimited).");

        var request = new AgentMessage
        {
            Msg = "open_channel", Kind = kind, ListenAddr = listenAddress, RemoteAddr = remoteAddress,
            ListenNetwork = listenNetwork, AllowNonLoopbackBind = allowNonLoopbackBind,
            SocksUsername = socksUsername, SocksPassword = socksPassword,
            MaxConnections = maxConnections,
        };
        return OpenChannelAsync(request, (id, opened) =>
        {
            var forward = new MeowshellForward(this, id, opened.BoundAddr ?? listenAddress, socksUsername, socksPassword);
            return (forward, (IAgentChannelSink)new AgentIgnoreSink());
        }, cancellationToken);
    }

    internal async Task CloseForwardAsync(uint id, CancellationToken cancellationToken)
    {
        // Unlike a shell/exec channel, the agent never sends "exit_status" --
        // it acknowledges a forward's close explicitly instead, with its own
        // "channel_closed" (see agent.go's closeChannel), sent only once
        // ch.listener.Close() has actually returned. Waiting for it here
        // means a caller can trust that by the time CloseAsync() returns,
        // the port is genuinely free again (e.g. safe to rebind) rather than
        // merely that the close request was sent. This explicit close is
        // also still the only terminal signal that exists at all for a
        // forward, so it has to also be what removes the local entry:
        // without it, every forward ever opened on a connection stays in
        // _channels for the connection's whole lifetime, not just until it's
        // closed.
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingCloses[id] = tcs;
        try
        {
            await WriteControlAsync(id, new AgentMessage { Msg = "close_channel" }, cancellationToken).ConfigureAwait(false);
            using var registration = cancellationToken.Register(() => tcs.TrySetCanceled(cancellationToken));
            await tcs.Task.ConfigureAwait(false);
        }
        finally
        {
            _pendingCloses.TryRemove(id, out _);
            _channels.TryRemove(id, out _);
        }
    }

    // Each open_channel request carries its own request ID, correlated
    // against the response the same way SFTP ops already are -- rather than
    // one global pending-callback slot. That matters because a single slot
    // is only safe while calls are strictly serialized: if a caller's
    // CancellationToken fires while the agent's channel_opened/error for
    // that request is still in flight, clearing the slot on our side
    // doesn't stop the agent from creating (or having already created) the
    // channel. A later call already in flight when that stale response
    // arrives would previously have silently swallowed it (or worse,
    // matched it to the wrong caller's request); with each request tracked
    // by ID, a late response either resolves the right caller or, if
    // nobody is waiting on it anymore, tells us to close the orphaned
    // channel immediately (see the "channel_opened"/"error" handling in
    // HandleControlAsync) instead of leaking it for the life of the
    // connection.
    //
    // OnOpened/OnFailed run synchronously, directly inside HandleControlAsync
    // as it processes "channel_opened"/"error" -- not as a continuation the
    // awaiting caller's own task resumes on, which (with the TCS below using
    // RunContinuationsAsynchronously, as every other completion signal in
    // this class does) could run arbitrarily later, after the read loop has
    // already moved on to the next frame. That gap is real: a remote command
    // that exits essentially immediately can have its exit_status right
    // behind channel_opened in the same read, and if the new channel isn't
    // in _channels yet by the time that arrives, it's silently dropped --
    // the caller's Completed never resolves. Registering the channel here,
    // as part of handling channel_opened itself, guarantees it's visible to
    // the very next frame the read loop processes.
    private readonly record struct PendingOpen(Action<uint, AgentMessage> OnOpened, Action<Exception> OnFailed);

    private async Task<T> OpenChannelAsync<T>(AgentMessage request, Func<uint, AgentMessage, (T Result, IAgentChannelSink? Sink)> makeResult, CancellationToken cancellationToken)
    {
        var requestId = NextRequestId();
        request.RequestId = requestId;
        var tcs = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingOpens[requestId] = new PendingOpen(
            OnOpened: (channelId, opened) =>
            {
                var (result, sink) = makeResult(channelId, opened);
                if (sink is not null) _channels[channelId] = new AgentChannelDataPump(sink);
                tcs.TrySetResult(result);
            },
            OnFailed: ex => tcs.TrySetException(ex));
        try
        {
            await WriteControlAsync(0, request, cancellationToken).ConfigureAwait(false);
            using var registration = cancellationToken.Register(() => tcs.TrySetCanceled(cancellationToken));
            return await tcs.Task.ConfigureAwait(false);
        }
        finally
        {
            _pendingOpens.TryRemove(requestId, out _);
        }
    }

    internal async Task WriteControlAsync(uint channelId, AgentMessage message, CancellationToken cancellationToken)
    {
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { await MeowshellAgentProtocol.WriteControlAsync(_stdin, channelId, message, cancellationToken).ConfigureAwait(false); }
        finally { _writeLock.Release(); }
    }

    internal async Task SendDataAsync(uint channelId, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { await MeowshellAgentProtocol.WriteDataAsync(_stdin, channelId, data, cancellationToken).ConfigureAwait(false); }
        finally { _writeLock.Release(); }
    }

    private string NextRequestId() => "c" + Interlocked.Increment(ref _nextRequestId).ToString(System.Globalization.CultureInfo.InvariantCulture);

    private async Task RunReadLoopAsync()
    {
        try
        {
            while (true)
            {
                var frame = await MeowshellAgentProtocol.ReadFrameAsync(_stdout, CancellationToken.None).ConfigureAwait(false);
                if (frame is null) break;
                if (frame.Value.Type == MeowshellAgentProtocol.FrameTypeData)
                {
                    await HandleDataAsync(frame.Value.ChannelId, frame.Value.Payload).ConfigureAwait(false);
                    continue;
                }
                // Reject explicitly rather than falling through to JSON
                // parsing: an unrecognized frame type means either the
                // stream is desynced (in which case trusting the rest of
                // this frame's bytes as a length-prefixed boundary is
                // already unsafe) or the agent sent something this build
                // doesn't understand -- either way, a clear protocol error
                // beats silently attempting to parse arbitrary bytes as a
                // control message.
                if (frame.Value.Type != MeowshellAgentProtocol.FrameTypeControl)
                    throw new TailcatException("meowshell agent protocol error", 0, $"unknown frame type {frame.Value.Type}");
                // The null-forgiving deserialize below used to let a literal
                // JSON "null" control frame turn into an unguarded
                // NullReferenceException a few lines later (msg.Msg on a
                // null msg) -- still caught by this method's own try/catch
                // and still faulting the connection (correctly: a malformed
                // control frame means this stream can no longer be trusted
                // to be in sync), but with a confusing exception instead of
                // a clear protocol-error diagnostic.
                var msg = System.Text.Json.JsonSerializer.Deserialize<AgentMessage>(frame.Value.Payload, MeowshellAgentProtocol.JsonOptions)
                    ?? throw new TailcatException("meowshell agent protocol error", 0, "control frame payload was JSON null");
                await HandleControlAsync(frame.Value.ChannelId, msg).ConfigureAwait(false);
            }
            FaultEverything(new TailcatException("meowshell agent exited unexpectedly", 0, _diagnostics.Tail()));
        }
        catch (Exception ex)
        {
            FaultEverything(ex);
        }
    }

    private async Task HandleDataAsync(uint channelId, byte[] payload)
    {
        if (payload.Length == 0) return;
        var stream = payload[0];
        var data = payload.AsMemory(1);
        if (_channels.TryGetValue(channelId, out var sink))
            await sink.OnDataAsync(stream, data).ConfigureAwait(false);
    }

    private async Task HandleControlAsync(uint channelId, AgentMessage msg)
    {
        switch (msg.Msg)
        {
            case "connected":
                _connected.TrySetResult();
                return;
            case "prompt_request":
                var promptTask = Task.Run(() => HandlePromptAsync(msg));
                _promptTasks[promptTask] = 0;
                _ = promptTask.ContinueWith(t => _promptTasks.TryRemove(t, out _), TaskScheduler.Default);
                return;
            case "channel_opened":
                if (msg.RequestId is not null && _pendingOpens.TryRemove(msg.RequestId, out var openedCallbacks))
                {
                    openedCallbacks.OnOpened(channelId, msg);
                    return;
                }
                // Nobody is waiting on this request anymore -- the caller's
                // CancellationToken fired before this response arrived. The
                // agent already created the channel on our behalf; without
                // this, it would leak for the life of the connection.
                _ = WriteControlAsync(channelId, new AgentMessage { Msg = "close_channel" }, CancellationToken.None);
                return;
            case "channel_closed":
                if (_pendingCloses.TryRemove(channelId, out var closedTcs))
                {
                    closedTcs.TrySetResult();
                }
                return;
            case "sftp_result":
                if (msg.RequestId is not null && _pendingRequests.TryRemove(msg.RequestId, out var resultTcs))
                {
                    resultTcs.TrySetResult(msg);
                    return;
                }
                break;
            case "error":
                if (msg.RequestId is not null && _pendingRequests.TryRemove(msg.RequestId, out var errorTcs))
                {
                    errorTcs.TrySetResult(msg);
                    return;
                }
                if (msg.RequestId is not null && _pendingOpens.TryRemove(msg.RequestId, out var openFailedCallbacks))
                {
                    openFailedCallbacks.OnFailed(AgentError(msg, "opening a channel"));
                    return;
                }
                if (channelId == 0)
                {
                    if (!_connected.Task.IsCompleted)
                    {
                        _connected.TrySetException(AgentError(msg, "connecting"));
                        return;
                    }
                    FaultEverything(AgentError(msg, "connection"));
                    return;
                }
                break;
        }

        if (_channels.TryGetValue(channelId, out var sink))
            await sink.OnControlAsync(msg).ConfigureAwait(false);

        // "exit_status" always ends a channel, safe to remove on
        // unconditionally (harmless if Upload/DownloadAsync already did, in
        // their own finally blocks). A per-channel "error" only ends it when
        // the agent explicitly says so (N5, see AgentMessage.EndsChannel and
        // controlMessage.Terminal's own comment on the Go side): some (a
        // failed agent-forwarding setup, a rejected resize) leave the
        // channel alive, others (a shell/exec channel dying unexpectedly
        // with no exit_status to follow) are the only terminal signal that
        // channel ever gets. Removing on every "error" used to silently drop
        // all further data/control traffic for a channel that was actually
        // still running; never removing on one used to leak every channel
        // whose only terminal signal was an "error" for the life of the
        // connection -- nothing else ever removed a shell/exec entry once
        // opened otherwise, on a long-lived connection that opens many short
        // commands.
        if (msg.EndsChannel)
            _channels.TryRemove(channelId, out _);
    }

    private async Task HandlePromptAsync(AgentMessage msg)
    {
        var response = new AgentMessage { Msg = "prompt_response", RequestId = msg.RequestId };
        try
        {
            switch (msg.PromptKind)
            {
                case "host_key":
                    if (HostKeyPromptRequested is { } hostKeyHandler)
                        response.Accept = await hostKeyHandler(new MeowshellHostKeyPrompt(msg.Remote ?? "", msg.Fingerprint ?? ""), _lifetimeCts.Token).ConfigureAwait(false);
                    else
                        response.Cancelled = true;
                    break;
                case "password":
                    if (PasswordRequested is { } passwordHandler)
                        response.Answer = await passwordHandler(msg.Remote ?? "", _lifetimeCts.Token).ConfigureAwait(false);
                    else
                        response.Cancelled = true;
                    break;
                case "passphrase":
                    if (PassphraseRequested is { } passphraseHandler)
                        response.Answer = await passphraseHandler(_lifetimeCts.Token).ConfigureAwait(false);
                    else
                        response.Cancelled = true;
                    break;
                case "keyboard_interactive":
                    if (KeyboardInteractiveRequested is { } kbdHandler)
                        response.Answers = await kbdHandler(new MeowshellKeyboardInteractivePrompt(msg.Remote ?? "", msg.Instruction ?? "", msg.Questions ?? [], msg.Echos ?? []), _lifetimeCts.Token).ConfigureAwait(false);
                    else
                        response.Cancelled = true;
                    break;
                case "sign":
                    if (SignRequested is { } signHandler)
                        response.Signature = await signHandler(new MeowshellSignRequest(msg.KeyId ?? "", msg.Algorithm ?? "", msg.SignData ?? []), _lifetimeCts.Token).ConfigureAwait(false);
                    else
                        response.Cancelled = true;
                    break;
                default:
                    response.Cancelled = true;
                    break;
            }
        }
        catch
        {
            response.Cancelled = true;
        }
        try { await WriteControlAsync(0, response, CancellationToken.None).ConfigureAwait(false); } catch { }
    }

    private static TailcatException AgentError(AgentMessage msg, string doingWhat) =>
        new($"meowshell agent error {doingWhat}", 0, msg.Message ?? "", MeowshellErrorCodeExtensions.Parse(msg.Code));

    private void FaultEverything(Exception ex)
    {
        _connected.TrySetException(ex);
        foreach (var kv in _pendingOpens) kv.Value.OnFailed(ex);
        foreach (var kv in _pendingRequests) kv.Value.TrySetException(ex);
        foreach (var kv in _pendingCloses) kv.Value.TrySetException(ex);
        foreach (var kv in _channels) kv.Value.OnFault(ex);
    }

    private static readonly TimeSpan StopGracePeriod = TimeSpan.FromSeconds(3);

    /// <summary>Ends the connection: closes stdin, then kills the process outright if it has not exited within a few seconds. Safe to call repeatedly, including concurrently.</summary>
    public async Task StopAsync()
    {
        // _stopLock (not just the _stopped bool it guards) makes this safe
        // under concurrent callers: an unsynchronized check-then-set let two
        // overlapping StopAsync/DisposeAsync calls both pass the check
        // before either set it, each independently closing streams and
        // racing DisposeAsync's later _process.Dispose()/_writeLock.Dispose()
        // -- the same pattern TailcatListener.StopAsync already uses.
        await _stopLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_stopped) return;
            _stopped = true;

            // Cancel first, before anything else blocks on shutdown: a
            // PassphraseRequested/HostKeyPromptRequested/... handler stuck
            // waiting on a UI that never completes should hear about
            // cancellation as early as possible, not only once this method
            // has already finished tearing down the process.
            _lifetimeCts.Cancel();

            if (!_process.HasExited)
            {
                try { _process.StandardInput.Close(); } catch { }
                using var grace = new CancellationTokenSource(StopGracePeriod);
                try { await _process.WaitForExitAsync(grace.Token).ConfigureAwait(false); }
                catch (OperationCanceledException)
                {
                    // Kill() only requests termination -- it does not wait for the
                    // OS to actually reap the child, so a caller checking liveness
                    // right after StopAsync returns could still see it as running
                    // (a lingering zombie) if we returned here without waiting.
                    MeowshellProcessControl.TryKill(_process);
                    using var killGrace = new CancellationTokenSource(StopGracePeriod);
                    try { await _process.WaitForExitAsync(killGrace.Token).ConfigureAwait(false); } catch { }
                }
            }
            // Release bounded channel pumps before waiting for the read loop. A
            // consumer that stopped reading may have backpressured that loop; faulting
            // its sink completes the pipe and lets shutdown make progress.
            FaultEverything(new OperationCanceledException("meowshell agent connection stopped"));
            try { await _readLoop.ConfigureAwait(false); } catch { }

            // Best-effort: give already-cancelled prompt tasks a bounded
            // window to actually finish (a well-behaved handler observing
            // _lifetimeCts should return almost immediately) so StopAsync
            // returning means the connection's own background work is
            // quiescent, not just that it's been asked to stop. A handler
            // that ignores cancellation entirely can still outlive this --
            // there is no way to force an application callback to return --
            // but it no longer holds up shutdown indefinitely.
            var pending = _promptTasks.Keys.ToArray();
            if (pending.Length > 0)
            {
                try { await Task.WhenAll(pending).WaitAsync(StopGracePeriod).ConfigureAwait(false); } catch { }
            }
        }
        finally
        {
            _stopLock.Release();
        }
    }

    /// <summary>Ends the connection and releases everything it holds.</summary>
    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        _process.Dispose();
        if (OperatingSystem.IsWindows()) _job?.Dispose();
        _writeLock.Dispose();
        _lifetimeCts.Dispose();
    }
}

internal interface IAgentChannelSink
{
    Task OnDataAsync(byte stream, ReadOnlyMemory<byte> data);
    Task OnControlAsync(AgentMessage msg);
    void OnFault(Exception ex);
}

internal sealed class AgentChannelDataPump : IAgentChannelSink
{
    private readonly record struct QueueItem(bool IsData, byte Stream, ReadOnlyMemory<byte> Data, AgentMessage? Control);

    private readonly IAgentChannelSink _inner;
    private readonly System.Threading.Channels.Channel<QueueItem> _queue =
        System.Threading.Channels.Channel.CreateBounded<QueueItem>(new System.Threading.Channels.BoundedChannelOptions(32)
        {
            SingleReader = true,
            SingleWriter = true,
            FullMode = System.Threading.Channels.BoundedChannelFullMode.Wait,
        });
    private readonly Task _pumpTask;

    // Touched only from OnDataAsync/OnControlAsync, which the read loop
    // (RunReadLoopAsync -> HandleDataAsync/HandleControlAsync) only ever
    // calls one frame at a time on itself -- no concurrent callers, so a
    // plain bool is enough.
    private bool _failed;

    public AgentChannelDataPump(IAgentChannelSink inner)
    {
        _inner = inner;
        _pumpTask = Task.Run(RunAsync);
    }

    private async Task RunAsync()
    {
        try
        {
            await foreach (var item in _queue.Reader.ReadAllAsync().ConfigureAwait(false))
            {
                if (item.IsData)
                {
                    try { await _inner.OnDataAsync(item.Stream, item.Data).ConfigureAwait(false); }
                    catch { }
                }
                else
                {
                    await _inner.OnControlAsync(item.Control!).ConfigureAwait(false);
                }
            }
        }
        catch (Exception ex)
        {
            // _pumpTask (this method) is fire-and-forget -- nothing ever
            // awaits or observes it -- so an exception escaping here (from
            // OnControlAsync; OnDataAsync failures are already swallowed
            // above) would otherwise vanish silently, leaving whatever this
            // channel's sink represents (an upload, a download, a shell)
            // hung forever waiting for a completion signal that will now
            // never arrive. Route it through OnFault so the operation
            // actually fails instead.
            try { _inner.OnFault(ex); } catch { }
        }
    }

    // N1: OnDataAsync/OnControlAsync used to await the bounded queue's own
    // WriteAsync, which blocks once the queue is full (32 items) until this
    // channel's own RunAsync pump has drained some of it. That awaited
    // WriteAsync ran directly inside RunReadLoopAsync's single shared frame
    // loop (via HandleDataAsync/HandleControlAsync), so one channel whose
    // consumer stalled -- a forward's peer that stops reading, an upload's
    // destination file starved for disk I/O, anything downstream of
    // _inner.OnDataAsync -- froze delivery for every other multiplexed
    // channel on the same connection, not just its own. TryWrite never
    // blocks: when the queue is already full, this channel alone is failed
    // (matching the Go agent's own handleData, which does the same "fail
    // only this channel" thing for the mirror-image direction -- see
    // agent.go's own comment on failChannelWrite) instead of the shared read
    // loop ever waiting on it.
    public Task OnDataAsync(byte stream, ReadOnlyMemory<byte> data)
    {
        if (!TryEnqueue(new QueueItem(true, stream, data, null)))
            FailBackpressure();
        return Task.CompletedTask;
    }

    public Task OnControlAsync(AgentMessage msg)
    {
        if (TryEnqueue(new QueueItem(false, 0, ReadOnlyMemory<byte>.Empty, msg)))
        {
            // N5: used to complete on every "error", terminal or not -- a
            // non-terminal one (a failed agent-forwarding setup, a rejected
            // resize) closed this queue for writing regardless, so the very
            // next OnDataAsync/OnControlAsync call for this otherwise
            // perfectly healthy channel would TryWrite against an already-
            // completed channel and fail, wrongly faulting it. EndsChannel
            // is the one shared rule for what actually ends a channel.
            if (msg.EndsChannel)
                _queue.Writer.TryComplete();
        }
        else
        {
            FailBackpressure();
        }
        return Task.CompletedTask;
    }

    private bool TryEnqueue(QueueItem item) => !_failed && _queue.Writer.TryWrite(item);

    private void FailBackpressure()
    {
        if (_failed) return;
        _failed = true;
        OnFault(new TailcatException("channel data is not being consumed fast enough", 0, ""));
    }

    public void OnFault(Exception ex)
    {
        _queue.Writer.TryComplete();
        _inner.OnFault(ex);
    }
}

internal sealed class AgentIgnoreSink : IAgentChannelSink
{
    public Task OnDataAsync(byte stream, ReadOnlyMemory<byte> data) => Task.CompletedTask;
    public Task OnControlAsync(AgentMessage msg) => Task.CompletedTask;
    public void OnFault(Exception ex) { }
}

internal sealed class AgentRequestResponseSink(TaskCompletionSource<int> completion) : IAgentChannelSink
{
    public Task OnDataAsync(byte stream, ReadOnlyMemory<byte> data) => Task.CompletedTask;

    public Task OnControlAsync(AgentMessage msg)
    {
        if (msg.Msg == "exit_status") completion.TrySetResult(msg.ExitCode);
        else if (msg.Msg == "error") completion.TrySetException(new TailcatException("upload failed", 0, msg.Message ?? "", MeowshellErrorCodeExtensions.Parse(msg.Code)));
        return Task.CompletedTask;
    }

    public void OnFault(Exception ex) => completion.TrySetException(ex);
}

internal sealed class AgentDownloadSink : IAgentChannelSink
{
    private readonly Pipe _pipe = new();
    private readonly TaskCompletionSource _completed = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public long TotalBytes { get; set; }
    public Stream Content => _pipe.Reader.AsStream();
    public Task Completed => _completed.Task;

    public async Task OnDataAsync(byte stream, ReadOnlyMemory<byte> data)
    {
        var result = await _pipe.Writer.WriteAsync(data).ConfigureAwait(false);
        if (result.IsCompleted) return;
    }

    public Task OnControlAsync(AgentMessage msg)
    {
        switch (msg.Msg)
        {
            case "exit_status":
                _pipe.Writer.Complete();
                _completed.TrySetResult();
                break;
            case "error":
                var ex = new TailcatException("download failed", 0, msg.Message ?? "", MeowshellErrorCodeExtensions.Parse(msg.Code));
                _pipe.Writer.Complete(ex);
                _completed.TrySetException(ex);
                break;
        }
        return Task.CompletedTask;
    }

    public void OnFault(Exception ex)
    {
        _pipe.Writer.Complete(ex);
        _completed.TrySetException(ex);
    }
}

/// <summary>An open shell or exec channel: <see cref="Output"/>/<see cref="Error"/> stream what the remote wrote to stdout/stderr, <see cref="WriteAsync"/> sends keystrokes/input, and <see cref="Completed"/> resolves with the remote's real exit code.</summary>
public sealed class MeowshellAgentShellChannel : IAgentChannelSink, IAsyncDisposable
{
    private readonly MeowshellAgentConnection _connection;
    private readonly uint _id;
    private readonly Pipe _stdout = new();
    private readonly Pipe _stderr = new();
    private readonly TaskCompletionSource<int> _exitCode = new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal MeowshellAgentShellChannel(MeowshellAgentConnection connection, uint id)
    {
        _connection = connection;
        _id = id;
    }

    /// <summary>Bytes the remote wrote to its stdout (or, with a pseudo-terminal, everything -- most servers merge stderr into the pty stream).</summary>
    public Stream Output => _stdout.Reader.AsStream();

    /// <summary>Bytes the remote wrote to its stderr. Only meaningfully separate from <see cref="Output"/> for a no-pty exec channel.</summary>
    public Stream Error => _stderr.Reader.AsStream();

    /// <summary>Resolves with the remote command's real exit code once the channel ends. Faults with a <see cref="TailcatException"/> on a connection failure.</summary>
    public Task<int> Completed => _exitCode.Task;

    /// <summary>Sends raw bytes -- typically keystrokes -- to the remote session.</summary>
    public Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default) =>
        _connection.SendDataAsync(_id, data, cancellationToken);

    /// <summary>Resizes the pseudo-terminal, taking effect immediately -- unlike <see cref="TailcatSshSession"/>, this can be called any time after the channel opens.</summary>
    public Task ResizeAsync(int columns, int rows, CancellationToken cancellationToken = default) =>
        _connection.WriteControlAsync(_id, new AgentMessage { Msg = "resize", Cols = columns, Rows = rows }, cancellationToken);

    /// <summary>Ends the channel.</summary>
    public Task CloseAsync(CancellationToken cancellationToken = default) =>
        _connection.WriteControlAsync(_id, new AgentMessage { Msg = "close_channel" }, cancellationToken);

    Task IAgentChannelSink.OnDataAsync(byte stream, ReadOnlyMemory<byte> data)
    {
        var pipe = stream == MeowshellAgentProtocol.StreamStderr ? _stderr : _stdout;
        return pipe.Writer.WriteAsync(data).AsTask();
    }

    Task IAgentChannelSink.OnControlAsync(AgentMessage msg)
    {
        switch (msg.Msg)
        {
            case "exit_status":
                _stdout.Writer.Complete();
                _stderr.Writer.Complete();
                _exitCode.TrySetResult(msg.ExitCode);
                break;
            case "error":
                // N5: only a terminal "error" (no exit_status will ever
                // follow for this channel) faults Completed/Output/Error --
                // a non-terminal one (a failed agent-forwarding setup, a
                // rejected resize) reports a problem on a channel that's
                // still running and will still send a real exit_status
                // later; treating it as fatal here used to end this
                // channel's public API over a hiccup that never actually
                // stopped it.
                if (msg.EndsChannel)
                {
                    var ex = new TailcatException("session failed", 0, msg.Message ?? "", MeowshellErrorCodeExtensions.Parse(msg.Code));
                    _stdout.Writer.Complete(ex);
                    _stderr.Writer.Complete(ex);
                    _exitCode.TrySetException(ex);
                }
                break;
        }
        return Task.CompletedTask;
    }

    void IAgentChannelSink.OnFault(Exception ex)
    {
        _stdout.Writer.Complete(ex);
        _stderr.Writer.Complete(ex);
        _exitCode.TrySetException(ex);
    }

    /// <summary>Ends the channel.</summary>
    public async ValueTask DisposeAsync()
    {
        try { await CloseAsync().ConfigureAwait(false); } catch { }
    }
}

/// <summary>A running "-L"/"-R"/"-D" forward, opened by <see cref="MeowshellAgentConnection.OpenLocalForwardAsync"/> and friends.</summary>
public sealed class MeowshellForward : IAsyncDisposable
{
    private readonly MeowshellAgentConnection _connection;
    private readonly uint _id;

    internal MeowshellForward(MeowshellAgentConnection connection, uint id, string boundAddress, string? socksUsername, string? socksPassword)
    {
        _connection = connection;
        _id = id;
        BoundAddress = boundAddress;
        SocksUsername = socksUsername;
        SocksPassword = socksPassword;
    }

    /// <summary>The actual bound listen address -- resolved by the OS when the request asked for port 0.</summary>
    public string BoundAddress { get; }

    /// <summary>The SOCKS5 username a client must present to use this proxy, when opened with auth enabled. Null for a forward with no auth, or for a forward_local/forward_remote channel.</summary>
    public string? SocksUsername { get; }

    /// <summary>The SOCKS5 password paired with <see cref="SocksUsername"/>.</summary>
    public string? SocksPassword { get; }

    /// <summary>Stops the forward: new connections are refused; ones already forwarded finish or fail on their own.</summary>
    public Task CloseAsync(CancellationToken cancellationToken = default) => _connection.CloseForwardAsync(_id, cancellationToken);

    /// <summary>Same as <see cref="CloseAsync(CancellationToken)"/>.</summary>
    public ValueTask DisposeAsync() => new(CloseAsync());
}
