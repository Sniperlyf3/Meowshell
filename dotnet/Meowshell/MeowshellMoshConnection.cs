#nullable enable
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;

namespace Meowshell;

/// <summary>
/// A roaming Mosh terminal bootstrapped through SSH. Authentication and host-key
/// verification use the same callbacks and credential material as
/// <see cref="MeowshellAgentConnection"/>; after the bootstrap succeeds, the
/// SSH connection is released and terminal traffic moves over Mosh/UDP.
/// </summary>
public sealed class MeowshellMoshConnection : IAsyncDisposable
{
    private readonly Process _process;
    private readonly JobObject? _job;
    private readonly Stream _stdin;
    private readonly Stream _stdout;
    private readonly TailcatDiagnostics _diagnostics = new();
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly CancellationTokenSource _lifetimeCts = new();
    private readonly ConcurrentDictionary<Task, byte> _promptTasks = new();
    private readonly TaskCompletionSource _connected = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Task _readLoop;
    private int _stopped;

    private MeowshellMoshConnection(Process process, JobObject? job)
    {
        _process = process;
        _job = job;
        _stdin = process.StandardInput.BaseStream;
        _stdout = process.StandardOutput.BaseStream;
        _readLoop = Task.Run(ReadLoopAsync);
    }

    /// <summary>Diagnostic output from meowshell/tailcat (connection setup, errors). Raised on a background thread.</summary>
    public event Action<string>? Log;

    /// <summary>An unrecognized host key on the SSH bootstrap. No handler (or the handler throwing) rejects the key.</summary>
    public event Func<MeowshellHostKeyPrompt, CancellationToken, Task<bool>>? HostKeyPromptRequested;

    /// <summary>A password is needed. No handler cancels the auth attempt.</summary>
    public event Func<string, CancellationToken, Task<string>>? PasswordRequested;

    /// <summary>An encrypted supplied private key needs its passphrase. No handler cancels the auth attempt.</summary>
    public event Func<CancellationToken, Task<string>>? PassphraseRequested;

    /// <summary>A keyboard-interactive (OTP/PAM) challenge. May fire more than once per connection attempt. No handler cancels the auth attempt.</summary>
    public event Func<MeowshellKeyboardInteractivePrompt, CancellationToken, Task<string[]>>? KeyboardInteractiveRequested;

    /// <summary>A Keystore-backed key needs to sign something, under the algorithm in <see cref="MeowshellSignRequest.Algorithm"/>. No handler refuses the signature.</summary>
    public event Func<MeowshellSignRequest, CancellationToken, Task<byte[]>>? SignRequested;

    /// <summary>Raw terminal output after the Mosh state machine has reconstructed it.</summary>
    public event EventHandler<ReadOnlyMemory<byte>>? OutputReceived;

    /// <summary>Raised when the native Mosh process terminates unexpectedly or its framed protocol fails.</summary>
    public event EventHandler<Exception>? ConnectionLost;

    /// <summary>Whether the SSH bootstrap and Mosh handoff have both completed and the connection has not since been stopped.</summary>
    public bool IsConnected => _connected.Task.IsCompletedSuccessfully && Volatile.Read(ref _stopped) == 0;

    /// <summary>
    /// Authenticates to <paramref name="destination"/> over SSH, starts
    /// <c>mosh-server</c> there, then switches to Mosh's UDP transport.
    /// </summary>
    public static async Task<MeowshellMoshConnection> ConnectAsync(
        TailcatClientOptions options,
        string destination,
        MeowshellAgentConfigureOptions? configure = null,
        string? port = null,
        string? knownHostsPath = null,
        string? proxyUrl = null,
        Action<MeowshellMoshConnection>? configureConnection = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(destination);
        TimeSpanValidation.EnsurePositiveAndBounded(options.Timeout, nameof(options.Timeout));

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
        psi.ArgumentList.Add("mosh-agent");
        if (!string.IsNullOrEmpty(port)) psi.ArgumentList.Add($"-p={port}");
        if (!string.IsNullOrEmpty(knownHostsPath)) psi.ArgumentList.Add($"--known-hosts={knownHostsPath}");
        if (!string.IsNullOrEmpty(proxyUrl)) psi.ArgumentList.Add($"--proxy={proxyUrl}");
        psi.ArgumentList.Add(destination);
        psi.Environment["TAILCAT_BIN"] = tailcat;
        TailcatProcessEnvironment.ApplyHome(psi, options.HomeDirectory);
        if (options.ProcessEnvironmentOverrides is not null)
            foreach (var pair in options.ProcessEnvironmentOverrides)
                psi.Environment[pair.Key] = pair.Value;

        var process = new Process { StartInfo = psi, EnableRaisingEvents = true };
        var job = MeowshellProcessControl.Start(process);
        var connection = new MeowshellMoshConnection(process, job);
        try
        {
            configureConnection?.Invoke(connection);
            process.ErrorDataReceived += (_, e) =>
            {
                if (e.Data is null) return;
                connection._diagnostics.Add(e.Data);
                try { connection.Log?.Invoke(e.Data); } catch { }
            };
            process.BeginErrorReadLine();

            await connection.SendConfigureAsync(configure ?? new MeowshellAgentConfigureOptions(), cancellationToken).ConfigureAwait(false);
            var settled = await Task.WhenAny(connection._connected.Task, Task.Delay(options.Timeout, cancellationToken)).ConfigureAwait(false);
            if (settled != connection._connected.Task)
            {
                cancellationToken.ThrowIfCancellationRequested();
                throw new TailcatException("meowshell Mosh client did not connect in time", 0, connection._diagnostics.Tail(), MeowshellErrorCode.Timeout);
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

    private Task SendConfigureAsync(MeowshellAgentConfigureOptions configure, CancellationToken cancellationToken) =>
        WriteControlAsync(0, new AgentMessage
        {
            Msg = "configure",
            DisableAgent = configure.DisableLocalAgent,
            Keys = configure.PrivateKeys?.ToArray(),
            Certificates = configure.Certificates?.ToArray(),
            KeystoreKeyIds = configure.KeystoreKeyIds?.ToArray(),
            KeystorePublicKeys = configure.KeystorePublicKeys?.ToArray(),
            AgentForwarding = false,
            AllowLegacyKeyAlgorithms = configure.AllowLegacyKeyAlgorithms,
        }, cancellationToken);

    /// <summary>Sends terminal keystrokes to the Mosh session.</summary>
    public async Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        ThrowIfStopped();
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { await MeowshellAgentProtocol.WriteDataAsync(_stdin, 1, data, cancellationToken).ConfigureAwait(false); }
        finally { _writeLock.Release(); }
    }

    /// <summary>Sends a terminal resize to the Mosh server.</summary>
    public Task ResizeAsync(int columns, int rows, CancellationToken cancellationToken = default)
    {
        if (columns <= 0) throw new ArgumentOutOfRangeException(nameof(columns));
        if (rows <= 0) throw new ArgumentOutOfRangeException(nameof(rows));
        if (columns > ushort.MaxValue) throw new ArgumentOutOfRangeException(nameof(columns));
        if (rows > ushort.MaxValue) throw new ArgumentOutOfRangeException(nameof(rows));
        ThrowIfStopped();
        return WriteControlAsync(1, new AgentMessage { Msg = "resize", Cols = columns, Rows = rows }, cancellationToken);
    }

    private async Task WriteControlAsync(uint channelId, AgentMessage message, CancellationToken cancellationToken)
    {
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { await MeowshellAgentProtocol.WriteControlAsync(_stdin, channelId, message, cancellationToken).ConfigureAwait(false); }
        finally { _writeLock.Release(); }
    }

    private async Task ReadLoopAsync()
    {
        Exception? failure = null;
        try
        {
            while (true)
            {
                var frame = await MeowshellAgentProtocol.ReadFrameAsync(_stdout, CancellationToken.None).ConfigureAwait(false);
                if (frame is null) break;
                if (frame.Value.Type == MeowshellAgentProtocol.FrameTypeData)
                {
                    var payload = frame.Value.Payload;
                    if (payload.Length > 0 && payload[0] is MeowshellAgentProtocol.StreamStdout or MeowshellAgentProtocol.StreamStderr)
                        OutputReceived?.Invoke(this, payload.AsMemory(1));
                    continue;
                }
                if (frame.Value.Type != MeowshellAgentProtocol.FrameTypeControl)
                    throw new TailcatException("meowshell Mosh protocol error", 0, $"unknown frame type {frame.Value.Type}");

                var msg = JsonSerializer.Deserialize<AgentMessage>(frame.Value.Payload, MeowshellAgentProtocol.JsonOptions)
                    ?? throw new TailcatException("meowshell Mosh protocol error", 0, "control frame payload was JSON null");
                switch (msg.Msg)
                {
                    case "connected":
                        _connected.TrySetResult();
                        break;
                    case "prompt_request":
                        var promptTask = Task.Run(() => HandlePromptAsync(msg));
                        _promptTasks[promptTask] = 0;
                        _ = promptTask.ContinueWith(t => _promptTasks.TryRemove(t, out _), TaskScheduler.Default);
                        break;
                    case "error":
                        var error = new TailcatException(
                            "meowshell Mosh error",
                            0,
                            msg.Message ?? _diagnostics.Tail(),
                            MeowshellErrorCodeExtensions.Parse(msg.Code));
                        if (!_connected.Task.IsCompleted)
                            _connected.TrySetException(error);
                        else
                            throw error;
                        break;
                }
            }

            if (!_connected.Task.IsCompleted)
                _connected.TrySetException(new TailcatException("meowshell Mosh client exited before connecting", 0, _diagnostics.Tail()));
            else if (Volatile.Read(ref _stopped) == 0)
                failure = new TailcatException("meowshell Mosh client exited unexpectedly", 0, _diagnostics.Tail());
        }
        catch (Exception ex)
        {
            if (!_connected.Task.IsCompleted)
                _connected.TrySetException(ex);
            else if (Volatile.Read(ref _stopped) == 0)
                failure = ex;
        }

        if (failure is not null)
        {
            try { ConnectionLost?.Invoke(this, failure); } catch { }
        }
    }

    private async Task HandlePromptAsync(AgentMessage msg)
    {
        var response = new AgentMessage { Msg = "prompt_response", RequestId = msg.RequestId };
        try
        {
            switch (msg.PromptKind)
            {
                case "host_key" when HostKeyPromptRequested is { } hostKey:
                    response.Accept = await hostKey(new MeowshellHostKeyPrompt(msg.Remote ?? "", msg.Fingerprint ?? ""), _lifetimeCts.Token).ConfigureAwait(false);
                    break;
                case "password" when PasswordRequested is { } password:
                    response.Answer = await password(msg.Remote ?? "", _lifetimeCts.Token).ConfigureAwait(false);
                    break;
                case "passphrase" when PassphraseRequested is { } passphrase:
                    response.Answer = await passphrase(_lifetimeCts.Token).ConfigureAwait(false);
                    break;
                case "keyboard_interactive" when KeyboardInteractiveRequested is { } keyboard:
                    response.Answers = await keyboard(
                        new MeowshellKeyboardInteractivePrompt(msg.Remote ?? "", msg.Instruction ?? "", msg.Questions ?? [], msg.Echos ?? []),
                        _lifetimeCts.Token).ConfigureAwait(false);
                    break;
                case "sign" when SignRequested is { } sign:
                    response.Signature = await sign(
                        new MeowshellSignRequest(msg.KeyId ?? "", msg.Algorithm ?? "", msg.SignData ?? []),
                        _lifetimeCts.Token).ConfigureAwait(false);
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

    private void ThrowIfStopped()
    {
        if (Volatile.Read(ref _stopped) != 0)
            throw new ObjectDisposedException(nameof(MeowshellMoshConnection));
    }

    /// <summary>Ends the connection and releases everything it holds.</summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _stopped, 1) != 0) return;
        _lifetimeCts.Cancel();

        try
        {
            if (!_process.HasExited)
            {
                try { await WriteControlAsync(1, new AgentMessage { Msg = "close_channel" }, CancellationToken.None).ConfigureAwait(false); } catch { }
                try { _process.StandardInput.Close(); } catch { }
                using var grace = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                try { await _process.WaitForExitAsync(grace.Token).ConfigureAwait(false); }
                catch (OperationCanceledException)
                {
                    MeowshellProcessControl.TryKill(_process);
                    using var killGrace = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    try { await _process.WaitForExitAsync(killGrace.Token).ConfigureAwait(false); } catch { }
                }
            }
            try { await _readLoop.ConfigureAwait(false); } catch { }
            var pending = _promptTasks.Keys.ToArray();
            if (pending.Length > 0)
            {
                try { await Task.WhenAll(pending).WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false); } catch { }
            }
        }
        finally
        {
            _process.Dispose();
            if (OperatingSystem.IsWindows()) _job?.Dispose();
            _writeLock.Dispose();
            _lifetimeCts.Dispose();
        }
    }
}
