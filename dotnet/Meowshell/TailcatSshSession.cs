#nullable enable

namespace Meowshell;

/// <summary>An interactive session over a tailcat address, with a pseudo-terminal by default -- native (no system ssh client involved) unlike <see cref="TailcatClient.SshAsync"/>. A thin wrapper around its own dedicated <see cref="MeowshellAgentConnection"/> and one shell/exec channel on it.</summary>
public sealed class TailcatSshSession : IAsyncDisposable
{
    private readonly MeowshellAgentConnection _connection;
    private readonly MeowshellAgentShellChannel _channel;
    private readonly TaskCompletionSource _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly SemaphoreSlim _stopLock = new(1, 1);
    private bool _stopped;

    /// <summary>Raw bytes the remote pseudo-terminal produced. Do not read this concurrently from more than one place.</summary>
    public Stream Output => _channel.Output;

    /// <summary>Resolves when the session ends: successfully after <see cref="StopAsync"/>, or when a session running a command finishes on its own. Faults with a <see cref="TailcatException"/> if the connection is lost unexpectedly.</summary>
    public Task Completed => _exited.Task;

    /// <summary>Diagnostic output from meowshell/tailcat (connection setup, errors). Raised on a background thread.</summary>
    public event Action<string>? Log;

    private TailcatSshSession(MeowshellAgentConnection connection, MeowshellAgentShellChannel channel)
    {
        _connection = connection;
        _channel = channel;
        connection.Log += line => Log?.Invoke(line);
        _ = ObserveCompletionAsync();
    }

    private async Task ObserveCompletionAsync()
    {
        try
        {
            await _channel.Completed.ConfigureAwait(false);
            _exited.TrySetResult();
        }
        catch (Exception ex)
        {
            if (_stopped) _exited.TrySetResult();
            else _exited.TrySetException(ex);
        }
    }

    /// <summary>Opens a session against <paramref name="destination"/>: an interactive pseudo-terminal shell by default, or <paramref name="command"/> instead if given.</summary>
    /// <param name="options">Where the binaries live and how to reach the server.</param>
    /// <param name="destination">A tailcat address, or a DNS name carrying a "tailcat=" TXT record.</param>
    /// <param name="command">Run this instead of an interactive shell, e.g. <c>["ls", "-la"]</c>. Elements are joined with plain spaces -- no quoting is added.</param>
    /// <param name="columns">Pseudo-terminal width.</param>
    /// <param name="rows">Pseudo-terminal height.</param>
    /// <param name="requestPty">Whether to allocate a pseudo-terminal. Defaults to true for an interactive shell.</param>
    /// <param name="term">TERM to request for the pseudo-terminal. Defaults to "xterm-256color".</param>
    /// <param name="port">The server's SSH service port, when it isn't 22.</param>
    /// <param name="onLog">Called for each line of meowshell/tailcat's own diagnostic output, in addition to <see cref="Log"/>, starting with the connection setup's own lines -- including those of a connection that fails before this method returns.</param>
    /// <param name="cancellationToken">Cancels waiting for the connection to settle; does not cancel or stop the session itself once returned.</param>
    /// <exception cref="TailcatException">The session failed to connect within <see cref="TailcatClientOptions.Timeout"/>.</exception>
    public static async Task<TailcatSshSession> ConnectAsync(
        TailcatClientOptions options, string destination, IReadOnlyList<string>? command = null,
        int columns = 80, int rows = 24, bool? requestPty = null, string? term = null, string? port = null,
        Action<string>? onLog = null, CancellationToken cancellationToken = default)
    {
        // Subscribed through configureConnection, not on the returned object:
        // ConnectAsync does not return until the handshake is over, so a
        // subscriber attached afterwards misses every diagnostic line the
        // connection setup produced -- which is all of them, and the only
        // ones that exist at all on a connection that then fails, since that
        // throws before a caller ever gets a reference to attach to. A
        // caller passing onLog to find out why a connection is not working
        // used to receive nothing whatsoever.
        var connection = await MeowshellAgentConnection.ConnectAsync(
            options, destination, port: port,
            configureConnection: onLog is null ? null : connection => connection.Log += onLog,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        try
        {
            var channel = command is null
                ? await connection.OpenShellAsync(columns, rows, term, requestPty, cancellationToken).ConfigureAwait(false)
                : await connection.OpenExecAsync(command, requestPty, columns, rows, term, cancellationToken).ConfigureAwait(false);
            return new TailcatSshSession(connection, channel);
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Sends raw bytes -- typically keystrokes -- to the remote session.</summary>
    public Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default) =>
        _channel.WriteAsync(data, cancellationToken);

    /// <summary>Ends the session: closes the channel (like Ctrl+D, letting a shell exit on its own), then tears down its dedicated connection. Safe to call repeatedly.</summary>
    public async Task StopAsync()
    {
        await _stopLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_stopped) return;
            _stopped = true;

            try { await _channel.DisposeAsync().ConfigureAwait(false); } catch { }
            await _connection.StopAsync().ConfigureAwait(false);
            _exited.TrySetResult();
        }
        finally
        {
            _stopLock.Release();
        }
    }

    /// <summary>Ends the session and releases everything it holds.</summary>
    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        _stopLock.Dispose();
        await _connection.DisposeAsync().ConfigureAwait(false);
    }
}
