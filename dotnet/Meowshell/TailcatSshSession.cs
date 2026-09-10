#nullable enable

namespace Meowshell;

/// <summary>
/// An interactive session over a tailcat address, with a pseudo-terminal by
/// default -- native (no system ssh client involved, on any platform)
/// unlike <see cref="TailcatClient.SshAsync"/>, which shells out to one and
/// inherits the caller's own console. That makes SshAsync the simpler
/// choice for a CLI app that already has a real console to hand it, and
/// this the one for anywhere there is no such console at all (an Android
/// app being the main case) or that wants programmatic control over the
/// session instead.
///
/// A thin wrapper around its own dedicated <see cref="MeowshellAgentConnection"/>
/// and one shell/exec channel on it -- one login, one process, exactly as
/// before, just built on the same daemon <see cref="MeowshellAgentConnection"/>
/// uses directly instead of "meowshell connect"'s separate one-shot
/// implementation. Reach for <see cref="MeowshellAgentConnection"/> itself
/// instead when a shell, file transfer, and a forward all need to share one
/// login, or live resize matters (this session's pseudo-terminal size is
/// fixed for its life, set at <see cref="ConnectAsync"/>).
///
/// This only carries bytes: read <see cref="Output"/> for whatever the
/// remote pseudo-terminal renders and write keystrokes with
/// <see cref="WriteAsync"/>. Interpreting that output (ANSI/VT100 escape
/// sequences, an actual terminal widget) is entirely the caller's own
/// responsibility.
/// </summary>
public sealed class TailcatSshSession : IAsyncDisposable
{
    private readonly MeowshellAgentConnection _connection;
    private readonly MeowshellAgentShellChannel _channel;
    private readonly TaskCompletionSource _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly SemaphoreSlim _stopLock = new(1, 1);
    private bool _stopped;

    /// <summary>
    /// Raw bytes the remote pseudo-terminal produced. Do not read this
    /// concurrently from more than one place.
    /// </summary>
    public Stream Output => _channel.Output;

    /// <summary>
    /// Resolves when the session ends: successfully after
    /// <see cref="StopAsync"/>, or when a session running a command (not an
    /// interactive shell) finishes on its own. Faults with a
    /// <see cref="TailcatException"/> if the connection is lost unexpectedly.
    /// </summary>
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
            // A fault here is also the normal shape of a deliberate
            // StopAsync (closing the connection faults every channel on
            // it -- see MeowshellAgentConnection.FaultEverything), not
            // just an unexpected connection loss; _stopped tells them
            // apart the same way the old process-per-session
            // implementation's Exited handler used it.
            if (_stopped) _exited.TrySetResult();
            else _exited.TrySetException(ex);
        }
    }

    /// <summary>
    /// Opens a session against <paramref name="destination"/>: an
    /// interactive pseudo-terminal shell by default, or
    /// <paramref name="command"/> instead if given (still with a
    /// pseudo-terminal, unless <paramref name="requestPty"/> is set false).
    /// </summary>
    /// <param name="options">Where the binaries live and how to reach the server.</param>
    /// <param name="destination">A tailcat address, or a DNS name carrying a "tailcat=" TXT record.</param>
    /// <param name="command">Run this instead of an interactive shell, e.g. <c>["ls", "-la"]</c>. Elements are joined with plain spaces, the same as a real ssh client sends a trailing command line -- no quoting is added, so an element that must survive as one word remotely (e.g. <c>["sh", "-c", "exit 42"]</c>'s last element) needs its own quotes if it contains spaces.</param>
    /// <param name="columns">Pseudo-terminal width.</param>
    /// <param name="rows">Pseudo-terminal height.</param>
    /// <param name="requestPty">Whether to allocate a pseudo-terminal. Defaults to true for an interactive shell (no <paramref name="command"/>); pass true explicitly to also get one for a command.</param>
    /// <param name="term">TERM to request for the pseudo-terminal. Defaults to "xterm-256color".</param>
    /// <param name="port">The server's SSH service port, when it isn't 22.</param>
    /// <param name="onLog">Called for each line of meowshell/tailcat's own diagnostic output, in addition to <see cref="Log"/>.</param>
    /// <param name="cancellationToken">Cancels waiting for the connection to settle; does not cancel or stop the session itself once returned.</param>
    /// <exception cref="TailcatException">The session failed to connect within <see cref="TailcatClientOptions.Timeout"/> (a bad address, a handshake failure, a lost connection).</exception>
    public static async Task<TailcatSshSession> ConnectAsync(
        TailcatClientOptions options, string destination, IReadOnlyList<string>? command = null,
        int columns = 80, int rows = 24, bool? requestPty = null, string? term = null, string? port = null,
        Action<string>? onLog = null, CancellationToken cancellationToken = default)
    {
        var connection = await MeowshellAgentConnection.ConnectAsync(
            options, destination, port: port, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (onLog is not null) connection.Log += onLog;

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

    /// <summary>
    /// Ends the session: closes the channel (like Ctrl+D, letting a shell
    /// exit on its own), then tears down its dedicated connection. Safe to
    /// call repeatedly.
    /// </summary>
    public async Task StopAsync()
    {
        await _stopLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_stopped) return;
            _stopped = true;

            try { await _channel.DisposeAsync().ConfigureAwait(false); } catch { /* connection already gone */ }
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
