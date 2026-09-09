#nullable enable
using System.Diagnostics;

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
/// This only carries bytes: read <see cref="Output"/> for whatever the
/// remote pseudo-terminal renders and write keystrokes with
/// <see cref="WriteAsync"/>. Interpreting that output (ANSI/VT100 escape
/// sequences, an actual terminal widget) is entirely the caller's own
/// responsibility. The pseudo-terminal's size is fixed for the life of the
/// session -- set at <see cref="ConnectAsync"/> and not resizable
/// afterwards.
/// </summary>
public sealed class TailcatSshSession : IAsyncDisposable
{
    private readonly Process _process;
    private readonly TaskCompletionSource _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly SemaphoreSlim _stopLock = new(1, 1);
    private readonly TailcatDiagnostics _diagnostics = new();
    private bool _stopped;

    /// <summary>
    /// Raw bytes the remote pseudo-terminal produced. Do not read this
    /// concurrently from more than one place.
    /// </summary>
    public Stream Output { get; }

    /// <summary>
    /// Resolves when the session ends: successfully after
    /// <see cref="StopAsync"/>, or when a session running a command (not an
    /// interactive shell) finishes on its own. Faults with a
    /// <see cref="TailcatException"/> if the process exits unexpectedly
    /// (a crash, a lost connection).
    /// </summary>
    public Task Completed => _exited.Task;

    /// <summary>Diagnostic output from meowshell/tailcat (connection setup, errors). Raised on a background thread.</summary>
    public event Action<string>? Log;

    private TailcatSshSession(Process process)
    {
        _process = process;
        Output = process.StandardOutput.BaseStream;
    }

    /// <summary>
    /// Opens a session against <paramref name="destination"/>: an
    /// interactive pseudo-terminal shell by default, or
    /// <paramref name="command"/> instead if given (still with a
    /// pseudo-terminal, unless <paramref name="requestPty"/> is set false).
    /// Routed through meowshell's own "connect" (never a system ssh
    /// client), the same subprocess bridge <see cref="TailcatClient.CpAsync(TailcatClientOptions,TailcatPath,TailcatPath,bool,bool,string?)"/>
    /// uses.
    /// </summary>
    /// <param name="options">Where the binaries live and how to reach the server.</param>
    /// <param name="destination">A tailcat address, or a DNS name carrying a "tailcat=" TXT record.</param>
    /// <param name="command">Run this instead of an interactive shell, e.g. <c>["ls", "-la"]</c>. Each element is sent to the remote shell as one shell-quoted token.</param>
    /// <param name="columns">Pseudo-terminal width.</param>
    /// <param name="rows">Pseudo-terminal height.</param>
    /// <param name="requestPty">Whether to allocate a pseudo-terminal. Defaults to true for an interactive shell (no <paramref name="command"/>); pass true explicitly to also get one for a command.</param>
    /// <param name="term">TERM to request for the pseudo-terminal. Defaults to "xterm-256color".</param>
    /// <param name="port">The server's SSH service port, when it isn't 22.</param>
    /// <param name="onLog">Called for each line of meowshell/tailcat's own diagnostic output, in addition to <see cref="Log"/>.</param>
    /// <param name="cancellationToken">Cancels waiting for the connection to settle (see the timeout behavior below); does not cancel or stop the session itself once returned.</param>
    /// <exception cref="TailcatException">The session failed to connect within <see cref="TailcatClientOptions.Timeout"/> (a bad address, a handshake failure, a lost connection). A session that is still connecting when the timeout elapses is returned rather than treated as a failure -- only a fault that surfaces within the window is.</exception>
    public static async Task<TailcatSshSession> ConnectAsync(
        TailcatClientOptions options, string destination, IReadOnlyList<string>? command = null,
        int columns = 80, int rows = 24, bool? requestPty = null, string? term = null, string? port = null,
        Action<string>? onLog = null, CancellationToken cancellationToken = default)
    {
        var (meowshell, tailcat) = MeowshellBinaries.Locate(options.BinaryDirectory, options.Naming);
        Directory.CreateDirectory(options.HomeDirectory);
        var psi = new ProcessStartInfo(meowshell)
        {
            WorkingDirectory = options.HomeDirectory,
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("connect");
        if (requestPty ?? true) psi.ArgumentList.Add("-t");
        psi.ArgumentList.Add($"--cols={columns}");
        psi.ArgumentList.Add($"--rows={rows}");
        if (!string.IsNullOrEmpty(term))
            psi.ArgumentList.Add($"--term={term}");
        if (!string.IsNullOrEmpty(port))
            psi.ArgumentList.Add($"-p={port}");
        if (!string.IsNullOrEmpty(options.DerpMapUrl))
            psi.ArgumentList.Add($"--derpmap-url={options.DerpMapUrl}");
        if (options.Verbose)
            psi.ArgumentList.Add("--verbose");
        psi.ArgumentList.Add(destination);
        if (command is not null)
            foreach (var token in command) psi.ArgumentList.Add(token);

        // meowshell looks for a sibling file literally named "tailcat"; under
        // NativeLibraryDir everything is lib*.so, so point it at the binary.
        psi.Environment["TAILCAT_BIN"] = tailcat;
        psi.Environment["HOME"] = options.HomeDirectory;

        var process = new Process { StartInfo = psi, EnableRaisingEvents = true };
        MeowshellProcessControl.Start(process);
        // StandardOutput throws until the process has actually started, so
        // this has to come after Start -- unlike TailcatListener, which
        // never touches the streams directly and so has no such ordering
        // requirement.
        var session = new TailcatSshSession(process);

        process.Exited += async (_, _) =>
        {
            // Exited can fire before the async reads behind
            // BeginErrorReadLine finish delivering the last lines;
            // WaitForExitAsync (unlike the Exited event itself) is
            // documented to synchronize with that, so _diagnostics is
            // complete by the time this reads it.
            await process.WaitForExitAsync().ConfigureAwait(false);
            if (session._stopped || process.ExitCode == 0) session._exited.TrySetResult();
            else session._exited.TrySetException(new TailcatException(
                "meowshell connect exited unexpectedly", process.ExitCode, session._diagnostics.Tail()));
        };
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is null) return;
            session._diagnostics.Add(e.Data);
            session.Log?.Invoke(e.Data);
            onLog?.Invoke(e.Data);
        };
        process.BeginErrorReadLine();

        // Fails fast on an immediate problem (a malformed address, a
        // handshake failure -- these surface in well under a second) without
        // capping how long a genuinely slow-but-working connection can take:
        // only a fault that lands inside the window turns into ConnectAsync
        // throwing. A command that legitimately finishes within the window
        // is not treated as a failure, and a still-connecting or
        // still-running session past the window is returned as-is.
        var settled = await Task.WhenAny(
            session.Completed, Task.Delay(options.Timeout, cancellationToken)).ConfigureAwait(false);
        if (settled == session.Completed && session.Completed.IsFaulted)
        {
            await session.Completed.ConfigureAwait(false);
        }
        return session;
    }

    /// <summary>Sends raw bytes -- typically keystrokes -- to the remote session.</summary>
    public Task WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default) =>
        _process.StandardInput.BaseStream.WriteAsync(data, cancellationToken).AsTask();

    private static readonly TimeSpan StopGracePeriod = TimeSpan.FromSeconds(3);

    /// <summary>
    /// Ends the session: closes stdin (like Ctrl+D, letting a shell exit on
    /// its own), then kills the process outright if it has not exited
    /// within a few seconds. Safe to call repeatedly.
    /// </summary>
    public async Task StopAsync()
    {
        await _stopLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_stopped) return;
            _stopped = true;

            if (!_process.HasExited)
            {
                try { _process.StandardInput.Close(); } catch { /* already gone */ }
                using var grace = new CancellationTokenSource(StopGracePeriod);
                try
                {
                    await _process.WaitForExitAsync(grace.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    MeowshellProcessControl.TryKill(_process);
                }
            }
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
        _process.Dispose();
    }
}
