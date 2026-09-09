#nullable enable
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Meowshell;

/// <summary>
/// The process lifecycle shared by every long-lived meowshell-spawned
/// listener (<see cref="MeowshellServer"/>, <see cref="MeowshellSocksProxy"/>,
/// <see cref="MeowshellPortForward"/>): captures stderr regardless of
/// whether anything is listening, completes or faults <see cref="Completed"/>
/// depending on whether the exit was requested, and stops the process
/// (SIGTERM, then SIGKILL if that doesn't land in time).
/// </summary>
internal sealed class TailcatListener : IAsyncDisposable
{
    private const int SIGTERM = 15;

    [DllImport("libc", SetLastError = true)]
    private static extern int kill(int pid, int sig);

    private readonly TimeSpan _gracePeriod;
    private readonly TaskCompletionSource _exited =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly SemaphoreSlim _stopLock = new(1, 1);
    private readonly TailcatDiagnostics _diagnostics = new();
    private JobObject? _job;
    private bool _stopped;

    /// <summary>The underlying process, for a caller that needs it directly (MeowshellServer polls it for an early exit before it has an address to report).</summary>
    public Process Process { get; }

    /// <summary>
    /// Completes when the process has exited. Succeeds after a
    /// <see cref="StopAsync"/> call; faults with a <see cref="TailcatException"/>
    /// if the process dies on its own first (a crash, an OOM kill).
    /// </summary>
    public Task Completed => _exited.Task;

    /// <summary>Diagnostic output from tailcat. Raised on a background thread.</summary>
    public event Action<string>? Log;

    private TailcatListener(Process process, TimeSpan gracePeriod)
    {
        Process = process;
        _gracePeriod = gracePeriod;
    }

    /// <summary>
    /// Starts <paramref name="process"/> (already configured with a
    /// <see cref="ProcessStartInfo"/> that redirects stdout/stderr) and
    /// wires up output capture and the crash-fault <see cref="Completed"/>
    /// semantics. On Windows, also assigns the process to a kill-on-close
    /// job object, so it doesn't outlive a crashed host even if
    /// <see cref="StopAsync"/> is never called.
    /// </summary>
    public static TailcatListener Start(Process process, TimeSpan gracePeriod, Action<string>? onLog)
    {
        process.EnableRaisingEvents = true;
        var listener = new TailcatListener(process, gracePeriod);
        process.Start();
        if (OperatingSystem.IsWindows())
        {
            listener._job = JobObject.Wrap(process);
        }

        process.Exited += async (_, _) =>
        {
            // Exited can fire before the async reads behind
            // BeginErrorReadLine finish delivering the last lines;
            // WaitForExitAsync (unlike the Exited event itself) is
            // documented to synchronize with that, so _diagnostics is
            // complete by the time this reads it.
            await process.WaitForExitAsync().ConfigureAwait(false);
            if (listener._stopped) listener._exited.TrySetResult();
            else listener._exited.TrySetException(new TailcatException(
                "tailcat exited unexpectedly", process.ExitCode, listener._diagnostics.Tail()));
        };
        process.OutputDataReceived += (_, e) => { if (e.Data is not null) { listener.Log?.Invoke(e.Data); onLog?.Invoke(e.Data); } };
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is null) return;
            listener._diagnostics.Add(e.Data);
            listener.Log?.Invoke(e.Data);
            onLog?.Invoke(e.Data);
        };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        return listener;
    }

    /// <summary>
    /// Throws a <see cref="TailcatException"/> if the process has already
    /// exited, first synchronizing with the diagnostics stream the same
    /// way the <see cref="Completed"/> fault path does -- for a caller
    /// (MeowshellServer) polling for an early exit before it considers
    /// itself started.
    /// </summary>
    public async Task ThrowIfExitedAsync(string summary, CancellationToken cancellationToken = default)
    {
        if (!Process.HasExited) return;
        await Process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        throw new TailcatException(summary, Process.ExitCode, _diagnostics.Tail());
    }

    /// <summary>Stops the process: SIGTERM, then SIGKILL if it does not go quietly. Safe to call repeatedly.</summary>
    public async Task StopAsync()
    {
        await _stopLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_stopped) return;
            _stopped = true;

            if (!Process.HasExited)
            {
                MeowshellProcessControl.RequestStop(Process, kill, SIGTERM);
                using var grace = new CancellationTokenSource(_gracePeriod);
                try
                {
                    await Process.WaitForExitAsync(grace.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    MeowshellProcessControl.TryKill(Process);
                }
            }
            _exited.TrySetResult();
        }
        finally
        {
            _stopLock.Release();
        }
    }

    /// <summary>Stops the process and releases everything it holds.</summary>
    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        _stopLock.Dispose();
        Process.Dispose();
        if (OperatingSystem.IsWindows())
        {
            _job?.Dispose();
        }
    }
}
