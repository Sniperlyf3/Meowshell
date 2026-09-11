#nullable enable
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Meowshell;

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

    public Process Process { get; }

    public Task Completed => _exited.Task;

    public event Action<string>? Log;

    private TailcatListener(Process process, TimeSpan gracePeriod)
    {
        Process = process;
        _gracePeriod = gracePeriod;
    }

    public static TailcatListener Start(Process process, TimeSpan gracePeriod, Action<string>? onLog)
    {
        process.EnableRaisingEvents = true;
        var listener = new TailcatListener(process, gracePeriod);
        // Subscribe before Start: a malformed command can exit quickly enough
        // that registering afterwards misses Exited and leaves Completed hung.
        process.Exited += async (_, _) =>
        {
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
        MeowshellProcessControl.Start(process);
        if (OperatingSystem.IsWindows())
        {
            listener._job = JobObject.Wrap(process);
        }
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        return listener;
    }

    public async Task ThrowIfExitedAsync(string summary, CancellationToken cancellationToken = default)
    {
        if (!Process.HasExited) return;
        await Process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        throw new TailcatException(summary, Process.ExitCode, _diagnostics.Tail());
    }

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
