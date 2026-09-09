#nullable enable
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Meowshell;

/// <summary>Configuration for a <see cref="MeowshellPortForward"/>.</summary>
public sealed record MeowshellPortForwardOptions
{
    /// <summary>Directory holding the meowshell and tailcat binaries. See <see cref="MeowshellOptions.BinaryDirectory"/>.</summary>
    public string? BinaryDirectory { get; init; }

    /// <summary>See <see cref="MeowshellOptions.Naming"/>.</summary>
    public BinaryNaming Naming { get; init; } = BinaryNaming.ForCurrentPlatform();

    /// <summary>A writable HOME. Use the app's FilesDir.</summary>
    public required string HomeDirectory { get; init; }

    /// <summary>The tailcat address to forward to.</summary>
    public required string Address { get; init; }

    /// <summary>
    /// At least one port mapping: a bare port (same local and remote port),
    /// <c>local:remote</c>, or <c>local:remote-ip:remote-port</c> (the
    /// server must be running as an exit node). A local port of 0 asks the
    /// OS for a free port; each listener prints its address once it is
    /// listening.
    /// </summary>
    public required IReadOnlyList<string> Mappings { get; init; }

    /// <summary>
    /// Listen address, used as the local address for a mapping that only
    /// specifies a port. Empty means tailcat's own default (127.0.0.1).
    /// Passed to tailcat's own <c>--bind</c>.
    /// </summary>
    public string? Bind { get; init; }

    /// <summary>tailcat client key name or path (see 'tailcat genkey').</summary>
    public string? ClientKey { get; init; }

    /// <summary>See <see cref="MeowshellOptions.DerpMapUrl"/>.</summary>
    public string? DerpMapUrl { get; init; }

    /// <summary>See <see cref="MeowshellOptions.Verbose"/>.</summary>
    public bool Verbose { get; init; }

    /// <summary>How long SIGTERM gets before SIGKILL.</summary>
    public TimeSpan GracePeriod { get; init; } = TimeSpan.FromSeconds(3);
}

/// <summary>
/// Forwards local TCP ports to a tailcat server, until stopped. A
/// long-lived local listener, so -- like <see cref="MeowshellServer"/> --
/// it goes through meowshell rather than a bare tailcat, to inherit the
/// same crash backstop (Windows job object here; PR_SET_PDEATHSIG is armed
/// inside meowshell on Unix, before it execs tailcat).
/// </summary>
public sealed class MeowshellPortForward : IAsyncDisposable
{
    private const int SIGTERM = 15;

    [DllImport("libc", SetLastError = true)]
    private static extern int kill(int pid, int sig);

    private readonly Process _process;
    private readonly TimeSpan _gracePeriod;
    private readonly TaskCompletionSource _exited =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly SemaphoreSlim _stopLock = new(1, 1);
    private readonly TailcatDiagnostics _diagnostics = new();
    private JobObject? _job;
    private bool _stopped;

    /// <summary>
    /// Completes when the process has exited. Succeeds after a
    /// <see cref="StopAsync"/> call; faults with a <see cref="TailcatException"/>
    /// if the process dies on its own first.
    /// </summary>
    public Task Completed => _exited.Task;

    /// <summary>
    /// Diagnostic output from tailcat, including each listener's bound
    /// address once it is listening (most useful for a mapping that asked
    /// for an OS-assigned port). Raised on a background thread.
    /// </summary>
    public event Action<string>? Log;

    private MeowshellPortForward(Process process, TimeSpan gracePeriod)
    {
        _process = process;
        _gracePeriod = gracePeriod;
    }

    /// <summary>Starts forwarding.</summary>
    /// <exception cref="ArgumentException">No mappings were given.</exception>
    /// <exception cref="FileNotFoundException">A native binary is missing.</exception>
    public static async Task<MeowshellPortForward> StartAsync(
        MeowshellPortForwardOptions options, Action<string>? onLog = null)
    {
        if (options.Mappings.Count == 0)
        {
            throw new ArgumentException("At least one port mapping is required.", nameof(options));
        }

        var (meowshell, _) = MeowshellBinaries.Locate(options.BinaryDirectory, options.Naming);
        Directory.CreateDirectory(options.HomeDirectory);

        var psi = new ProcessStartInfo
        {
            FileName = meowshell,
            WorkingDirectory = options.HomeDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("forward");
        if (!string.IsNullOrEmpty(options.Bind))
            psi.ArgumentList.Add($"--bind={options.Bind}");
        if (!string.IsNullOrEmpty(options.ClientKey))
            psi.ArgumentList.Add($"--key={options.ClientKey}");
        if (!string.IsNullOrEmpty(options.DerpMapUrl))
            psi.ArgumentList.Add($"--derpmap-url={options.DerpMapUrl}");
        if (options.Verbose)
            psi.ArgumentList.Add("--verbose");
        psi.ArgumentList.Add(options.Address);
        foreach (var mapping in options.Mappings)
            psi.ArgumentList.Add(mapping);
        psi.Environment["HOME"] = options.HomeDirectory;

        var process = new Process { StartInfo = psi, EnableRaisingEvents = true };
        var forward = new MeowshellPortForward(process, options.GracePeriod);
        try
        {
            process.Start();
            if (OperatingSystem.IsWindows())
                forward._job = JobObject.Wrap(process);

            process.Exited += async (_, _) =>
            {
                // See MeowshellServer's own Exited handler for why
                // WaitForExitAsync has to run before _diagnostics is safe
                // to read: Exited can fire before BeginErrorReadLine's
                // async reads finish delivering the last lines.
                await process.WaitForExitAsync().ConfigureAwait(false);
                if (forward._stopped) forward._exited.TrySetResult();
                else forward._exited.TrySetException(new TailcatException(
                    "tailcat exited unexpectedly", process.ExitCode, forward._diagnostics.Tail()));
            };
            process.OutputDataReceived += (_, e) => { if (e.Data is not null) { forward.Log?.Invoke(e.Data); onLog?.Invoke(e.Data); } };
            process.ErrorDataReceived += (_, e) =>
            {
                if (e.Data is null) return;
                forward._diagnostics.Add(e.Data);
                forward.Log?.Invoke(e.Data);
                onLog?.Invoke(e.Data);
            };
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            return forward;
        }
        catch
        {
            await forward.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Stops forwarding: SIGTERM, then SIGKILL if it does not go quietly. Safe to call repeatedly.</summary>
    public async Task StopAsync()
    {
        await _stopLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_stopped) return;
            _stopped = true;

            if (!_process.HasExited)
            {
                MeowshellProcessControl.RequestStop(_process, kill, SIGTERM);
                using var grace = new CancellationTokenSource(_gracePeriod);
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

    /// <summary>Stops forwarding and releases everything it holds.</summary>
    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        _stopLock.Dispose();
        _process.Dispose();
        if (OperatingSystem.IsWindows())
        {
            _job?.Dispose();
        }
    }
}
