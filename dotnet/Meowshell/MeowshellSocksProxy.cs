#nullable enable
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Meowshell;

/// <summary>Configuration for a <see cref="MeowshellSocksProxy"/>.</summary>
public sealed record MeowshellSocksOptions
{
    /// <summary>Directory holding the meowshell and tailcat binaries. See <see cref="MeowshellOptions.BinaryDirectory"/>.</summary>
    public string? BinaryDirectory { get; init; }

    /// <summary>See <see cref="MeowshellOptions.Naming"/>.</summary>
    public BinaryNaming Naming { get; init; } = BinaryNaming.ForCurrentPlatform();

    /// <summary>A writable HOME. Use the app's FilesDir.</summary>
    public required string HomeDirectory { get; init; }

    /// <summary>
    /// SOCKS5 proxy listen <c>[address]:port</c>; a bare port means
    /// localhost, a bare address means an OS-assigned port. Empty lets
    /// tailcat pick its own default. Passed to tailcat's own
    /// <c>--listen</c>.
    /// </summary>
    public string? Listen { get; init; }

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
/// Runs a SOCKS5 proxy that dials tailcat servers, until stopped. A
/// long-lived local listener, so -- like <see cref="MeowshellServer"/> --
/// it goes through meowshell rather than a bare tailcat, to inherit the
/// same crash backstop (Windows job object here; PR_SET_PDEATHSIG is armed
/// inside meowshell on Unix, before it execs tailcat).
/// </summary>
public sealed class MeowshellSocksProxy : IAsyncDisposable
{
    private const int SIGTERM = 15;

    [DllImport("libc", SetLastError = true)]
    private static extern int kill(int pid, int sig);

    private readonly Process _process;
    private readonly TimeSpan _gracePeriod;
    private readonly TaskCompletionSource _exited =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly SemaphoreSlim _stopLock = new(1, 1);
    private JobObject? _job;
    private bool _stopped;

    /// <summary>Completes when the process has exited, however it ended.</summary>
    public Task Completed => _exited.Task;

    /// <summary>Diagnostic output from tailcat. Raised on a background thread.</summary>
    public event Action<string>? Log;

    private MeowshellSocksProxy(Process process, TimeSpan gracePeriod)
    {
        _process = process;
        _gracePeriod = gracePeriod;
    }

    /// <summary>Starts the proxy.</summary>
    /// <exception cref="FileNotFoundException">A native binary is missing.</exception>
    public static async Task<MeowshellSocksProxy> StartAsync(
        MeowshellSocksOptions options, Action<string>? onLog = null)
    {
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
        psi.ArgumentList.Add("socks");
        if (!string.IsNullOrEmpty(options.Listen))
            psi.ArgumentList.Add($"--listen={options.Listen}");
        if (!string.IsNullOrEmpty(options.ClientKey))
            psi.ArgumentList.Add($"--key={options.ClientKey}");
        if (!string.IsNullOrEmpty(options.DerpMapUrl))
            psi.ArgumentList.Add($"--derpmap-url={options.DerpMapUrl}");
        if (options.Verbose)
            psi.ArgumentList.Add("--verbose");
        psi.Environment["HOME"] = options.HomeDirectory;

        var process = new Process { StartInfo = psi, EnableRaisingEvents = true };
        var proxy = new MeowshellSocksProxy(process, options.GracePeriod);
        try
        {
            process.Start();
            if (OperatingSystem.IsWindows())
                proxy._job = JobObject.Wrap(process);

            process.Exited += (_, _) => proxy._exited.TrySetResult();
            process.OutputDataReceived += (_, e) => { if (e.Data is not null) { proxy.Log?.Invoke(e.Data); onLog?.Invoke(e.Data); } };
            process.ErrorDataReceived += (_, e) => { if (e.Data is not null) { proxy.Log?.Invoke(e.Data); onLog?.Invoke(e.Data); } };
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            return proxy;
        }
        catch
        {
            await proxy.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Stops the proxy: SIGTERM, then SIGKILL if it does not go quietly. Safe to call repeatedly.</summary>
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

    /// <summary>Stops the proxy and releases everything it holds.</summary>
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
