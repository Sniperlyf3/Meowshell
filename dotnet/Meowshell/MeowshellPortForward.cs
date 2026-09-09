#nullable enable
using System.Diagnostics;

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
    private readonly TailcatListener _listener;

    /// <summary>
    /// Completes when the process has exited. Succeeds after a
    /// <see cref="StopAsync"/> call; faults with a <see cref="TailcatException"/>
    /// if the process dies on its own first.
    /// </summary>
    public Task Completed => _listener.Completed;

    /// <summary>
    /// Diagnostic output from tailcat, including each listener's bound
    /// address once it is listening (most useful for a mapping that asked
    /// for an OS-assigned port). Raised on a background thread.
    /// </summary>
    public event Action<string>? Log
    {
        add => _listener.Log += value;
        remove => _listener.Log -= value;
    }

    private MeowshellPortForward(TailcatListener listener) => _listener = listener;

    /// <summary>Starts forwarding.</summary>
    /// <exception cref="ArgumentException">No mappings were given.</exception>
    /// <exception cref="FileNotFoundException">A native binary is missing.</exception>
    public static Task<MeowshellPortForward> StartAsync(
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

        var process = new Process { StartInfo = psi };
        try
        {
            var listener = TailcatListener.Start(process, options.GracePeriod, onLog);
            return Task.FromResult(new MeowshellPortForward(listener));
        }
        catch
        {
            MeowshellProcessControl.TryKill(process);
            throw;
        }
    }

    /// <summary>Stops forwarding: SIGTERM, then SIGKILL if it does not go quietly. Safe to call repeatedly.</summary>
    public Task StopAsync() => _listener.StopAsync();

    /// <summary>Stops forwarding and releases everything it holds.</summary>
    public ValueTask DisposeAsync() => _listener.DisposeAsync();
}
