#nullable enable
using System.Diagnostics;

namespace Meowshell;

/// <summary>Configuration for a <see cref="MeowshellPortForward"/>.</summary>
public sealed record MeowshellPortForwardOptions : TailcatListenerOptions
{
    /// <summary>The tailcat address to forward to.</summary>
    public required string Address { get; init; }

    /// <summary>At least one port mapping: a bare port, <c>local:remote</c>, or <c>local:remote-ip:remote-port</c> (the server must be an exit node). A local port of 0 asks the OS for a free port.</summary>
    public required IReadOnlyList<string> Mappings { get; init; }

    /// <summary>Listen address, used as the local address for a mapping that only specifies a port. Empty means tailcat's own default (127.0.0.1). Passed to tailcat's own <c>--bind</c>.</summary>
    public string? Bind { get; init; }

    /// <summary>tailcat client key name or path (see 'tailcat genkey').</summary>
    public string? ClientKey { get; init; }
}

/// <summary>Forwards local TCP ports to a tailcat server, until stopped.</summary>
public sealed class MeowshellPortForward : IAsyncDisposable
{
    private readonly TailcatListener _listener;

    /// <summary>Completes when the process has exited. Succeeds after a <see cref="StopAsync"/> call; faults with a <see cref="TailcatException"/> if the process dies on its own first.</summary>
    public Task Completed => _listener.Completed;

    /// <summary>Diagnostic output from tailcat, including each listener's bound address once it is listening. Raised on a background thread.</summary>
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
        TimeSpanValidation.EnsurePositiveAndBounded(options.GracePeriod, nameof(options.GracePeriod));

        var (meowshell, tailcat) = MeowshellBinaries.Locate(options.BinaryDirectory, options.Naming);
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
        TailcatProcessEnvironment.ApplyHome(psi, options.HomeDirectory);
        // Without this, the spawned "meowshell forward" resolves tailcat via
        // an inherited TAILCAT_BIN / sibling-binary / $PATH search of its
        // own, silently overriding whatever BinaryDirectory the caller just
        // explicitly selected -- letting an inherited environment variable
        // substitute a different native binary for the one the caller
        // trusted.
        psi.Environment["TAILCAT_BIN"] = tailcat;

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
