#nullable enable
using System.Diagnostics;

namespace Meowshell;

/// <summary>Configuration for a <see cref="MeowshellSocksProxy"/>.</summary>
public sealed record MeowshellSocksOptions : TailcatListenerOptions
{
    /// <summary>SOCKS5 proxy listen <c>[address]:port</c>; a bare port means localhost, a bare address means an OS-assigned port. Empty lets tailcat pick its own default. Passed to tailcat's own <c>--listen</c>.</summary>
    public string? Listen { get; init; }

    /// <summary>tailcat client key name or path (see 'tailcat genkey').</summary>
    public string? ClientKey { get; init; }
}

/// <summary>Runs a SOCKS5 proxy that dials tailcat servers, until stopped.</summary>
public sealed class MeowshellSocksProxy : IAsyncDisposable
{
    private readonly TailcatListener _listener;

    /// <summary>Completes when the process has exited. Succeeds after a <see cref="StopAsync"/> call; faults with a <see cref="TailcatException"/> if the process dies on its own first.</summary>
    public Task Completed => _listener.Completed;

    /// <summary>Diagnostic output from tailcat. Raised on a background thread.</summary>
    public event Action<string>? Log
    {
        add => _listener.Log += value;
        remove => _listener.Log -= value;
    }

    private MeowshellSocksProxy(TailcatListener listener) => _listener = listener;

    /// <summary>Starts the proxy.</summary>
    /// <exception cref="FileNotFoundException">A native binary is missing.</exception>
    public static Task<MeowshellSocksProxy> StartAsync(
        MeowshellSocksOptions options, Action<string>? onLog = null)
    {
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
        psi.ArgumentList.Add("socks");
        if (!string.IsNullOrEmpty(options.Listen))
            psi.ArgumentList.Add($"--listen={options.Listen}");
        if (!string.IsNullOrEmpty(options.ClientKey))
            psi.ArgumentList.Add($"--key={options.ClientKey}");
        if (!string.IsNullOrEmpty(options.DerpMapUrl))
            psi.ArgumentList.Add($"--derpmap-url={options.DerpMapUrl}");
        if (options.Verbose)
            psi.ArgumentList.Add("--verbose");
        TailcatProcessEnvironment.ApplyHome(psi, options.HomeDirectory);
        // See MeowshellPortForward.StartAsync: without this, the spawned
        // "meowshell socks" resolves tailcat via an inherited TAILCAT_BIN /
        // sibling-binary / $PATH search of its own, silently overriding the
        // BinaryDirectory the caller explicitly selected.
        psi.Environment["TAILCAT_BIN"] = tailcat;

        var process = new Process { StartInfo = psi };
        try
        {
            var listener = TailcatListener.Start(process, options.GracePeriod, onLog);
            return Task.FromResult(new MeowshellSocksProxy(listener));
        }
        catch
        {
            MeowshellProcessControl.TryKill(process);
            throw;
        }
    }

    /// <summary>Stops the proxy: SIGTERM, then SIGKILL if it does not go quietly. Safe to call repeatedly.</summary>
    public Task StopAsync() => _listener.StopAsync();

    /// <summary>Stops the proxy and releases everything it holds.</summary>
    public ValueTask DisposeAsync() => _listener.DisposeAsync();
}
