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

    /// <summary>The actual bound SOCKS5 endpoint reported by tailcat, including the OS-assigned port when port 0 was requested.</summary>
    public string ListenAddress { get; }

    /// <summary>Completes when the process has exited. Succeeds after a <see cref="StopAsync"/> call; faults with a <see cref="TailcatException"/> if the process dies on its own first.</summary>
    public Task Completed => _listener.Completed;

    /// <summary>Diagnostic output from tailcat. Raised on a background thread.</summary>
    public event Action<string>? Log
    {
        add => _listener.Log += value;
        remove => _listener.Log -= value;
    }

    private MeowshellSocksProxy(TailcatListener listener, string listenAddress)
    {
        _listener = listener;
        ListenAddress = listenAddress;
    }

    /// <summary>Starts the proxy.</summary>
    /// <exception cref="FileNotFoundException">A native binary is missing.</exception>
    public static async Task<MeowshellSocksProxy> StartAsync(
        MeowshellSocksOptions options, Action<string>? onLog = null,
        CancellationToken cancellationToken = default)
    {
        TimeSpanValidation.EnsurePositiveAndBounded(options.StartTimeout, nameof(options.StartTimeout));
        TimeSpanValidation.EnsurePositiveAndBounded(options.GracePeriod, nameof(options.GracePeriod));

        var (meowshell, tailcat) = MeowshellBinaries.Locate(options.BinaryDirectory, options.Naming);
        MeowshellHomeDirectory.EnsureSecure(options.HomeDirectory);

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
        TailcatListener? listener = null;
        var ready = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);

        void HandleLog(string line)
        {
            const string marker = "SOCKS running at ";
            var at = line.IndexOf(marker, StringComparison.Ordinal);
            if (at >= 0)
            {
                var address = line[(at + marker.Length)..].Trim();
                if (address.StartsWith("socks5h://", StringComparison.OrdinalIgnoreCase))
                    address = address["socks5h://".Length..];
                if (address.Length > 0) ready.TrySetResult(address);
            }

            try { onLog?.Invoke(line); } catch { }
        }

        try
        {
            listener = TailcatListener.Start(process, options.GracePeriod, HandleLog);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(options.StartTimeout);
            var timeoutTask = Task.Delay(Timeout.InfiniteTimeSpan, timeout.Token);
            var completed = await Task.WhenAny(ready.Task, listener.Completed, timeoutTask).ConfigureAwait(false);
            if (completed == listener.Completed)
                await listener.Completed.ConfigureAwait(false);
            if (completed != ready.Task)
            {
                cancellationToken.ThrowIfCancellationRequested();
                throw new TimeoutException($"SOCKS proxy did not bind within {options.StartTimeout}");
            }
            timeout.Cancel();
            return new MeowshellSocksProxy(listener, await ready.Task.ConfigureAwait(false));
        }
        catch
        {
            if (listener is not null) await listener.DisposeAsync().ConfigureAwait(false);
            else MeowshellProcessControl.TryKill(process);
            throw;
        }
    }

    /// <summary>Stops the proxy: SIGTERM, then SIGKILL if it does not go quietly. Safe to call repeatedly.</summary>
    public Task StopAsync() => _listener.StopAsync();

    /// <summary>Stops the proxy and releases everything it holds.</summary>
    public ValueTask DisposeAsync() => _listener.DisposeAsync();
}
