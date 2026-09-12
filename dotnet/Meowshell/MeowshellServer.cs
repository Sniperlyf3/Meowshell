#nullable enable
using System.Diagnostics;

namespace Meowshell;

/// <summary>How the meowshell and tailcat executables are named on disk.</summary>
/// <param name="Prefix">Prepended to the tool name.</param>
/// <param name="Suffix">Appended to the tool name.</param>
public readonly record struct BinaryNaming(string Prefix, string Suffix)
{
    /// <summary>Android: only lib*.so is unpacked into the native library directory.</summary>
    public static BinaryNaming Android { get; } = new("lib", ".so");

    /// <summary>Windows executables.</summary>
    public static BinaryNaming Windows { get; } = new("", ".exe");

    /// <summary>Linux and other unix-likes.</summary>
    public static BinaryNaming Plain { get; } = new("", "");

    /// <summary>The convention for the platform this process is running on.</summary>
    public static BinaryNaming ForCurrentPlatform()
    {
        if (OperatingSystem.IsAndroid()) return Android;
        if (OperatingSystem.IsWindows()) return Windows;
        return Plain;
    }

    /// <summary>The file name for one tool, e.g. "tailcat".</summary>
    public string FileName(string tool) => Prefix + tool + Suffix;
}

/// <summary>Configuration for a <see cref="MeowshellServer"/>.</summary>
public sealed record MeowshellOptions : TailcatListenerOptions
{
    /// <summary>Scratch directory for the address handoff file. Use CacheDir.</summary>
    public required string WorkDirectory { get; init; }

    /// <summary>How long the server may live before it is shut down.</summary>
    public TimeSpan Lifetime { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>SSH public key sources permitted to log in: authorized_keys paths, literal key lines, or names like "alice@github". Mutually exclusive with <see cref="InsecureNoAuth"/>.</summary>
    public string? AuthorizedKeys { get; init; }

    /// <summary>Serve a shell to anyone holding the address, with no SSH auth. The address is then the only credential, so pair it with <see cref="AllowClientKeys"/>.</summary>
    public bool InsecureNoAuth { get; init; }

    /// <summary>Comma-separated tailcat client node keys allowed to connect.</summary>
    public string? AllowClientKeys { get; init; }

    /// <summary>Generate a throwaway key so the address dies with the process. Leave true. Ignored when <see cref="PrivateKeyJson"/> is set.</summary>
    public bool EphemeralKey { get; init; } = true;

    /// <summary>Contents of a tailcat *.private.json, supplied at runtime rather than stored on the device. Piped to meowshell on stdin, never exists as a named file.</summary>
    public string? PrivateKeyJson { get; init; }

    /// <summary>How long to wait for the server to publish its address.</summary>
    public TimeSpan StartTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Embed the DERP server's own info in the published address instead of a region reference. Passed to tailcat's own <c>--full-address</c>.</summary>
    public bool FullAddress { get; init; }

    /// <summary>Include a WireGuard pre-shared key in the address (recommended). Passed to tailcat's own <c>--psk</c>.</summary>
    public bool Psk { get; init; } = true;

    /// <summary>Directory to serve to SFTP clients, with an optional <c>:ro</c>/<c>:rw</c>/<c>:wo</c>/<c>:wo+</c> suffix. Passed to tailcat's own <c>--files</c>.</summary>
    public string? Files { get; init; }

    /// <summary>Let a client's forward/SOCKS channels reach any port this machine can dial, not just the SSH/files ports above -- tailcat's own "exit-node" service. Passed to meowshell's own <c>--exit-node</c>.</summary>
    public bool AllowExitNode { get; init; }

    /// <summary>Run this command for every session instead of a login shell, like OpenSSH's ForceCommand. Empty runs a normal login shell.</summary>
    public IReadOnlyList<string> ForcedCommand { get; init; } = [];

    /// <summary>The one entry point: works unchanged on Android, Windows, and Linux, with no platform code of your own.</summary>
    /// <remarks>
    /// An Android app targeting API 29+ may only execute a file from ApplicationInfo.NativeLibraryDir, and only has
    /// one there if the OS extracted it at install time, which requires your own app to set
    /// <c>&lt;AndroidExtractNativeLibraries&gt;true&lt;/AndroidExtractNativeLibraries&gt;</c> -- a referenced
    /// library cannot set that on your manifest for you.
    /// </remarks>
    /// <param name="lifetime">How long the server may live before it shuts itself down.</param>
    public static MeowshellOptions Create(TimeSpan lifetime)
    {
#if ANDROID
        var ctx = Android.App.Application.Context;
        return new MeowshellOptions
        {
            BinaryDirectory = ctx.ApplicationInfo!.NativeLibraryDir!,
            HomeDirectory = Path.Combine(ctx.FilesDir!.AbsolutePath, "meowshell"),
            WorkDirectory = ctx.CacheDir!.AbsolutePath,
            Lifetime = lifetime,
        };
#else
        // N3: this used to be Path.Combine(Path.GetTempPath(), "meowshell")
        // -- a fixed, predictable name inside a directory every local user
        // can write to, so anyone who got there first could plant a
        // symlink at that exact path (redirecting session key material and
        // known_hosts, since this becomes HOME for the spawned process,
        // wherever they chose) or simply leave the directory readable by
        // others. MeowshellHomeDirectory.ResolveDefault() resolves a
        // private, per-user location instead and verifies (or establishes)
        // that it's actually private before handing it back.
        var homeDir = MeowshellHomeDirectory.ResolveDefault();
        return new MeowshellOptions
        {
            HomeDirectory = homeDir,
            WorkDirectory = homeDir,
            Lifetime = lifetime,
        };
#endif
    }
}

/// <summary>Runs a tailcat shell server for a bounded period and shuts it down afterwards.</summary>
public sealed class MeowshellServer : IAsyncDisposable
{
    private readonly MeowshellOptions _options;
    private readonly TailcatListener _listener;
    private readonly string _addressFile;
    private readonly CancellationTokenSource _deadline = new();
    private Task _deadlineTask = Task.CompletedTask;

    internal Task DeadlineTaskForTests => _deadlineTask;

    /// <summary>The tailcat address clients connect to: <c>tailcat ssh &lt;address&gt;</c>.</summary>
    public string Address { get; private set; } = "";

    /// <summary>UTC instant at which the server shuts itself down.</summary>
    public DateTimeOffset ExpiresAt { get; }

    /// <summary>Time left before the server shuts itself down.</summary>
    public TimeSpan Remaining =>
        ExpiresAt - DateTimeOffset.UtcNow is { Ticks: > 0 } t ? t : TimeSpan.Zero;

    /// <summary>Completes when the server process has exited. Succeeds after a <see cref="StopAsync"/> call or the deadline; faults with a <see cref="TailcatException"/> if the process dies on its own first.</summary>
    public Task Completed => _listener.Completed;

    /// <summary>Diagnostic output from tailcat. Raised on a background thread.</summary>
    public event Action<string>? Log
    {
        add => _listener.Log += value;
        remove => _listener.Log -= value;
    }

    private MeowshellServer(MeowshellOptions options, TailcatListener listener, string addressFile)
    {
        _options = options;
        _listener = listener;
        _addressFile = addressFile;
        ExpiresAt = DateTimeOffset.UtcNow + options.Lifetime;
    }

    /// <summary>Starts the server and returns once it has published an address.</summary>
    /// <param name="options">Where the binaries live and how the session is configured.</param>
    /// <param name="cancellationToken">Abandons the start; the process is cleaned up.</param>
    /// <param name="onLog">Diagnostic output from tailcat, called as it arrives -- also fires when StartAsync itself throws, unlike the <see cref="Log"/> event.</param>
    /// <exception cref="ArgumentException">Both authentication modes were set, nothing was chosen to serve, or <see cref="MeowshellOptions.Files"/> was combined with a forced command on the ssh/no-auth-ssh service.</exception>
    /// <exception cref="FileNotFoundException">A native binary is missing.</exception>
    /// <exception cref="TailcatException">tailcat exited before publishing an address.</exception>
    /// <exception cref="TimeoutException">No address appeared within <see cref="MeowshellOptions.StartTimeout"/>.</exception>
    public static async Task<MeowshellServer> StartAsync(
        MeowshellOptions options, CancellationToken cancellationToken = default, Action<string>? onLog = null)
    {
        TimeSpanValidation.EnsurePositiveAndBounded(options.Lifetime, nameof(options.Lifetime));
        TimeSpanValidation.EnsurePositiveAndBounded(options.StartTimeout, nameof(options.StartTimeout));
        TimeSpanValidation.EnsurePositiveAndBounded(options.GracePeriod, nameof(options.GracePeriod));

        var hasSSH = !string.IsNullOrEmpty(options.AuthorizedKeys) || options.InsecureNoAuth;
        if (!string.IsNullOrEmpty(options.AuthorizedKeys) && options.InsecureNoAuth)
        {
            throw new ArgumentException(
                "Set at most one of AuthorizedKeys or InsecureNoAuth.", nameof(options));
        }
        if (!hasSSH && string.IsNullOrEmpty(options.Files) && !options.AllowExitNode && options.ForcedCommand.Count == 0)
        {
            throw new ArgumentException(
                "Set at least one of AuthorizedKeys, InsecureNoAuth, Files, AllowExitNode, or ForcedCommand.", nameof(options));
        }
        if (!string.IsNullOrEmpty(options.Files) && hasSSH && options.ForcedCommand.Count > 0)
        {
            throw new ArgumentException(
                "Files cannot be combined with a ForcedCommand on the ssh/no-auth-ssh service, which would allow nothing but that command.",
                nameof(options));
        }

        var (meowshell, tailcat) = MeowshellBinaries.Locate(options.BinaryDirectory, options.Naming);

        Directory.CreateDirectory(options.WorkDirectory);
        Directory.CreateDirectory(options.HomeDirectory);
        var addressFile = Path.Combine(
            options.WorkDirectory, $"tailcat-addr-{Guid.NewGuid():N}");

        var psi = new ProcessStartInfo
        {
            FileName = meowshell,
            WorkingDirectory = options.HomeDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("serve");
        if (options.InsecureNoAuth)
            psi.ArgumentList.Add("--insecure-no-auth");
        else if (!string.IsNullOrEmpty(options.AuthorizedKeys))
            psi.ArgumentList.Add($"--authorized-keys={options.AuthorizedKeys}");
        if (!string.IsNullOrEmpty(options.AllowClientKeys))
            psi.ArgumentList.Add($"--allow={options.AllowClientKeys}");
        if (options.PrivateKeyJson is not null)
        {
            psi.ArgumentList.Add("--key-stdin");
            psi.RedirectStandardInput = true;
        }
        else if (options.EphemeralKey)
        {
            psi.ArgumentList.Add("--key=new");
        }
        if (!string.IsNullOrEmpty(options.DerpMapUrl))
            psi.ArgumentList.Add($"--derpmap-url={options.DerpMapUrl}");
        if (options.Verbose)
            psi.ArgumentList.Add("--verbose");
        if (options.FullAddress)
            psi.ArgumentList.Add("--full-address");
        if (!options.Psk)
            psi.ArgumentList.Add("--psk=false");
        if (!string.IsNullOrEmpty(options.Files))
            psi.ArgumentList.Add($"--files={options.Files}");
        if (options.AllowExitNode)
            psi.ArgumentList.Add("--exit-node");
        if (options.ForcedCommand.Count > 0)
        {
            psi.ArgumentList.Add("--");
            foreach (var token in options.ForcedCommand)
                psi.ArgumentList.Add(token);
        }

        psi.Environment["TAILCAT_BIN"] = tailcat;
        psi.Environment["HOME"] = options.HomeDirectory;
        psi.Environment["TMPDIR"] = options.WorkDirectory;
        psi.Environment["TAILCAT_ADDR_FILE"] = addressFile;

        var process = new Process { StartInfo = psi };
        MeowshellServer? server = null;
        TailcatListener? listener = null;
        try
        {
            listener = TailcatListener.Start(process, options.GracePeriod, onLog);
            server = new MeowshellServer(options, listener, addressFile);

            if (options.PrivateKeyJson is not null)
            {
                // Bounded by StartTimeout the same way WaitForAddressAsync
                // below is: a plain, unbounded WriteAsync here means a child
                // that starts but never consumes stdin can hang StartAsync
                // indefinitely, before StartTimeout ever gets a chance to
                // apply -- and the caller's own cancellationToken alone
                // wouldn't add a bound if they left it at the default.
                using var writeTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                writeTimeout.CancelAfter(options.StartTimeout);
                try
                {
                    await process.StandardInput.WriteAsync(options.PrivateKeyJson.AsMemory(), writeTimeout.Token)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    throw new TimeoutException($"writing the private key to tailcat's stdin did not finish within {options.StartTimeout}");
                }
                process.StandardInput.Close();
            }

            server.Address = await server.WaitForAddressAsync(cancellationToken)
                .ConfigureAwait(false);
            server.StartDeadline();
            return server;
        }
        catch
        {
            if (server is not null) await server.DisposeAsync().ConfigureAwait(false);
            else if (listener is not null) await listener.DisposeAsync().ConfigureAwait(false);
            else MeowshellProcessControl.TryKill(process);
            throw;
        }
    }

    private async Task<string> WaitForAddressAsync(CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.StartTimeout);

        while (true)
        {
            if (File.Exists(_addressFile))
            {
                var text = (await File.ReadAllTextAsync(_addressFile, cancellationToken)
                    .ConfigureAwait(false)).Trim();
                if (text.Length > 0) return text;
            }
            await _listener.ThrowIfExitedAsync(
                "tailcat exited before publishing an address", cancellationToken).ConfigureAwait(false);
            try
            {
                await Task.Delay(50, timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException(
                    $"tailcat published no address within {_options.StartTimeout}");
            }
        }
    }

    private void StartDeadline() => _deadlineTask = Task.Run(async () =>
    {
        try
        {
            await Task.Delay(_options.Lifetime, _deadline.Token).ConfigureAwait(false);
            await StopAsync().ConfigureAwait(false);
        }
        catch (OperationCanceledException) { }
    });

    /// <summary>Shuts the server down: SIGTERM, then SIGKILL if it does not go quietly. Safe to call repeatedly.</summary>
    public async Task StopAsync()
    {
        try
        {
            await _deadline.CancelAsync().ConfigureAwait(false);
            await _listener.StopAsync().ConfigureAwait(false);
        }
        finally
        {
            try { if (File.Exists(_addressFile)) File.Delete(_addressFile); } catch { }
        }
    }

    /// <summary>Stops the server and releases everything it holds.</summary>
    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        // Observed rather than left to fault silently as an unobserved task
        // exception: StopAsync() above already cancels _deadline, so this
        // normally only awaits OperationCanceledException home, but nothing
        // upstream should have to trust that StartDeadline's background task
        // can never fail any other way.
        try { await _deadlineTask.ConfigureAwait(false); } catch { }
        _deadline.Dispose();
        await _listener.DisposeAsync().ConfigureAwait(false);
    }
}
