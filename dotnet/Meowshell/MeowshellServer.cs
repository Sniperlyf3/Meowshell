#nullable enable
using System.Diagnostics;
using System.Runtime.InteropServices;

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
public sealed record MeowshellOptions
{
    /// <summary>
    /// Directory holding the meowshell and tailcat binaries. Leave null to
    /// search for the ones shipped by a runtime package; see
    /// <see cref="BinaryLocator"/>. On Android this must be
    /// ApplicationInfo.NativeLibraryDir, because for apps targeting API 29+
    /// it is the only location an app may execute a file from.
    /// </summary>
    public string? BinaryDirectory { get; init; }

    /// <summary>
    /// How the binaries are named in <see cref="BinaryDirectory"/>. Defaults
    /// to the convention for the running platform: <c>lib*.so</c> on Android,
    /// because only files named that way are unpacked into the native library
    /// directory; <c>*.exe</c> on Windows; a bare name elsewhere.
    /// </summary>
    public BinaryNaming Naming { get; init; } = BinaryNaming.ForCurrentPlatform();

    /// <summary>A writable HOME for the session. Use the app's FilesDir.</summary>
    public required string HomeDirectory { get; init; }

    /// <summary>Scratch directory for the address handoff file. Use CacheDir.</summary>
    public required string WorkDirectory { get; init; }

    /// <summary>How long the server may live before it is shut down.</summary>
    public TimeSpan Lifetime { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// SSH public key sources permitted to log in: authorized_keys paths,
    /// literal key lines, or names like "alice@github". Mutually exclusive
    /// with <see cref="InsecureNoAuth"/>.
    /// </summary>
    public string? AuthorizedKeys { get; init; }

    /// <summary>
    /// Serve a shell to anyone holding the address, with no SSH auth. The
    /// address is then the only credential, so pair it with
    /// <see cref="AllowClientKeys"/>.
    /// </summary>
    public bool InsecureNoAuth { get; init; }

    /// <summary>Comma-separated tailcat client node keys allowed to connect.</summary>
    public string? AllowClientKeys { get; init; }

    /// <summary>
    /// Generate a throwaway key so the address dies with the process. Leave
    /// true: with a saved "default" key present, tailcat would silently reuse
    /// a stable address instead. Ignored when <see cref="PrivateKeyJson"/> is
    /// set.
    /// </summary>
    public bool EphemeralKey { get; init; } = true;

    /// <summary>
    /// Contents of a tailcat *.private.json, supplied at runtime rather than
    /// stored on the device. It is piped to meowshell on stdin and staged on
    /// an unlinked descriptor, so it never exists as a named file. Use this
    /// when your backend hands out a per-session key whose address you
    /// already hold.
    /// </summary>
    public string? PrivateKeyJson { get; init; }

    /// <summary>How long to wait for the server to publish its address.</summary>
    public TimeSpan StartTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>How long SIGTERM gets before SIGKILL.</summary>
    public TimeSpan GracePeriod { get; init; } = TimeSpan.FromSeconds(3);

    /// <summary>
    /// URL of a self-hosted, JSON-encoded DERP map to use instead of
    /// tailcat's default (<c>https://tailcat.dev/derpmap.json</c>). Passed
    /// to tailcat's own <c>--derpmap-url</c>.
    /// </summary>
    public string? DerpMapUrl { get; init; }

    /// <summary>Passed to tailcat's own <c>--verbose</c>.</summary>
    public bool Verbose { get; init; }

    /// <summary>
    /// Embed the DERP server's own info in the published address instead of
    /// a region reference, so a client can connect without first fetching a
    /// DERP map. Passed to tailcat's own <c>--full-address</c>.
    /// </summary>
    public bool FullAddress { get; init; }

    /// <summary>
    /// Include a WireGuard pre-shared key in the address (recommended).
    /// Disabling it only shortens the address and trades away security, for
    /// compatibility with tailcat clients v0.5.0 and earlier. Passed to
    /// tailcat's own <c>--psk</c>.
    /// </summary>
    public bool Psk { get; init; } = true;

    /// <summary>
    /// Directory to serve to SFTP clients (scp, sftp), with an optional
    /// <c>:ro</c> (read-only, the default), <c>:rw</c>, <c>:wo</c> (flat
    /// write-only drop box), or <c>:wo+</c> (recursive write-only drop box)
    /// suffix. Combinable with <see cref="AuthorizedKeys"/> or
    /// <see cref="InsecureNoAuth"/> to also serve a shell, but not with
    /// <see cref="ForcedCommand"/> on either of those, which would allow
    /// nothing but that command. Passed to tailcat's own <c>--files</c>.
    /// </summary>
    public string? Files { get; init; }

    /// <summary>
    /// Run this command for every session instead of a login shell, like
    /// OpenSSH's ForceCommand: the client gets no shell, no client-chosen
    /// command, and no SFTP subsystem. The command sees the peer's node key
    /// in <c>TAILCAT_PEER_KEY</c> (in <see cref="AllowClientKeys"/>'s
    /// format), plus <c>TAILCAT_REMOTE_ADDR</c> and
    /// <c>TAILCAT_LOCAL_ADDR</c>. Passed to tailcat's own <c>serve ... --
    /// &lt;command&gt;</c>. Empty runs a normal login shell.
    /// </summary>
    public IReadOnlyList<string> ForcedCommand { get; init; } = [];

    /// <summary>
    /// The one entry point: works unchanged on Android, Windows, and Linux,
    /// with no platform code, and no paths, of your own. Add just this
    /// package -- it carries the right native binaries for wherever you're
    /// building, see <see cref="BinaryLocator"/> -- and:
    /// <code>
    /// var options = MeowshellOptions.Create(TimeSpan.FromMinutes(5)) with
    /// {
    ///     InsecureNoAuth = true, // or AuthorizedKeys = "...";
    /// };
    /// await using var server = await MeowshellServer.StartAsync(options);
    /// </code>
    /// Which platform's directories and binary layout apply is resolved at
    /// build time, from which target framework compiled this method into
    /// your app -- an Android build and a desktop build of the same call
    /// never carry both, so there is nothing to detect at runtime and
    /// nothing to get wrong by picking the wrong overload.
    /// </summary>
    /// <remarks>
    /// The one thing this cannot reach into your app to set for you: an
    /// Android app targeting API 29+ may only execute a file from
    /// ApplicationInfo.NativeLibraryDir, and only has one there if the OS
    /// extracted it at install time, which requires your own app to set
    /// <c>&lt;AndroidExtractNativeLibraries&gt;true&lt;/AndroidExtractNativeLibraries&gt;</c>
    /// (or the equivalent <c>android:extractNativeLibs="true"</c> manifest
    /// attribute) -- a referenced library cannot set that on your manifest
    /// for you.
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
        return new MeowshellOptions
        {
            HomeDirectory = Path.Combine(Path.GetTempPath(), "meowshell"),
            WorkDirectory = Path.GetTempPath(),
            Lifetime = lifetime,
        };
#endif
    }
}

/// <summary>
/// Runs a tailcat shell server for a bounded period and shuts it down
/// afterwards. Start it, hand <see cref="Address"/> to whoever is connecting,
/// and dispose when done; the deadline fires on its own if you do not.
/// </summary>
public sealed class MeowshellServer : IAsyncDisposable
{
    private const int SIGTERM = 15;

    [DllImport("libc", SetLastError = true)]
    private static extern int kill(int pid, int sig);

    private readonly MeowshellOptions _options;
    private readonly Process _process;
    private readonly string _addressFile;
    private readonly CancellationTokenSource _deadline = new();
    private readonly TaskCompletionSource _exited =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly SemaphoreSlim _stopLock = new(1, 1);
    private readonly TailcatDiagnostics _diagnostics = new();
    private bool _stopped;
    // Windows-only crash backstop: if the host process dies without running
    // StopAsync, closing this handle is what stops tailcat surviving as an
    // orphan. See JobObject's own doc comment for why Unix needs no
    // equivalent (there, PR_SET_PDEATHSIG in exec_unix.go does the same job).
    private JobObject? _job;

    /// <summary>The tailcat address clients connect to: <c>tailcat ssh &lt;address&gt;</c>.</summary>
    public string Address { get; private set; } = "";

    /// <summary>UTC instant at which the server shuts itself down.</summary>
    public DateTimeOffset ExpiresAt { get; }

    /// <summary>Time left before the server shuts itself down.</summary>
    public TimeSpan Remaining =>
        ExpiresAt - DateTimeOffset.UtcNow is { Ticks: > 0 } t ? t : TimeSpan.Zero;

    /// <summary>
    /// Completes when the server process has exited. Succeeds after a
    /// <see cref="StopAsync"/> call or the deadline; faults with a
    /// <see cref="TailcatException"/> if the process dies on its own first
    /// (a crash, an OOM kill), so awaiting this is enough to notice and
    /// diagnose that without polling.
    /// </summary>
    public Task Completed => _exited.Task;

    /// <summary>Diagnostic output from tailcat. Raised on a background thread.</summary>
    public event Action<string>? Log;

    private MeowshellServer(MeowshellOptions options, Process process, string addressFile)
    {
        _options = options;
        _process = process;
        _addressFile = addressFile;
        ExpiresAt = DateTimeOffset.UtcNow + options.Lifetime;
    }

    /// <summary>
    /// Starts the server and returns once it has published an address.
    /// </summary>
    /// <param name="options">Where the binaries live and how the session is configured.</param>
    /// <param name="cancellationToken">Abandons the start; the process is cleaned up.</param>
    /// <param name="onLog">
    /// Diagnostic output from tailcat, called as it arrives. Unlike the
    /// <see cref="Log"/> event on the instance this method returns, this
    /// also fires when StartAsync itself throws: tailcat's own stderr is
    /// usually the actual reason it exited before publishing an address,
    /// and the instance carrying <see cref="Log"/> is never handed back to
    /// the caller on that path, so without this there is nothing to attach
    /// a subscriber to.
    /// </param>
    /// <exception cref="ArgumentException">
    /// Both authentication modes were set, nothing was chosen to serve, or
    /// <see cref="MeowshellOptions.Files"/> was combined with a forced
    /// command on the ssh/no-auth-ssh service.
    /// </exception>
    /// <exception cref="FileNotFoundException">A native binary is missing.</exception>
    /// <exception cref="TailcatException">tailcat exited before publishing an address.</exception>
    /// <exception cref="TimeoutException">No address appeared within <see cref="MeowshellOptions.StartTimeout"/>.</exception>
    public static async Task<MeowshellServer> StartAsync(
        MeowshellOptions options, CancellationToken cancellationToken = default, Action<string>? onLog = null)
    {
        var hasSSH = !string.IsNullOrEmpty(options.AuthorizedKeys) || options.InsecureNoAuth;
        if (!string.IsNullOrEmpty(options.AuthorizedKeys) && options.InsecureNoAuth)
        {
            throw new ArgumentException(
                "Set at most one of AuthorizedKeys or InsecureNoAuth.", nameof(options));
        }
        if (!hasSSH && string.IsNullOrEmpty(options.Files) && options.ForcedCommand.Count == 0)
        {
            throw new ArgumentException(
                "Set at least one of AuthorizedKeys, InsecureNoAuth, Files, or ForcedCommand.", nameof(options));
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
        if (options.ForcedCommand.Count > 0)
        {
            psi.ArgumentList.Add("--");
            foreach (var token in options.ForcedCommand)
                psi.ArgumentList.Add(token);
        }

        // meowshell looks for a sibling file literally named "tailcat"; under
        // NativeLibraryDir everything is lib*.so, so point it at the binary.
        psi.Environment["TAILCAT_BIN"] = tailcat;
        // tailcat aborts a session when user.Current fails, which on Android
        // happens whenever HOME is unset.
        psi.Environment["HOME"] = options.HomeDirectory;
        psi.Environment["TMPDIR"] = options.WorkDirectory;
        psi.Environment["TAILCAT_ADDR_FILE"] = addressFile;

        var process = new Process { StartInfo = psi, EnableRaisingEvents = true };
        MeowshellServer? server = null;
        try
        {
            process.Start();
            server = new MeowshellServer(options, process, addressFile);
            if (OperatingSystem.IsWindows())
            {
                server._job = JobObject.Wrap(process);
            }

            if (options.PrivateKeyJson is not null)
            {
                // meowshell reads the whole key before exec'ing tailcat, so
                // the pipe has to be closed for it to proceed.
                await process.StandardInput.WriteAsync(options.PrivateKeyJson)
                    .ConfigureAwait(false);
                process.StandardInput.Close();
            }

            process.Exited += async (_, _) =>
            {
                // Exited can fire before the async reads behind
                // BeginErrorReadLine finish delivering the last lines;
                // WaitForExitAsync (unlike the Exited event itself) is
                // documented to synchronize with that, so _diagnostics is
                // complete by the time this reads it.
                await process.WaitForExitAsync().ConfigureAwait(false);
                if (server._stopped) server._exited.TrySetResult();
                else server._exited.TrySetException(new TailcatException(
                    "tailcat exited unexpectedly", process.ExitCode, server._diagnostics.Tail()));
            };
            process.OutputDataReceived += (_, e) => { if (e.Data is not null) { server.Log?.Invoke(e.Data); onLog?.Invoke(e.Data); } };
            process.ErrorDataReceived += (_, e) =>
            {
                if (e.Data is null) return;
                server._diagnostics.Add(e.Data);
                server.Log?.Invoke(e.Data);
                onLog?.Invoke(e.Data);
            };
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            server.Address = await server.WaitForAddressAsync(cancellationToken)
                .ConfigureAwait(false);
            server.StartDeadline();
            return server;
        }
        catch
        {
            if (server is not null) await server.DisposeAsync().ConfigureAwait(false);
            else MeowshellProcessControl.TryKill(process);
            throw;
        }
    }

    /// <summary>
    /// tailcat writes its address to TAILCAT_ADDR_FILE once it is listening,
    /// which is more robust than parsing stdout.
    /// </summary>
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
            if (_process.HasExited)
            {
                // See the Exited handler in StartAsync for why this is
                // needed before _diagnostics can be trusted as complete.
                await _process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
                throw new TailcatException(
                    "tailcat exited before publishing an address", _process.ExitCode, _diagnostics.Tail());
            }
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

    private void StartDeadline() => _ = Task.Run(async () =>
    {
        try
        {
            await Task.Delay(_options.Lifetime, _deadline.Token).ConfigureAwait(false);
            await StopAsync().ConfigureAwait(false);
        }
        catch (OperationCanceledException) { /* stopped early */ }
    });

    /// <summary>
    /// Shuts the server down: SIGTERM, then SIGKILL if it does not go quietly.
    /// Safe to call repeatedly.
    /// </summary>
    public async Task StopAsync()
    {
        await _stopLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_stopped) return;
            _stopped = true;
            await _deadline.CancelAsync().ConfigureAwait(false);

            if (!_process.HasExited)
            {
                MeowshellProcessControl.RequestStop(_process, kill, SIGTERM);
                using var grace = new CancellationTokenSource(_options.GracePeriod);
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
            try { if (File.Exists(_addressFile)) File.Delete(_addressFile); } catch { /* best effort */ }
        }
    }

    /// <summary>Stops the server and releases everything it holds.</summary>
    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        _deadline.Dispose();
        _stopLock.Dispose();
        _process.Dispose();
        if (OperatingSystem.IsWindows())
        {
            _job?.Dispose();
        }
    }

}
