#nullable enable
using System.Diagnostics;
using System.Globalization;

namespace Meowshell;

/// <summary>The result of running a one-shot tailcat command.</summary>
/// <param name="ExitCode">The process's exit code.</param>
/// <param name="Stdout">Standard output, trimmed.</param>
/// <param name="Stderr">Standard error, trimmed.</param>
public readonly record struct TailcatResult(int ExitCode, string Stdout, string Stderr)
{
    /// <summary><see cref="ExitCode"/> is 0.</summary>
    public bool Success => ExitCode == 0;
}

/// <summary>Configuration shared by every <see cref="TailcatClient"/> call.</summary>
public sealed record TailcatClientOptions
{
    /// <summary>Directory holding the meowshell and tailcat binaries. See <see cref="MeowshellOptions.BinaryDirectory"/>.</summary>
    public string? BinaryDirectory { get; init; }

    /// <summary>See <see cref="MeowshellOptions.Naming"/>.</summary>
    public BinaryNaming Naming { get; init; } = BinaryNaming.ForCurrentPlatform();

    /// <summary>A writable HOME. Use the app's FilesDir.</summary>
    public required string HomeDirectory { get; init; }

    /// <summary>See <see cref="MeowshellOptions.DerpMapUrl"/>.</summary>
    public string? DerpMapUrl { get; init; }

    /// <summary>See <see cref="MeowshellOptions.Verbose"/>.</summary>
    public bool Verbose { get; init; }

    /// <summary>How long to wait for the command to finish.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);
}

/// <summary>Configuration for <see cref="TailcatClient.GenerateKeyAsync"/>.</summary>
public sealed record TailcatKeyOptions
{
    /// <summary>
    /// Key name (written to <c>$CONFIG/tailcat/keys/&lt;name&gt;.private.json</c>)
    /// or a path, if it contains a slash.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>Generate a client identity key (no DERP region), for use in an <c>--allow</c> list, instead of a server key.</summary>
    public bool Client { get; init; }

    /// <summary>Overwrite an existing key of the same name.</summary>
    public bool Force { get; init; }

    /// <summary>
    /// Region ID, code, or substring, or one or more comma-separated
    /// hostnames to use custom DERP server(s). "auto" (the default) picks
    /// one by latency at each server startup.
    /// </summary>
    public string? Region { get; init; }

    /// <summary>Discover the nearest DERP region once, now, and bake it into the key and address.</summary>
    public bool FixedRegion { get; init; }

    /// <summary>Embed the DERP map nodes in the address. Implies <see cref="FixedRegion"/> unless <see cref="Region"/> names one.</summary>
    public bool EmbedDerpMap { get; init; }

    /// <summary>See <see cref="MeowshellOptions.Psk"/>.</summary>
    public bool Psk { get; init; } = true;
}

/// <summary>
/// One-shot tailcat operations that call the bare <c>tailcat</c> binary
/// directly, not meowshell: none of these spawn a shell (the reason
/// meowshell exists) or run for long enough to risk being orphaned by a
/// crashed host (the reason <see cref="MeowshellServer"/>,
/// <see cref="MeowshellSocksProxy"/> and <see cref="MeowshellPortForward"/>
/// go through it).
/// </summary>
public static class TailcatClient
{
    private static ProcessStartInfo Prepare(TailcatClientOptions options)
    {
        var (_, tailcat) = MeowshellBinaries.Locate(options.BinaryDirectory, options.Naming);
        Directory.CreateDirectory(options.HomeDirectory);
        var psi = new ProcessStartInfo(tailcat)
        {
            WorkingDirectory = options.HomeDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        if (!string.IsNullOrEmpty(options.DerpMapUrl))
            psi.ArgumentList.Add($"--derpmap-url={options.DerpMapUrl}");
        if (options.Verbose)
            psi.ArgumentList.Add("--verbose");
        psi.Environment["HOME"] = options.HomeDirectory;
        return psi;
    }

    private static async Task<TailcatResult> RunAsync(TailcatClientOptions options, params string[] args)
    {
        var psi = Prepare(options);
        foreach (var a in args) psi.ArgumentList.Add(a);

        using var process = Process.Start(psi)!;
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(options.Timeout);
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { /* already gone */ }
            throw new TimeoutException($"tailcat {string.Join(' ', args)} did not finish within {options.Timeout}");
        }
        return new TailcatResult(
            process.ExitCode,
            (await stdoutTask.ConfigureAwait(false)).Trim(),
            (await stderrTask.ConfigureAwait(false)).Trim());
    }

    /// <summary>
    /// Generates a key and returns its tailcat address.
    /// </summary>
    /// <exception cref="InvalidOperationException">tailcat exited non-zero.</exception>
    public static async Task<string> GenerateKeyAsync(TailcatClientOptions options, TailcatKeyOptions key)
    {
        var args = new List<string> { "genkey", $"--key={key.Name}" };
        if (key.Client) args.Add("--client");
        if (key.Force) args.Add("--force");
        if (!string.IsNullOrEmpty(key.Region)) args.Add($"--region={key.Region}");
        if (key.FixedRegion) args.Add("--fixed-region");
        if (key.EmbedDerpMap) args.Add("--embed-derp-map");
        if (!key.Psk) args.Add("--psk=false");

        var result = await RunAsync(options, [.. args]).ConfigureAwait(false);
        if (!result.Success)
            throw new InvalidOperationException($"tailcat genkey failed (exit {result.ExitCode}): {result.Stderr}");
        // genkey's last line of stdout is the address (earlier lines can
        // include a "# wrote file to ..." notice); client keys print only
        // the public key, on their own single line.
        var lines = result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (lines.Length == 0)
            throw new InvalidOperationException("tailcat genkey printed nothing");
        return lines[^1];
    }

    /// <summary>Deletes a saved key.</summary>
    /// <exception cref="InvalidOperationException">tailcat exited non-zero.</exception>
    public static async Task DeleteKeyAsync(TailcatClientOptions options, string name)
    {
        var result = await RunAsync(options, "genkey", $"--key={name}", "--delete").ConfigureAwait(false);
        if (!result.Success)
            throw new InvalidOperationException($"tailcat genkey --delete failed (exit {result.ExitCode}): {result.Stderr}");
    }

    /// <summary>Lists saved key names.</summary>
    /// <exception cref="InvalidOperationException">tailcat exited non-zero.</exception>
    public static async Task<IReadOnlyList<string>> ListKeysAsync(TailcatClientOptions options)
    {
        var result = await RunAsync(options, "genkey", "--list").ConfigureAwait(false);
        if (!result.Success)
            throw new InvalidOperationException($"tailcat genkey --list failed (exit {result.ExitCode}): {result.Stderr}");
        return result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    /// <summary>Decodes a tailcat address, returning its fields as JSON. Parse and interpret with <c>System.Text.Json</c> as needed.</summary>
    /// <exception cref="InvalidOperationException">tailcat exited non-zero (e.g. an invalid address).</exception>
    public static async Task<string> ParseAsync(TailcatClientOptions options, string address)
    {
        var result = await RunAsync(options, "parse", address).ConfigureAwait(false);
        if (!result.Success)
            throw new InvalidOperationException($"tailcat parse failed (exit {result.ExitCode}): {result.Stderr}");
        return result.Stdout;
    }

    /// <summary>Expands a short tailcat address to embed its DERP server info, so a client can connect without fetching a DERP map.</summary>
    /// <exception cref="InvalidOperationException">tailcat exited non-zero.</exception>
    public static async Task<string> ResolveAsync(TailcatClientOptions options, string address)
    {
        var result = await RunAsync(options, "resolve", address).ConfigureAwait(false);
        if (!result.Success)
            throw new InvalidOperationException($"tailcat resolve failed (exit {result.ExitCode}): {result.Stderr}");
        return result.Stdout;
    }

    /// <summary>Prints the public key of the client key that would be used (the saved "client-default" key, or one named by <paramref name="clientKey"/>).</summary>
    /// <exception cref="InvalidOperationException">tailcat exited non-zero.</exception>
    public static async Task<string> PrintPubAsync(TailcatClientOptions options, string? clientKey = null)
    {
        var args = new List<string> { "printpub" };
        if (!string.IsNullOrEmpty(clientKey)) args.Insert(0, $"--key={clientKey}");
        var result = await RunAsync(options, [.. args]).ConfigureAwait(false);
        if (!result.Success)
            throw new InvalidOperationException($"tailcat printpub failed (exit {result.ExitCode}): {result.Stderr}");
        return result.Stdout;
    }

    /// <summary>
    /// Pings a server, reporting whether each pong arrived via DERP or a
    /// direct path. Does not throw on a non-zero exit (e.g.
    /// <paramref name="untilDirect"/> timing out without going direct) --
    /// check <see cref="TailcatResult.Success"/>.
    /// </summary>
    public static Task<TailcatResult> PingAsync(
        TailcatClientOptions options, string address, bool untilDirect = false, TimeSpan? timeout = null)
    {
        var args = new List<string> { "ping" };
        if (untilDirect) args.Add("--until-direct");
        // Go's duration flag parser wants "5s", not TimeSpan's default
        // "00:00:05"; a plain number of seconds with an "s" suffix is
        // always valid for it, fractional or not.
        if (timeout is { } t) args.Add($"--timeout={t.TotalSeconds.ToString(CultureInfo.InvariantCulture)}s");
        args.Add(address);
        return RunAsync(options, [.. args]);
    }

    /// <summary>Lists files on a tailcat server (a "files" service, or the home directory of an ssh/no-auth-ssh one), over SFTP directly -- no ssh or sftp binary is involved.</summary>
    /// <param name="options">Where the binaries live and how to reach the server.</param>
    /// <param name="target">A tailcat address, optionally suffixed <c>:path</c>.</param>
    /// <param name="longListing">Include permissions, size, and modification time.</param>
    /// <exception cref="InvalidOperationException">tailcat exited non-zero.</exception>
    public static async Task<string> ListFilesAsync(TailcatClientOptions options, string target, bool longListing = false)
    {
        var args = new List<string> { "ls" };
        if (longListing) args.Add("-l");
        args.Add(target);
        var result = await RunAsync(options, [.. args]).ConfigureAwait(false);
        if (!result.Success)
            throw new InvalidOperationException($"tailcat ls failed (exit {result.ExitCode}): {result.Stderr}");
        return result.Stdout;
    }

    /// <summary>
    /// Connects the system ssh client through a tailcat server.
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">
    /// Running on Android: this shells out to a system <c>ssh</c> binary, which an app sandbox does not provide.
    /// Use <see cref="MeowshellServer"/> or <c>meowshell connect</c> for shell access there instead.
    /// </exception>
    public static Task<TailcatResult> SshAsync(
        TailcatClientOptions options, string destination, IReadOnlyList<string>? command = null, string? port = null)
    {
        RequireNotAndroid("ssh");
        var args = new List<string> { "ssh" };
        if (!string.IsNullOrEmpty(port)) args.AddRange(["-p", port]);
        args.Add(destination);
        if (command is not null) args.AddRange(command);
        return RunAsync(options, [.. args]);
    }

    /// <summary>
    /// Copies files to or from a tailcat server, using the system scp.
    /// </summary>
    /// <param name="options">Where the binaries live and how to reach the server.</param>
    /// <param name="paths">One or more sources followed by a target, scp-style; a remote path is written <c>&lt;tc-addr&gt;:[path]</c>.</param>
    /// <param name="recursive">Recursively copy directories.</param>
    /// <param name="preserve">Preserve modification times and modes.</param>
    /// <exception cref="PlatformNotSupportedException">
    /// Running on Android: this shells out to a system <c>scp</c> binary, which an app sandbox does not provide.
    /// </exception>
    public static Task<TailcatResult> CpAsync(
        TailcatClientOptions options, IReadOnlyList<string> paths, bool recursive = false, bool preserve = false)
    {
        RequireNotAndroid("cp");
        var args = new List<string> { "cp" };
        if (recursive) args.Add("-r");
        if (preserve) args.Add("-p");
        args.AddRange(paths);
        return RunAsync(options, [.. args]);
    }

    private static void RequireNotAndroid(string command)
    {
        if (OperatingSystem.IsAndroid())
        {
            throw new PlatformNotSupportedException(
                $"tailcat {command} shells out to the system {command switch { "cp" => "scp", var c => c }} " +
                "client, which an Android app sandbox doesn't provide. Use MeowshellServer or " +
                "'meowshell connect' for shell access instead.");
        }
    }
}
