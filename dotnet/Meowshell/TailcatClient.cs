#nullable enable
using System.Diagnostics;
using System.Globalization;
using System.Text.Json;

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
public sealed record TailcatClientOptions : TailcatOptions
{
    /// <summary>How long to wait for the command to finish.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);
}

/// <summary>Configuration for <see cref="TailcatClient.GenerateKeyAsync"/>.</summary>
public sealed record TailcatKeyOptions
{
    /// <summary>Key name (written to <c>$CONFIG/tailcat/keys/&lt;name&gt;.private.json</c>) or a path, if it contains a slash.</summary>
    public required string Name { get; init; }

    /// <summary>Generate a client identity key (no DERP region), for use in an <c>--allow</c> list, instead of a server key.</summary>
    public bool Client { get; init; }

    /// <summary>Overwrite an existing key of the same name.</summary>
    public bool Force { get; init; }

    /// <summary>Region ID, code, or substring, or one or more comma-separated hostnames to use custom DERP server(s). "auto" (the default) picks one by latency at each server startup.</summary>
    public string? Region { get; init; }

    /// <summary>Discover the nearest DERP region once, now, and bake it into the key and address.</summary>
    public bool FixedRegion { get; init; }

    /// <summary>Embed the DERP map nodes in the address. Implies <see cref="FixedRegion"/> unless <see cref="Region"/> names one.</summary>
    public bool EmbedDerpMap { get; init; }

    /// <summary>See <see cref="MeowshellOptions.Psk"/>.</summary>
    public bool Psk { get; init; } = true;
}

/// <summary>One-shot tailcat operations that call the bare <c>tailcat</c> binary directly, not meowshell.</summary>
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
        TailcatProcessEnvironment.ApplyHome(psi, options.HomeDirectory);
        return psi;
    }

    private static Task<TailcatResult> RunAsync(TailcatClientOptions options, params string[] args)
    {
        var psi = Prepare(options);
        foreach (var a in args) psi.ArgumentList.Add(a);
        // Name the operation by its verb alone (e.g. "tailcat ping"), not the
        // full argument vector: several callers (PingAsync, ListFilesAsync,
        // SshAsync, CpAsync) put a tailcat address -- treated as
        // credential-like elsewhere in this codebase's own security model --
        // or other caller-supplied values directly in args, and this message
        // ends up in a TimeoutException that an application can easily let
        // reach a log or crash reporter.
        var verb = args.Length > 0 ? args[0] : "";
        return RunAsync(psi, options.Timeout, $"tailcat {verb}");
    }

    // Bounds how much of a one-shot command's stdout/stderr this buffers in
    // memory. ReadToEndAsync has no such cap on its own, so a misbehaving
    // tailcat binary, or a destination that gets to influence output (e.g.
    // what a hostile server returns to "ls"), could otherwise grow memory
    // without bound. Well above any realistic legitimate output (address
    // lists, JSON metadata, directory listings) while still bounding worst
    // case.
    private const int MaxOutputBytes = 16 * 1024 * 1024;

    private sealed class OutputLimitFlag
    {
        public volatile bool Exceeded;
    }

    private static async Task<string> ReadBoundedAsync(StreamReader reader, OutputLimitFlag limitFlag, CancellationTokenSource haltSource, CancellationToken cancellationToken)
    {
        var buffer = new char[8192];
        var sb = new System.Text.StringBuilder();
        long total = 0;
        while (true)
        {
            int n;
            try
            {
                n = await reader.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return sb.ToString();
            }
            if (n == 0) break;
            total += n;
            if (total > MaxOutputBytes)
            {
                limitFlag.Exceeded = true;
                haltSource.Cancel();
                return sb.ToString();
            }
            sb.Append(buffer, 0, n);
        }
        return sb.ToString();
    }

    private static async Task<TailcatResult> RunAsync(ProcessStartInfo psi, TimeSpan timeout, string commandForTimeoutMessage)
    {
        // Validated here, the one place every caller (RunAsync(options, args),
        // GetEnvironmentAsync, RunMeowshellCpAsync) funnels through, and
        // before the process below is started: a bad timeout must never
        // leak a spawned child that nothing will ever wait for or kill.
        TimeSpanValidation.EnsurePositiveAndBounded(timeout, nameof(timeout));
        using var process = new Process { StartInfo = psi };
        using var job = MeowshellProcessControl.Start(process);
        using var cts = new CancellationTokenSource(timeout);
        var limitFlag = new OutputLimitFlag();
        var stdoutTask = ReadBoundedAsync(process.StandardOutput, limitFlag, cts, cts.Token);
        var stderrTask = ReadBoundedAsync(process.StandardError, limitFlag, cts, cts.Token);
        try
        {
            await process.WaitForExitAsync(cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Kill() only requests termination -- wait (bounded) for the OS
            // to actually reap the child before returning, the same fix
            // already applied to MeowshellAgentConnection/TailcatListener:
            // otherwise a caller has no guarantee the process is actually
            // gone by the time this throws.
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                    using var killGrace = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    try { await process.WaitForExitAsync(killGrace.Token).ConfigureAwait(false); } catch { }
                }
            }
            catch { }
            if (limitFlag.Exceeded)
                throw new TailcatException($"{commandForTimeoutMessage} produced more than {MaxOutputBytes:N0} bytes of output", exitCode: -1, "");
            throw new TimeoutException($"{commandForTimeoutMessage} did not finish within {timeout}");
        }
        return new TailcatResult(
            process.ExitCode,
            (await stdoutTask.ConfigureAwait(false)).Trim(),
            (await stderrTask.ConfigureAwait(false)).Trim());
    }

    private static TailcatException Failure(string command, TailcatResult result) =>
        new($"tailcat {command} failed", result.ExitCode, result.Stderr);

    private static TailcatException UnexpectedOutput(string command, string detail) =>
        new($"unexpected output from tailcat {command}", exitCode: 0, detail);

    /// <summary>Generates a key and returns its tailcat address (or, for a <see cref="TailcatKeyOptions.Client"/> key, its public key).</summary>
    /// <exception cref="TailcatException">tailcat exited non-zero, or printed something other than the expected address/public key.</exception>
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
        if (!result.Success) throw Failure("genkey", result);

        var lines = result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (lines.Length == 0)
            throw UnexpectedOutput("genkey", "printed nothing");
        var last = lines[^1];
        var wantPrefix = key.Client ? "nodekey:" : "tc";
        if (!last.StartsWith(wantPrefix, StringComparison.Ordinal))
            throw UnexpectedOutput("genkey", $"expected {(key.Client ? "a public key (\"nodekey:...\")" : "a tailcat address (\"tc...\")")}, got: {last}");
        return last;
    }

    /// <summary>Deletes a saved key.</summary>
    /// <exception cref="TailcatException">tailcat exited non-zero.</exception>
    public static async Task DeleteKeyAsync(TailcatClientOptions options, string name)
    {
        var result = await RunAsync(options, "genkey", $"--key={name}", "--delete").ConfigureAwait(false);
        if (!result.Success) throw Failure("genkey --delete", result);
    }

    /// <summary>Lists saved key names.</summary>
    /// <exception cref="TailcatException">tailcat exited non-zero.</exception>
    public static async Task<IReadOnlyList<string>> ListKeysAsync(TailcatClientOptions options)
    {
        var result = await RunAsync(options, "genkey", "--list").ConfigureAwait(false);
        if (!result.Success) throw Failure("genkey --list", result);
        return result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    /// <summary>Decodes a tailcat address into the fields it actually carries.</summary>
    /// <exception cref="TailcatException">tailcat exited non-zero (e.g. an invalid address), or its JSON didn't match the expected shape.</exception>
    public static async Task<TailcatParsedAddress> ParseAsync(TailcatClientOptions options, TailcatAddress address)
    {
        var result = await RunAsync(options, "parse", address).ConfigureAwait(false);
        if (!result.Success) throw Failure("parse", result);
        try
        {
            return JsonSerializer.Deserialize<TailcatParsedAddress>(result.Stdout)
                ?? throw UnexpectedOutput("parse", "printed \"null\"");
        }
        catch (JsonException ex)
        {
            throw UnexpectedOutput("parse", $"couldn't parse its JSON ({ex.Message}): {result.Stdout}");
        }
    }

    /// <summary>Expands a short tailcat address to embed its DERP server info, so a client can connect without fetching a DERP map.</summary>
    /// <param name="options">Where the binaries live and how to reach the server.</param>
    /// <param name="address">A tailcat address, or a DNS name carrying a "tailcat=" TXT record.</param>
    /// <exception cref="TailcatException">tailcat exited non-zero, or didn't print a tailcat address.</exception>
    public static async Task<TailcatAddress> ResolveAsync(TailcatClientOptions options, string address)
    {
        var result = await RunAsync(options, "resolve", address).ConfigureAwait(false);
        if (!result.Success) throw Failure("resolve", result);
        if (!result.Stdout.StartsWith("tc", StringComparison.Ordinal))
            throw UnexpectedOutput("resolve", $"expected a tailcat address, got: {result.Stdout}");
        return new TailcatAddress(result.Stdout);
    }

    /// <summary>Prints the public key of the client key that would be used (the saved "client-default" key, or one named by <paramref name="clientKey"/>).</summary>
    /// <exception cref="TailcatException">tailcat exited non-zero, or didn't print a public key.</exception>
    public static async Task<string> PrintPubAsync(TailcatClientOptions options, string? clientKey = null)
    {
        var args = new List<string> { "printpub" };
        if (!string.IsNullOrEmpty(clientKey)) args.Insert(0, $"--key={clientKey}");
        var result = await RunAsync(options, [.. args]).ConfigureAwait(false);
        if (!result.Success) throw Failure("printpub", result);
        if (!result.Stdout.StartsWith("nodekey:", StringComparison.Ordinal))
            throw UnexpectedOutput("printpub", $"expected a public key (\"nodekey:...\"), got: {result.Stdout}");
        return result.Stdout;
    }

    /// <summary>Pings a server, reporting whether the pong arrived via DERP or a direct path. Does not throw on a non-zero exit -- check <see cref="TailcatPingResult.Success"/>.</summary>
    public static async Task<TailcatPingResult> PingAsync(
        TailcatClientOptions options, string address, bool untilDirect = false, TimeSpan? timeout = null)
    {
        var args = new List<string> { "ping" };
        if (untilDirect) args.Add("--until-direct");

        if (timeout is { } t) args.Add($"--timeout={t.TotalSeconds.ToString(CultureInfo.InvariantCulture)}s");
        args.Add(address);
        var result = await RunAsync(options, [.. args]).ConfigureAwait(false);
        return TailcatPingResult.From(result);
    }

    /// <summary>Lists files on a tailcat server, over SFTP directly -- no ssh or sftp binary is involved.</summary>
    /// <param name="options">Where the binaries live and how to reach the server.</param>
    /// <param name="target">A remote path: <see cref="TailcatPath.Remote"/> or <see cref="TailcatPath.RemoteHost"/>.</param>
    /// <param name="longListing">Include permissions, size, and modification time.</param>
    /// <exception cref="ArgumentException"><paramref name="target"/> is a local path.</exception>
    /// <exception cref="TailcatException">tailcat exited non-zero, or a line didn't match the expected shape.</exception>
    public static Task<IReadOnlyList<TailcatFileEntry>> ListFilesAsync(
        TailcatClientOptions options, TailcatPath target, bool longListing = false)
    {
        if (!target.IsRemote)
        {
            throw new ArgumentException(
                "target must be remote: TailcatPath.Remote(address) or TailcatPath.RemoteHost(dnsName).", nameof(target));
        }
        return ListFilesAsync(options, target.ToString(), longListing);
    }

    /// <summary>Lists files on a tailcat server, given the raw scp-style "server:path" text directly -- prefer the <see cref="TailcatPath"/> overload.</summary>
    /// <param name="options">Where the binaries live and how to reach the server.</param>
    /// <param name="target">A tailcat address or DNS name, optionally suffixed <c>:path</c>.</param>
    /// <param name="longListing">Include permissions, size, and modification time.</param>
    /// <exception cref="TailcatException">tailcat exited non-zero, or a line didn't match the expected shape.</exception>
    public static async Task<IReadOnlyList<TailcatFileEntry>> ListFilesAsync(
        TailcatClientOptions options, string target, bool longListing = false)
    {
        var args = new List<string> { "ls" };
        if (longListing) args.Add("-l");
        args.Add(target);
        var result = await RunAsync(options, [.. args]).ConfigureAwait(false);
        if (!result.Success) throw Failure("ls", result);
        return TailcatFileEntry.ParseAll(result.Stdout, longListing);
    }

    /// <summary>Connects the system ssh client through a tailcat server.</summary>
    /// <exception cref="PlatformNotSupportedException">Running on Android: this shells out to a system <c>ssh</c> binary, which an app sandbox does not provide.</exception>
    public static Task<TailcatResult> SshAsync(
        TailcatClientOptions options, string destination, IReadOnlyList<string>? command = null, string? port = null)
    {
        if (OperatingSystem.IsAndroid())
        {
            throw new PlatformNotSupportedException(
                "tailcat ssh shells out to the system ssh client, which an Android app sandbox doesn't provide. " +
                "Use MeowshellServer or 'meowshell connect' for shell access instead.");
        }
        var args = new List<string> { "ssh" };
        if (!string.IsNullOrEmpty(port)) args.AddRange(["-p", port]);
        args.Add(destination);
        if (command is not null) args.AddRange(command);
        return RunAsync(options, [.. args]);
    }

    /// <summary>Copies one source to <paramref name="target"/>.</summary>
    /// <param name="options">Where the binaries live and how to reach the server.</param>
    /// <param name="source">The file or directory to copy: <see cref="TailcatPath.Local"/> to upload, or <see cref="TailcatPath.Remote"/>/<see cref="TailcatPath.RemoteHost"/> to download.</param>
    /// <param name="target">Where to copy it to: local for a download, remote for an upload.</param>
    /// <param name="recursive">Recursively copy directories.</param>
    /// <param name="preserve">Preserve modification times and modes.</param>
    /// <param name="port">The server's SSH (file service) port, when it isn't 22.</param>
    /// <exception cref="ArgumentException">Neither <paramref name="source"/> nor <paramref name="target"/> is remote.</exception>
    public static Task<TailcatResult> CpAsync(
        TailcatClientOptions options, TailcatPath source, TailcatPath target,
        bool recursive = false, bool preserve = false, string? port = null) =>
        CpAsync(options, [source], target, recursive, preserve, port);

    /// <summary>Copies one or more sources to <paramref name="target"/> -- the multi-source form of <see cref="CpAsync(TailcatClientOptions, TailcatPath, TailcatPath, bool, bool, string?)"/>.</summary>
    /// <param name="options">Where the binaries live and how to reach the server.</param>
    /// <param name="sources">The files or directories to copy.</param>
    /// <param name="target">Where to copy them to.</param>
    /// <param name="recursive">Recursively copy directories.</param>
    /// <param name="preserve">Preserve modification times and modes.</param>
    /// <param name="port">The server's SSH (file service) port, when it isn't 22.</param>
    /// <exception cref="ArgumentException"><paramref name="sources"/> is empty; none of <paramref name="sources"/> or <paramref name="target"/> is remote; or they don't all name the same server.</exception>
    public static Task<TailcatResult> CpAsync(
        TailcatClientOptions options, IReadOnlyList<TailcatPath> sources, TailcatPath target,
        bool recursive = false, bool preserve = false, string? port = null)
    {
        if (sources.Count == 0)
            throw new ArgumentException("At least one source is required.", nameof(sources));

        var servers = new List<string>();
        foreach (var p in sources.Append(target))
        {
            if (p.Server is { } server && !servers.Contains(server)) servers.Add(server);
        }
        if (servers.Count == 0)
        {
            throw new ArgumentException(
                "At least one of the sources or the target must be remote (TailcatPath.Remote/RemoteHost); there would be no tailcat server to route the copy through.",
                nameof(sources));
        }
        if (servers.Count > 1)
        {
            throw new ArgumentException(
                $"All remote paths must name the same server ({string.Join(" and ", servers)} differ).", nameof(sources));
        }

        var cpArgs = new List<string>();
        if (recursive) cpArgs.Add("-r");
        if (preserve) cpArgs.Add("-p");
        if (!string.IsNullOrEmpty(port)) cpArgs.AddRange(["-P", port]);
        cpArgs.AddRange(sources.Select(s => s.ToString()));
        cpArgs.Add(target.ToString());

        return OperatingSystem.IsAndroid()
            ? RunMeowshellCpAsync(options, cpArgs)
            : RunAsync(options, ["cp", .. cpArgs]);
    }

    /// <summary>meowshell's own resolved environment for a session, exactly as it would hand it to a real <see cref="MeowshellServer"/>/<see cref="TailcatSshSession"/> session.</summary>
    /// <param name="options">Where the binaries live.</param>
    /// <exception cref="TailcatException">meowshell exited non-zero.</exception>
    public static async Task<TailcatEnvironment> GetEnvironmentAsync(TailcatClientOptions options)
    {
        var (meowshell, tailcat) = MeowshellBinaries.Locate(options.BinaryDirectory, options.Naming);
        Directory.CreateDirectory(options.HomeDirectory);
        var psi = new ProcessStartInfo(meowshell)
        {
            WorkingDirectory = options.HomeDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("env");
        psi.Environment["TAILCAT_BIN"] = tailcat;
        TailcatProcessEnvironment.ApplyHome(psi, options.HomeDirectory);
        var result = await RunAsync(psi, options.Timeout, "meowshell env").ConfigureAwait(false);
        if (!result.Success) throw Failure("env", result);
        return TailcatEnvironment.Parse(result.Stdout);
    }

    private static Task<TailcatResult> RunMeowshellCpAsync(TailcatClientOptions options, IReadOnlyList<string> cpArgs)
    {
        var (meowshell, tailcat) = MeowshellBinaries.Locate(options.BinaryDirectory, options.Naming);
        Directory.CreateDirectory(options.HomeDirectory);
        var psi = new ProcessStartInfo(meowshell)
        {
            WorkingDirectory = options.HomeDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        psi.ArgumentList.Add("cp");
        if (!string.IsNullOrEmpty(options.DerpMapUrl))
            psi.ArgumentList.Add($"--derpmap-url={options.DerpMapUrl}");
        if (options.Verbose)
            psi.ArgumentList.Add("--verbose");
        foreach (var a in cpArgs) psi.ArgumentList.Add(a);

        psi.Environment["TAILCAT_BIN"] = tailcat;
        TailcatProcessEnvironment.ApplyHome(psi, options.HomeDirectory);
        return RunAsync(psi, options.Timeout, "meowshell cp " + string.Join(' ', cpArgs));
    }
}
