#nullable enable
using System.Text;

namespace Meowshell;

/// <summary>The completed result of a non-interactive SSH command.</summary>
/// <param name="ExitCode">The remote process exit code.</param>
/// <param name="StandardOutput">UTF-8 decoded stdout.</param>
/// <param name="StandardError">UTF-8 decoded stderr.</param>
public sealed record MeowshellExecResult(int ExitCode, string StandardOutput, string StandardError)
{
    /// <summary>True when the remote command exited with code 0.</summary>
    public bool Succeeded => ExitCode == 0;
}

/// <summary>High-level execution helpers for <see cref="MeowshellAgentConnection"/>.</summary>
public static class MeowshellAgentExecution
{
    /// <summary>
    /// Runs one non-interactive command over an existing agent connection and returns its complete
    /// stdout, stderr, and exit code. Stdout and stderr are drained concurrently so a command that
    /// fills either SSH stream cannot deadlock waiting for the other stream to be consumed.
    /// </summary>
    /// <param name="connection">The already-connected SSH agent connection.</param>
    /// <param name="command">Command text interpreted by the remote SSH server.</param>
    /// <param name="timeout">Optional per-command timeout. Timeout closes only this exec channel; the persistent connection remains available.</param>
    /// <param name="cancellationToken">Cancels this command and closes only its exec channel.</param>
    /// <exception cref="ArgumentNullException"><paramref name="connection"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="command"/> is empty or whitespace.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="timeout"/> is not positive.</exception>
    /// <exception cref="TailcatException">The command exceeded <paramref name="timeout"/> or the SSH channel failed.</exception>
    public static Task<MeowshellExecResult> RunCommandAsync(
        this MeowshellAgentConnection connection,
        string command,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(connection);
        if (string.IsNullOrWhiteSpace(command))
            throw new ArgumentException("Command must not be empty.", nameof(command));

        return RunCommandAsync(connection, [command], timeout, cancellationToken);
    }

    /// <summary>
    /// Runs one non-interactive command over an existing agent connection and returns its complete
    /// stdout, stderr, and exit code. Elements are passed to <see cref="MeowshellAgentConnection.OpenExecAsync"/>,
    /// which joins them with spaces and does not add shell quoting.
    /// </summary>
    public static async Task<MeowshellExecResult> RunCommandAsync(
        this MeowshellAgentConnection connection,
        IReadOnlyList<string> command,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(command);
        if (command.Count == 0 || command.All(string.IsNullOrWhiteSpace))
            throw new ArgumentException("Command must contain at least one non-empty element.", nameof(command));
        if (timeout is { } commandTimeout && commandTimeout <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(timeout), timeout, "Timeout must be positive.");

        using var timeoutCts = timeout is null ? null : new CancellationTokenSource(timeout.Value);
        using var linkedCts = timeoutCts is null
            ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken)
            : CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

        MeowshellAgentShellChannel? channel = null;
        try
        {
            channel = await connection.OpenExecAsync(command, pty: false, cancellationToken: linkedCts.Token).ConfigureAwait(false);

            var stdoutTask = ReadUtf8Async(channel.Output, linkedCts.Token);
            var stderrTask = ReadUtf8Async(channel.Error, linkedCts.Token);
            var exitCodeTask = channel.Completed.WaitAsync(linkedCts.Token);

            await Task.WhenAll(stdoutTask, stderrTask, exitCodeTask).ConfigureAwait(false);
            return new MeowshellExecResult(
                await exitCodeTask.ConfigureAwait(false),
                await stdoutTask.ConfigureAwait(false),
                await stderrTask.ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (timeoutCts?.IsCancellationRequested == true && !cancellationToken.IsCancellationRequested)
        {
            if (channel is not null)
            {
                try { await channel.CloseAsync(CancellationToken.None).ConfigureAwait(false); } catch { }
            }

            throw new TailcatException(
                "SSH command timed out",
                0,
                $"command exceeded the {timeout} timeout",
                MeowshellErrorCode.Timeout);
        }
        catch (OperationCanceledException)
        {
            if (channel is not null)
            {
                try { await channel.CloseAsync(CancellationToken.None).ConfigureAwait(false); } catch { }
            }
            throw;
        }
        finally
        {
            if (channel is not null)
                await channel.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static async Task<string> ReadUtf8Async(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);
        return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, checked((int)buffer.Length));
    }
}
