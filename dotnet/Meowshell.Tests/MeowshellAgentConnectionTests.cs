using System.ComponentModel;
using System.Diagnostics;
using Meowshell;

namespace Meowshell.Tests;

public sealed class MeowshellAgentConnectionTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("meowshell-agent-test-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static readonly SemaphoreSlim s_fakeAgentBuildLock = new(1, 1);
    private static string? s_fakeAgentBin;

    private static string? FindRepoRoot()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
        {
            if (Directory.Exists(Path.Combine(d.FullName, "e2e", "fakeagent"))) return d.FullName;
        }
        return null;
    }

    /// <summary>
    /// Builds e2e/fakeagent (see that program's own doc comment) once per test
    /// run and caches the result, or returns null -- for a test to no-op on,
    /// the same convention MeowshellServerE2ETests.RealBinaries uses -- when
    /// there's no Go toolchain available to build it with.
    /// </summary>
    private static async Task<string?> BuildFakeAgentAsync()
    {
        if (s_fakeAgentBin is not null) return s_fakeAgentBin;
        await s_fakeAgentBuildLock.WaitAsync();
        try
        {
            if (s_fakeAgentBin is not null) return s_fakeAgentBin;
            var repoRoot = FindRepoRoot();
            if (repoRoot is null) return null;

            var outPath = Path.Combine(Path.GetTempPath(), "meowshell-fakeagent-test" + (OperatingSystem.IsWindows() ? ".exe" : ""));
            var psi = new ProcessStartInfo("go")
            {
                WorkingDirectory = repoRoot,
                UseShellExecute = false,
                RedirectStandardError = true,
            };
            psi.ArgumentList.Add("build");
            psi.ArgumentList.Add("-o");
            psi.ArgumentList.Add(outPath);
            psi.ArgumentList.Add("./e2e/fakeagent");

            Process process;
            try { process = Process.Start(psi)!; }
            catch (Win32Exception) { return null; } // no "go" on PATH
            await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();
            if (process.ExitCode != 0) return null;

            s_fakeAgentBin = outPath;
            return outPath;
        }
        finally
        {
            s_fakeAgentBuildLock.Release();
        }
    }

    [Fact]
    public async Task CancellationStopsTheAgentAndRemainsCancellation()
    {
        if (OperatingSystem.IsWindows()) return;

        var bin = Path.Combine(_dir, "bin");
        Directory.CreateDirectory(bin);
        var pidFile = Path.Combine(_dir, "agent.pid");
        var script = $"#!/bin/sh\nprintf '%s' $$ > '{pidFile}'\nexec sleep 30\n";
        var naming = BinaryNaming.ForCurrentPlatform();
        foreach (var name in new[] { naming.FileName("meowshell"), naming.FileName("tailcat") })
        {
            var path = Path.Combine(bin, name);
            await File.WriteAllTextAsync(path, script);
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        using var cancellation = new CancellationTokenSource();
        var connecting = MeowshellAgentConnection.ConnectAsync(new TailcatClientOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "home"),
            Timeout = TimeSpan.FromSeconds(10),
        }, "example.invalid", cancellationToken: cancellation.Token);

        // Synchronize with the child instead of cancelling after an arbitrary
        // delay: process startup can legitimately exceed 250 ms on a busy CI
        // runner, which made this regression test test scheduler speed.
        await WaitForFileAsync(pidFile, TimeSpan.FromSeconds(5));
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => connecting);

        var pid = int.Parse(await File.ReadAllTextAsync(pidFile), System.Globalization.CultureInfo.InvariantCulture);
        Assert.False(IsRunning(pid), "the cancelled connection leaked its agent process");
    }

    /// <summary>
    /// Connects to e2e/fakeagent (see its own doc comment) the same way
    /// every test below needs to, or returns null for the caller to no-op
    /// on when there's no Go toolchain to build it with.
    /// </summary>
    private async Task<(MeowshellAgentConnection Connection, string ResultsPath)?> ConnectToFakeAgentAsync(
        string destination = "example.invalid", Action<MeowshellAgentConnection>? configureConnection = null)
    {
        var fakeAgent = await BuildFakeAgentAsync();
        if (fakeAgent is null) return null;

        var bin = Path.Combine(_dir, "bin");
        Directory.CreateDirectory(bin);
        var naming = BinaryNaming.ForCurrentPlatform();
        var meowshellPath = Path.Combine(bin, naming.FileName("meowshell"));
        // MeowshellBinaries.Locate requires a "tailcat" to exist alongside
        // "meowshell" even though this test's destination never causes it to
        // actually be invoked -- the same fake binary stands in for both.
        foreach (var name in new[] { naming.FileName("meowshell"), naming.FileName("tailcat") })
        {
            var path = Path.Combine(bin, name);
            File.Copy(fakeAgent, path);
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        var connection = await MeowshellAgentConnection.ConnectAsync(new TailcatClientOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "home"),
            Timeout = TimeSpan.FromSeconds(10),
        }, destination, configureConnection: configureConnection);
        return (connection, meowshellPath + ".results");
    }

    /// <summary>Polls a fake-agent results file for a line, up to a bound generous enough that a miss means the line is never coming, not that this ran on a slow machine.</summary>
    private static async Task<bool> WaitForResultAsync(string resultsPath, string marker, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (File.Exists(resultsPath) && (await File.ReadAllTextAsync(resultsPath)).Contains(marker)) return true;
            await Task.Delay(25);
        }
        return File.Exists(resultsPath) && (await File.ReadAllTextAsync(resultsPath)).Contains(marker);
    }

    /// <summary>
    /// Regression test: OpenChannelAsync used to track the one open_channel
    /// request in flight through a single pair of success/failure delegate
    /// fields, cleared as soon as the caller's CancellationToken fired --
    /// regardless of whether the agent had already started (or finished)
    /// creating that channel. A channel_opened arriving after that point had
    /// nothing listening for it and was silently dropped, leaking whatever
    /// the agent had just opened (a listener, an SFTP file, a shell) for the
    /// life of the connection. Each open_channel now carries its own request
    /// ID, correlated the same way SFTP ops already are, so a late response
    /// can still be recognized and closed instead of leaking.
    /// </summary>
    [Fact]
    public async Task CancelledOpenChannelIsClosedWhenTheAgentsLateReplyArrives()
    {
        if (OperatingSystem.IsWindows()) return;
        if (await ConnectToFakeAgentAsync() is not var (connection, resultsPath)) return;
        await using var _ = connection;

        // e2e/fakeagent always waits 300ms before replying to open_channel,
        // specifically so a test doesn't have to race a real (and much
        // faster, so much harder to reliably beat) open to exercise this.
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => connection.OpenLocalForwardAsync("127.0.0.1:0", "10.0.0.1:80", cancellationToken: cancellation.Token));

        Assert.True(await WaitForResultAsync(resultsPath, "CLOSED", TimeSpan.FromSeconds(5)),
            "the agent's channel_opened response (after the caller had already cancelled) was never followed by a close_channel -- the channel leaked");
    }

    /// <summary>
    /// Regression test: UploadAsync's transfer loop (after a successful
    /// open) had no try/finally around it at all. Cancelling mid-transfer
    /// (or any other failure there) skipped the close_channel the happy
    /// path sends explicitly, leaking the remote file handle and SFTP
    /// channel for the life of the connection. Cancels synchronously from
    /// inside the progress callback -- guaranteed to land between two
    /// SendDataAsync calls, never racing wall-clock timing against how fast
    /// a chunk upload happens to be.
    /// </summary>
    [Fact]
    public async Task CancelledUploadClosesTheRemoteChannel()
    {
        if (OperatingSystem.IsWindows()) return;
        if (await ConnectToFakeAgentAsync() is not var (connection, resultsPath)) return;
        await using var _ = connection;

        var localPath = Path.Combine(_dir, "upload-source.bin");
        await File.WriteAllBytesAsync(localPath, new byte[256 * 1024]); // several 64KB chunks

        using var cancellation = new CancellationTokenSource();
        var progress = new SyncProgress<long>(_ => cancellation.Cancel());

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            connection.UploadAsync(localPath, "remote.bin", progress: progress, cancellationToken: cancellation.Token));

        Assert.True(await WaitForResultAsync(resultsPath, "CLOSED", TimeSpan.FromSeconds(5)),
            "cancelling mid-upload never sent close_channel -- the remote file/channel leaked");
    }

    /// <summary>
    /// Regression test: DownloadAsync's finally block already removed the
    /// local channel entry on cancellation, but never told the agent to
    /// stop -- so the agent kept reading and sending the rest of the remote
    /// file into a channel nothing was listening for anymore. Cancelling a
    /// download must cancel the transfer, not just stop consuming it.
    /// e2e/fakeagent never sends any data or exit_status for a download
    /// channel, so once its 300ms open delay has passed, DownloadAsync's
    /// read loop is necessarily blocked waiting for data that will never
    /// arrive -- cancelling well after that (a 1s margin) is bounded by a
    /// known fixed delay, not a race against real transfer speed.
    /// </summary>
    [Fact]
    public async Task CancelledDownloadClosesTheRemoteChannel()
    {
        if (OperatingSystem.IsWindows()) return;
        if (await ConnectToFakeAgentAsync() is not var (connection, resultsPath)) return;
        await using var _ = connection;

        var localPath = Path.Combine(_dir, "download-dest.bin");
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(1));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            connection.DownloadAsync("remote.bin", localPath, cancellationToken: cancellation.Token));

        Assert.True(await WaitForResultAsync(resultsPath, "CLOSED", TimeSpan.FromSeconds(5)),
            "cancelling a stalled download never sent close_channel -- the agent kept reading/sending the remote file");
    }

    /// <summary>
    /// Regression test: DownloadAsync used to open/truncate the final destination
    /// before the transfer had succeeded. Any remote error after partial data
    /// permanently destroyed a previously valid local file. Downloads now stage
    /// into a sibling temporary file and only replace the destination after a
    /// successful terminal status.
    /// </summary>
    [Fact]
    public async Task FailedDownloadLeavesExistingDestinationUntouched()
    {
        if (OperatingSystem.IsWindows()) return;
        if (await ConnectToFakeAgentAsync() is not var (connection, _)) return;
        await using var _ = connection;

        var localPath = Path.Combine(_dir, "important-existing.bin");
        var original = "original-good-data"u8.ToArray();
        await File.WriteAllBytesAsync(localPath, original);

        await Assert.ThrowsAsync<TailcatException>(() =>
            connection.DownloadAsync("partial-then-error", localPath));

        Assert.Equal(original, await File.ReadAllBytesAsync(localPath));
        Assert.Empty(Directory.GetFiles(_dir, "important-existing.bin.meowshell-download-*"));
    }

    /// <summary>
    /// Regression test: nothing ever removed a finished shell/exec channel's
    /// entry from _channels. HandleControlAsync dispatched "exit_status" to
    /// the channel's sink and stopped there; MeowshellAgentShellChannel's own
    /// DisposeAsync only sends close_channel, it never touched _channels
    /// either. On a long-lived connection that opens many short commands
    /// (a persistent daemon's whole reason to exist), that's unbounded
    /// growth -- every completed channel stays referenced for the rest of
    /// the connection's life. e2e/fakeagent sends channel_opened followed
    /// immediately by exit_status for any kind other than sftp_download (see
    /// its own comment), so a shell open here completes on its own without
    /// this test needing to drive a real remote command.
    /// </summary>
    [Fact]
    public async Task FinishedShellChannelIsRemovedFromChannels()
    {
        if (OperatingSystem.IsWindows()) return;
        if (await ConnectToFakeAgentAsync() is not var (connection, _)) return;
        await using var _ = connection;

        // Not asserting the count mid-open: e2e/fakeagent completes a shell
        // essentially instantly (channel_opened immediately followed by
        // exit_status), so there is no reliable window where it's open but
        // not yet finished to observe -- the property that actually matters,
        // and the one this is a regression test for, is what the count
        // settles back to once everything is done.
        var before = connection.ChannelCountForTests;
        await using (var shell = await connection.OpenShellAsync())
        {
            await shell.Completed.WaitAsync(TimeSpan.FromSeconds(5));
        }

        Assert.Equal(before, connection.ChannelCountForTests);
    }

    /// <summary>
    /// Same leak, the forward side: MeowshellForward.DisposeAsync only ever
    /// sent close_channel -- the agent never sends anything back when a
    /// forward's listener closes (see closeChannel in forwarding.go), so
    /// there is no terminal message to remove the entry on. CloseForwardAsync
    /// now removes it itself, since an explicit close is the only signal
    /// that exists at all here.
    /// </summary>
    [Fact]
    public async Task ClosedForwardIsRemovedFromChannels()
    {
        if (OperatingSystem.IsWindows()) return;
        if (await ConnectToFakeAgentAsync() is not var (connection, _)) return;
        await using var _ = connection;

        var before = connection.ChannelCountForTests;
        var forward = await connection.OpenLocalForwardAsync("127.0.0.1:0", "10.0.0.1:80");
        Assert.Equal(before + 1, connection.ChannelCountForTests);

        await forward.DisposeAsync();

        Assert.Equal(before, connection.ChannelCountForTests);
    }

    /// <summary>Regression test for N5: a non-terminal "error" (Terminal:
    /// false -- the real agent sends one of these for a failed
    /// agent-forwarding setup or a rejected resize request) on an otherwise
    /// healthy shell/exec channel used to be wire-indistinguishable from a
    /// terminal one, so MeowshellAgentShellChannel's OnControlAsync faulted
    /// Completed/Output/Error over it, and AgentChannelDataPump completed its
    /// own internal queue -- both as if the channel had actually died, even
    /// though the agent kept sending real data and a real exit_status for it
    /// afterward. e2e/fakeagent's "warn-then-finish" command sends exactly
    /// that sequence (a non-terminal error, then data, then exit_status).</summary>
    [Fact]
    public async Task NonTerminalErrorDoesNotFaultTheChannel()
    {
        if (OperatingSystem.IsWindows()) return;
        if (await ConnectToFakeAgentAsync() is not var (connection, _)) return;
        await using var _ = connection;

        await using var shell = await connection.OpenExecAsync(["warn-then-finish"]);

        var output = await new StreamReader(shell.Output).ReadToEndAsync().WaitAsync(TimeSpan.FromSeconds(5));
        var exitCode = await shell.Completed.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal("still works", output);
        Assert.Equal(0, exitCode);
    }

    /// <summary>Regression test for N14: maxConnections is meant to bound the
    /// agent's per-forward accept concurrency (see forwarding.go's
    /// acceptForwardedConns), so a negative value has no coherent meaning and
    /// must be rejected here rather than silently reaching the agent as some
    /// other value entirely (JSON has no unsigned int type on the wire, so a
    /// negative int would otherwise just serialize as-is).</summary>
    [Fact]
    public async Task OpenLocalForwardRejectsANegativeMaxConnections()
    {
        if (OperatingSystem.IsWindows()) return;
        if (await ConnectToFakeAgentAsync() is not var (connection, _)) return;
        await using var _ = connection;

        var before = connection.ChannelCountForTests;
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => connection.OpenLocalForwardAsync("127.0.0.1:0", "10.0.0.1:80", maxConnections: -1));
        Assert.Equal(before, connection.ChannelCountForTests);
    }

    /// <summary>Regression test for N15: CloseAsync used to return as soon as
    /// the close_channel request was written, with no acknowledgment that the
    /// agent had actually stopped the listener -- so a caller that
    /// immediately tried to rebind the same port after CloseAsync() returned
    /// could still lose the race against the agent's own (fast, but not
    /// instant) ch.listener.Close(). e2e/fakeagent delays its "channel_closed"
    /// reply by closeDelay for a forward opened with the magic
    /// "delay-close-ack" remote address (see that program's own comments), so
    /// this measures that CloseAsync() actually blocks for roughly that long
    /// instead of returning immediately.</summary>
    [Fact]
    public async Task CloseAsyncWaitsForTheAgentsChannelClosedAcknowledgment()
    {
        if (OperatingSystem.IsWindows()) return;
        if (await ConnectToFakeAgentAsync() is not var (connection, _)) return;
        await using var _ = connection;

        var forward = await connection.OpenLocalForwardAsync("127.0.0.1:0", "delay-close-ack");

        var started = Stopwatch.StartNew();
        await forward.CloseAsync();
        started.Stop();

        Assert.True(started.Elapsed >= TimeSpan.FromMilliseconds(250),
            $"CloseAsync() returned after {started.Elapsed}, want it to have waited for the agent's delayed channel_closed acknowledgment (~300ms)");
    }

    private sealed class SyncProgress<T>(Action<T> report) : IProgress<T>
    {
        public void Report(T value) => report(value);
    }

    private static async Task WaitForFileAsync(string path, TimeSpan timeout)
    {
        using var cancellation = new CancellationTokenSource(timeout);
        while (!File.Exists(path))
        {
            await Task.Delay(10, cancellation.Token);
        }
    }

    private static bool IsRunning(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    [Fact]
    public async Task OpenLocalForwardRejectsAnExcessiveMaxConnections()
    {
        if (OperatingSystem.IsWindows()) return;
        if (await ConnectToFakeAgentAsync() is not var (connection, _)) return;
        await using var _ = connection;

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => connection.OpenLocalForwardAsync(
                "127.0.0.1:0", "10.0.0.1:80", maxConnections: 65_536));
    }

    [Fact]
    public async Task SocksAuthRejectsPartialOrOversizedCredentials()
    {
        if (OperatingSystem.IsWindows()) return;
        if (await ConnectToFakeAgentAsync() is not var (connection, _)) return;
        await using var _ = connection;

        await Assert.ThrowsAsync<ArgumentException>(
            () => connection.OpenSocksForwardAsync(
                "127.0.0.1:0", socksUsername: "only-user", socksPassword: null));

        var tooLong = new string('x', 256);
        await Assert.ThrowsAsync<ArgumentException>(
            () => connection.OpenSocksForwardAsync(
                "127.0.0.1:0", socksUsername: tooLong, socksPassword: "password"));
    }


    private sealed class BlockingDataSink(TaskCompletionSource entered, TaskCompletionSource release) : IAgentChannelSink
    {
        public async Task OnDataAsync(byte stream, ReadOnlyMemory<byte> data)
        {
            entered.TrySetResult();
            await release.Task;
        }

        public Task OnControlAsync(AgentMessage msg) => Task.CompletedTask;
        public void OnFault(Exception ex) { }
    }

    [Fact]
    public async Task ReceiveBackpressureRequestsRemoteChannelCleanupExactlyOnce()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var backpressure = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var callbackCount = 0;

        var pump = new AgentChannelDataPump(
            new BlockingDataSink(entered, release),
            () =>
            {
                Interlocked.Increment(ref callbackCount);
                backpressure.TrySetResult();
            });

        // The pump consumes the first item and blocks in the inner sink.
        await pump.OnDataAsync(0, new byte[] { 1 });
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));

        // Fill its 32-entry bounded queue, then overflow it. Every producer
        // call must return synchronously; the overflow faults only this
        // channel and asks the owner to close the remote side.
        for (var i = 0; i < 40; i++)
            await pump.OnDataAsync(0, new byte[] { 2 });

        await backpressure.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal(1, Volatile.Read(ref callbackCount));

        // Further frames for the failed channel must not request repeated
        // close operations.
        for (var i = 0; i < 10; i++)
            await pump.OnDataAsync(0, new byte[] { 3 });
        Assert.Equal(1, Volatile.Read(ref callbackCount));

        release.TrySetResult();
    }


    private const string PromptDestination = "prompt-before-connect";

    [Fact]
    public async Task ConfigureConnectionSubscribesInTimeForTheHandshakePrompts()
    {
        if (OperatingSystem.IsWindows()) return;
        var fingerprints = new List<string>();
        if (await ConnectToFakeAgentAsync(PromptDestination, connection =>
        {
            connection.HostKeyPromptRequested += (prompt, _) =>
            {
                fingerprints.Add(prompt.Fingerprint);
                return Task.FromResult(true);
            };
            connection.PasswordRequested += (_, _) => Task.FromResult("hunter2");
        }) is not var (connection, resultsPath)) return;
        await using var _ = connection;

        Assert.True(await WaitForResultAsync(resultsPath, "HOST_KEY ACCEPT true", TimeSpan.FromSeconds(5)));
        Assert.True(await WaitForResultAsync(resultsPath, "PASSWORD ANSWER hunter2", TimeSpan.FromSeconds(5)));
        Assert.NotEmpty(fingerprints);
        Assert.All(fingerprints, fingerprint => Assert.StartsWith("SHA256:", fingerprint));
    }

    [Fact]
    public async Task WithoutConfigureConnectionHandshakePromptsGoUnanswered()
    {
        if (OperatingSystem.IsWindows()) return;
        if (await ConnectToFakeAgentAsync(PromptDestination) is not var (connection, resultsPath)) return;
        await using var _ = connection;

        Assert.True(await WaitForResultAsync(resultsPath, "HOST_KEY CANCELLED", TimeSpan.FromSeconds(5)));
    }

}
