using System.ComponentModel;
using System.Diagnostics;
using Meowshell;

namespace Meowshell.Tests;

/// <summary>
/// MeowshellMoshConnection (dotnet/Meowshell/MeowshellMoshConnection.cs) is a
/// separate implementation from MeowshellAgentConnection -- its own read
/// loop, its own prompt dispatch, its own Dispose -- sharing only the wire
/// format (MeowshellAgentProtocol) and the "meowshell mosh-agent" subprocess
/// convention. Before this file, nothing in either repo exercised it: no
/// test file or test body anywhere referenced Mosh at all. e2e/fakeagent
/// (see its own doc comment) stands in for the compiled "meowshell" binary
/// the same way MeowshellAgentConnectionTests.cs uses it, extended here with
/// two Mosh-specific magic destinations (moshEchoDestination,
/// moshErrorBeforeConnectDestination) for the behavior a real Mosh session
/// can't be made to reproduce on demand: a deterministic data round trip,
/// and a bootstrap failure arriving before the handshake completes.
/// </summary>
public sealed class MeowshellMoshConnectionTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("meowshell-mosh-test-").FullName;

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
    /// Builds e2e/fakeagent (see that program's own doc comment) once per
    /// test run and caches the result, or returns null -- for a test to
    /// no-op on, the same convention MeowshellAgentConnectionTests.cs and
    /// MeowshellServerE2ETests.RealBinaries use -- when there's no Go
    /// toolchain available to build it with.
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

            var outPath = Path.Combine(Path.GetTempPath(), "meowshell-fakeagent-mosh-test" + (OperatingSystem.IsWindows() ? ".exe" : ""));
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

    /// <summary>
    /// Connects to e2e/fakeagent (extended with Mosh's two magic
    /// destinations -- see the class comment) as "meowshell mosh-agent" the
    /// same way every test below needs to, or returns null for the caller
    /// to no-op on when there's no Go toolchain to build it with.
    /// </summary>
    private async Task<(MeowshellMoshConnection Connection, string ResultsPath)?> ConnectToFakeAgentAsync(
        string destination = "example.invalid", Action<MeowshellMoshConnection>? configureConnection = null, TimeSpan? timeout = null)
    {
        var fakeAgent = await BuildFakeAgentAsync();
        if (fakeAgent is null) return null;

        var bin = Path.Combine(_dir, "bin");
        Directory.CreateDirectory(bin);
        var naming = BinaryNaming.ForCurrentPlatform();
        var meowshellPath = Path.Combine(bin, naming.FileName("meowshell"));
        // MeowshellBinaries.Locate requires a "tailcat" to exist alongside
        // "meowshell" even though mosh-agent never actually invokes it --
        // the same fake binary stands in for both.
        foreach (var name in new[] { naming.FileName("meowshell"), naming.FileName("tailcat") })
        {
            var path = Path.Combine(bin, name);
            File.Copy(fakeAgent, path);
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        var connection = await MeowshellMoshConnection.ConnectAsync(new TailcatClientOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "home"),
            Timeout = timeout ?? TimeSpan.FromSeconds(10),
        }, destination, configureConnection: configureConnection);
        return (connection, meowshellPath + ".results");
    }

    [Fact]
    public async Task ConnectsSuccessfullyAndReportsConnected()
    {
        if (OperatingSystem.IsWindows()) return;
        if (await ConnectToFakeAgentAsync() is not var (connection, _)) return;
        await using var _ = connection;

        Assert.True(connection.IsConnected);
    }

    private const string PromptDestination = "prompt-before-connect";

    /// <summary>
    /// Mirrors MeowshellAgentConnectionTests.ConfigureConnectionSubscribesInTimeForTheHandshakePrompts:
    /// CLAUDE.md is explicit that prompts are raised *during* ConnectAsync
    /// and a caller must subscribe through configureConnection, since
    /// handlers attached to the object ConnectAsync eventually returns are
    /// too late to be asked. MeowshellMoshConnection re-implements this
    /// subscription and dispatch independently of MeowshellAgentConnection
    /// (HandlePromptAsync, its own switch over PromptKind), so it needs its
    /// own proof, not an assumption that sharing the wire format means
    /// sharing this behavior correctly too.
    /// </summary>
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

    /// <summary>
    /// CLAUDE.md: "A prompt with no handler is answered 'cancelled', which
    /// the Go side treats as a refusal, not as a default yes." This is the
    /// one line in the whole feature most worth pinning down for Mosh
    /// specifically -- HandlePromptAsync's default case sets
    /// response.Cancelled = true, and it would be easy for a future edit to
    /// that switch to instead leave Accept at its bool default (false is
    /// correct, but for the wrong reason) or, worse, change the default
    /// case's behavior entirely.
    /// </summary>
    [Fact]
    public async Task WithoutConfigureConnectionHandshakePromptsGoUnanswered()
    {
        if (OperatingSystem.IsWindows()) return;
        if (await ConnectToFakeAgentAsync(PromptDestination) is not var (connection, resultsPath)) return;
        await using var _ = connection;

        Assert.True(await WaitForResultAsync(resultsPath, "HOST_KEY CANCELLED", TimeSpan.FromSeconds(5)));
    }

    private const string MoshErrorBeforeConnectDestination = "mosh-error-before-connect";

    /// <summary>
    /// Regression coverage for MeowshellMoshConnection's ReadLoopAsync: an
    /// "error" control message arriving before "connected" must fail
    /// ConnectAsync with that error (TrySetException on _connected), not
    /// leave the caller waiting until the ConnectAsync timeout expires, and
    /// not report a successful connection that never happened. This is the
    /// shape a real Mosh bootstrap failure discovered mid-handshake takes
    /// (an unreachable UDP endpoint, mosh-server missing on the remote).
    /// </summary>
    [Fact]
    public async Task ErrorBeforeConnectedFailsConnectAsyncWithThatError()
    {
        if (OperatingSystem.IsWindows()) return;
        var fakeAgent = await BuildFakeAgentAsync();
        if (fakeAgent is null) return;

        var bin = Path.Combine(_dir, "bin");
        Directory.CreateDirectory(bin);
        var naming = BinaryNaming.ForCurrentPlatform();
        foreach (var name in new[] { naming.FileName("meowshell"), naming.FileName("tailcat") })
        {
            var path = Path.Combine(bin, name);
            File.Copy(fakeAgent, path);
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        var ex = await Assert.ThrowsAsync<TailcatException>(() => MeowshellMoshConnection.ConnectAsync(new TailcatClientOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "home"),
            Timeout = TimeSpan.FromSeconds(10),
        }, MoshErrorBeforeConnectDestination));

        Assert.Equal(MeowshellErrorCode.AuthFailed, ex.Code);
    }

    private const string MoshEchoDestination = "mosh-echo";

    /// <summary>
    /// Proves WriteAsync -> the agent -> ReadLoopAsync -> OutputReceived
    /// actually round-trips real bytes, including ones outside printable
    /// ASCII, through MeowshellMoshConnection end to end. A real mosh-server
    /// session cannot be scripted to echo a chosen byte sequence
    /// deterministically (what comes back depends on a real shell and a
    /// real pty), which is exactly the gap moshEchoDestination exists to
    /// close in the fake agent.
    /// </summary>
    [Fact]
    public async Task WriteAsyncRoundTripsThroughOutputReceived()
    {
        if (OperatingSystem.IsWindows()) return;
        if (await ConnectToFakeAgentAsync(MoshEchoDestination) is not var (connection, _)) return;
        await using var _ = connection;

        var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        connection.OutputReceived += (_, data) => received.TrySetResult(data.ToArray());

        var sent = new byte[] { 0x00, 0x01, (byte)'h', (byte)'i', 0xFF, 0x7F };
        await connection.WriteAsync(sent);

        var settled = await Task.WhenAny(received.Task, Task.Delay(TimeSpan.FromSeconds(5)));
        Assert.True(settled == received.Task, "OutputReceived never fired after WriteAsync");
        Assert.Equal(sent, await received.Task);
    }

    [Theory]
    [InlineData(0, 24)]
    [InlineData(80, 0)]
    [InlineData(-1, 24)]
    [InlineData(80, -1)]
    [InlineData(ushort.MaxValue + 1, 24)]
    [InlineData(80, ushort.MaxValue + 1)]
    public async Task ResizeAsyncRejectsOutOfRangeDimensions(int columns, int rows)
    {
        if (OperatingSystem.IsWindows()) return;
        if (await ConnectToFakeAgentAsync() is not var (connection, _)) return;
        await using var _ = connection;

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => connection.ResizeAsync(columns, rows));
    }

    [Fact]
    public async Task ResizeAsyncAcceptsOrdinaryDimensions()
    {
        if (OperatingSystem.IsWindows()) return;
        if (await ConnectToFakeAgentAsync() is not var (connection, _)) return;
        await using var _ = connection;

        // Just needs to not throw and not fault the connection -- the fake
        // agent has no special handling for "resize" and silently accepts
        // it, matching a real Mosh session mid-flight.
        await connection.ResizeAsync(120, 40);
        Assert.True(connection.IsConnected);
    }

    /// <summary>
    /// DisposeAsync writes close_channel on channel 1, then closes stdin and
    /// waits for the process to exit, only escalating to a kill after a 3
    /// second grace period. The fake agent's read loop returns as soon as
    /// stdin closes (see e2e/fakeagent's own doc comment, point 4, for the
    /// same acknowledgment convention MeowshellForward relies on) whether or
    /// not it understood close_channel -- so this on its own can't
    /// distinguish "close_channel was sent" from "stdin closing was enough
    /// all along". Asserting on the fake agent's CLOSED result line (only
    /// written when it actually parses that control message) closes that
    /// gap, while the elapsed-time bound catches the case where DisposeAsync
    /// stopped closing stdin at all and had to fall through to the kill
    /// grace period instead.
    /// </summary>
    [Fact]
    public async Task DisposeAsyncSendsCloseChannelAndExitsWithoutNeedingAKill()
    {
        if (OperatingSystem.IsWindows()) return;
        if (await ConnectToFakeAgentAsync() is not var (connection, resultsPath)) return;

        var started = Stopwatch.StartNew();
        await connection.DisposeAsync();
        started.Stop();

        Assert.True(await WaitForResultAsync(resultsPath, "CLOSED 1", TimeSpan.FromSeconds(5)),
            "DisposeAsync did not send a close_channel the fake agent recorded receiving");
        Assert.True(started.Elapsed < TimeSpan.FromSeconds(3),
            $"DisposeAsync took {started.Elapsed}, want well under the 3s kill grace period -- it should exit via stdin closing, not by being killed");
    }

    /// <summary>
    /// Regression test, mirroring MeowshellAgentConnectionTests.CancellationStopsTheAgentAndRemainsCancellation:
    /// cancelling ConnectAsync must both surface as OperationCanceledException
    /// and actually terminate the child "meowshell mosh-agent" process --
    /// MeowshellMoshConnection has its own ConnectAsync and its own
    /// DisposeAsync (used in the catch block when the handshake doesn't
    /// finish in time), so a leak here would be a bug specific to this
    /// class, not something MeowshellAgentConnection's own coverage would
    /// ever catch.
    ///
    /// The stand-in process must never exit by itself: an earlier draft used
    /// "exec sleep 30", and DisposeAsync's close_channel/stdin-close path
    /// does nothing to a plain sleep, so with the kill step removed
    /// (mutation-tested below) DisposeAsync's "await _readLoop" blocked on
    /// that process's still-open stdout for the entire 30 seconds -- at
    /// which point sleep exited on its own, the read loop unblocked, and the
    /// pid-liveness check below found it already gone. The test passed
    /// whether or not the kill happened, just slower. "tail -f /dev/null"
    /// never exits by itself, and the WaitAsync bound below turns "hangs
    /// until DisposeAsync's read-loop join gives up" into a fast, clearly
    /// diagnosed failure instead of a many-minute stall.
    /// </summary>
    [Fact]
    public async Task CancellationDuringConnectStopsTheProcess()
    {
        if (OperatingSystem.IsWindows()) return;

        var bin = Path.Combine(_dir, "bin");
        Directory.CreateDirectory(bin);
        var pidFile = Path.Combine(_dir, "agent.pid");
        var script = $"#!/bin/sh\nprintf '%s' $$ > '{pidFile}'\nexec tail -f /dev/null\n";
        var naming = BinaryNaming.ForCurrentPlatform();
        foreach (var name in new[] { naming.FileName("meowshell"), naming.FileName("tailcat") })
        {
            var path = Path.Combine(bin, name);
            await File.WriteAllTextAsync(path, script);
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        using var cancellation = new CancellationTokenSource();
        var connecting = MeowshellMoshConnection.ConnectAsync(new TailcatClientOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "home"),
            Timeout = TimeSpan.FromSeconds(30),
        }, "example.invalid", cancellationToken: cancellation.Token);

        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (!File.Exists(pidFile) && DateTime.UtcNow < deadline) await Task.Delay(10);
        Assert.True(File.Exists(pidFile), "the fake mosh-agent process never started");
        var pid = int.Parse(await File.ReadAllTextAsync(pidFile), System.Globalization.CultureInfo.InvariantCulture);

        try
        {
            cancellation.Cancel();
            // 15s bound: comfortably above the ~6s worst case of the real
            // 3s close/stdin-close grace plus a 3s kill grace, comfortably
            // below "forever" if DisposeAsync's read-loop join is left
            // waiting on a process nothing ever kills.
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => connecting).WaitAsync(TimeSpan.FromSeconds(15));

            var stillRunning = true;
            var killDeadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
            while (DateTime.UtcNow < killDeadline)
            {
                if (!IsRunning(pid)) { stillRunning = false; break; }
                await Task.Delay(25);
            }
            Assert.False(stillRunning, "the cancelled Mosh connection leaked its agent process");
        }
        finally
        {
            // Best-effort: a test failure above (the process was never
            // killed) would otherwise leave a "tail -f /dev/null" running
            // in this sandbox indefinitely.
            if (IsRunning(pid)) { try { Process.GetProcessById(pid).Kill(entireProcessTree: true); } catch { } }
        }
    }

    /// <summary>
    /// A "meowshell mosh-agent" that never replies at all (a hung SSH
    /// bootstrap or a stuck mosh-server exec on the real binary) must fail
    /// ConnectAsync with MeowshellErrorCode.Timeout once options.Timeout
    /// elapses, not hang forever -- and must not leak the child process
    /// once it does.
    ///
    /// Same "tail -f /dev/null" + bounded WaitAsync reasoning as
    /// CancellationDuringConnectStopsTheProcess above: the timeout path
    /// throws from inside ConnectAsync's try block and is caught by the same
    /// "await DisposeAsync(); throw;" as cancellation, so it is exposed to
    /// the identical masking failure mode if the stand-in process can exit
    /// on its own.
    /// </summary>
    [Fact]
    public async Task ConnectAsyncTimesOutWhenTheAgentNeverResponds()
    {
        if (OperatingSystem.IsWindows()) return;

        var bin = Path.Combine(_dir, "bin");
        Directory.CreateDirectory(bin);
        var pidFile = Path.Combine(_dir, "agent.pid");
        var script = $"#!/bin/sh\nprintf '%s' $$ > '{pidFile}'\nexec tail -f /dev/null\n";
        var naming = BinaryNaming.ForCurrentPlatform();
        foreach (var name in new[] { naming.FileName("meowshell"), naming.FileName("tailcat") })
        {
            var path = Path.Combine(bin, name);
            await File.WriteAllTextAsync(path, script);
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        var connecting = MeowshellMoshConnection.ConnectAsync(new TailcatClientOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "home"),
            Timeout = TimeSpan.FromMilliseconds(500),
        }, "example.invalid");

        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (!File.Exists(pidFile) && DateTime.UtcNow < deadline) await Task.Delay(10);
        Assert.True(File.Exists(pidFile), "the fake mosh-agent process never started");
        var pid = int.Parse(await File.ReadAllTextAsync(pidFile), System.Globalization.CultureInfo.InvariantCulture);

        try
        {
            var ex = await Assert.ThrowsAsync<TailcatException>(() => connecting).WaitAsync(TimeSpan.FromSeconds(15));
            Assert.Equal(MeowshellErrorCode.Timeout, ex.Code);

            var stillRunning = true;
            var killDeadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
            while (DateTime.UtcNow < killDeadline)
            {
                if (!IsRunning(pid)) { stillRunning = false; break; }
                await Task.Delay(25);
            }
            Assert.False(stillRunning, "the timed-out Mosh connection leaked its agent process");
        }
        finally
        {
            if (IsRunning(pid)) { try { Process.GetProcessById(pid).Kill(entireProcessTree: true); } catch { } }
        }
    }
}
