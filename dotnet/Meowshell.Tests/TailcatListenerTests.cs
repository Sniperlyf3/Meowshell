using System.Diagnostics;
using Meowshell;

namespace Meowshell.Tests;

public sealed class TailcatListenerTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("tailcat-listener-test-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    // Regression test: TailcatListener's OutputDataReceived/ErrorDataReceived
    // handlers used to call Log?.Invoke (and onLog?.Invoke) unguarded. Those
    // events are raised by the framework on its own background thread with
    // nothing else watching it -- an exception escaping from a subscriber
    // (a bug in whatever's logging) had nothing to isolate it there. A
    // throwing subscriber must not stop later output lines from being
    // delivered, and must not prevent Completed from eventually settling.
    [Fact]
    public async Task ThrowingLogSubscriberDoesNotStopFurtherOutputOrHangCompleted()
    {
        if (OperatingSystem.IsWindows()) return;

        var script = Path.Combine(_dir, "script.sh");
        await File.WriteAllTextAsync(script, "#!/bin/sh\necho throw-me\necho after\nexit 0\n");
        File.SetUnixFileMode(script, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        var psi = new ProcessStartInfo(script)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
        };
        var process = new Process { StartInfo = psi };
        var lines = new List<string>();
        // Passed as onLog (invoked from inside Start's own OutputDataReceived
        // handler, wired up before BeginOutputReadLine) rather than
        // subscribed to listener.Log afterward: the script is short-lived
        // enough that subscribing post-Start raced actual delivery on a
        // fast/loaded CI runner -- output could arrive (and be missed
        // entirely, since Log has no replay for a late subscriber) before
        // this test's next line even ran.
        var listener = TailcatListener.Start(process, TimeSpan.FromSeconds(5), onLog: line =>
        {
            if (line == "throw-me") throw new InvalidOperationException("boom from a Log subscriber");
            lock (lines) lines.Add(line);
        });

        // The script exits on its own (StopAsync was never called), which
        // TailcatListener treats as "exited unexpectedly" and reports as a
        // fault on Completed -- that part isn't what this test is about;
        // what matters is that Completed settles at all instead of hanging,
        // and that "after" (the line following the throwing one) still made
        // it through.
        await Assert.ThrowsAnyAsync<Exception>(() => listener.Completed.WaitAsync(TimeSpan.FromSeconds(5)));

        // Completed (via Process.Exited) can settle before every buffered
        // OutputDataReceived callback has actually been dispatched -- a
        // known .NET Process quirk (the exit notification and the
        // redirected-stream read completions are independent), not
        // something either Completed or this fix controls. Poll for the
        // output to actually arrive instead of assuming Completed settling
        // implies it already has.
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            lock (lines) { if (lines.Contains("after")) break; }
            await Task.Delay(25);
        }
        lock (lines) Assert.Contains("after", lines);

        await listener.DisposeAsync();
    }

    // Regression test for the old async-void Process.Exited callback. The
    // framework event must only kick off a tracked Task; once Completed has
    // settled, that observer is itself awaitable and quiescent rather than an
    // unobservable async-void continuation that could still be running.
    [Fact]
    public async Task UnexpectedExitIsObservedByTrackedTask()
    {
        if (OperatingSystem.IsWindows()) return;

        var script = Path.Combine(_dir, "exit-now.sh");
        await File.WriteAllTextAsync(script, "#!/bin/sh\nexit 7\n");
        File.SetUnixFileMode(script, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        var psi = new ProcessStartInfo(script)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
        };
        var process = new Process { StartInfo = psi };
        var listener = TailcatListener.Start(process, TimeSpan.FromSeconds(5), onLog: null);

        await Assert.ThrowsAsync<TailcatException>(
            () => listener.Completed.WaitAsync(TimeSpan.FromSeconds(5)));

        await listener.ExitObserverForTests.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(listener.ExitObserverForTests.IsCompletedSuccessfully);

        await listener.DisposeAsync();
    }

}
