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
        var listener = TailcatListener.Start(process, TimeSpan.FromSeconds(5), onLog: null);
        listener.Log += line =>
        {
            if (line == "throw-me") throw new InvalidOperationException("boom from a Log subscriber");
            lock (lines) lines.Add(line);
        };

        // The script exits on its own (StopAsync was never called), which
        // TailcatListener treats as "exited unexpectedly" and reports as a
        // fault on Completed -- that part isn't what this test is about;
        // what matters is that Completed settles at all instead of hanging,
        // and that "after" (the line following the throwing one) still made
        // it through.
        await Assert.ThrowsAnyAsync<Exception>(() => listener.Completed.WaitAsync(TimeSpan.FromSeconds(5)));

        Assert.Contains("after", lines);

        await listener.DisposeAsync();
    }
}
