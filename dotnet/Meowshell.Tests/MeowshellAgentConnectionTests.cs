using System.Diagnostics;
using Meowshell;

namespace Meowshell.Tests;

public sealed class MeowshellAgentConnectionTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("meowshell-agent-test-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

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
}
