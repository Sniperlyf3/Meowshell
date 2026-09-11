using System.Diagnostics;
using Meowshell;

namespace Meowshell.Tests;

public sealed class JobObjectTests
{
    // Regression test for the old Process.Start -> JobObject.Wrap race and
    // silent fallback. Start must not return a Windows child that is outside
    // the pre-created kill-on-close job.
    [Fact]
    public async Task StartReturnsOnlyAfterChildIsInKillOnCloseJob()
    {
        if (!OperatingSystem.IsWindows()) return;

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo("cmd.exe", "/c ping 127.0.0.1 -n 30 > nul")
            {
                UseShellExecute = false,
            },
        };

        using var job = MeowshellProcessControl.Start(process);
        Assert.NotNull(job);
        Assert.True(job.IsAssigned(process));

        job.Dispose();

        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.NotEqual(0, process.ExitCode);
    }
}
