#nullable enable
using System.ComponentModel;
using System.Diagnostics;

namespace Meowshell;

internal static class MeowshellProcessControl
{
    private const int ETXTBSY = 26;
    internal const string ParentJobEnvironmentVariable = "MEOWSHELL_PARENT_JOB";

    public static JobObject? Start(Process process)
    {
        JobObject? job = null;
        if (OperatingSystem.IsWindows())
        {
            job = JobObject.CreateForChild();
            process.StartInfo.Environment[ParentJobEnvironmentVariable] = job.Name!;
        }

        try
        {
            for (var attempt = 1; ; attempt++)
            {
                try
                {
                    process.Start();
                    break;
                }
                catch (Win32Exception ex) when (ex.NativeErrorCode == ETXTBSY && attempt < 5)
                {
                    Thread.Sleep(50 * attempt);
                }
            }

            // Parent-side assignment is a fallback and a verification step.
            // Meowshell/tailcat join the named job at process entry, before
            // they can spawn descendants; if an externally supplied binary
            // ignores the environment variable, this still attaches it here.
            if (OperatingSystem.IsWindows())
                job!.EnsureAssigned(process);
            return job;
        }
        catch
        {
            job?.Dispose();
            throw;
        }
    }

    public static void RequestStop(Process process, Func<int, int, int> kill, int sigterm)
    {
        if (OperatingSystem.IsWindows())
        {
            TryKill(process);
            return;
        }
        kill(process.Id, sigterm);
    }

    public static void TryKill(Process p)
    {
        try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch { }
    }
}
