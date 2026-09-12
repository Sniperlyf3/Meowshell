#nullable enable
using System.ComponentModel;
using System.Diagnostics;

namespace Meowshell;

internal static class MeowshellProcessControl
{
    private const int ETXTBSY = 26;
    internal const string ParentJobEnvironmentVariable = "MEOWSHELL_PARENT_JOB";
    internal const string ManagedParentPidEnvironmentVariable = "MEOWSHELL_MANAGED_PARENT_PID";

    public static JobObject? Start(Process process)
    {
        JobObject? job = null;
        if (OperatingSystem.IsWindows())
        {
            job = JobObject.CreateForChild();
            process.StartInfo.Environment[ParentJobEnvironmentVariable] = job.Name!;
        }
        else if (OperatingSystem.IsLinux() || OperatingSystem.IsAndroid())
        {
            // PR_SET_PDEATHSIG is tied to the specific parent *thread* that
            // created the child, not to this managed host process as a whole.
            // Under the .NET thread pool that can SIGKILL a healthy child
            // when only the spawning worker thread disappears. Pass the host
            // process PID instead; meowshell/tailcat use a process-level
            // watchdog for managed launches.
            process.StartInfo.Environment[ManagedParentPidEnvironmentVariable] =
                Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture);
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
            // JobObject is [SupportedOSPlatform("windows")]; job is always
            // null on other platforms, but the analyzer can't see that
            // through the assignment above, so this needs its own explicit
            // guard to avoid a CA1416 platform-compatibility build error.
            if (OperatingSystem.IsWindows())
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
