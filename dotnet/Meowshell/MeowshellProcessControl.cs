#nullable enable
using System.Diagnostics;

namespace Meowshell;

/// <summary>
/// The stop/kill mechanics shared by every long-lived meowshell-spawned
/// process (<see cref="MeowshellServer"/>, <see cref="MeowshellSocksProxy"/>,
/// <see cref="MeowshellPortForward"/>): request a graceful stop, then kill
/// outright if that does not land in time.
/// </summary>
internal static class MeowshellProcessControl
{
    /// <summary>
    /// Asks the process to stop. Unix gets SIGTERM so tailcat can close the
    /// tunnel; Windows has no equivalent signal, so there the process is
    /// killed outright, which still tears sessions down but less tidily.
    /// </summary>
    public static void RequestStop(Process process, Func<int, int, int> kill, int sigterm)
    {
        if (OperatingSystem.IsWindows())
        {
            TryKill(process);
            return;
        }
        kill(process.Id, sigterm);
    }

    /// <summary>
    /// Kills the tree, not just the process. On Windows meowshell stays as
    /// a parent of tailcat, so killing it alone would orphan the server; on
    /// Unix the exec means there is only one process, and asking for the
    /// tree is harmless.
    /// </summary>
    public static void TryKill(Process p)
    {
        try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch { /* already gone */ }
    }
}
