#nullable enable
using System.ComponentModel;
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
    // errno ETXTBSY: Linux briefly refuses to exec a file that was just
    // written, until the kernel (or a filesystem scanner that reopened it)
    // finishes releasing its own handle. Only ever observed against a
    // binary copied into place moments earlier -- an already-installed
    // executable never hits this -- so a short bounded retry clears it
    // without masking a real failure to start.
    private const int ETXTBSY = 26;

    /// <summary>Starts <paramref name="process"/>, retrying briefly on ETXTBSY.</summary>
    public static void Start(Process process)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                process.Start();
                return;
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == ETXTBSY && attempt < 5)
            {
                Thread.Sleep(50 * attempt);
            }
        }
    }

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
