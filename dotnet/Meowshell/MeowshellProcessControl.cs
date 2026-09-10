#nullable enable
using System.ComponentModel;
using System.Diagnostics;

namespace Meowshell;

internal static class MeowshellProcessControl
{
    private const int ETXTBSY = 26;

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
