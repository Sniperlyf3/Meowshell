#nullable enable
using System.Diagnostics;

namespace Meowshell;

internal static class TailcatProcessEnvironment
{
    /// <summary>
    /// Keeps tailcat/meowshell runtime state underneath the caller-selected
    /// HomeDirectory even when the parent process already defines an
    /// OS-specific config-root override.  Go's os.UserConfigDir prefers
    /// XDG_CONFIG_HOME on Unix and APPDATA on Windows, so setting HOME alone
    /// is insufficient to isolate saved keys/configuration.
    /// </summary>
    public static void ApplyHome(ProcessStartInfo psi, string homeDirectory)
    {
        psi.Environment["HOME"] = homeDirectory;

        if (OperatingSystem.IsWindows())
        {
            psi.Environment["APPDATA"] = Path.Combine(homeDirectory, "AppData", "Roaming");
            psi.Environment["LOCALAPPDATA"] = Path.Combine(homeDirectory, "AppData", "Local");
        }
        else
        {
            psi.Environment["XDG_CONFIG_HOME"] = Path.Combine(homeDirectory, ".config");
        }
    }
}
