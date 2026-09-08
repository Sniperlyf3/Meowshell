using System.Runtime.InteropServices;

namespace Meowshell;

/// <summary>
/// Finds the meowshell and tailcat executables that ship alongside an
/// application.
/// </summary>
/// <remarks>
/// The runtime packages lay binaries out the way NuGet expects native assets,
/// under <c>runtimes/&lt;rid&gt;/native/</c>. Depending on how an app is
/// published those either stay in that layout beside the assembly or are
/// flattened into the output directory, and on Android the platform unpacks
/// them into its own native library directory instead. All three are searched.
/// </remarks>
public static class BinaryLocator
{
    /// <summary>Environment variable naming a directory to search first.</summary>
    public const string DirectoryVariable = "MEOWSHELL_BINARIES";

    /// <summary>
    /// The RID whose native assets this process would use, e.g.
    /// <c>linux-arm64</c> or <c>android-arm64</c>.
    /// </summary>
    public static string RuntimeIdentifier
    {
        get
        {
            var os =
                OperatingSystem.IsAndroid() ? "android" :
                OperatingSystem.IsWindows() ? "win" :
                OperatingSystem.IsMacOS() ? "osx" :
                "linux";
            var arch = RuntimeInformation.ProcessArchitecture switch
            {
                Architecture.X64 => "x64",
                Architecture.X86 => "x86",
                Architecture.Arm64 => "arm64",
                Architecture.Arm => "arm",
                var other => other.ToString().ToLowerInvariant(),
            };
            return $"{os}-{arch}";
        }
    }

    /// <summary>
    /// Directories to search, most specific first. Exposed so a caller can
    /// report what was tried when nothing is found.
    /// </summary>
    /// <param name="baseDirectory">Where the application was loaded from.</param>
    public static IEnumerable<string> SearchPath(string baseDirectory)
    {
        var explicitDir = Environment.GetEnvironmentVariable(DirectoryVariable);
        if (!string.IsNullOrEmpty(explicitDir))
        {
            yield return explicitDir;
        }
        // A RID-specific publish flattens native assets next to the assembly.
        yield return baseDirectory;
        // A RID-agnostic build keeps the package layout.
        yield return Path.Combine(baseDirectory, "runtimes", RuntimeIdentifier, "native");
    }

    /// <summary>
    /// Returns the first directory on the search path holding both binaries,
    /// or null if neither is complete.
    /// </summary>
    /// <param name="naming">How the binaries are named on this platform.</param>
    /// <param name="baseDirectory">Defaults to the application's base directory.</param>
    public static string? Locate(BinaryNaming naming, string? baseDirectory = null)
    {
        baseDirectory ??= AppContext.BaseDirectory;
        foreach (var dir in SearchPath(baseDirectory))
        {
            if (Directory.Exists(dir)
                && File.Exists(Path.Combine(dir, naming.FileName("meowshell")))
                && File.Exists(Path.Combine(dir, naming.FileName("tailcat"))))
            {
                return dir;
            }
        }
        return null;
    }
}
