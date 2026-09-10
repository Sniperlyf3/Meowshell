using System.Runtime.InteropServices;

namespace Meowshell;

/// <summary>Finds the meowshell and tailcat executables that ship alongside an application.</summary>
public static class BinaryLocator
{
    /// <summary>Environment variable naming a directory to search first.</summary>
    public const string DirectoryVariable = "MEOWSHELL_BINARIES";

    /// <summary>The RID whose native assets this process would use, e.g. <c>linux-arm64</c> or <c>android-arm64</c>.</summary>
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

    /// <summary>Directories to search, most specific first. Exposed so a caller can report what was tried when nothing is found.</summary>
    public static IEnumerable<string> SearchPath(string baseDirectory)
    {
        var explicitDir = Environment.GetEnvironmentVariable(DirectoryVariable);
        if (!string.IsNullOrEmpty(explicitDir))
        {
            yield return explicitDir;
        }

        yield return baseDirectory;

        yield return Path.Combine(baseDirectory, "runtimes", RuntimeIdentifier, "native");
    }

    /// <summary>Returns the first directory on the search path holding both binaries, or null if neither is complete.</summary>
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
