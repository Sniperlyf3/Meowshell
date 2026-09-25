namespace Meowshell.Tests;

/// <summary>
/// Where the real-binary E2E tests get their tailcat and meowshell from.
/// </summary>
/// <remarks>
/// Neither variable set means a local run without binaries: the E2E tests
/// return early, as they always have. Anything else is a CI configuration,
/// and a wrong one throws. Every E2E class used to return early on a
/// <em>missing file</em> too, so a mistyped or not-yet-built
/// <c>DOTNET_E2E_*</c> path turned the whole real-binary suite into a
/// green no-op -- the same way the Go agent E2E suite ran none of its tests
/// on Windows for as long as it existed.
/// </remarks>
internal static class E2EBinaries
{
    public const string TailcatEnvVar = "DOTNET_E2E_TAILCAT_BIN";
    public const string MeowshellEnvVar = "DOTNET_E2E_MEOWSHELL_BIN";

    /// <returns>The two source paths, or null when neither variable is set.</returns>
    public static (string Tailcat, string Meowshell)? Sources() =>
        Sources(Environment.GetEnvironmentVariable(TailcatEnvVar), Environment.GetEnvironmentVariable(MeowshellEnvVar));

    internal static (string Tailcat, string Meowshell)? Sources(string? tailcat, string? meowshell)
    {
        if (string.IsNullOrEmpty(tailcat) && string.IsNullOrEmpty(meowshell)) return null;
        if (string.IsNullOrEmpty(tailcat) || string.IsNullOrEmpty(meowshell))
            throw new InvalidOperationException(
                $"Set both ${TailcatEnvVar} and ${MeowshellEnvVar}, or neither; only one is set.");
        foreach (var (name, path) in new[] { (TailcatEnvVar, tailcat), (MeowshellEnvVar, meowshell) })
        {
            if (!File.Exists(path))
                throw new InvalidOperationException($"${name} is set to {path}, which does not exist.");
        }
        return (tailcat, meowshell);
    }
}
