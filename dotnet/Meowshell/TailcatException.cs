#nullable enable

namespace Meowshell;

/// <summary>
/// tailcat (or meowshell) did not behave as expected: it exited with a
/// non-zero code, exited unexpectedly while something was supposed to keep
/// running, or produced output that doesn't match the shape this library
/// parses. <see cref="Diagnostics"/> carries tailcat's own explanation --
/// its captured stderr, or a description of the unexpected output -- so
/// catching this one exception is normally enough to know what went wrong,
/// with no need to subscribe to a <c>Log</c> event or inspect a process
/// directly.
/// </summary>
public sealed class TailcatException : Exception
{
    /// <summary>
    /// The process's exit code, or 0 if it exited successfully but its
    /// output didn't parse as expected.
    /// </summary>
    public int ExitCode { get; }

    /// <summary>
    /// tailcat's own explanation: captured stderr (possibly just the tail
    /// of it, for a long-lived process), or a description of the
    /// unexpected output when <see cref="ExitCode"/> is 0.
    /// </summary>
    public string Diagnostics { get; }

    /// <summary>Builds a message combining a short summary with the captured diagnostics.</summary>
    public TailcatException(string summary, int exitCode, string diagnostics)
        : base(Compose(summary, diagnostics))
    {
        ExitCode = exitCode;
        Diagnostics = diagnostics;
    }

    private static string Compose(string summary, string diagnostics) =>
        string.IsNullOrWhiteSpace(diagnostics) ? summary : $"{summary}: {diagnostics}";
}
