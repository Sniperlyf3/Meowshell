#nullable enable

namespace Meowshell;

/// <summary>tailcat (or meowshell) did not behave as expected -- a non-zero exit, an unexpected exit, or output that doesn't parse. <see cref="Diagnostics"/> carries tailcat's own explanation.</summary>
public sealed class TailcatException : Exception
{
    /// <summary>The process's exit code, or 0 if it exited successfully but its output didn't parse as expected.</summary>
    public int ExitCode { get; }

    /// <summary>tailcat's own explanation: captured stderr, or a description of the unexpected output when <see cref="ExitCode"/> is 0.</summary>
    public string Diagnostics { get; }

    /// <summary>The typed reason this failed, when one is known -- always set for a <see cref="MeowshellAgentConnection"/> failure, <see cref="MeowshellErrorCode.None"/> otherwise.</summary>
    public MeowshellErrorCode Code { get; }

    /// <summary>Builds a message combining a short summary with the captured diagnostics.</summary>
    public TailcatException(string summary, int exitCode, string diagnostics, MeowshellErrorCode code = MeowshellErrorCode.None)
        : base(Compose(summary, diagnostics))
    {
        ExitCode = exitCode;
        Diagnostics = diagnostics;
        Code = code;
    }

    private static string Compose(string summary, string diagnostics) =>
        string.IsNullOrWhiteSpace(diagnostics) ? summary : $"{summary}: {diagnostics}";
}
