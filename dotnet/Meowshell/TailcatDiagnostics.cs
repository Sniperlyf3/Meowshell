#nullable enable

namespace Meowshell;

/// <summary>
/// A bounded tail of a process's stderr, kept regardless of whether
/// anything is subscribed to its <c>Log</c> event -- so that when
/// <see cref="MeowshellServer"/>, <see cref="MeowshellSocksProxy"/>, or
/// <see cref="MeowshellPortForward"/> exits unexpectedly, there is
/// something to put in the resulting <see cref="TailcatException"/>
/// besides a bare exit code.
/// </summary>
internal sealed class TailcatDiagnostics
{
    private const int MaxLines = 50;
    private readonly object _lock = new();
    private readonly Queue<string> _lines = new();

    public void Add(string? line)
    {
        if (string.IsNullOrEmpty(line)) return;
        lock (_lock)
        {
            _lines.Enqueue(line);
            while (_lines.Count > MaxLines) _lines.Dequeue();
        }
    }

    /// <summary>The captured lines, oldest first, joined with newlines.</summary>
    public string Tail()
    {
        lock (_lock) return string.Join('\n', _lines);
    }
}
