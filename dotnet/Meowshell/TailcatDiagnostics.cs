#nullable enable

namespace Meowshell;

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

    public string Tail()
    {
        lock (_lock) return string.Join('\n', _lines);
    }
}
