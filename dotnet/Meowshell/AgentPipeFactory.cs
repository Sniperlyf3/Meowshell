#nullable enable
using System.IO.Pipelines;

namespace Meowshell;

/// <summary>Creates bounded output pipes with enough burst headroom for interactive SSH/SFTP traffic.</summary>
internal static class AgentPipeFactory
{
    // The default Pipe pause threshold is small enough that a burst of tiny SSH frames can
    // block the per-channel pump even while an active consumer is reading. Once blocked,
    // the separate 32-frame isolation queue can overflow and falsely fault a healthy channel.
    // One MiB still bounds an abandoned consumer tightly while giving normal PTY/SFTP bursts
    // enough byte-oriented headroom. The queue remains bounded and continues to isolate a
    // genuinely stalled channel from the shared multiplexed connection.
    internal const long PauseWriterThreshold = 1L << 20;
    internal const long ResumeWriterThreshold = 1L << 19;

    internal static Pipe CreateOutputPipe() => new(new PipeOptions(
        pauseWriterThreshold: PauseWriterThreshold,
        resumeWriterThreshold: ResumeWriterThreshold,
        useSynchronizationContext: false));
}
