#nullable enable
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Meowshell;

/// <summary>
/// The framed control protocol "meowshell agent" speaks on its
/// stdin/stdout, mirroring <c>cmd/meowshell/protocol.go</c> exactly (frame
/// layout, message field names, and JSON casing all have to match its Go
/// counterpart byte for byte). Internal: <see cref="MeowshellAgentConnection"/>
/// is the public surface built on top of it.
/// </summary>
internal static class MeowshellAgentProtocol
{
    public const byte FrameTypeControl = 0;
    public const byte FrameTypeData = 1;

    public const byte StreamStdout = 0;
    public const byte StreamStderr = 1;

    private const int FrameHeaderLength = 5; // type (1) + channel id (4), counted in the length prefix
    private const int MaxFrameLength = 64 << 20;

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
    };

    /// <summary>One frame: a control message (JSON payload) or a data chunk (raw bytes, tagged with a stream byte for stdout/stderr).</summary>
    public readonly record struct AgentFrame(byte Type, uint ChannelId, byte[] Payload);

    public static async Task WriteFrameAsync(Stream stream, AgentFrame frame, CancellationToken cancellationToken)
    {
        var buf = new byte[4 + FrameHeaderLength + frame.Payload.Length];
        WriteUInt32BigEndian(buf.AsSpan(0, 4), (uint)(FrameHeaderLength + frame.Payload.Length));
        buf[4] = frame.Type;
        WriteUInt32BigEndian(buf.AsSpan(5, 4), frame.ChannelId);
        frame.Payload.CopyTo(buf.AsSpan(9));
        await stream.WriteAsync(buf, cancellationToken).ConfigureAwait(false);
    }

    public static Task WriteControlAsync(Stream stream, uint channelId, AgentMessage message, CancellationToken cancellationToken)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(message, JsonOptions);
        return WriteFrameAsync(stream, new AgentFrame(FrameTypeControl, channelId, body), cancellationToken);
    }

    /// <summary>
    /// Writes a client-to-agent data frame: raw bytes, no stream-tag byte.
    /// The tag only exists on the agent-to-client direction (stdout vs
    /// stderr for a shell/exec channel; see <see cref="StreamStdout"/>/
    /// <see cref="StreamStderr"/>) -- everything the client sends is
    /// keystrokes/command input or upload bytes, never something split
    /// across two streams, matching Go's own agent.go handleData exactly.
    /// </summary>
    public static Task WriteDataAsync(Stream stream, uint channelId, ReadOnlyMemory<byte> data, CancellationToken cancellationToken) =>
        WriteFrameAsync(stream, new AgentFrame(FrameTypeData, channelId, data.ToArray()), cancellationToken);

    /// <summary>
    /// Reads one frame, or returns null at a clean EOF (the agent process
    /// closed its stdout, e.g. after the connection ended).
    /// </summary>
    public static async Task<AgentFrame?> ReadFrameAsync(Stream stream, CancellationToken cancellationToken)
    {
        var lenBuf = new byte[4];
        if (!await ReadFullAsync(stream, lenBuf, cancellationToken).ConfigureAwait(false))
            return null;
        var n = ReadUInt32BigEndian(lenBuf);
        if (n < FrameHeaderLength)
            throw new TailcatException("meowshell agent protocol error", 0, $"frame length {n} shorter than the header alone");
        if (n > MaxFrameLength)
            throw new TailcatException("meowshell agent protocol error", 0, $"frame length {n} exceeds the {MaxFrameLength} limit");

        var body = new byte[n];
        if (!await ReadFullAsync(stream, body, cancellationToken).ConfigureAwait(false))
            throw new TailcatException("meowshell agent protocol error", 0, "connection closed mid-frame");

        var payload = new byte[n - FrameHeaderLength];
        Array.Copy(body, FrameHeaderLength, payload, 0, payload.Length);
        return new AgentFrame(body[0], ReadUInt32BigEndian(body.AsSpan(1, 4)), payload);
    }

    /// <summary>Reads exactly buf.Length bytes, or returns false if the stream ends before the first byte of this read (a clean EOF between frames).</summary>
    private static async Task<bool> ReadFullAsync(Stream stream, byte[] buf, CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < buf.Length)
        {
            var n = await stream.ReadAsync(buf.AsMemory(total), cancellationToken).ConfigureAwait(false);
            if (n == 0)
            {
                if (total == 0) return false;
                throw new TailcatException("meowshell agent protocol error", 0, "connection closed mid-frame");
            }
            total += n;
        }
        return true;
    }

    private static void WriteUInt32BigEndian(Span<byte> dest, uint value)
    {
        dest[0] = (byte)(value >> 24);
        dest[1] = (byte)(value >> 16);
        dest[2] = (byte)(value >> 8);
        dest[3] = (byte)value;
    }

    private static uint ReadUInt32BigEndian(ReadOnlySpan<byte> src) =>
        ((uint)src[0] << 24) | ((uint)src[1] << 16) | ((uint)src[2] << 8) | src[3];
}

/// <summary>
/// The JSON payload of a control frame -- one flat class mirroring Go's
/// <c>controlMessage</c> field for field (see protocol.go's own doc comment
/// for why it's one flat shape rather than a type per message). Internal:
/// <see cref="MeowshellAgentConnection"/> and its channel/prompt types are
/// the public API built on top of this.
/// </summary>
internal sealed class AgentMessage
{
    public string Msg { get; set; } = "";

    // open_channel
    public string? Kind { get; set; }
    public string[]? Command { get; set; }
    public bool? Pty { get; set; }
    public int Cols { get; set; }
    public int Rows { get; set; }
    public string? Term { get; set; }

    // exit_status
    public int ExitCode { get; set; }

    // error
    public string? Code { get; set; }
    public string? Message { get; set; }

    // prompt_request / prompt_response
    public string? RequestId { get; set; }
    public string? PromptKind { get; set; }
    public string? Remote { get; set; }
    public string? Fingerprint { get; set; }
    public string? Prompt { get; set; }
    public string? Instruction { get; set; }
    public string[]? Questions { get; set; }
    public bool[]? Echos { get; set; }
    public bool Accept { get; set; }
    public string? Answer { get; set; }
    public string[]? Answers { get; set; }
    public bool Cancelled { get; set; }

    // sign prompt
    public string? KeyId { get; set; }
    public string? Algorithm { get; set; }
    public byte[]? SignData { get; set; }
    public byte[]? Signature { get; set; }

    // configure
    public bool DisableAgent { get; set; }
    public byte[][]? Keys { get; set; }
    public byte[][]? Certificates { get; set; }
    public string[]? KeystoreKeyIds { get; set; }
    public byte[][]? KeystorePublicKeys { get; set; }
    public bool AgentForwarding { get; set; }

    /// <summary>SOCKS5/HTTP CONNECT proxy for the first TCP hop, part of configure so it never lands on the agent process's own argv.</summary>
    public string? ProxyUrl { get; set; }

    // sftp_op / sftp_result
    public string? Op { get; set; }
    public string? Path { get; set; }
    public string? NewPath { get; set; }
    public uint Mode { get; set; }
    public int Uid { get; set; }
    public int Gid { get; set; }
    public string? Target { get; set; }
    public long Size { get; set; }
    public long ModTime { get; set; }
    public bool Preserve { get; set; }
    public long BytesDone { get; set; }
    public AgentSftpEntry[]? Entries { get; set; }

    // forwarding
    public string? ListenAddr { get; set; }
    public string? RemoteAddr { get; set; }
    public string? BoundAddr { get; set; }

    /// <summary>"tcp" (default, when null/empty) or "unix" -- selects what ListenAddr means for forward_local/forward_socks.</summary>
    public string? ListenNetwork { get; set; }

    /// <summary>Must be set true to bind a "tcp" listener to anything other than loopback; ignored for ListenNetwork "unix".</summary>
    public bool AllowNonLoopbackBind { get; set; }

    /// <summary>forward_socks only: RFC 1929 username/password SOCKS5 auth. Both empty means no auth.</summary>
    public string? SocksUsername { get; set; }
    public string? SocksPassword { get; set; }
}

/// <summary>One directory entry or a single file's metadata -- an sftp_op "ls"/"stat"/"lstat" result, mirroring Go's <c>sftpEntry</c>.</summary>
internal sealed class AgentSftpEntry
{
    public string Name { get; set; } = "";
    public long Size { get; set; }
    public uint Mode { get; set; }
    public long ModTime { get; set; }
    public bool IsDir { get; set; }
}
