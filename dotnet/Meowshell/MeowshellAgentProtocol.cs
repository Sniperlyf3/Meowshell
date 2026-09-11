#nullable enable
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Meowshell;

internal static class MeowshellAgentProtocol
{
    public const byte FrameTypeControl = 0;
    public const byte FrameTypeData = 1;

    public const byte StreamStdout = 0;
    public const byte StreamStderr = 1;

    private const int FrameHeaderLength = 5;
    private const int MaxFrameLength = 64 << 20;

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
    };

    public readonly record struct AgentFrame(byte Type, uint ChannelId, byte[] Payload);

    public static async Task WriteFrameAsync(Stream stream, AgentFrame frame, CancellationToken cancellationToken)
    {
        var frameLength = checked(FrameHeaderLength + frame.Payload.Length);
        if (frameLength > MaxFrameLength)
            throw new TailcatException("meowshell agent protocol error", 0, $"frame length {frameLength} exceeds the {MaxFrameLength} limit");
        var buf = new byte[4 + frameLength];
        WriteUInt32BigEndian(buf.AsSpan(0, 4), (uint)frameLength);
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

    public static Task WriteDataAsync(Stream stream, uint channelId, ReadOnlyMemory<byte> data, CancellationToken cancellationToken) =>
        WriteFrameAsync(stream, new AgentFrame(FrameTypeData, channelId, data.ToArray()), cancellationToken);

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

        // Read the header and payload directly into their final buffers
        // instead of one body-sized buffer that then gets copied into a
        // second, payload-sized one: at the 64MiB frame limit, that used to
        // mean two ~64MiB allocations live at once (and a full-frame copy)
        // for a single incoming frame.
        var header = new byte[FrameHeaderLength];
        if (!await ReadFullAsync(stream, header, cancellationToken).ConfigureAwait(false))
            throw new TailcatException("meowshell agent protocol error", 0, "connection closed mid-frame");

        var payload = new byte[n - FrameHeaderLength];
        if (!await ReadFullAsync(stream, payload, cancellationToken).ConfigureAwait(false))
            throw new TailcatException("meowshell agent protocol error", 0, "connection closed mid-frame");

        return new AgentFrame(header[0], ReadUInt32BigEndian(header.AsSpan(1, 4)), payload);
    }

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

internal sealed class AgentMessage
{
    public string Msg { get; set; } = "";

    public string? Kind { get; set; }
    public string[]? Command { get; set; }
    public bool? Pty { get; set; }
    public int Cols { get; set; }
    public int Rows { get; set; }
    public string? Term { get; set; }

    public int ExitCode { get; set; }

    public string? Code { get; set; }
    public string? Message { get; set; }

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

    public string? KeyId { get; set; }
    public string? Algorithm { get; set; }
    public byte[]? SignData { get; set; }
    public byte[]? Signature { get; set; }

    public bool DisableAgent { get; set; }
    public byte[][]? Keys { get; set; }
    public byte[][]? Certificates { get; set; }
    public string[]? KeystoreKeyIds { get; set; }
    public byte[][]? KeystorePublicKeys { get; set; }
    public bool AgentForwarding { get; set; }

    public string? ProxyUrl { get; set; }

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

    public string? ListenAddr { get; set; }
    public string? RemoteAddr { get; set; }
    public string? BoundAddr { get; set; }

    public string? ListenNetwork { get; set; }

    public bool AllowNonLoopbackBind { get; set; }

    public string? SocksUsername { get; set; }
    public string? SocksPassword { get; set; }
}

internal sealed class AgentSftpEntry
{
    public string Name { get; set; } = "";
    public long Size { get; set; }
    public uint Mode { get; set; }
    public long ModTime { get; set; }
    public bool IsDir { get; set; }
}
