#nullable enable

namespace Meowshell;

/// <summary>
/// Why an agent operation failed, mirroring Go's <c>errorCode</c>
/// (cmd/meowshell/protocol.go) -- lets a caller branch on what happened
/// instead of pattern-matching scraped diagnostic text.
/// <see cref="HostKeyChanged"/> in particular should drive a hard-stop
/// warning UI, never a silent retry.
/// </summary>
public enum MeowshellErrorCode
{
    /// <summary>No error code was given -- a failure that didn't come from the agent protocol at all (the process itself crashed or exited unexpectedly).</summary>
    None = 0,

    /// <summary>Authentication was refused (a wrong password/passphrase, a key the server doesn't accept, ...).</summary>
    AuthFailed,

    /// <summary>A TCP-transport connection's host key has no known_hosts entry yet -- surfaced only if a <see cref="MeowshellAgentConnection.HostKeyPromptRequested"/> handler rejected it or none was subscribed.</summary>
    HostKeyUnknown,

    /// <summary>A TCP-transport connection's host key does not match the one on file -- a possible MITM. Never auto-retried; treat this as a hard stop.</summary>
    HostKeyChanged,

    /// <summary>The destination (or a --jump hop) could not be reached over the network.</summary>
    NetworkUnreachable,

    /// <summary>The operation did not complete within its allotted time.</summary>
    Timeout,

    /// <summary>The connection died after being established (a keepalive went unanswered, the process exited).</summary>
    ConnectionLost,

    /// <summary>The agent and this client disagreed about the wire protocol -- a bug, not a remote-side failure.</summary>
    ProtocolError,

    /// <summary>The operation was cancelled, locally or by the user declining a prompt.</summary>
    Cancelled,

    /// <summary>The remote refused the operation for lack of permission.</summary>
    PermissionDenied,

    /// <summary>The remote path does not exist.</summary>
    NotFound,

    /// <summary>A failure the agent reported without (or with an unrecognized) more specific code.</summary>
    Unknown,
}

internal static class MeowshellErrorCodeExtensions
{
    public static MeowshellErrorCode Parse(string? wireValue) => wireValue switch
    {
        "auth_failed" => MeowshellErrorCode.AuthFailed,
        "host_key_unknown" => MeowshellErrorCode.HostKeyUnknown,
        "host_key_changed" => MeowshellErrorCode.HostKeyChanged,
        "network_unreachable" => MeowshellErrorCode.NetworkUnreachable,
        "timeout" => MeowshellErrorCode.Timeout,
        "connection_lost" => MeowshellErrorCode.ConnectionLost,
        "protocol_error" => MeowshellErrorCode.ProtocolError,
        "cancelled" => MeowshellErrorCode.Cancelled,
        "permission_denied" => MeowshellErrorCode.PermissionDenied,
        "not_found" => MeowshellErrorCode.NotFound,
        _ => MeowshellErrorCode.Unknown,
    };
}
