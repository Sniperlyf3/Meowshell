#nullable enable

namespace Meowshell;

/// <summary>Why an agent operation failed, mirroring Go's <c>errorCode</c> (cmd/meowshell/protocol.go).</summary>
public enum MeowshellErrorCode
{
    /// <summary>No error code was given -- a failure that didn't come from the agent protocol at all.</summary>
    None = 0,
    /// <summary>Authentication was refused.</summary>
    AuthFailed,
    /// <summary>A TCP-transport connection's host key has no known_hosts entry yet.</summary>
    HostKeyUnknown,
    /// <summary>A TCP-transport connection's host key does not match the one on file -- a possible MITM, never auto-retried.</summary>
    HostKeyChanged,
    /// <summary>The destination (or a --jump hop) could not be reached over the network.</summary>
    NetworkUnreachable,
    /// <summary>The operation did not complete within its allotted time.</summary>
    Timeout,
    /// <summary>The connection died after being established.</summary>
    ConnectionLost,
    /// <summary>The agent and this client disagreed about the wire protocol.</summary>
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
