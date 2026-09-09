#nullable enable

namespace Meowshell;

/// <summary>
/// A path for <see cref="TailcatClient.CpAsync(TailcatClientOptions, TailcatPath, TailcatPath, bool, bool, string?)"/>
/// and <see cref="TailcatClient.ListFilesAsync(TailcatClientOptions, TailcatPath, bool)"/>: either a
/// local filesystem path, or a path on a tailcat server. Building the
/// scp-style "&lt;tc-addr&gt;:path" text by hand is easy to get subtly
/// wrong (forgetting the colon, swapping source and target); constructing
/// one of these instead makes that string, and only that string.
/// </summary>
public sealed record TailcatPath
{
    /// <summary>The local filesystem path, when this is a local path.</summary>
    public string? LocalPath { get; }

    /// <summary>The server's tailcat address, when this is a remote path named by one.</summary>
    public TailcatAddress? Address { get; }

    /// <summary>
    /// The path on the server, relative to its served directory (a
    /// "files" service) or home directory (an ssh/no-auth-ssh one). Null
    /// means the server's default: the served/home directory itself for
    /// <see cref="TailcatClient.ListFilesAsync(TailcatClientOptions, TailcatPath, bool)"/>,
    /// or "keep the source's own name" for a
    /// <see cref="TailcatClient.CpAsync(TailcatClientOptions, TailcatPath, TailcatPath, bool, bool, string?)"/>
    /// target.
    /// </summary>
    public string? RemotePath { get; }

    private readonly string? _remoteHost;

    private TailcatPath(string? localPath, TailcatAddress? address, string? remoteHost, string? remotePath)
    {
        LocalPath = localPath;
        Address = address;
        _remoteHost = remoteHost;
        RemotePath = remotePath;
    }

    /// <summary>Whether this names a path on a server rather than the local filesystem.</summary>
    public bool IsRemote => Address is not null || _remoteHost is not null;

    /// <summary>A path on the local filesystem.</summary>
    public static TailcatPath Local(string path) => new(path, null, null, null);

    /// <summary>A path on the tailcat server at <paramref name="address"/>. Null <paramref name="path"/> means the server's default (see <see cref="RemotePath"/>).</summary>
    public static TailcatPath Remote(TailcatAddress address, string? path = null) => new(null, address, null, path);

    /// <summary>A path on the tailcat server named by <paramref name="dnsName"/>, which must carry a "tailcat=" TXT record, instead of a literal address.</summary>
    public static TailcatPath RemoteHost(string dnsName, string? path = null) => new(null, null, dnsName, path);

    /// <summary>A local path. Lets a plain string be passed anywhere a <see cref="TailcatPath"/> is expected.</summary>
    public static implicit operator TailcatPath(string localPath) => Local(localPath);

    /// <summary>The server this path names (its address as text, or its DNS name), for grouping every remote path in one call by which server they target. Null for a local path.</summary>
    internal string? Server => Address?.ToString() ?? _remoteHost;

    /// <summary>The scp-style argument tailcat expects: "server:path" for a remote path, the bare path for a local one.</summary>
    public override string ToString() => IsRemote ? $"{Server}:{RemotePath}" : LocalPath!;
}
