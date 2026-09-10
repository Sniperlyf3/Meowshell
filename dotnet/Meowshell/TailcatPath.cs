#nullable enable

namespace Meowshell;

/// <summary>A path for <see cref="TailcatClient.CpAsync(TailcatClientOptions, TailcatPath, TailcatPath, bool, bool, string?)"/> and <see cref="TailcatClient.ListFilesAsync(TailcatClientOptions, TailcatPath, bool)"/>: either a local filesystem path, or a path on a tailcat server.</summary>
public sealed record TailcatPath
{
    /// <summary>The local filesystem path, when this is a local path.</summary>
    public string? LocalPath { get; }

    /// <summary>The server's tailcat address, when this is a remote path named by one.</summary>
    public TailcatAddress? Address { get; }

    /// <summary>The path on the server, relative to its served directory or home directory. Null means the server's default.</summary>
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

    internal string? Server => Address?.ToString() ?? _remoteHost;

    /// <summary>The scp-style argument tailcat expects: "server:path" for a remote path, the bare path for a local one.</summary>
    public override string ToString() => IsRemote ? $"{Server}:{RemotePath}" : LocalPath!;
}
