namespace Meowshell;

/// <summary>
/// One intermediate SSH hop in a credential-isolated jump chain.
/// </summary>
/// <remarks>
/// Each hop is established as its own Meowshell agent connection with its own
/// authentication material and prompt handlers. The next hop is reached through
/// a short-lived SOCKS5 forward on the previous connection, so credentials are
/// never shared or offered across hosts.
/// </remarks>
public sealed record MeowshellJumpHost(
    string Destination,
    MeowshellAgentConfigureOptions? Configure = null,
    string? Port = null,
    Action<MeowshellAgentConnection>? ConfigureConnection = null);

/// <summary>
/// A ProxyJump-style SSH chain whose intermediate hops each have independent
/// credentials and authentication prompts.
/// </summary>
/// <remarks>
/// The older <c>jumpHosts</c> argument on <see cref="MeowshellAgentConnection.ConnectAsync"/>
/// intentionally remains available for callers that use one authentication set
/// for an entire chain. Use this type whenever different hosts need different
/// credentials. Each intermediate connection opens an authenticated loopback
/// SOCKS5 endpoint and the following SSH connection dials through it. That keeps
/// the following host's original hostname/IP intact for known_hosts verification
/// while ensuring its credentials are only presented to that host.
/// </remarks>
public sealed class MeowshellJumpChain : IAsyncDisposable
{
    private readonly List<MeowshellAgentConnection> _connections;
    private readonly List<MeowshellForward> _forwards;
    private bool _disposed;

    private MeowshellJumpChain(
        MeowshellAgentConnection connection,
        List<MeowshellAgentConnection> connections,
        List<MeowshellForward> forwards)
    {
        Connection = connection;
        _connections = connections;
        _forwards = forwards;
    }

    /// <summary>The final destination connection. Open shells, SFTP and forwards on this connection.</summary>
    public MeowshellAgentConnection Connection { get; }

    /// <summary>
    /// Establishes <paramref name="jumpHosts"/> in order, closest-to-here first,
    /// then connects to <paramref name="destination"/> through the completed chain.
    /// </summary>
    /// <param name="options">Meowshell process/binary options shared by every hop.</param>
    /// <param name="destination">Final SSH destination.</param>
    /// <param name="configure">Authentication material for the final destination only.</param>
    /// <param name="jumpHosts">Intermediate hops, each with its own authentication material.</param>
    /// <param name="port">Final destination SSH port.</param>
    /// <param name="knownHostsPath">known_hosts path used for every TCP host in the chain.</param>
    /// <param name="proxyUrl">Optional upstream SOCKS5/HTTP CONNECT proxy used before the first hop.</param>
    /// <param name="configureConnection">Prompt/log handlers for the final destination.</param>
    /// <param name="cancellationToken">Cancels chain establishment.</param>
    public static async Task<MeowshellJumpChain> ConnectAsync(
        TailcatClientOptions options,
        string destination,
        MeowshellAgentConfigureOptions? configure = null,
        IReadOnlyList<MeowshellJumpHost>? jumpHosts = null,
        string? port = null,
        string? knownHostsPath = null,
        string? proxyUrl = null,
        Action<MeowshellAgentConnection>? configureConnection = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(destination);

        var connections = new List<MeowshellAgentConnection>();
        var forwards = new List<MeowshellForward>();
        var nextProxy = proxyUrl;

        try
        {
            if (jumpHosts is not null)
            {
                foreach (var hop in jumpHosts)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    ArgumentException.ThrowIfNullOrWhiteSpace(hop.Destination);

                    var connection = await MeowshellAgentConnection.ConnectAsync(
                        options,
                        hop.Destination,
                        configure: hop.Configure,
                        port: hop.Port,
                        jumpHosts: null,
                        knownHostsPath: knownHostsPath,
                        proxyUrl: nextProxy,
                        configureConnection: hop.ConfigureConnection,
                        cancellationToken: cancellationToken)
                        .ConfigureAwait(false);

                    connections.Add(connection);

                    // Authentication is intentionally enabled even though this is
                    // loopback-only. On Android another app can still reach a local
                    // TCP listener, so an unpredictable credential prevents it from
                    // borrowing the hop while the chain is alive.
                    var socks = await connection.OpenSocksForwardAsync(
                        "127.0.0.1:0",
                        requireAuth: true,
                        cancellationToken: cancellationToken)
                        .ConfigureAwait(false);

                    forwards.Add(socks);
                    nextProxy = SocksProxyUrl(socks);
                }
            }

            var final = await MeowshellAgentConnection.ConnectAsync(
                options,
                destination,
                configure: configure,
                port: port,
                jumpHosts: null,
                knownHostsPath: knownHostsPath,
                proxyUrl: nextProxy,
                configureConnection: configureConnection,
                cancellationToken: cancellationToken)
                .ConfigureAwait(false);

            connections.Add(final);
            return new MeowshellJumpChain(final, connections, forwards);
        }
        catch
        {
            await DisposePartialAsync(connections, forwards).ConfigureAwait(false);
            throw;
        }
    }

    private static string SocksProxyUrl(MeowshellForward forward)
    {
        if (string.IsNullOrWhiteSpace(forward.SocksUsername)
            || string.IsNullOrWhiteSpace(forward.SocksPassword))
        {
            throw new InvalidOperationException("Jump-chain SOCKS forward did not return authentication credentials.");
        }

        return $"socks5://{Uri.EscapeDataString(forward.SocksUsername)}:{Uri.EscapeDataString(forward.SocksPassword)}@{forward.BoundAddress}";
    }

    /// <summary>Closes the final connection, intermediate proxies, and jump hosts in reverse order.</summary>
    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        await DisposePartialAsync(_connections, _forwards).ConfigureAwait(false);
    }

    private static async Task DisposePartialAsync(
        IReadOnlyList<MeowshellAgentConnection> connections,
        IReadOnlyList<MeowshellForward> forwards)
    {
        for (var i = forwards.Count - 1; i >= 0; i--)
        {
            try { await forwards[i].DisposeAsync().ConfigureAwait(false); }
            catch { }
        }

        for (var i = connections.Count - 1; i >= 0; i--)
        {
            try { await connections[i].DisposeAsync().ConfigureAwait(false); }
            catch { }
        }
    }
}
