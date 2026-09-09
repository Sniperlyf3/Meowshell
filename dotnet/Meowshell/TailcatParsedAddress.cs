#nullable enable
using System.Text.Json.Serialization;

namespace Meowshell;

/// <summary>
/// The fields a tailcat address actually carries, as decoded by
/// <c>tailcat parse</c>. Mirrors tailcat's own wire format one field at a
/// time (see tailscale/tailcat's wire.go) -- property names match its
/// JSON exactly (a few carry an explicit <c>JsonPropertyName</c> where
/// tailcat's own casing, e.g. "RegionID", isn't idiomatic C#), so this
/// deserializes directly with no custom converter. A field is null/empty
/// exactly when the address doesn't carry it: a short address (the common
/// case) has no <see cref="Region"/>; a full address (<c>tailcat
/// resolve</c>'s output, or one generated with <c>--full-address</c>)
/// embeds <see cref="Region"/> instead.
/// </summary>
/// <param name="ServerPublic">The server's public node key, e.g. "nodekey:...".</param>
/// <param name="ServerDiscoPublic">The server's public discovery key, e.g. "discokey:...", when the address carries one.</param>
/// <param name="PresharedKey">The WireGuard pre-shared key, e.g. "psk:...", when the address carries one (addresses from current servers always do, unless generated with <c>--psk=false</c>).</param>
/// <param name="Region">DERP relay details embedded directly in the address, when present, instead of referencing a region by <see cref="RegionId"/>.</param>
/// <param name="RegionId">The DERP region ID this address's server registers at, when the address references one by ID rather than embedding it.</param>
public sealed record TailcatParsedAddress(
    string ServerPublic,
    string? ServerDiscoPublic,
    string? PresharedKey,
    IReadOnlyList<TailcatDerpRegion>? Region,
    [property: JsonPropertyName("RegionID")] long RegionId);

/// <summary>One DERP region, as embedded in a full tailcat address.</summary>
/// <param name="RegionId">The region's numeric ID, when the address carries one alongside the embedded nodes.</param>
/// <param name="RegionCode">The region's short code (e.g. "nyc"), when present.</param>
/// <param name="RegionName">The region's display name, when present.</param>
/// <param name="Nodes">The DERP nodes making up this region.</param>
public sealed record TailcatDerpRegion(
    [property: JsonPropertyName("RegionID")] long RegionId,
    string? RegionCode,
    string? RegionName,
    IReadOnlyList<TailcatDerpNode>? Nodes);

/// <summary>One DERP relay node, as embedded in a full tailcat address.</summary>
/// <param name="Name">The node's short name within its region, when present.</param>
/// <param name="RegionId">The node's region ID, when it differs from its region's own (a frontend node), or is present at all.</param>
/// <param name="HostName">The hostname (or, for a self-hosted relay, an IP literal) clients dial.</param>
/// <param name="CertName">The expected TLS certificate name, when it differs from <see cref="HostName"/>.</param>
/// <param name="IPv4">An IPv4 literal to dial directly, skipping DNS, when present.</param>
/// <param name="IPv6">An IPv6 literal to dial directly, skipping DNS, when present.</param>
/// <param name="StunPort">The node's STUN port, when it differs from the default.</param>
/// <param name="DerpPort">The node's DERP (HTTPS) port, when it differs from the default (443).</param>
/// <param name="InsecureForTests">Whether the node accepts a plaintext or self-signed connection -- only ever true for a local test relay, never a real deployment.</param>
public sealed record TailcatDerpNode(
    string? Name,
    [property: JsonPropertyName("RegionID")] long RegionId,
    string? HostName,
    string? CertName,
    string? IPv4,
    string? IPv6,
    [property: JsonPropertyName("STUNPort")] int StunPort,
    [property: JsonPropertyName("DERPPort")] int DerpPort,
    bool InsecureForTests);
