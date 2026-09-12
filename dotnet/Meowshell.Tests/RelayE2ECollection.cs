using Xunit;

namespace Meowshell.Tests;

// These classes all create real clients and ephemeral servers on the same
// public relay. Keeping them in one collection prevents xUnit from producing
// an artificial registration burst while leaving unrelated unit tests free to
// run in parallel.
[CollectionDefinition(Name)]
public sealed class RelayE2ECollection
{
    public const string Name = "Public relay E2E";
}


internal static class RelayE2E
{
    private static readonly IReadOnlyDictionary<string, string?> HermeticServerEnvironment =
        new Dictionary<string, string?>
        {
            ["TS_DEBUG_TAILCAT_LOCAL_DERP"] = "1",
            ["TAILCAT_DERPMAP_URL"] = "none",
        };

    public static MeowshellOptions HermeticServer(MeowshellOptions options) =>
        options with { ProcessEnvironmentOverrides = HermeticServerEnvironment };

    public static Task<MeowshellServer> StartServerAsync(
        MeowshellOptions options,
        CancellationToken cancellationToken = default,
        Action<string>? onLog = null) =>
        MeowshellServer.StartAsync(HermeticServer(options), cancellationToken, onLog);
}
