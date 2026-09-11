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
