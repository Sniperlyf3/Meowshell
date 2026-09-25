namespace Meowshell.Tests;

// E2EBinaries decides whether the real-binary E2E suite runs, fails, or
// quietly does nothing, so its three answers are pinned here rather than
// trusted to whichever CI configuration happens to exercise them.
public sealed class E2EBinariesTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("e2e-binaries-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string Touch(string name)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllText(path, "");
        return path;
    }

    [Fact]
    public void NeitherVariableSetMeansALocalRunThatSkips() =>
        Assert.Null(E2EBinaries.Sources(null, ""));

    [Fact]
    public void BothPointingAtFilesAreReturned()
    {
        var tailcat = Touch("tailcat");
        var meowshell = Touch("meowshell");
        Assert.Equal((tailcat, meowshell), E2EBinaries.Sources(tailcat, meowshell));
    }

    // Regression test: a set path to a file that isn't there used to read as
    // "no binaries", and every real-binary E2E test passed without running.
    [Fact]
    public void ASetPathThatDoesNotExistFailsInsteadOfSkipping()
    {
        var missing = Path.Combine(_dir, "not-built-yet");
        var ex = Assert.Throws<InvalidOperationException>(() => E2EBinaries.Sources(Touch("tailcat"), missing));
        Assert.Contains(E2EBinaries.MeowshellEnvVar, ex.Message);
        Assert.Contains(missing, ex.Message);
    }

    [Fact]
    public void OnlyOneVariableSetFailsInsteadOfSkipping() =>
        Assert.Throws<InvalidOperationException>(() => E2EBinaries.Sources(Touch("tailcat"), null));
}
