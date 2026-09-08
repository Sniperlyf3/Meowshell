using System.Diagnostics;
using System.Text.RegularExpressions;
using Meowshell;

namespace Meowshell.PackageTests;

/// <summary>
/// Consumes Meowshell the way a real app would: as a package, not as
/// this repo's source, and with only that one package referenced (see the
/// csproj). Meowshell.Runtime.linux reaches this project only as a
/// transitive dependency, so this proves two things at once: that adding
/// just Meowshell is enough to end up with the right binaries on disk
/// (nothing else here ever adds a runtime package explicitly), and that
/// once there, MeowshellServer finds and runs them on its own, through
/// BinaryLocator's search of the package's runtimes/&lt;rid&gt;/native
/// layout. Meowshell.Tests cannot prove either: it references the
/// library by ProjectReference and hands MeowshellServer a directory it
/// built itself, so a broken package layout or a missing dependency would
/// both pass there and only surface once a consumer actually installed
/// the package.
/// </summary>
public sealed class PackageConsumptionTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("tailcat-pkgtest-").FullName;

    // tailcat client error output (e.g. a failed connection) commonly
    // echoes the target address back; with InsecureNoAuth that address
    // alone is a live credential, and the server here is still running
    // when this could fire, so it must never reach a CI log verbatim.
    private static readonly Regex AddressPattern = new(@"\btc[A-Za-z0-9_-]{10,}", RegexOptions.Compiled);
    private static string Redact(string text) => AddressPattern.Replace(text, "tc<redacted>");

    // Best-effort second layer alongside Redact() above: "::add-mask::" is a
    // GitHub Actions runner command, not a .NET/xunit feature, so there is no
    // guarantee dotnet test's captured console output is scanned for it the
    // way a shell step's stdout is. Redact() is what actually keeps the
    // address out of a failure message; this just registers it too, in case
    // it helps.
    private static void Mask(string value)
    {
        if (!string.IsNullOrEmpty(value)) Console.WriteLine("::add-mask::" + value);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void TheRuntimePackageIsFoundWithoutBeingToldWhereItIs()
    {
        var naming = BinaryNaming.ForCurrentPlatform();
        var dir = BinaryLocator.Locate(naming);

        Assert.False(string.IsNullOrEmpty(dir));
        Assert.True(File.Exists(Path.Combine(dir!, naming.FileName("tailcat"))));
        Assert.True(File.Exists(Path.Combine(dir!, naming.FileName("meowshell"))));
    }

    [Fact]
    public async Task ARealSessionRunsUsingOnlyThePackagesOwnDiscovery()
    {
        // BinaryDirectory is left unset: StartAsync must locate the
        // binaries itself, exactly as it would for a real consumer that
        // never sets it either.
        var options = new MeowshellOptions
        {
            HomeDirectory = Path.Combine(_dir, "home"),
            WorkDirectory = Path.Combine(_dir, "work"),
            InsecureNoAuth = true,
            StartTimeout = TimeSpan.FromSeconds(30),
        };

        await using var server = await MeowshellServer.StartAsync(options);
        Assert.False(string.IsNullOrWhiteSpace(server.Address));
        Mask(server.Address);

        var naming = BinaryNaming.ForCurrentPlatform();
        var tailcat = Path.Combine(BinaryLocator.Locate(naming)!, naming.FileName("tailcat"));
        var marker = $"pkg-e2e-{Guid.NewGuid():N}";

        var psi = new ProcessStartInfo(tailcat)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        psi.ArgumentList.Add("ssh");
        psi.ArgumentList.Add(server.Address);
        psi.ArgumentList.Add($"echo {marker}");

        using var client = Process.Start(psi)!;
        var stdoutTask = client.StandardOutput.ReadToEndAsync();
        var stderrTask = client.StandardError.ReadToEndAsync();
        var exited = await Task.Run(() => client.WaitForExit(30_000));
        Assert.True(exited, "tailcat ssh did not exit in time");
        var stdout = await stdoutTask;
        Assert.True(client.ExitCode == 0, $"tailcat ssh failed: {Redact(await stderrTask)}");
        Assert.Contains(marker, stdout);

        await server.StopAsync();
    }
}
