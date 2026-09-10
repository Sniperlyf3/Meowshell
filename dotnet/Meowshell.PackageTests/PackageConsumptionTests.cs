using System.Diagnostics;
using System.Text.RegularExpressions;
using Meowshell;

namespace Meowshell.PackageTests;

public sealed class PackageConsumptionTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("tailcat-pkgtest-").FullName;

    private static readonly Regex AddressPattern = new(@"\btc[A-Za-z0-9_-]{10,}", RegexOptions.Compiled);
    private static string Redact(string text) => AddressPattern.Replace(text, "tc<redacted>");

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
