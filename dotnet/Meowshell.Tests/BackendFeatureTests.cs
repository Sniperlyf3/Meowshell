using Meowshell;

namespace Meowshell.Tests;

public sealed class BackendFeatureTests : IDisposable
{
    private const string Address = "tcTESTADDRESS000000000000";
    private readonly string _dir = Directory.CreateTempSubdirectory("meowshell-backend-features-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public async Task ServeTargetsCanBeTheOnlyServerServiceAndArePassedThrough()
    {
        var (options, argsFile) = ServerOptions();
        await using var server = await MeowshellServer.StartAsync(options with
        {
            InsecureNoAuth = false,
            ServeTargets = ["80", "443", "8000-8010"],
        });

        var args = File.ReadAllLines(argsFile);
        Assert.Contains("--services=80,443,8000-8010", args);
    }

    [Fact]
    public async Task BlankServeTargetIsRejectedBeforeStartingAProcess()
    {
        var (options, argsFile) = ServerOptions();
        await Assert.ThrowsAsync<ArgumentException>(() => MeowshellServer.StartAsync(options with
        {
            InsecureNoAuth = false,
            ServeTargets = ["80", " "],
        }));
        Assert.False(File.Exists(argsFile));
    }

    [Fact]
    public async Task UdpForwardPassesFlagAndParsesUdpReadiness()
    {
        var bin = CreateBin();
        var argsFile = Path.Combine(_dir, "udp-forward-args");
        var meowshell = Path.Combine(bin, "libmeowshell.so");
        File.WriteAllText(meowshell,
            $"#!/bin/bash\nprintf '%s\\n' \"$@\" > {argsFile}\n" +
            "echo '# forwarding udp 127.0.0.1:15353 -> remote 53' >&2\n" +
            "exec sleep 300\n");
        MakeExecutable(meowshell);

        await using var forward = await MeowshellPortForward.StartAsync(new MeowshellPortForwardOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "udp-home"),
            Naming = BinaryNaming.Android,
            Address = Address,
            Mappings = ["0:53"],
            Udp = true,
            GracePeriod = TimeSpan.FromSeconds(2),
        });

        var args = File.ReadAllLines(argsFile);
        Assert.Contains("--udp", args);
        Assert.Equal(["127.0.0.1:15353"], forward.BoundAddresses);
    }

    private (MeowshellOptions Options, string ArgsFile) ServerOptions()
    {
        var bin = CreateBin();
        var argsFile = Path.Combine(_dir, "server-args-" + Guid.NewGuid().ToString("N"));
        var meowshell = Path.Combine(bin, "libmeowshell.so");
        File.WriteAllText(meowshell,
            $"#!/bin/bash\nprintf '%s\\n' \"$@\" > {argsFile}\n" +
            $"printf '%s' '{Address}' > \"$TAILCAT_ADDR_FILE\"\n" +
            "exec sleep 300\n");
        MakeExecutable(meowshell);

        return (new MeowshellOptions
        {
            BinaryDirectory = bin,
            HomeDirectory = Path.Combine(_dir, "home-" + Guid.NewGuid().ToString("N")),
            WorkDirectory = Path.Combine(_dir, "work-" + Guid.NewGuid().ToString("N")),
            Naming = BinaryNaming.Android,
            InsecureNoAuth = true,
            Lifetime = TimeSpan.FromMinutes(5),
            GracePeriod = TimeSpan.FromSeconds(2),
        }, argsFile);
    }

    private string CreateBin()
    {
        var bin = Path.Combine(_dir, "bin");
        Directory.CreateDirectory(bin);
        var tailcat = Path.Combine(bin, "libtailcat.so");
        if (!File.Exists(tailcat))
        {
            File.WriteAllText(tailcat, "#!/bin/bash\ntrue\n");
            MakeExecutable(tailcat);
        }
        return bin;
    }

    private static void MakeExecutable(string path) => File.SetUnixFileMode(
        path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
}
