using System.Text;
using Android.App;
using Android.OS;
using Android.Util;
using Android.Widget;
using Meowshell;

[assembly: Android.App.UsesPermission(Android.Manifest.Permission.Internet)]

namespace Meowshell.AndroidProbe;

[Activity(Label = "Meowshell Probe", MainLauncher = true, Exported = true)]
public sealed class MainActivity : Activity
{
    private const string Tag = "MeowshellProbe";

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);
        var status = new TextView(this) { Text = "running…" };
        SetContentView(status);
        _ = RunProbeAsync(status);
    }

    private async Task RunProbeAsync(TextView status)
    {
        try
        {
            var options = MeowshellOptions.Create(TimeSpan.FromMinutes(3)) with
            {
                InsecureNoAuth = true,
                StartTimeout = TimeSpan.FromSeconds(45),
            };

            Log.Info(Tag, $"PROBE_START nativeLibraryDir={options.BinaryDirectory}");

            await using var server = await MeowshellServer.StartAsync(
                options, onLog: line => Log.Info(Tag, $"tailcat: {line}"));
            if (string.IsNullOrWhiteSpace(server.Address))
            {
                throw new InvalidOperationException("StartAsync returned an empty address");
            }

            await RunCpProbeAsync(options);
            await RunSshSessionProbeAsync(options, server.Address);

            Log.Info(Tag, $"PROBE_PASS address_len={server.Address.Length}");
            status.Text = "PROBE_PASS";

            await server.Completed;
        }
        catch (Exception ex)
        {
            Log.Error(Tag, $"PROBE_FAIL {ex}");
            status.Text = "PROBE_FAIL: " + ex.Message;
        }
    }

    private async Task RunCpProbeAsync(MeowshellOptions shellOptions)
    {
        try
        {
            var served = Path.Combine(CacheDir!.AbsolutePath, "cp-probe-served");
            Directory.CreateDirectory(served);
            var content = $"cp probe {Guid.NewGuid():N}\n";
            await File.WriteAllTextAsync(Path.Combine(served, "probe.txt"), content);

            var filesOptions = shellOptions with
            {
                InsecureNoAuth = false,
                AuthorizedKeys = null,
                Files = served + ":ro",
            };
            await using var filesServer = await MeowshellServer.StartAsync(
                filesOptions, onLog: line => Log.Info(Tag, $"tailcat(cp-probe): {line}"));

            var clientOptions = new TailcatClientOptions
            {
                BinaryDirectory = shellOptions.BinaryDirectory,
                HomeDirectory = shellOptions.HomeDirectory,
            };
            var downloadPath = Path.Combine(CacheDir!.AbsolutePath, "cp-probe-downloaded.txt");
            var result = await TailcatClient.CpAsync(
                clientOptions,
                TailcatPath.Remote(new TailcatAddress(filesServer.Address), "probe.txt"),
                TailcatPath.Local(downloadPath));
            if (!result.Success)
                throw new InvalidOperationException($"CpAsync failed: {result.Stderr}");

            var downloaded = await File.ReadAllTextAsync(downloadPath);
            if (downloaded != content)
                throw new InvalidOperationException($"content mismatch: wrote {content.Length} chars, read back {downloaded.Length}");

            await filesServer.StopAsync();
            Log.Info(Tag, "PROBE_CP_PASS");
        }
        catch (Exception ex)
        {
            Log.Error(Tag, $"PROBE_CP_FAIL {ex}");
        }
    }

    private async Task RunSshSessionProbeAsync(MeowshellOptions shellOptions, string address)
    {
        try
        {
            var clientOptions = new TailcatClientOptions
            {
                BinaryDirectory = shellOptions.BinaryDirectory,
                HomeDirectory = shellOptions.HomeDirectory,
            };
            await using var session = await TailcatSshSession.ConnectAsync(clientOptions, address);

            var marker = $"ssh-probe-{Guid.NewGuid():N}";
            await session.WriteAsync(Encoding.UTF8.GetBytes($"echo {marker}\n"));
            await session.WriteAsync(Encoding.UTF8.GetBytes("exit\n"));

            var buffer = new byte[4096];
            var seen = new StringBuilder();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            while (!seen.ToString().Contains(marker))
            {
                var read = await session.Output.ReadAsync(buffer, timeout.Token);
                if (read == 0) break;
                seen.Append(Encoding.UTF8.GetString(buffer, 0, read));
            }
            if (!seen.ToString().Contains(marker))
                throw new InvalidOperationException($"marker never appeared in the session's output ({seen.Length} chars read)");

            await session.Completed;
            Log.Info(Tag, "PROBE_SSH_PASS");
        }
        catch (Exception ex)
        {
            Log.Error(Tag, $"PROBE_SSH_FAIL {ex}");
        }
    }
}
