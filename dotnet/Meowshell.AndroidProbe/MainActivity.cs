using Android.App;
using Android.OS;
using Android.Util;
using Android.Widget;
using Meowshell;

// Denied by default; without it tailcat cannot reach the network at all,
// which would fail this probe for a reason that has nothing to do with
// whether the binaries were found.
[assembly: Android.App.UsesPermission(Android.Manifest.Permission.Internet)]

namespace Meowshell.AndroidProbe;

/// <summary>
/// Runs once on launch: calls MeowshellOptions.Create exactly as any
/// consumer would, with no path of any kind supplied by this probe, and
/// starts a real MeowshellServer -- proving both that this app's own
/// build extracted the packaged binaries where Create expects them, and
/// that Create's Android branch (compiled into Meowshell only for the
/// android target framework, see MeowshellServer.cs) actually finds them.
/// Reports the result to logcat under the tag "MeowshellProbe", which
/// dotnet/android-probe-e2e.sh polls for.
///
/// Deliberately does not stop the server once PROBE_PASS is reported:
/// android-probe-e2e.sh then dials in from a host tailcat and runs real
/// commands, which is the only thing that proves a session actually
/// works inside a real installed app's sandbox, rather than just that
/// Start() returned an address. The server's own Lifetime is what tears
/// it down; the emulator itself is torn down right after regardless.
/// </summary>
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
            // No path, no Context, no platform check: exactly what a real
            // consumer writes, on any platform.
            var options = MeowshellOptions.Create(TimeSpan.FromMinutes(3)) with
            {
                InsecureNoAuth = true,
                StartTimeout = TimeSpan.FromSeconds(45),
            };

            Log.Info(Tag, $"PROBE_START nativeLibraryDir={options.BinaryDirectory}");

            // onLog, not server.Log: StartAsync never hands the instance
            // back when it throws, which is exactly the case that needs
            // tailcat's own stderr the most.
            await using var server = await MeowshellServer.StartAsync(
                options, onLog: line => Log.Info(Tag, $"tailcat: {line}"));
            if (string.IsNullOrWhiteSpace(server.Address))
            {
                throw new InvalidOperationException("StartAsync returned an empty address");
            }

            // Runs (and logs its own PROBE_CP_PASS/PROBE_CP_FAIL) before
            // PROBE_PASS below: android-probe-e2e.sh's polling loop exits as
            // soon as it sees PROBE_PASS, so that marker has to already be
            // in logcat by then, not still pending on a fire-and-forget task.
            await RunCpProbeAsync(options);

            Log.Info(Tag, $"PROBE_PASS address_len={server.Address.Length}");
            status.Text = "PROBE_PASS";

            // Stay up for android-probe-e2e.sh's host round-trip; see the
            // class doc comment. Completed resolves once the Lifetime
            // deadline (or an early failure) tears the server down.
            await server.Completed;
        }
        catch (Exception ex)
        {
            Log.Error(Tag, $"PROBE_FAIL {ex}");
            status.Text = "PROBE_FAIL: " + ex.Message;
        }
    }

    /// <summary>
    /// A second, fully self-contained round trip, independent of the shell
    /// server above: starts its own files-only server and pulls a file back
    /// from it via TailcatClient.CpAsync. This is the only way to prove
    /// CpAsync's Android branch (meowshell's own "cp", speaking SFTP
    /// directly, never the system scp this sandbox has no room for)
    /// actually works under a real installed app's exec constraints, not
    /// just adb shell's much looser ones. Non-fatal: a failure here is
    /// logged and reported, but does not stop the shell probe above from
    /// staying up for android-probe-e2e.sh's own host round-trip.
    /// </summary>
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
}
