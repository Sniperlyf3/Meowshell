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
}
