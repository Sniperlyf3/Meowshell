using Android.App;
using Android.Content;
using Android.OS;
using Android.Util;
using Android.Widget;
using Meowshell;

// Denied by default; without it tailcat cannot reach the network at all.
[assembly: Android.App.UsesPermission(Android.Manifest.Permission.Internet)]

namespace Meowshell.Demo;

/// <summary>
/// A real, installable demo: one button generates a fresh throwaway shell
/// address, one field lets you copy it. Tap "Regenerate" again and the old
/// address stops working immediately -- a new server, a new ephemeral key,
/// a new address.
///
/// Built the same way Meowshell.AndroidProbe is (MeowshellOptions.Create,
/// no path or platform check of any kind) but kept running and interactive,
/// since the point here is a person actually using it, not a pass/fail check.
/// </summary>
[Activity(Label = "Meowshell Demo", MainLauncher = true, Exported = true)]
public sealed class MainActivity : Activity
{
    // Long enough that nobody using the app hits it by surprise; Regenerate
    // starts a fresh server (and so a fresh deadline) at any time regardless.
    private static readonly TimeSpan ServerLifetime = TimeSpan.FromHours(4);

    private TextView _addressField = null!;
    private TextView _statusText = null!;
    private Button _regenerateButton = null!;
    private MeowshellServer? _server;

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);

        var padding = (int)(16 * Resources!.DisplayMetrics!.Density);
        var root = new LinearLayout(this)
        {
            Orientation = Orientation.Vertical,
        };
        root.SetPadding(padding, padding, padding, padding);

        var title = new TextView(this) { Text = "Tailcat shell address" };
        title.SetTextSize(ComplexUnitType.Sp, 16);
        root.AddView(title);

        _addressField = new TextView(this) { Text = "starting…" };
        _addressField.SetTextIsSelectable(true);
        _addressField.SetPadding(0, padding / 2, 0, padding / 2);
        _addressField.Click += (_, _) => CopyAddressToClipboard();
        root.AddView(_addressField);

        var hint = new TextView(this) { Text = "Tap the address to copy it. Connect with: tailcat ssh <address>" };
        hint.SetTextSize(ComplexUnitType.Sp, 12);
        root.AddView(hint);

        _regenerateButton = new Button(this) { Text = "Regenerate" };
        _regenerateButton.Click += (_, _) => _ = RegenerateAsync();
        root.AddView(_regenerateButton);

        _statusText = new TextView(this);
        _statusText.SetPadding(0, padding / 2, 0, 0);
        root.AddView(_statusText);

        SetContentView(root);

        _ = RegenerateAsync();
    }

    private async Task RegenerateAsync()
    {
        _regenerateButton.Enabled = false;
        _statusText.Text = "starting a new server…";
        _addressField.Text = "…";

        var old = _server;
        _server = null;
        if (old is not null)
        {
            // The old address must stop working before a new one is handed
            // out, not after: otherwise both would be live at once.
            await old.DisposeAsync();
        }

        try
        {
            // No path, no Context, no platform check: exactly what a real
            // consumer writes, on any platform. EphemeralKey defaults to
            // true, so this alone is what makes "Regenerate" regenerate --
            // a fresh key, and so a fresh address, every call.
            var options = MeowshellOptions.Create(ServerLifetime) with
            {
                InsecureNoAuth = true,
            };
            _server = await MeowshellServer.StartAsync(options);
            _addressField.Text = _server.Address;
            _statusText.Text = "ready";
        }
        catch (Exception ex)
        {
            _addressField.Text = "";
            _statusText.Text = "failed to start: " + ex.Message;
        }
        finally
        {
            _regenerateButton.Enabled = true;
        }
    }

    private void CopyAddressToClipboard()
    {
        if (_server is null || string.IsNullOrEmpty(_server.Address)) return;
        var clipboard = (ClipboardManager)GetSystemService(ClipboardService)!;
        clipboard.PrimaryClip = ClipData.NewPlainText("tailcat address", _server.Address);
        Toast.MakeText(this, "Copied", ToastLength.Short)?.Show();
    }

    protected override async void OnDestroy()
    {
        base.OnDestroy();
        if (_server is not null)
        {
            await _server.DisposeAsync();
        }
    }
}
