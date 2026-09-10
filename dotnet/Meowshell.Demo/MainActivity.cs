using Android.App;
using Android.Content;
using Android.OS;
using Android.Util;
using Android.Widget;
using Meowshell;

[assembly: Android.App.UsesPermission(Android.Manifest.Permission.Internet)]

namespace Meowshell.Demo;

[Activity(Label = "Meowshell Demo", MainLauncher = true, Exported = true)]
public sealed class MainActivity : Activity
{
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
            await old.DisposeAsync();
        }

        try
        {
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
