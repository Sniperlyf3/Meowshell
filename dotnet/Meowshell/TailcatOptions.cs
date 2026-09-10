#nullable enable

namespace Meowshell;

/// <summary>Configuration shared by everything in this library that reaches a tailcat server: where the binaries live, and how to dial out.</summary>
public abstract record TailcatOptions
{
    /// <summary>Directory holding the meowshell and tailcat binaries. Leave null to search for the ones shipped by a runtime package; see <see cref="BinaryLocator"/>. On Android this must be ApplicationInfo.NativeLibraryDir.</summary>
    public string? BinaryDirectory { get; init; }

    /// <summary>How the binaries are named in <see cref="BinaryDirectory"/>. Defaults to the convention for the running platform.</summary>
    public BinaryNaming Naming { get; init; } = BinaryNaming.ForCurrentPlatform();

    /// <summary>A writable HOME. Use the app's FilesDir.</summary>
    public required string HomeDirectory { get; init; }

    /// <summary>URL of a self-hosted, JSON-encoded DERP map to use instead of tailcat's default. Passed to tailcat's own <c>--derpmap-url</c>.</summary>
    public string? DerpMapUrl { get; init; }

    /// <summary>Passed to tailcat's own <c>--verbose</c>.</summary>
    public bool Verbose { get; init; }
}

/// <summary>Configuration shared by every long-lived listener this library wraps, on top of <see cref="TailcatOptions"/>.</summary>
public abstract record TailcatListenerOptions : TailcatOptions
{
    /// <summary>How long SIGTERM gets before SIGKILL.</summary>
    public TimeSpan GracePeriod { get; init; } = TimeSpan.FromSeconds(3);
}
