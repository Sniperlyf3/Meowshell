#nullable enable

namespace Meowshell;

/// <summary>Validates externally-supplied timeouts before anything is started.</summary>
internal static class TimeSpanValidation
{
    /// <summary>
    /// The range a <see cref="CancellationTokenSource"/> delay or <see cref="Task.Delay(TimeSpan)"/> actually
    /// accepts is 0 up to about 24.8 days, or the single special value <see cref="Timeout.InfiniteTimeSpan"/> --
    /// anything else throws <see cref="ArgumentOutOfRangeException"/> from deep inside whichever background task
    /// happens to use it first, which for a value like <see cref="MeowshellServer.StartAsync"/>'s <c>StartTimeout</c>
    /// or <see cref="TailcatClient"/>'s <c>Timeout</c> is well after a child process has already been spawned --
    /// leaking it, since disposing a <see cref="System.Diagnostics.Process"/> does not kill it. Called at the top
    /// of every entry point that starts a process, before anything is started, so a bad value fails immediately
    /// and cleanly instead of orphaning a process partway through.
    /// </summary>
    public static void EnsurePositiveAndBounded(TimeSpan value, string paramName)
    {
        if (value <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(paramName, value, $"{paramName} must be positive.");
        if (value > TimeSpan.FromMilliseconds(int.MaxValue))
            throw new ArgumentOutOfRangeException(paramName, value, $"{paramName} must not exceed {TimeSpan.FromMilliseconds(int.MaxValue)}.");
    }
}

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

    // Test-only escape hatch for process-scoped native environment knobs such
    // as TS_DEBUG_TAILCAT_LOCAL_DERP. Keeping this internal prevents callers
    // from turning arbitrary environment injection into part of the public
    // API while allowing E2E tests to scope debug knobs to exactly one child.
    internal IReadOnlyDictionary<string, string?>? ProcessEnvironmentOverrides { get; init; }
}

/// <summary>Configuration shared by every long-lived listener this library wraps, on top of <see cref="TailcatOptions"/>.</summary>
public abstract record TailcatListenerOptions : TailcatOptions
{
    /// <summary>How long to wait for the native listener to bind and report readiness.</summary>
    public TimeSpan StartTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>How long SIGTERM gets before SIGKILL.</summary>
    public TimeSpan GracePeriod { get; init; } = TimeSpan.FromSeconds(3);
}
