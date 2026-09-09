# Meowshell (.NET library)

Runs a tailcat shell server for a bounded period and shuts it down
afterwards, so you can open a real remote shell — Android, Linux, or
Windows — over Tailscale's data plane, without its control plane.

Targets `net8.0` (plus a Android-specific build for the `net10.0-android36.0`
target framework), with no dependencies beyond the packaged binaries below.

```sh
dotnet add package Meowshell
```

That alone is enough: `Meowshell.Runtime.{linux,windows,android}` — whichever
matches what you're building — comes along as a transitive dependency, and
`MeowshellOptions.Create` resolves the right paths for the platform it was
compiled for. No `Context`, no path, no platform check of your own.

```csharp
var options = MeowshellOptions.Create(TimeSpan.FromMinutes(5)) with
{
    AuthorizedKeys  = "alice@github",
    AllowClientKeys = "nodekey:...",
};
await using var server = await MeowshellServer.StartAsync(options);

Console.WriteLine($"connect with: tailcat ssh {server.Address}");
await server.Completed;   // or let the deadline fire, or dispose early
```

The other machine connects with plain tailcat — `tailcat ssh <address>` —
and needs an `ssh` binary on its PATH, since tailcat's client shells out to
the system one. `meowshell` itself is server-side only; don't install it on
the client.

On Android, the manifest must opt into extraction, or the binaries stay
inside the APK and never exist on disk to execute:

```xml
<application android:extractNativeLibs="true" />
```

`Meowshell` fails your build with a clear error if the corresponding MSBuild
property (`<AndroidExtractNativeLibraries>true</AndroidExtractNativeLibraries>`)
isn't set on an Android-targeting project — this is a build-time check, not
a runtime surprise.

## Supplying a key at runtime

To debug a fleet device, generate its key yourself and keep the address:

```sh
tailcat genkey --key=device-0001   # prints the address; keep it in your records
```

Hand the key to the device only when you want a session — nothing has to
come back off the device, since you already know how to reach it:

```csharp
await using var server = await MeowshellServer.StartAsync(
    MeowshellOptions.Create(TimeSpan.FromMinutes(10)) with
    {
        PrivateKeyJson  = await FetchSessionKeyAsync(),   // from your backend
        AllowClientKeys = "nodekey:<your client key>",
        AuthorizedKeys  = "you@github",
    });
// server.Address is the address you already know; no handoff needed
```

`PrivateKeyJson` is piped to `meowshell --key-stdin`, staged on an unlinked
file descriptor, and never exists as a named file. Neither end needs an open
port — both dial out to a DERP relay, so this works from behind CGNAT.

Set `AllowClientKeys` to your own client public key (`tailcat printpub`), so
a leaked device key alone doesn't grant a shell — a caller needs your client
key too.

## Packages

| Package | Contents |
| --- | --- |
| `Meowshell` | The library above: `MeowshellServer`, `MeowshellOptions`, `BinaryLocator`. |
| `Meowshell.Runtime.linux` | `tailcat`/`meowshell` for `linux-x64`, `linux-arm64`, `linux-arm`, `linux-x86`. |
| `Meowshell.Runtime.windows` | `tailcat.exe`/`meowshell.exe` for `win-x64`, `win-arm64`. |
| `Meowshell.Runtime.android` | `libtailcat.so`/`libmeowshell.so` for `android-arm64`, `android-arm`, `android-x64`, `android-x86`. |

Each runtime package lays its binaries out under `runtimes/<rid>/native/`,
NuGet's own convention for native assets, so a plain `BinaryLocator.Locate`
finds them with no configuration. Set `BinaryDirectory` on
`MeowshellOptions`, or the `MEOWSHELL_BINARIES` environment variable, to
point at a different location instead.

## What `MeowshellServer` handles, and what it cannot

It sets `TAILCAT_BIN` (`meowshell` looks for a sibling literally named
`tailcat`, which doesn't exist under Android's native library directory
where everything is `lib*.so`), sets a writable `HOME` (tailcat aborts a
session when `user.Current` fails, which on Android means whenever `HOME` is
unset), reads the address from a handoff file rather than scraping stdout,
and stops with SIGTERM before SIGKILL. It defaults to a fresh ephemeral key
per call — without that, tailcat would reuse a saved `default` key if one
exists, silently turning a throwaway address into a permanent one.

The deadline itself is enforced in-process, so it only fires while your app
is alive and running its own code. If the host process is killed outright
instead — a crash, an OOM kill, a force-stop — the OS closes the gap for
you: on Linux and Android, tailcat is armed with `PR_SET_PDEATHSIG` and the
kernel kills it the moment its parent disappears; on Windows, tailcat is
assigned to a job object that the OS tears down as soon as your process's
handles are released, which happens automatically on a crash.
