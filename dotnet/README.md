# Meowshell (.NET library)

A complete C# wrapper around [tailcat](https://github.com/tailscale/tailcat):
a real remote shell, a SOCKS5 proxy, port forwarding, and one-shot key/file
operations — Android, Linux, or Windows — over Tailscale's data plane,
without its control plane. Start with the shell server below; the
[full surface](#the-full-surface) covers the rest.

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

## The full surface

`Meowshell` is a complete C# wrapper around tailcat's CLI, not just the
shell server above:

| Type | Wraps | Use it for |
| --- | --- | --- |
| `MeowshellServer` | `meowshell serve` | An interactive shell, an SFTP file service, or a forced command for one session — combinable (a shell plus file access), or standalone. |
| `MeowshellSocksProxy` | `meowshell socks` | A local SOCKS5 proxy that dials out through a tailcat server. |
| `MeowshellPortForward` | `meowshell forward` | One or more local TCP ports forwarded to a tailcat server. |
| `TailcatClient` | `tailcat genkey` / `parse` / `resolve` / `printpub` / `ping` / `ls` / `ssh` / `cp` | One-shot key management, address inspection, connectivity checks, file listing, and (not on Android) `ssh`/`scp`. |

### Why the long-lived ones go through meowshell

`MeowshellServer`, `MeowshellSocksProxy`, and `MeowshellPortForward` all
launch `meowshell` rather than `tailcat` directly — even a SOCKS proxy or a
port forward, which don't need meowshell's shell-environment fix at all.
The reason is orphan protection: before it execs `tailcat`, meowshell arms a
parent-death signal (Linux and Android) or assigns itself to a kill-on-close
job object (Windows), so if the host process dies without stopping the
listener first — a crash, an OOM kill, a force-stop — the OS tears it down
too, instead of leaving it running as an orphan. That risk exists on any
platform, but it's most worth guarding against on Android, where the OS
kills app processes far more readily — backgrounding, memory pressure — than
it does on a desktop or a server. `TailcatClient`'s operations skip all of
this and call `tailcat` directly: they're one-shot, so there's nothing left
running afterward to orphan.

### Every option

**`MeowshellOptions`** (for `MeowshellServer`) — `HomeDirectory` and
`WorkDirectory` are required; everything else has a default.

| Option | Default | What it does |
| --- | --- | --- |
| `Lifetime` | 5 minutes | How long the server may live before it shuts itself down. |
| `AuthorizedKeys` | — | SSH key sources allowed to log in (paths, literal keys, or `user@github`). Mutually exclusive with `InsecureNoAuth`. |
| `InsecureNoAuth` | `false` | Serve a shell to anyone holding the address, with no SSH auth — pair with `AllowClientKeys`. |
| `AllowClientKeys` | — | Comma-separated tailcat client keys allowed to connect. |
| `EphemeralKey` | `true` | Generate a throwaway key so the address dies with the process, instead of reusing a saved one. Ignored when `PrivateKeyJson` is set. |
| `PrivateKeyJson` | — | A `*.private.json`'s contents, piped in on stdin rather than stored on disk. |
| `StartTimeout` | 30s | How long to wait for the server to publish its address. |
| `GracePeriod` | 3s | How long SIGTERM gets before SIGKILL. |
| `DerpMapUrl` | tailcat's own default | A self-hosted, JSON-encoded DERP map to use instead. |
| `Verbose` | `false` | tailcat's own `--verbose`. |
| `FullAddress` | `false` | Embed the DERP server's info in the address, so a client can connect without fetching a DERP map. |
| `Psk` | `true` | Include a WireGuard pre-shared key in the address. Only disable it for tailcat clients v0.5.0 and earlier. |
| `Files` | — | A directory to serve over SFTP, with an optional `:ro`/`:rw`/`:wo`/`:wo+` suffix. Combinable with `AuthorizedKeys`/`InsecureNoAuth` to also serve a shell — but not together with `ForcedCommand`, which would leave the ssh service serving nothing but that one command. |
| `ForcedCommand` | none (login shell) | Run this command for every session instead of a shell, OpenSSH-`ForceCommand`-style. The command sees `TAILCAT_PEER_KEY`, `TAILCAT_REMOTE_ADDR`, `TAILCAT_LOCAL_ADDR`. |

`AuthorizedKeys`/`InsecureNoAuth`, `Files`, and `ForcedCommand` combine
freely except for that one case above — set none of the three and
`StartAsync` throws, since there'd be nothing to serve.

**`MeowshellSocksOptions`** (for `MeowshellSocksProxy`) — `HomeDirectory` required.

| Option | Default | What it does |
| --- | --- | --- |
| `Listen` | tailcat's own default | `[address]:port` to listen on; a bare port means localhost, a bare address an OS-assigned port. |
| `ClientKey` | tailcat's saved default | tailcat client key name or path. |
| `DerpMapUrl` | tailcat's own default | Same as `MeowshellOptions.DerpMapUrl`. |
| `Verbose` | `false` | Same as `MeowshellOptions.Verbose`. |
| `GracePeriod` | 3s | Same as `MeowshellOptions.GracePeriod`. |

**`MeowshellPortForwardOptions`** (for `MeowshellPortForward`) —
`HomeDirectory`, `Address`, and `Mappings` (at least one) required.

| Option | Default | What it does |
| --- | --- | --- |
| `Mappings` | — | A bare port, `local:remote`, or `local:remote-ip:remote-port` (the server must be an exit node). Local port `0` asks the OS for a free port. |
| `Bind` | `127.0.0.1` | Local address for a mapping that only names a port. |
| `ClientKey` | tailcat's saved default | Same as `MeowshellSocksOptions.ClientKey`. |
| `DerpMapUrl` | tailcat's own default | Same as `MeowshellOptions.DerpMapUrl`. |
| `Verbose` | `false` | Same as `MeowshellOptions.Verbose`. |
| `GracePeriod` | 3s | Same as `MeowshellOptions.GracePeriod`. |

**`TailcatClientOptions`** (shared by every `TailcatClient` call) — `HomeDirectory` required.

| Option | Default | What it does |
| --- | --- | --- |
| `DerpMapUrl` | tailcat's own default | Same as `MeowshellOptions.DerpMapUrl`. |
| `Verbose` | `false` | Same as `MeowshellOptions.Verbose`. |
| `Timeout` | 30s | How long to wait for the command to finish before killing it. |

`TailcatClient` methods: `GenerateKeyAsync`, `DeleteKeyAsync`, `ListKeysAsync`
(`tailcat genkey`'s three modes), `ParseAsync` (returns a typed
`TailcatParsedAddress`, not raw JSON), `ResolveAsync` (returns a
`TailcatAddress`), `PrintPubAsync`, `PingAsync` (returns a
`TailcatPingResult` — its `Pong` is the parsed "pong in ... via ..." line
when tailcat printed one, and `Success` doesn't throw on its own, since
e.g. `--until-direct` timing out is meaningful information, not an error),
`ListFilesAsync` (`tailcat ls`, pure Go SFTP — no `ssh`/`sftp` binary
involved — returns typed `TailcatFileEntry` records, not raw text), and
`SshAsync`/`CpAsync`. `GenerateKeyAsync` takes a **`TailcatKeyOptions`** —
`Name` required:

| Option | Default | What it does |
| --- | --- | --- |
| `Client` | `false` | Generate a client identity key (no DERP region) for an `--allow` list, instead of a server key. |
| `Force` | `false` | Overwrite an existing key of the same name. |
| `Region` | `auto` (nearest by latency, chosen fresh each server start) | A DERP region ID/code/substring, or comma-separated custom hostnames. |
| `FixedRegion` | `false` | Discover the nearest region once, now, and bake it into the key. |
| `EmbedDerpMap` | `false` | Embed the DERP map nodes in the address (implies `FixedRegion` unless `Region` names one). |
| `Psk` | `true` | Same as `MeowshellOptions.Psk`. |

### Errors

Everything that can go wrong at the process level -- a non-zero exit, or a
zero exit with output that doesn't match the shape this library parses --
comes back as one type, `TailcatException`, carrying `ExitCode` and
`Diagnostics` (tailcat's own captured stderr, or a description of the
unexpected output). Its `Message` already includes `Diagnostics`, so
catching it is normally enough to know what went wrong, with no need to
subscribe to a `Log` event or inspect a process yourself:

```csharp
try
{
    await using var server = await MeowshellServer.StartAsync(options);
    await server.Completed;
}
catch (TailcatException ex)
{
    Console.WriteLine($"tailcat failed ({ex.ExitCode}): {ex.Diagnostics}");
}
```

`MeowshellServer`, `MeowshellSocksProxy`, and `MeowshellPortForward` all
capture their process's stderr internally for this, whether or not
anything is subscribed to `Log`. Their `Completed` task reflects it too:
it completes successfully after a `StopAsync` call or the deadline, but
faults with a `TailcatException` if the process dies on its own first --
a crash, an OOM kill -- so awaiting `Completed` is enough to notice and
diagnose that without polling.

### What's not available on Android

`TailcatClient.SshAsync` and `CpAsync` shell out to a system `ssh`/`scp`
client, which a typical Android app sandbox doesn't provide. Both methods
exist in the API on every platform — same class, same signatures, full
IntelliSense — but throw `PlatformNotSupportedException` specifically when
running on Android, naming the alternative: `MeowshellServer` for shell
access, `TailcatClient.ListFilesAsync` for listing files over SFTP (no
system binary needed there). Everything else in this library, including
`Files`/`ForcedCommand` on `MeowshellServer`, works the same on Android as
anywhere else.

## Packages

| Package | Contents |
| --- | --- |
| `Meowshell` | Everything above: `MeowshellServer`, `MeowshellSocksProxy`, `MeowshellPortForward`, `TailcatClient`, `BinaryLocator`. |
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
you; see [why the long-lived ones go through meowshell](#why-the-long-lived-ones-go-through-meowshell)
above for how.
