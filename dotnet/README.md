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
| `TailcatClient` | `tailcat genkey` / `parse` / `resolve` / `printpub` / `ping` / `ls` / `ssh` / `cp` | One-shot key management, address inspection, connectivity checks, file listing and transfer, and (not on Android) a console-attached `ssh` session. All work on Android too, `ssh` included via `TailcatSshSession` below. |
| `TailcatSshSession` | `meowshell connect` | A native (no system `ssh`/`sftp` binary, on any platform) interactive pseudo-terminal session, driven programmatically — raw `Output`/`WriteAsync`, not a console. The one to use anywhere there's no real console to inherit (an Android app, most of all). |
| `MeowshellAgentConnection` | `meowshell agent` | A persistent, multiplexed connection — shell/exec, the full SFTP verb set, and `-L`/`-R`/`-D` port forwarding, all over one login instead of a fresh process and handshake per operation. Also the only one of these that can reach a general (non-tailcat) SSH host, with real host-key verification and password/keyboard-interactive/certificate/Keystore-callback auth. See [below](#a-persistent-multiplexed-connection). |

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

`BinaryDirectory`/`Naming`/`HomeDirectory`/`DerpMapUrl`/`Verbose` (and, on
the three listeners, `GracePeriod`) are declared once, on `TailcatOptions`
and `TailcatListenerOptions`, and inherited by all four options types below
— not duplicated per type.

Leaving `DerpMapUrl` unset doesn't just mean "tailcat's own default" in the
literal sense of always resolving the same way: it means the flag is
omitted from the command line entirely, so tailcat's own fallback applies —
including its `TAILCAT_DERPMAP_URL` environment variable. Set that once in
the host process's environment to point every `Meowshell`/`TailcatClient`
call at a self-hosted relay without touching `DerpMapUrl` anywhere; this
repo's own CI does exactly that (see [`e2e/README.md`](../e2e/README.md)).

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
| `AllowExitNode` | `false` | Let a client's `MeowshellPortForward`/`MeowshellSocksProxy` (or a `MeowshellAgentConnection`'s own forward_local/forward_socks) reach any port this machine can dial, not just the ports above — tailcat's own "exit-node" service. Without it, forwarding to an unlisted port is refused outright, no matter which client API asks. Pair with `AllowClientKeys` to restrict who gets that reach. |
| `ForcedCommand` | none (login shell) | Run this command for every session instead of a shell, OpenSSH-`ForceCommand`-style. The command sees `TAILCAT_PEER_KEY`, `TAILCAT_REMOTE_ADDR`, `TAILCAT_LOCAL_ADDR`. |

`AuthorizedKeys`/`InsecureNoAuth`, `Files`, `AllowExitNode`, and
`ForcedCommand` combine freely except for that one case above — set none
of the four and `StartAsync` throws, since there'd be nothing to serve.

**`MeowshellSocksOptions`** (for `MeowshellSocksProxy`) — `HomeDirectory` required.

| Option | Default | What it does |
| --- | --- | --- |
| `Listen` | tailcat's own default | `[address]:port` to listen on; a bare port means localhost, a bare address an OS-assigned port. |
| `ClientKey` | tailcat's saved default | tailcat client key name or path. |
| `DerpMapUrl` | tailcat's own default | Same as `MeowshellOptions.DerpMapUrl`. |
| `Verbose` | `false` | Same as `MeowshellOptions.Verbose`. |
| `GracePeriod` | 3s | Same as `MeowshellOptions.GracePeriod`. |

`MeowshellSocksProxy` exposes a real SOCKS5 proxy, including the UDP
ASSOCIATE command — but there is currently no `MeowshellServer` on the
other end that will accept a relayed UDP datagram: `tailcat serve`'s
shipping CLI never wires up its own UDP relay support (only its test
suite and README examples do), so a UDP ASSOCIATE request against any
real `MeowshellServer`/`tailcat serve` destination fails once traffic
actually needs to flow, even though the SOCKS5 handshake for it succeeds.
TCP CONNECT and port forwarding are unaffected. Fixing this for real
would mean patching tailcat's own vendored CLI (`patches/tailcat/`), not
just meowshell — noted here as a known upstream gap rather than
something this library's API can currently paper over.

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
involved — returns typed `TailcatFileEntry` records, not raw text), `SshAsync`,
`CpAsync`, and `GetEnvironmentAsync` (`meowshell env` — the shell/home/user/
path/term/lang meowshell resolved for this environment, where it found the
tailcat binary, and any resolver warnings, as a typed `TailcatEnvironment`;
useful for diagnosing a broken sandbox up front rather than from a session
that fails mysteriously once it's already running). `GenerateKeyAsync` takes
a **`TailcatKeyOptions`** — `Name` required:

| Option | Default | What it does |
| --- | --- | --- |
| `Client` | `false` | Generate a client identity key (no DERP region) for an `--allow` list, instead of a server key. |
| `Force` | `false` | Overwrite an existing key of the same name. |
| `Region` | `auto` (nearest by latency, chosen fresh each server start) | A DERP region ID/code/substring, or comma-separated custom hostnames. |
| `FixedRegion` | `false` | Discover the nearest region once, now, and bake it into the key. |
| `EmbedDerpMap` | `false` | Embed the DERP map nodes in the address (implies `FixedRegion` unless `Region` names one). |
| `Psk` | `true` | Same as `MeowshellOptions.Psk`. |

### Remote paths

`CpAsync` and `ListFilesAsync` take **`TailcatPath`** instead of a
hand-built `"tc-addr:path"` string, so there's no scp-style text to get
subtly wrong (a missing colon, sources and target swapped):

```csharp
// Upload a local file to a directory a server offers read-write:
await TailcatClient.CpAsync(options,
    source: "photo.jpg",                                  // a plain string is always local
    target: TailcatPath.Remote(address, "photos/photo.jpg"));

// Download, and list what's there first:
var entries = await TailcatClient.ListFilesAsync(options, TailcatPath.Remote(address, "photos"));
await TailcatClient.CpAsync(options, TailcatPath.Remote(address, "photos/photo.jpg"), "local-copy.jpg");
```

`TailcatPath.Local(path)` (or a bare `string`, which converts implicitly),
`TailcatPath.Remote(address, path)`, and `TailcatPath.RemoteHost(dnsName, path)`
(for a server named by a DNS name with a "tailcat=" TXT record, instead of
a literal address) cover every case tailcat's own `cp`/`ls` accept. `CpAsync`
also takes a multi-source overload (`IReadOnlyList<TailcatPath> sources`)
for copying several local files to one remote directory in a single call,
and throws `ArgumentException` up front if nothing in the call is remote,
or if the sources and target don't all name the same server -- the same
rule tailcat itself enforces, just reported before a process ever runs.

### Interactive sessions without a console

`SshAsync` is the simplest option when there's a real console to hand
tailcat's own `ssh` client — it inherits the caller's stdio directly, the
same as running `ssh` yourself. That doesn't work at all in a process with
no console of its own (an Android app, most notably), and doesn't fit a
GUI app that wants to render the session in its own terminal widget rather
than a real OS console either way.

**`TailcatSshSession`** is for both of those: native (no system `ssh`
client involved, on any platform), giving you raw bytes instead of a
console.

```csharp
await using var session = await TailcatSshSession.ConnectAsync(options, address);
await session.WriteAsync("ls -la\n"u8.ToArray());
var buffer = new byte[4096];
int n;
while ((n = await session.Output.ReadAsync(buffer)) > 0)
{
    // Feed buffer[..n] to your own terminal renderer, or just Console.Write it.
    Console.Write(Encoding.UTF8.GetString(buffer, 0, n));
}
```

An interactive shell (the default, no `command` argument) gets a
pseudo-terminal, sized by `columns`/`rows` at connect time — there's no
live resize once the session is running. Pass `command` to run something
other than a shell, still with a pseudo-terminal unless you set
`requestPty: false`. `Completed` faults with a `TailcatException` if the
process dies unexpectedly, the same as the three listener types; call
`StopAsync` (or dispose the session) to end it deliberately.

### A persistent, multiplexed connection

`CpAsync` and `ListFilesAsync` each spawn their own bare-`tailcat` process
and their own full handshake — fine for one thing at a time, but opening a
shell *and* browsing files against the same host means two logins.
`TailcatSshSession` is already built on the daemon underneath (see
[above](#interactive-sessions-without-a-console)), but still opens its own
dedicated connection per session rather than sharing one with anything
else. **`MeowshellAgentConnection`** is what actually shares one: dial
once and keep the connection open, multiplexing every operation over it
as its own channel:

```csharp
await using var connection = await MeowshellAgentConnection.ConnectAsync(options, address);

await using var shell = await connection.OpenShellAsync();
await shell.WriteAsync("ls -la\n"u8.ToArray());
await shell.ResizeAsync(columns: 100, rows: 40);   // live, any time -- unlike TailcatSshSession

await connection.UploadAsync("photo.jpg", "photos/photo.jpg", preserve: true);
var entries = await connection.ListFilesAsync("photos");

await using var forward = await connection.OpenLocalForwardAsync("127.0.0.1:0", "10.0.0.5:5432");
Console.WriteLine($"forwarding through {forward.BoundAddress}");
```

**Forward/SOCKS access control.** A loopback TCP listener is reachable by
any other local process — on Android, by any other app on the device, not
just this one. So `OpenLocalForwardAsync`/`OpenRemoteForwardAsync`/
`OpenSocksForwardAsync` refuse to bind anything other than loopback
(`127.0.0.0/8`, `::1`, `localhost`) unless you pass `allowNonLoopbackBind:
true` deliberately, and `OpenSocksForwardAsync` requires SOCKS5
username/password auth (RFC 1929) by default — a random token is generated
for you and comes back on `MeowshellForward.SocksUsername`/`SocksPassword`;
pass `requireAuth: false` for the classic unauthenticated behavior, or your
own credentials instead of the generated pair. Where a caller (an Android
app, say) can hand a filesystem path to whatever will connect to the
forward, prefer a Unix domain socket over TCP loopback entirely —
`OpenLocalForwardOnUnixSocketAsync`/`OpenSocksForwardOnUnixSocketAsync`
bind a `0600` socket under a path you choose, so filesystem permissions
(not "which port happened to be free") are what restrict access:

```csharp
await using var forward = await connection.OpenLocalForwardOnUnixSocketAsync(
    Path.Combine(appPrivateDir, "pg.sock"), "10.0.0.5:5432");

await using var socks = await connection.OpenSocksForwardAsync("127.0.0.1:0");
Console.WriteLine($"SOCKS5 proxy at {socks.BoundAddress}, auth {socks.SocksUsername}:{socks.SocksPassword}");
```

It's also the only type here that can reach a **general SSH host**, not
just a tailcat address — pass `"[user@]host[:port]"` instead of a tailcat
address, and it dials over TCP with real host-key verification (a
`known_hosts` file, trust-on-first-use for a host seen for the first
time) instead of tailcat's own WireGuard-peer trust. `jumpHosts` chains
through one or more bastions first, and `proxyUrl` reaches the first hop
through a SOCKS5 or HTTP CONNECT proxy — credentials embedded in it never
land on the agent process's own command line (readable via `/proc/<pid>/cmdline`
by anything sharing enough local privilege), the same reasoning the auth
material below already gets right.

Auth beyond a local ssh-agent — which Android has none of, so this is
what actually makes an authenticated server reachable from an app —
comes from `MeowshellAgentConfigureOptions` (private keys and OpenSSH
certificates as bytes, never written to disk; Keystore-backed keys that
never leave the app at all, signing through the `SignRequested` event
instead) plus prompt events answered asynchronously: `HostKeyPromptRequested`,
`PasswordRequested`, `PassphraseRequested`, `KeyboardInteractiveRequested`.
Subscribe before calling `ConnectAsync`, since a prompt can fire mid-call.

The full SFTP verb set (`MkdirAsync`, `RenameAsync`, `ChmodAsync`,
`SymlinkAsync`, `TruncateAsync`, ...) is here too, alongside
`UploadAsync`/`DownloadAsync` with an `IProgress<T>` callback and
cancellation via the token — `CpAsync`/`ListFilesAsync` above cover the
common case with a simpler call shape; reach for this when you also need
a shell or a forward on the same connection, or need an op neither of
those expose.

**Forwarding note:** `OpenLocalForwardAsync`/`OpenSocksForwardAsync` also
work against a tailcat address, not just a general SSH host: tailcat's own
embedded SSH service never implements SSH-level port forwarding at all (it
only ever served a shell/SFTP), so these dial out through a native tailcat
client instead when the destination is a tailcat address — the same
mechanism `MeowshellPortForward`/`MeowshellSocksProxy` (over
`tailcat forward`/`tailcat socks`) already use. Either way, the *server*
has to allow it: `MeowshellOptions.AllowExitNode` requests tailcat's own
"exit-node" service, without which a forward to any port the server isn't
already otherwise serving is refused outright — a real, protocol-level
requirement of tailcat itself, the same for every client API. `OpenRemoteForwardAsync`
("-R", asking the *far end* to open a listener) is the one exception: it's
SSH-only, since tailcat has no equivalent feature to fall back to.

### Errors

Everything that can go wrong at the process level -- a non-zero exit, or a
zero exit with output that doesn't match the shape this library parses --
comes back as one type, `TailcatException`, carrying `ExitCode` and
`Diagnostics` (tailcat's own captured stderr, or a description of the
unexpected output). Its `Message` already includes `Diagnostics`, so
catching it is normally enough to know what went wrong, with no need to
subscribe to a `Log` event or inspect a process yourself. A failure from
`MeowshellAgentConnection` also carries a typed `Code` (`MeowshellErrorCode`)
-- `HostKeyChanged`, `AuthFailed`, `ConnectionLost`, and so on -- so a UI
can branch on what happened instead of pattern-matching `Diagnostics`
text; `HostKeyChanged` in particular is worth checking for explicitly,
since it means a possible MITM and should drive a hard-stop warning, not
a retry.

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

`TailcatClient.SshAsync` shells out to a system `ssh` client, which a
typical Android app sandbox doesn't provide. It exists in the API on every
platform — same class, same signature, full IntelliSense — but throws
`PlatformNotSupportedException` specifically when running on Android,
naming the alternative: `TailcatSshSession` for a programmatic session
there (or anywhere else you don't want SshAsync taking over your own
console), `MeowshellServer` for shell access as the server side instead.

Everything else works on Android too, unchanged in the API: `CpAsync` uses
the system `scp` everywhere else, but on Android routes through
meowshell's own native SFTP `cp` instead — same `TailcatPath` arguments,
same `TailcatResult`, no platform check needed in your own code.
`ListFilesAsync`, `TailcatSshSession`, and `MeowshellAgentConnection` never
depended on a system binary anywhere to begin with. `Files`/`ForcedCommand`
on `MeowshellServer` also work the same on Android as anywhere else.

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
