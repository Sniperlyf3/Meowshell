# Meowshell

[![CI](https://github.com/Sniperlyf3/Tailcat-Android/actions/workflows/ci.yml/badge.svg)](https://github.com/Sniperlyf3/Tailcat-Android/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/Meowshell.svg)](https://www.nuget.org/packages/Meowshell/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A remote shell you can drop into any .NET app — Android included — in one
line, with no server to run, no port to open, and no keys to manage by hand.

Meowshell packages [tailscale/tailcat](https://github.com/tailscale/tailcat)
(netcat over Tailscale's data plane, without its control plane) together with
`meowshell`, a companion launcher that fixes up the shell environment tailcat
hands a session so it works on Android too, not just desktop. Add the
`Meowshell` package, call one method, and you have a real interactive shell —
PTY, tab completion, job control — reachable from anywhere, torn down on
your own schedule.

```csharp
var options = MeowshellOptions.Create(TimeSpan.FromMinutes(5)) with
{
    AuthorizedKeys = "alice@github", // fetches alice's SSH keys from GitHub
};
await using var server = await MeowshellServer.StartAsync(options);
Console.WriteLine(server.Address); // tailcat ssh <address>, from anywhere
```

`AuthorizedKeys` is the mode to reach for by default. `InsecureNoAuth` exists
for when the address itself is the only credential you want — pair it with
`AllowClientKeys` so a leaked address alone isn't enough to get a shell.

That one call is the common case, but the same package is a complete C#
wrapper around tailcat: an SFTP file service and forced-command sessions
alongside the shell, a SOCKS5 proxy, TCP port forwarding, native interactive
sessions and file transfer as a *client* too (no system `ssh`/`scp` needed,
so this also works from inside an Android app), and one-shot operations for
key management, address inspection, and connectivity checks. A persistent
`MeowshellAgentConnection` goes further still: one login multiplexing a
shell, the full SFTP verb set, and port forwarding together, and the only
one of these that also reaches a general (non-tailcat) SSH host, with real
host-key verification and password/certificate/Keystore-backed auth. See
[`dotnet/README.md`](dotnet/README.md) for the full surface, every option,
and the one thing (a console-attached `ssh` client, as opposed to a
programmatic session) an Android app sandbox can't run.

## What's in this repo

- **`Meowshell`** — the .NET library above (`dotnet add package Meowshell`):
  shell/SFTP/forced-command sessions, a SOCKS5 proxy, port forwarding, and
  one-shot key/address/file operations. See
  [`dotnet/README.md`](dotnet/README.md) for the full API.
- **`Meowshell.Runtime.{linux,windows,android}`** — the native `tailcat` and
  `meowshell` binaries for each platform, pulled in automatically as a
  dependency of `Meowshell`.
- **`Meowshell.Demo`** — a real, installable Android app: one button
  generates a throwaway shell address.
- **`Meowshell.AndroidProbe`** — a minimal app that only proves the packaged
  binaries are found and run on a real device; what CI checks.
- **`meowshell`**, the CLI — a standalone launcher/shim around `tailcat`, for
  use outside .NET (Termux, `adb shell`, scripts).

## Supported platforms

| Platform | Architectures |
| --- | --- |
| Android | arm64-v8a, armeabi-v7a, x86_64, x86 |
| Linux | amd64, arm64, armv7, 386 |
| Windows | amd64, arm64 |

## Building from source

```sh
./build.sh                     # every target the toolchain allows
PLATFORMS=linux ./build.sh     # just one
```

Clones `tailscale/tailcat`, builds it alongside this repo's `meowshell`, and
writes binaries to `dist/`. Android needs the NDK (`ANDROID_NDK_HOME`, r19+)
for cgo-based DNS resolution; Linux and Windows are pure Go. See
`./verify-binaries.sh` and `e2e/` for how CI checks the result.

## Security

See [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md) for the current threat model,
findings, accepted risks, and verification status. The accompanying
[`REVIEW_MAP.md`](REVIEW_MAP.md) groups every first-party file by runtime
boundary and records the order and focus of the repository review.

## License

[MIT](LICENSE) for this repo's own code. The vendored/patched
`tailscale/tailcat` source it builds against is upstream's own,
BSD-3-Clause-licensed work.
