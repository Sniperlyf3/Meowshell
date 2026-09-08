# Meowshell

[![CI](https://github.com/Sniperlyf3/meowshell/actions/workflows/ci.yml/badge.svg)](https://github.com/Sniperlyf3/meowshell/actions/workflows/ci.yml)
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
`AllowClientKeys` so a leaked address alone isn't enough to get a shell; see
[`dotnet/README.md`](dotnet/README.md).

## What's in this repo

- **`Meowshell`** — the .NET library above (`dotnet add package Meowshell`).
  See [`dotnet/README.md`](dotnet/README.md) for the full API.
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

## Releasing

Versioning is `MajorMinor.BuildNumber` (e.g. `0.1.42`), computed once in
`dotnet/Directory.Build.props` and shared by every packed project — the
build/patch number is never hand-edited.

1. To cut a minor or major release, bump `MajorMinor` in
   `dotnet/Directory.Build.props`. Skip this for an ordinary release.
2. Push a tag matching `v*` (e.g. `v0.2.0`) — the tag name itself doesn't
   drive the version, it just triggers publishing.
3. The `publish` job in `.github/workflows/ci.yml` pushes the packed
   NuGet packages to nuget.org, gated on that tag push and a
   `NUGET_API_KEY` repo secret. It never runs on a pull request, fork or
   otherwise. For an extra manual approval step before the token is used,
   add a required-reviewer rule to the `nuget-publish` environment in repo
   settings.

## License

[MIT](LICENSE) for this repo's own code. The vendored/patched
`tailscale/tailcat` source it builds against is upstream's own,
BSD-3-Clause-licensed work.
