# Meowshell

A Go CLI (`cmd/meowshell`) wrapping [tailscale/tailcat](https://github.com/tailscale/tailcat),
plus a .NET library (`dotnet/Meowshell`) that drives `meowshell agent` as a
long-lived subprocess over a framed control protocol. The .NET side is what an
Android app consumes; the Go side is what actually speaks SSH.

## Before anything Go will build

`go.mod` carries `replace github.com/tailscale/tailcat => ./.tailcat-src`, so
`go build`, `go vet` and `go test` all fail with "replacement directory
./.tailcat-src does not exist" until that checkout is there. `./build.sh`
creates it; to do only that part:

```sh
git init .tailcat-src && git -C .tailcat-src remote add origin https://github.com/tailscale/tailcat.git
git -C .tailcat-src fetch --depth 1 origin "$(tr -d '[:space:]' < tailcat.ref)"
git -C .tailcat-src checkout FETCH_HEAD
# then every patch in patches/tailcat/ -- key-from-stdin needs --unidiff-zero
# (zero-context hunks), and android-netmon is followed by the go get below
(cd .tailcat-src && go get github.com/wlynxg/anet@v0.0.5 golang.org/x/crypto@v0.56.0)
```

The patches are not optional for E2E work: `key-from-stdin` is what makes
`meowshell serve --key-stdin` work at all.

## Commands

```sh
go vet ./... && go test ./...              # needs .tailcat-src (above)

# The 22 agent E2E tests skip unless both real binaries exist. ./build.sh
# makes them, or just the two this host needs:
go build -o dist/meowshell_linux_amd64 ./cmd/meowshell
(cd .tailcat-src && go build -tags "$(tr -d '[:space:]' < build-tags.txt)" \
    -o ../dist/tailcat_linux_amd64 ./cmd/tailcat)   # build-tags.txt is tailcat's own

mkdir -p nupkg                             # NuGet.config names it as a local source;
dotnet build dotnet/Meowshell.sln          # restore fails outright if it doesn't exist
dotnet test dotnet/Meowshell.sln

./e2e/start-testderp.sh                    # see the relay note below
./e2e/host-e2e.sh
```

Tests that need real binaries or a toolchain they can't find **no-op silently**
rather than failing (`FindRealBinaries`, `BuildFakeAgentAsync`, `findE2EBinary`).
A green run does not by itself mean your new test ran — mutate it and watch it
fail once before believing it.

Both E2E suites are wired into CI, but only just: the `dotnet` job sets
`DOTNET_E2E_*`, and the `build` job runs the Go agent E2E tests in a step
*after* `./build.sh`, because the `go test ./...` step before it has no `dist/`
yet and skipped all 22 for as long as they existed. Those two steps are the
only reason any of it runs — `findE2EBinary`'s `../../dist` fallback skips on a
missing file, while an explicit `$MEOWSHELL`/`$TAILCAT` is returned unchecked,
so keep setting them and a broken binary fails loudly instead of going quiet.
Windows is still dark: `windows-e2e` also runs `go test` before fetching the
artifact, and the dist name `findE2EBinary` falls back to is hardcoded
`linux_amd64`.

## E2E tests and the DERP relay

The one thing in this repo that reliably misleads. There are two ways to keep a
test off the public Tailscale relay, they look interchangeable, and they are
not. `e2e/README.md` has the full table; the rule:

- **The address is minted before the server starts** — `genkey` prints one, a
  test hands it over and dials it (`e2e/host-e2e.sh`) — use **`testderp`**, the
  shared loopback DERP *map* (`./e2e/start-testderp.sh`, `TAILCAT_DERPMAP_URL`).
  `genkey` and the server resolve their region from the same map, so the printed
  address is dialable, exactly as in production.
- **The test only ever dials what the server just published** — .NET E2E, Go
  agent E2E — use **`TS_DEBUG_TAILCAT_LOCAL_DERP=1`** (with
  `TAILCAT_DERPMAP_URL=none`), set per server process, no helper needed.

The trap: a server in `TS_DEBUG_TAILCAT_LOCAL_DERP` mode invents a loopback
relay *after* the key was made and overwrites the key's region with it. The
identity survives, so a published address still works — but an address `genkey`
printed earlier now names a region nobody is on. Switching `host-e2e.sh` to that
mode therefore "passes" only if you also stop dialing the printed address, which
quietly deletes the coverage of the flow a real user follows. Don't.

`tailcat Ping: context deadline exceeded` in CI means something reached the
public relay. Find what lost its relay configuration rather than re-running.

## Transports and host keys

Two transports, deliberately different trust models:

- **tailcat addresses** — `tailcatHostKeyCallback()` is `InsecureIgnoreHostKey`
  on purpose. The address itself is the cryptographic capability; there is no
  separate host key to verify.
- **TCP `[user@]host[:port]`** — real `known_hosts` verification with
  trust-on-first-use, in `cmd/meowshell/hostkeys.go`.

Keep `host_key_unknown` and `host_key_changed` distinct all the way to the
caller. The first is a question to put to a user (host is new, nobody has
accepted it yet); the second is a warning (recorded key no longer matches) and
is never a prompt. Collapsing either into `unknown` leaves a client unable to
tell "this host is new" from "the port is dead".

## The agent protocol

`cmd/meowshell/protocol.go` and `dotnet/Meowshell/MeowshellAgentProtocol.cs` are
two halves of one wire format — change them together. `e2e/fakeagent` is a
deliberately separate reimplementation used by the .NET tests to control timing
a real agent can't be made to reproduce; it takes no flags, so tests steer it
through the destination string and read results from `os.Args[0] + ".results"`.

Prompts (host key, password, passphrase, keyboard-interactive, keystore signing)
are raised *during* the handshake, inside `ConnectAsync`. Subscribe through its
`configureConnection` callback — handlers attached to the returned object are
too late to be asked. A prompt with no handler is answered "cancelled", which
the Go side treats as a refusal, not as a default yes.

## Conventions

Comments here carry unusual weight: most explain *why*, and many name the
specific bug or race they exist to prevent (`N5`, `N15`, "regression test:
...", "used to ..."). Match that density and that habit — say what breaks
without the code, not what the code does. Same for commit messages: state the
problem, then the fix, then how it was verified.

`SECURITY_REVIEW.md` and `REVIEW_MAP.md` are the record of a dated audit, not
living docs — don't update them for new work.
