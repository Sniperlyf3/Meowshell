# End-to-end tests

`android-e2e.sh`, `host-e2e.sh`, and `windows-e2e.ps1` each drive the real
`tailcat`/`meowshell` binaries built by `../build.sh` (or downloaded as CI
artifacts) through an actual session — no fakes, no mocks. They're run by
the `dotnet-android-e2e`, `host-e2e`, `windows-e2e`, and `dotnet` jobs in
`../.github/workflows/ci.yml`.

## The local DERP relay (`testderp`)

`testderp` is a small standalone Go program: a single-node, loopback-only
DERP relay plus a plain-HTTP server for the matching `tailcfg.DERPMap`
JSON. `start-testderp.sh` (Linux/macOS) and `start-testderp.ps1` (Windows)
build and start it in the background, then export `TAILCAT_DERPMAP_URL`
pointing at its map endpoint.

`host-e2e` and `windows-e2e` start one of these before their tests and kill
it afterward, so nothing in this repo's CI talks to the public Tailscale
relay infrastructure. That's not just isolation — it's what makes these
jobs no longer flaky from real network conditions: before this existed, E2E
failures could come from relay reachability, load, or latency, not from a
bug under test. ("tailcat Ping: context deadline exceeded" is what that
looks like when it comes back.)

## Two ways to avoid the public relay, and when each applies

There is a second mechanism, and the two are **not** interchangeable.
Picking the wrong one produces a suite that passes while testing something
a user never does.

| | `testderp` (this directory) | `TS_DEBUG_TAILCAT_LOCAL_DERP=1` |
| --- | --- | --- |
| What runs the relay | A separate process, started once per job | The tailcat **server** itself, per server |
| How anyone finds it | `TAILCAT_DERPMAP_URL` — a DERP *map*, like the public one | The server embeds it in the address it publishes |
| `genkey`-printed address | Names the same region the server lands on, so it is dialable | Stale by construction: see below |
| Used by | `host-e2e.sh`, `windows-e2e.ps1` | `.NET` E2E (`RelayE2E.HermeticServer`), Go agent E2E |

`TS_DEBUG_TAILCAT_LOCAL_DERP` makes a server start a loopback relay of its
own and then **replace the key's recorded region with it** (see the
`reg != nil` branch in tailcat's `cmd/tailcat/tailcat.go`, which rebuilds
the `ConnInfo` around the dev region). The identity is preserved, so the
address it publishes is still the same server — but any address printed
earlier by `genkey` now names a region nobody is listening on.

That costs the .NET and Go suites nothing: their servers use ephemeral keys
and those tests always dial the address the server just published. It is
the wrong mode for `host-e2e.sh`, which exists to cover what a person
actually does — `genkey` prints an address, you hand that address to
someone, they connect with it. Keeping that flow real means `genkey` and
the server must resolve their region from one shared DERP map, exactly as
they do in production; `testderp` is that map, moved to loopback. Reach for
it whenever a suite dials an address that was minted before the server
started.

No code needs to know a local relay is in play: `tailcat` reads
`TAILCAT_DERPMAP_URL` natively as a fallback when no `--derpmap-url` flag
is given, `meowshell` execs `tailcat` as a subprocess and inherits its
environment, and the `meowshell` agent's own `--derpmap-url` flag
(`cmd/meowshell/agent.go`, used in-process for exit-node forwarding) now
defaults from the same variable. Setting it once in a job's environment
reaches every tailcat/meowshell process that step launches, agent included.

### Running it locally

To reproduce an E2E failure without depending on the public relay:

```sh
./e2e/start-testderp.sh      # backgrounds the relay, prints its map URL
export TAILCAT_DERPMAP_URL=http://127.0.0.1:<port>/derpmap.json   # the URL it printed
./e2e/host-e2e.sh            # or whichever suite you're debugging
kill "$(cat /tmp/testderp.pid)"
```

In CI the export happens through `$GITHUB_ENV` and every later step in the
job inherits it; locally there is no such thing, hence the explicit
`export` above.

On Windows, use `start-testderp.ps1` instead — see the comments at the top
of that script for why it launches the relay via WMI/CIM (`Win32_Process.Create`)
rather than `Start-Process`: a plain child process is tied to the runner's
Job Object and gets killed the moment the starting step's shell exits,
before the later step that needs it ever runs.

### Region ID

The relay's synthetic `tailcfg.DERPMap` uses region ID 900, inside
Tailscale's reserved 900–999 "end users" range — safely out of the way of
any real region ID a client might otherwise resolve to.
