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

`windows-e2e` starts one of these before its tests and kills it afterward.
Everything else now reaches the same end by a shorter route: tailcat's own
`TS_DEBUG_TAILCAT_LOCAL_DERP=1`, which makes a *server* start a loopback
relay of its own, wait until it is registered before publishing an address,
and embed that relay in the address it publishes. Paired with
`TAILCAT_DERPMAP_URL=none`, which turns any accidental external DERP-map
lookup into a loud failure rather than a quiet fall back to the public
relay, that needs no helper process and no shared state between tests:
`host-e2e.sh`, the .NET E2E tests (`RelayE2E.HermeticServer`), and the Go
agent E2E tests each set it per server process.

Either way, nothing in this repo's CI talks to the public Tailscale relay
infrastructure. That's not just isolation — it's what keeps these jobs from
being flaky on real network conditions: before this existed, E2E failures
could come from relay reachability, load, or latency, not from a bug under
test. ("tailcat Ping: context deadline exceeded" is what that looks like
when it comes back.)

Two things follow from how the server-side mode works, both visible in
`host-e2e.sh`. Dial the address the server **published**, not the one
`genkey` printed: a local-DERP server replaces the key's recorded region
with its loopback one, so only the published address names a relay that is
actually running (the identity inside both still matches, which is what
ties them together). And set the two variables on the server process
alone, never export them for a whole script or job: `genkey` resolves a
real region from the public DERP map, and fails outright against `none`.

No code needs to know a local relay is in play: `tailcat` reads
`TAILCAT_DERPMAP_URL` natively as a fallback when no `--derpmap-url` flag
is given, `meowshell` execs `tailcat` as a subprocess and inherits its
environment, and the `meowshell` agent's own `--derpmap-url` flag
(`cmd/meowshell/agent.go`, used in-process for exit-node forwarding) now
defaults from the same variable. Pointed at a helper relay, setting it once
in a job's environment reaches every tailcat/meowshell process that step
launches, agent included; the `none` of the hermetic pair above is the one
value that must stay scoped to a server process, per the note on `genkey`.

### Running it locally

`host-e2e.sh` needs nothing set up — it starts its servers in local-DERP
mode itself, so it already runs without the public relay:

```sh
./e2e/host-e2e.sh
```

`start-testderp.sh` stays for debugging a suite that is not hermetic. In CI
only `windows-e2e` still starts a helper relay; the Android suites
deliberately do not, because the emulator's NAT means guest and host see a
host-loopback relay at different addresses:

```sh
./e2e/start-testderp.sh      # prints/exports TAILCAT_DERPMAP_URL, backgrounds the relay
./e2e/<suite>.sh
kill "$(cat /tmp/testderp.pid)"
```

On Windows, use `start-testderp.ps1` instead — see the comments at the top
of that script for why it launches the relay via WMI/CIM (`Win32_Process.Create`)
rather than `Start-Process`: a plain child process is tied to the runner's
Job Object and gets killed the moment the starting step's shell exits,
before the later step that needs it ever runs.

### Region ID

The relay's synthetic `tailcfg.DERPMap` uses region ID 900, inside
Tailscale's reserved 900–999 "end users" range — safely out of the way of
any real region ID a client might otherwise resolve to.
