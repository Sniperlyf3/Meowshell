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

Every E2E job (`host-e2e`, `windows-e2e`, and `dotnet`) starts one of these
before its tests and kills it afterward, so nothing in this repo's CI talks
to the public Tailscale relay infrastructure. That's not just isolation —
it's what makes these jobs no longer flaky from real network conditions:
before this existed, E2E failures could come from relay reachability, load,
or latency, not from a bug under test.

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
./e2e/start-testderp.sh      # prints/exports TAILCAT_DERPMAP_URL, backgrounds the relay
./e2e/host-e2e.sh            # or whichever suite you're debugging
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
