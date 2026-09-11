# Security review

**Review date:** 2026-09-11  
**Reviewed revision:** working tree based on the `work` branch  
**Scope:** the Go CLI/agent and protocol, the .NET process wrapper and agent
client, build/release automation, tests, and the locally fetched tailcat source
at the revision recorded in `tailcat.ref`. Generated native binaries, external
relay infrastructure, GitHub/NuGet account configuration, and Android platform
internals were not independently penetration-tested.

## Executive summary

The review found eight actionable weaknesses and remediated them in this
revision:

1. **High — HTTPS proxy transport was not encrypted.** The `https` proxy scheme
   followed the raw TCP path used for HTTP. This made proxy credentials and the
   CONNECT request visible to an on-path attacker and did not authenticate the
   proxy. HTTPS proxy connections now perform a normal, certificate-verified TLS
   handshake before sending HTTP.
2. **High — release builds consumed a mutable upstream branch.** Native artifacts
   defaulted to the then-current tailcat `main`, so identical Meowshell source
   could produce different binaries and an upstream compromise could enter a
   release without a repository change. The default and CI are now pinned to the
   reviewed full commit in `tailcat.ref`; explicit workflow input remains
   available for deliberate upstream testing.
3. **Medium — Unix forwarding could delete a non-socket path.** Starting a Unix
   listener unconditionally removed an existing caller-supplied path. It now
   uses `lstat` and only removes an actual socket, refusing regular files and
   symbolic links.
4. **Medium — the SSH dependency contained reachable denial-of-service flaws.**
   `govulncheck` identified GO-2026-6354 and GO-2026-6355 in the SSH handshake
   path in both Meowshell and the built tailcat source. Both build inputs now use
   `golang.org/x/crypto` v0.56.0, which contains the fixes.
5. **Medium — prompt responses could race shutdown or block the agent.** A
   duplicate response filled the one-element prompt channel and blocked the only
   frame reader; shutdown could also close the channel between lookup and send.
   Delivery is now synchronized with shutdown and duplicate responses are
   ignored without blocking.
6. **Medium — cancelled or failed .NET connection setup leaked its child.** A
   cancellation was also surfaced as a timeout. Setup now disposes the agent on
   every exceptional path and preserves `OperationCanceledException` semantics.
7. **Medium — HTTP proxy setup could hang and expose malformed credentials.**
   Cancellation only covered dialing, not the CONNECT response, and URL parse
   diagnostics could echo embedded passwords. Cancellation now closes the live
   connection, diagnostics redact or omit credentials, and default HTTP(S)
   proxy ports are supported.
8. **Low — a fast listener failure could be missed.** The .NET wrapper started
   a process before subscribing to its exit event, so `Completed` could hang if
   the child exited in that window. Event handlers are now installed first.

No hard-coded credentials, shell-based local process launch, unrestricted
local TCP bind by default, unbounded protocol frame allocation, or silent TCP
SSH host-key acceptance was found in the reviewed first-party code. The
repository already uses argument-list process launching, a 64 MiB frame cap,
TOFU `known_hosts` verification for ordinary SSH, loopback-only local forwards
by default, random SOCKS credentials by default, restrictive temporary key and
Unix-socket permissions, and commit-pinned GitHub Actions.

## Trust boundaries and attack surface

- **Remote peers and relays:** SSH handshakes, host keys, authentication prompts,
  session output, SFTP metadata/data, TCP forwarding, and SOCKS destinations.
- **Local child-process boundary:** the .NET client exchanges framed JSON and
  binary data with `meowshell agent` over redirected standard streams. A replaced
  packaged binary inherits the application's secrets and authority.
- **Local filesystem:** executable discovery, `HOME`, known-hosts, temporary key
  staging, download destinations, and Unix forwarding paths.
- **Caller-controlled configuration:** remote commands, proxy URLs and
  credentials, bind addresses, key material, jump hosts, SFTP paths, and
  deliberate insecure modes.
- **Build/release:** upstream tailcat source, Go/NuGet dependencies, downloaded
  toolchains, CI actions, native artifacts, and NuGet trusted publishing.

## Findings and disposition

### SR-01: HTTPS proxy scheme used plaintext TCP — fixed (High)

`dialHTTPConnectProxy` accepted both HTTP and HTTPS URLs but previously dialed
both with `net.Dialer`. Basic proxy credentials were therefore sent in cleartext
for an HTTPS URL, contrary to the scheme and caller expectations. The HTTPS path
now uses `tls.Dialer`, which validates the proxy certificate and infers SNI from
the proxy host. A regression test verifies that an HTTPS URL starts with a TLS
handshake rather than a plaintext CONNECT request.

### SR-02: mutable tailcat source in builds — fixed (High)

`build.sh` and four CI jobs defaulted to `main`. The default is now the complete
reviewed commit ID, stored in `tailcat.ref` for local builds and mirrored in CI.
Maintainers should update this pin through a reviewed change, inspect upstream
diffs, reapply both Android patches, run the full matrix, and run dependency
vulnerability scanning before release.

### SR-03: Unix listener removed arbitrary existing paths — fixed (Medium)

The agent removed the requested Unix-socket path before binding. A mistaken path
could destroy an application file; a local attacker able to change a shared
parent directory could substitute a symlink or regular file. Existing paths are
now inspected without following symlinks and removal is limited to socket nodes.
The remaining check/remove race is only exploitable by a principal that can
mutate the socket's parent directory. Callers should place sockets in a private
0700 directory (such as an application-owned runtime directory).

### SR-04: reachable SSH denial of service in x/crypto — fixed (Medium)

The reviewed v0.55.0 dependency allowed a peer to deadlock established or
undecided SSH channels (GO-2026-6354 and GO-2026-6355). Because the agent calls
`ssh.NewClientConn`, `govulncheck` found a reachable trace through
`dialSSHClient`; scanning the nested tailcat command found server and client
traces as well. The direct dependency and patched tailcat build module are both
upgraded to the fixed v0.56.0 release, and CI scans both modules.

### SR-05: prompt response concurrency hazards — fixed (Medium)

Prompt channels are closed during agent shutdown. Response delivery previously
released the prompt-map lock before sending, permitting a send-on-closed-channel
panic. A duplicate response could instead block forever on the full buffered
channel and stop all subsequent frames. Delivery now holds the lifecycle lock
and uses a non-blocking send; a regression test covers duplicate responses.

### SR-06: .NET agent leak and cancellation misclassification — fixed (Medium)

Once the agent child was started, exceptions while sending configuration or
waiting for connection escaped without disposal. In addition, cancellation won
the same `WhenAny` branch as timeout and was reported as a `TailcatException`.
Connection setup now has one exception cleanup path and checks caller
cancellation before creating a timeout error. A process-backed test verifies
both cancellation type and child cleanup.

### SR-07: CONNECT cancellation and credential-safe errors — fixed (Medium)

After the proxy TCP/TLS connection completed, a server that never returned an
HTTP response could hold connection setup forever despite caller cancellation.
`context.AfterFunc` now closes the connection while setup is in progress. Proxy
URL parse failures no longer include the raw credential-bearing URL, later
errors use `URL.Redacted`, missing hosts are rejected, and omitted HTTP/HTTPS
ports resolve to 80/443. Regression tests cover cancellation and secret-safe
parse errors.

### SR-08: listener exit-subscription race — fixed (Low)

`TailcatListener.Start` enabled events and launched the child before registering
its `Exited` callback. A child that failed immediately could exit in between,
leaving `Completed` unresolved and lifecycle callers waiting indefinitely. Exit
and output handlers are now registered before process start; existing crash
tests exercise the fast-failure path.

## Accepted design risks and hardening backlog

1. **Tailcat SSH host-key checking is intentionally disabled.** Tailcat sessions
   use `ssh.InsecureIgnoreHostKey`, relying on the cryptographic capability in
   the tailcat address/transport rather than OpenSSH-style host identity. This
   assumption must be revalidated whenever tailcat's address or handshake design
   changes. Ordinary TCP SSH correctly uses TOFU and rejects changed keys.
2. **`InsecureNoAuth` is intentionally dangerous.** It creates a shell whose
   bearer address is the credential. Keep the warning prominent, prefer
   `AuthorizedKeys`, combine address-only use with client-key restrictions, use
   short lifetimes, and never log or persist addresses unnecessarily.
3. **Remote exec is a command string, not an argv-safe execution API.** Command
   elements are joined with spaces because SSH exec transmits one command
   string. The .NET API documents that it adds no quoting. Applications must not
   concatenate untrusted values; use SFTP or a fixed remote helper protocol for
   untrusted inputs.
4. **The agent protocol permits 64 MiB frames.** The explicit bound prevents
   unlimited allocation but still permits substantial per-frame memory use. The
   child is local and trusted in the normal architecture. If the protocol is
   exposed to a less-trusted producer, lower the control-frame limit and stream
   large data separately.
5. **Forwarding is powerful by design.** Local TCP forwarding is loopback-only by
   default and SOCKS auth defaults on for TCP, but callers can opt into nonlocal
   binds or unauthenticated sockets. Applications should surface those choices as
   security-sensitive and apply destination allowlists when acting on untrusted
   requests.
6. **Build inputs remain broader than one repository.** Go modules, NuGet
   packages, the Go toolchain, Android NDK, and publishing infrastructure remain
   external trust dependencies. Automated `govulncheck`, transitive NuGet audit,
   and Dependabot now cover known advisories and routine upgrades. SBOM
   generation, artifact provenance/attestation, and release verification against
   reproducible hashes remain valuable follow-ups.
7. **Secret lifetime is not minimized everywhere.** Passwords, passphrases, and
   private keys cross managed strings/arrays or Go byte slices and cannot always
   be reliably zeroed. Prefer ssh-agent and Android Keystore sign callbacks over
   raw private-key/password configuration.

## Verification plan

The security fixes are covered by focused Go tests. The standard repository
checks are `go test ./...`, `go vet ./...`, `./verify-binaries.sh`, and
`dotnet test dotnet/Meowshell.sln --configuration Release`. Release review should
also run `govulncheck ./...` after materializing the pinned tailcat checkout and
a NuGet dependency audit in an environment with the required .NET SDK.

## Review verification results

The review environment was subsequently provisioned with .NET SDK 8.0.425 and
the pinned Linux amd64 binaries. All 86 non-E2E .NET tests passed. The complete
suite executed all 107 tests: 94 passed and 13 relay-dependent E2E cases failed
with `context deadline exceeded` or an SSH EOF after the tailcat connection
could not be established. Local real-binary E2E coverage, including listener
startup/shutdown and key/address operations, did pass. The environment routes
outbound HTTP(S) through a mandatory proxy, and the failures are consistent with
the tailcat transport being unable to reach its relay from this environment.
They are therefore recorded as an environment limitation rather than a passing
result or a demonstrated product regression. The full E2E suite still needs a
run from a network that permits the tailcat transport before release.
