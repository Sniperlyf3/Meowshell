# Repository review map

This is the ordered inventory used for the 2026-09-11 correctness and security
review. Files are grouped by the runtime boundary they implement rather than
alphabetically, so each producer is reviewed next to its consumers and tests.
Generated `bin/`, `obj/`, `dist/`, and `.tailcat-src/` content is excluded.

## 1. Entrypoints, configuration, and documentation

- `README.md`, `dotnet/README.md`, `LICENSE`
- `cmd/meowshell/main.go`, `cmd/meowshell/main_test.go`
- `cmd/meowshell/env.go`, `cmd/meowshell/env_test.go`
- `cmd/meowshell/shim_unix.go`, `cmd/meowshell/shim_windows.go`
- `cmd/meowshell/exec_unix.go`, `cmd/meowshell/exec_windows.go`

Review focus: option defaults, unsafe modes, environment trust, executable
selection, argument boundaries, and platform-specific process replacement.
Result: insecure modes are explicit and local process launches avoid a shell.
Remote exec remains a documented SSH command-string interface, not argv-safe.

## 2. Agent protocol and lifecycle

- `cmd/meowshell/protocol.go`, `cmd/meowshell/protocol_test.go`
- `cmd/meowshell/agent.go`, `cmd/meowshell/agent_e2e_test.go`
- `dotnet/Meowshell/MeowshellAgentProtocol.cs`
- `dotnet/Meowshell/MeowshellAgentConnection.cs`
- `dotnet/Meowshell.Tests/MeowshellAgentConnectionTests.cs`
- `dotnet/Meowshell.Tests/MeowshellAgentConnectionE2ETests.cs`
- `dotnet/Meowshell/MeowshellErrorCode.cs`

Review focus: framing bounds, message ordering, request/channel ownership,
cancellation, child cleanup, concurrency, backpressure, and error propagation.
Result: frames are bounded and .NET channel data is serialized through a pump.
This review fixed duplicate prompt responses blocking the Go frame loop, a
prompt-close send race, cancellation being misreported as timeout, and agent
process leakage on setup failure/cancellation.

## 3. SSH authentication, host identity, and transport

- `cmd/meowshell/connect.go`
- `cmd/meowshell/transport.go`, `cmd/meowshell/transport_test.go`
- `cmd/meowshell/hostkeys.go`
- `cmd/meowshell/agentauth.go`, `cmd/meowshell/agentauth_test.go`
- `cmd/meowshell/sshagent_unix.go`, `cmd/meowshell/sshagent_windows.go`
- `cmd/meowshell/keystage_unix.go`, `cmd/meowshell/keystage_windows.go`
- `cmd/meowshell/sftp.go`
- `cmd/meowshell/agent_auth_e2e_test.go`
- `cmd/meowshell/agent_tcp_e2e_test.go`
- `cmd/meowshell/agent_security_e2e_test.go`
- `dotnet/Meowshell/TailcatSshSession.cs`

Review focus: HTTPS/SOCKS proxy semantics, host-key verification, secret
handling, ssh-agent forwarding, temporary key permissions, authentication
prompts, and handshake timeouts. Result: HTTPS CONNECT now uses verified TLS;
ordinary TCP SSH uses TOFU and rejects changed keys. Tailcat's capability-based
identity intentionally does not use ordinary SSH host-key verification.

## 4. Forwarding and SOCKS

- `cmd/meowshell/forwarding.go`, `cmd/meowshell/forwarding_test.go`
- `cmd/meowshell/tailcatdial.go`
- `cmd/meowshell/agent_forward_e2e_test.go`
- `cmd/meowshell/agent_tailcat_forward_e2e_test.go`
- `dotnet/Meowshell/MeowshellPortForward.cs`
- `dotnet/Meowshell/MeowshellSocksProxy.cs`
- `dotnet/Meowshell.Tests/MeowshellPortForwardTests.cs`
- `dotnet/Meowshell.Tests/MeowshellSocksProxyTests.cs`
- `dotnet/Meowshell.Tests/MeowshellListenersE2ETests.cs`

Review focus: bind scope, opt-in exposure, SOCKS authentication, constant-time
credential comparison, destination handling, socket permissions, and cleanup.
Result: TCP listeners default to loopback, TCP SOCKS defaults to random auth,
and Unix paths cannot replace non-socket files.

## 5. SFTP and file copy

- `cmd/meowshell/agentsftp.go`, `cmd/meowshell/agent_sftp_e2e_test.go`
- `cmd/meowshell/cp.go`, `cmd/meowshell/cp_test.go`
- `dotnet/Meowshell/TailcatFileEntry.cs`
- SFTP and transfer methods/sinks in `dotnet/Meowshell/MeowshellAgentConnection.cs`
- transfer cases in `dotnet/Meowshell.Tests/TailcatClientE2ETests.cs`

Review focus: local/remote path classification, truncation, upload finalization,
metadata preservation, streaming/backpressure, errors, and cancellation. Result:
operations act with the connected user's authority; callers must enforce any
application-specific path allowlist before passing untrusted paths.

## 6. .NET process wrappers and public models

- `dotnet/Meowshell/MeowshellServer.cs`
- `dotnet/Meowshell/TailcatClient.cs`
- `dotnet/Meowshell/TailcatListener.cs`
- `dotnet/Meowshell/MeowshellProcessControl.cs`, `dotnet/Meowshell/JobObject.cs`
- `dotnet/Meowshell/BinaryLocator.cs`, `dotnet/Meowshell/MeowshellBinaries.cs`
- `dotnet/Meowshell/TailcatOptions.cs`, `TailcatAddress.cs`,
  `TailcatParsedAddress.cs`, `TailcatPath.cs`, `TailcatPingResult.cs`,
  `TailcatEnvironment.cs`, `TailcatDiagnostics.cs`, `TailcatException.cs`, and
  `GoDuration.cs` under `dotnet/Meowshell/`
- `dotnet/Meowshell.Tests/MeowshellServerTests.cs`
- `dotnet/Meowshell.Tests/MeowshellServerE2ETests.cs`
- `dotnet/Meowshell.Tests/TailcatClientTests.cs`
- `dotnet/Meowshell.Tests/TailcatClientE2ETests.cs`

Review focus: argument injection, process-tree cleanup, timeout/cancellation,
binary permissions/discovery, diagnostic secret exposure, parsing, and lifecycle
races. Result: `ArgumentList` and `UseShellExecute=false` are used consistently;
server addresses remain bearer secrets and must not be put in ordinary logs.

## 7. Packaging, Android integration, and demonstrations

- `dotnet/Meowshell/Meowshell.csproj`
- `dotnet/Meowshell.Runtime/Meowshell.Runtime.csproj`
- `dotnet/Meowshell/buildTransitive/net10.0-android36.0/Meowshell.targets`
- `dotnet/Meowshell.PackageTests/*`
- `dotnet/Meowshell.AndroidProbe/*`, `dotnet/android-probe-e2e.sh`
- `dotnet/Meowshell.Demo/*`
- `dotnet/Directory.Build.props`, `dotnet/nuget.config`, `dotnet/Meowshell.sln`
- `dotnet/verify-package.sh`

Review focus: native-asset RID mapping, executable permissions, transitive
runtime dependencies, package consumption, Android extraction, and vulnerable
NuGet dependencies. Test dependencies were refreshed and restore now audits all
direct/transitive dependencies, failing on NU1901–NU1904.

## 8. Build, release, and external-source controls

- `build.sh`, `tailcat.ref`, `verify-binaries.sh`
- `.github/workflows/ci.yml`, `.github/dependabot.yml`
- `go.mod`, `go.sum`
- `patches/tailcat/*`
- `e2e/host-e2e.sh`, `e2e/android-e2e.sh`, `e2e/windows-e2e.ps1`
- `scripts/stripcomments/main.go`
- `scripts/CommentStripper/CommentStripper.csproj`, `Program.cs`

Review focus: immutable third-party inputs, action pinning, least-privilege CI,
artifact validation, dependency advisories, publish credentials, and cross-OS
execution. Result: actions and tailcat are commit-pinned, publishing uses scoped
OIDC, `govulncheck` and transitive NuGet audit run automatically, and Dependabot
covers Go, NuGet, and Actions. Updating `tailcat.ref` still requires manual
upstream diff and patch review because Dependabot does not manage arbitrary Git
source pins.
