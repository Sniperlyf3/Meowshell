#!/usr/bin/env bash
# Run a `go test -v` command and fail unless the agent E2E tests really ran.
#
#   ./e2e/require-agent-e2e-ran.sh go test -v ./cmd/meowshell/ -count=1
#
# The agent E2E tests skip rather than fail when findE2EBinary finds no real
# binary, so a green `go test` says nothing about whether any of them ran:
# windows-e2e passed for as long as they existed with all of them skipped
# (it ran go test before fetching the binaries, and the fallback only knew
# the linux_amd64 file name). This fails the step if any test skipped for a
# missing binary, or if none resolved one at all -- the latter catches the
# tests having been filtered out or moved, which would skip nothing and
# still run nothing. The markers are the constants next to findE2EBinary in
# cmd/meowshell/agent_e2e_test.go; -v is required, or t.Logf/t.Skipf output
# never reaches the log.
set -uo pipefail

log=$(mktemp)
trap 'rm -f "$log"' EXIT

"$@" 2>&1 | tee "$log"
status=$?
if [ "$status" -ne 0 ]; then
	exit "$status"
fi

if grep -F 'E2E binary missing:' "$log" >/dev/null; then
	echo "::error::agent E2E tests skipped for a missing binary; set \$MEOWSHELL and \$TAILCAT to the binaries this job built or fetched:" >&2
	grep -F 'E2E binary missing:' "$log" >&2
	exit 1
fi
if ! grep -F 'E2E binary resolved:' "$log" >/dev/null; then
	echo "::error::no agent E2E test resolved a binary, so none of them ran (was -v dropped, or the tests filtered out?)" >&2
	exit 1
fi
echo "agent E2E guard: $(grep -cF 'E2E binary resolved:' "$log") binary lookups resolved, none skipped"
