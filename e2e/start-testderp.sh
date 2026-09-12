#!/usr/bin/env bash
# Starts e2e/testderp (a single-node, loopback-only DERP relay) in the
# background and exports TAILCAT_DERPMAP_URL for the rest of this job, so
# meowshell/tailcat E2E tests never depend on reaching the public Tailscale
# relay infrastructure. Every subsequent step in the job inherits the
# variable as a real environment variable (via $GITHUB_ENV), and tailcat
# itself already falls back to it when no --derpmap-url flag is given, so
# nothing else in this repo needs to change to pick it up.
set -euo pipefail

BIN=$(mktemp)
go build -o "$BIN" ./e2e/testderp

# Run the built binary directly, not "go run": go run leaves the compiled
# binary running as an orphaned child of its own wrapper process, so the pid
# this script tracks and later kills would be the wrapper's, not the relay's.
LOG=$(mktemp)
"$BIN" >"$LOG" 2>&1 &
echo $! > /tmp/testderp.pid

for _ in $(seq 1 100); do
	if url=$(grep -oP 'TAILCAT_DERPMAP_URL=\K.*' "$LOG" 2>/dev/null) && [ -n "$url" ]; then
		# Unset outside Actions: this script is also the documented way to
		# run an E2E suite locally (see README.md), where there is no
		# $GITHUB_ENV to export through and set -u would abort here.
		echo "TAILCAT_DERPMAP_URL=$url" >> "${GITHUB_ENV:-/dev/null}"
		echo "local DERP relay ready: $url"
		exit 0
	fi
	sleep 0.1
done

echo "::error::local DERP relay did not start in time" >&2
cat "$LOG" >&2
exit 1
