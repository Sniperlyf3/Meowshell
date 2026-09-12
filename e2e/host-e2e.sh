#!/usr/bin/env bash
# End-to-end test of the Linux binaries on this machine.
#
# It covers the same ground as the Android test without an emulator, so it
# is fast and does not depend on a device booting: the shim, a session over
# a real tailcat address, and a key handed over on stdin.
set -euo pipefail

DIST=${DIST:-dist}
TAILCAT=${TAILCAT:-$DIST/tailcat_linux_amd64}
MEOWSHELL=${MEOWSHELL:-$DIST/meowshell_linux_amd64}
MARKER="host-e2e-$$-$RANDOM"
failed=0

pass() { printf 'ok    %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1" >&2; failed=1; }
# shellcheck disable=SC2001 # prefixing every line; not a parameter expansion
indent() { printf '%s\n' "$1" | sed 's/^/      /'; }
assert_grep() { if printf '%s\n' "$3" | grep -q "$2"; then pass "$1"; else fail "$1"; fi; }
# tailcat's own diagnostics include the address it just published; with
# --insecure-no-auth that address alone is a live credential, so it must
# never reach a CI log verbatim (public repo, live-streamed while the job
# runs).
redact() { sed -E 's/\btc[A-Za-z0-9_-]{10,}/tc<redacted>/g'; }
# ::add-mask:: registers a value with the runner itself, so it gets
# replaced with *** in this job's log from here on regardless of what
# prints it later -- belt and suspenders alongside redact() above, which
# only covers print sites this script already knows about.
mask() { [ -n "$1" ] && printf '::add-mask::%s\n' "$1"; }

# The node key an address carries. A server picks a DERP region at startup
# and embeds it, so the address it publishes is not byte-identical to the
# one genkey printed; the identity inside is what has to match.
identity() { "$TAILCAT" parse "$1" | sed -n 's/.*"ServerPublic": "\([^"]*\)".*/\1/p'; }

# Every server below runs in tailcat's own hermetic local-DERP mode, the
# same one the .NET E2E tests use (RelayE2E.HermeticServer) and the Go ones
# set per-test: the server starts a loopback DERP relay, waits for it, and
# publishes an address that embeds it, so the whole exchange stays on this
# machine. Without it these sessions bootstrap over the public Tailscale
# relay, whose load is outside this repo's control -- the direct cause of
# the "tailcat Ping: context deadline exceeded" flake. "none" makes any
# accidental external DERP-map lookup fail loudly rather than silently
# reaching for that relay again.
#
# Applied per server process, never exported: genkey below resolves a real
# region from the public DERP map, and would fail outright against "none".
hermetic=(TS_DEBUG_TAILCAT_LOCAL_DERP=1 TAILCAT_DERPMAP_URL=none)

# Resolve before exporting: TAILCAT may already be absolute, and joining it
# onto $PWD would produce a path that exists nowhere.
TAILCAT=$(realpath "$TAILCAT")
MEOWSHELL=$(realpath "$MEOWSHELL")

work=$(mktemp -d)
export TAILCAT_BIN=$TAILCAT
export XDG_CONFIG_HOME=$work/config
export TMPDIR=$work/tmp
mkdir -p "$TMPDIR"

# shellcheck disable=SC2317 # invoked via trap
cleanup() {
	[ -n "${server_pid:-}" ] && { kill "$server_pid" 2>/dev/null || true; }
	[ -n "${SSH_AGENT_PID:-}" ] && { ssh-agent -k > /dev/null 2>&1 || true; }
	rm -rf "$work"
	true
}
trap cleanup EXIT

chmod +x "$TAILCAT" "$MEOWSHELL"

echo "== 1. binaries run =="
assert_grep "tailcat runs" "." "$("$TAILCAT" version)"
env_out=$("$MEOWSHELL" env)
indent "$env_out"
assert_grep "meowshell found tailcat via TAILCAT_BIN" "^tailcat /" "$env_out"

# The explicit flag must work without the environment variable.
flag_out=$(env -u TAILCAT_BIN "$MEOWSHELL" serve --tailcat="$TAILCAT" 2>&1 || true)
assert_grep "--tailcat is accepted" "choose what to serve" "$flag_out"
bad_out=$(env -u TAILCAT_BIN "$MEOWSHELL" serve --insecure-no-auth --tailcat=/nope 2>&1 || true)
assert_grep "--tailcat rejects a missing binary" "not an executable" "$bad_out"

echo "== 2. the shim execs a real shell and fixes a broken PATH =="
# shellcheck disable=SC2016 # the shell under test expands these
shim=$(env -u PATH HOME="$work" "$MEOWSHELL" -c 'echo P=$PATH; echo S=$SHELL; echo RAN_A_REAL_SHELL')
indent "$shim"
assert_grep "shim exec'd a shell"  "RAN_A_REAL_SHELL" "$shim"
assert_grep "shim set a real PATH" "^P=/.*bin"        "$shim"

echo "== 3. a session over a tailcat address, with the key given on stdin =="
provisioned=$("$TAILCAT" genkey --key=host-e2e | tail -1)
mask "$provisioned"
keyfile=$work/config/tailcat/keys/host-e2e.private.json
pass "provisioned a key (address is ${#provisioned} chars)"

env "${hermetic[@]}" TAILCAT_ADDR_FILE=$work/addr \
	"$MEOWSHELL" serve --key-stdin --insecure-no-auth \
	> "$work/server.log" 2>&1 < "$keyfile" &
server_pid=$!

addr=""
for _ in $(seq 40); do
	[ -s "$work/addr" ] && { addr=$(tr -d '\n' < "$work/addr"); mask "$addr"; break; }
	kill -0 "$server_pid" 2>/dev/null || break
	sleep 2
done
if [ -z "$addr" ]; then
	echo "--- server log (redacted) ---"; redact < "$work/server.log" || true
	fail "server published no address"; exit 1
fi
pass "server published an address"
if [ "$(identity "$addr")" = "$(identity "$provisioned")" ]; then
	pass "the published address carries the provisioned identity"
else
	fail "published address is a different identity from the provisioned one"
fi

# Dial the address the server published, not the one genkey printed. A
# local-DERP server replaces the key's recorded region with its own
# loopback one, so the published address is the only one naming a relay
# that is actually running; the identity check above is what ties it back
# to the key handed over on stdin.
if out=$(timeout 90 "$TAILCAT" ssh "$addr" "echo $MARKER; echo P=\$PATH" 2>&1); then
	indent "$out"
	assert_grep "remote command ran"           "$MARKER"  "$out"
	assert_grep "remote command had a PATH"    "P=/.*bin" "$out"
else
	indent "$out"; echo "--- server log (redacted) ---"; redact < "$work/server.log" || true
	fail "could not open a session"
fi

# shellcheck disable=SC2016 # $PATH is for the remote shell to expand
if out=$(printf 'tty; echo I_%s; echo IP=$PATH\nexit\n' "$MARKER" \
	| timeout 90 script -qec "$TAILCAT ssh $addr" /dev/null 2>&1); then
	out=$(printf '%s\n' "$out" | tr -d '\r')
	indent "$out" | head -20
	assert_grep "interactive session ran commands" "I_$MARKER" "$out"
	assert_grep "session has a real pty"           "/dev/pts/" "$out"
else
	indent "$out"; fail "interactive session failed"
fi

kill "$server_pid" 2>/dev/null || true
wait "$server_pid" 2>/dev/null || true
server_pid=

# 4. The configuration anyone would actually deploy: the address gets you
# to the server, a client key gets you past --allow, and an SSH key gets
# you a shell. Sections above all ran with authentication switched off.
echo "== 4. an authenticated session: --allow plus --authorized-keys =="
mkdir -p "$work/.ssh"
ssh-keygen -t ed25519 -N '' -q -f "$work/.ssh/id_ed25519"
cp "$work/.ssh/id_ed25519.pub" "$work/authorized_keys"

# Hand the key over through an agent rather than a home directory. tailcat
# does not pass -i, and OpenSSH resolves ~ from the passwd database rather
# than $HOME, so a config file written under a temporary HOME is never read.
# SSH_AUTH_SOCK is an environment variable, which does survive the exec
# chain from meowshell to tailcat to ssh.
eval "$(ssh-agent -s)" > /dev/null
ssh-add "$work/.ssh/id_ed25519" 2>/dev/null
pass "loaded the ssh key into an agent"

"$TAILCAT" genkey --client --key=client-default > /dev/null
clientpub=$("$TAILCAT" printpub)
mask "$clientpub"
pass "generated a client key ($clientpub)"

serverkey=$work/config/tailcat/keys/authed.private.json
authed=$("$TAILCAT" genkey --key=authed | tail -1)
mask "$authed"

env "${hermetic[@]}" TAILCAT_ADDR_FILE=$work/addr2 \
	"$MEOWSHELL" serve \
	--key="$serverkey" \
	--allow="$clientpub" \
	--authorized-keys="$work/authorized_keys" \
	> "$work/server2.log" 2>&1 &
server_pid=$!

addr2=""
for _ in $(seq 40); do
	[ -s "$work/addr2" ] && { addr2=$(tr -d '\n' < "$work/addr2"); mask "$addr2"; break; }
	kill -0 "$server_pid" 2>/dev/null || break
	sleep 2
done
if [ -z "$addr2" ]; then
	echo "--- server log (redacted) ---"; redact < "$work/server2.log" || true
	fail "authenticated server published no address"
else
	pass "authenticated server started (--key=<path> accepted)"
	if [ "$(identity "$addr2")" = "$(identity "$authed")" ]; then
		pass "--key=<path> reused the provisioned identity"
	else
		fail "--key=<path> served a different identity from the key file"
	fi

	# meowshell connect, rather than calling tailcat ssh directly.
	if out=$(timeout 90 "$MEOWSHELL" connect "$addr2" "echo A_$MARKER" 2>&1); then
		indent "$out"
		assert_grep "meowshell connect opened an authenticated session" "A_$MARKER" "$out"
	else
		indent "$out"; echo "--- server log (redacted) ---"; redact < "$work/server2.log" || true
		fail "meowshell connect could not open an authenticated session"
	fi

	# 5. The half that proves the gate is real: a client key that is not on
	# the allow list must not get in. Without this, --allow could be
	# ignored entirely and every test above would still pass.
	echo "== 5. a client key that is not allowed is refused =="
	other=$work/other
	mkdir -p "$other"
	XDG_CONFIG_HOME=$other "$TAILCAT" genkey --client --key=client-default > /dev/null
	otherpub=$(XDG_CONFIG_HOME=$other "$TAILCAT" printpub)
	if [ "$otherpub" = "$clientpub" ]; then
		fail "the second client key is identical to the first; the test proves nothing"
	elif out=$(XDG_CONFIG_HOME=$other timeout 25 \
			"$TAILCAT" ssh "$addr2" "echo LEAKED_$MARKER" 2>&1); then
		indent "$out"
		fail "a client key outside --allow got a session"
	else
		pass "a client key outside --allow was refused"
	fi
fi

staged=$(find "$TMPDIR" -name 'meowshell-key-*' 2>/dev/null | wc -l)
if [ "$staged" = 0 ]; then
	pass "the key was never left as a named file"
else
	fail "found $staged staged key file(s)"
fi

echo
if [ "$failed" -eq 0 ]; then
	echo "all host checks passed"
else
	echo "host checks failed" >&2
fi
exit "$failed"
