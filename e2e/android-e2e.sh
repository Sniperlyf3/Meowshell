#!/usr/bin/env bash
# End-to-end test against a running Android emulator (adb must see it).
#
# Verifies what only a real Android system can: that the binaries run there
# at all, that meowshell's shim repairs the session environment, and that a
# client on the host can open a working shell over a tailcat address.
set -euo pipefail

DIST=${DIST:-dist}
ABI=${ABI:-amd64}
HOST_TAILCAT=${HOST_TAILCAT:?set HOST_TAILCAT to a host-built tailcat binary}
DEV=/data/local/tmp/meowshell-e2e
MARKER="e2e-$$-$RANDOM"
failed=0

pass()   { printf 'ok    %s\n' "$1"; }
fail()   { printf 'FAIL  %s\n' "$1" >&2; failed=1; }
# shellcheck disable=SC2001 # prefixing every line; not a parameter expansion
indent() { printf '%s\n' "$1" | sed 's/^/      /'; }

assert_grep() { # assert_grep <description> <pattern> <text>
	if printf '%s\n' "$3" | grep -q "$2"; then pass "$1"; else fail "$1"; fi
}
assert_not_grep() { # assert_not_grep <description> <pattern> <text>
	if printf '%s\n' "$3" | grep -q "$2"; then fail "$1"; else pass "$1"; fi
}
server_log() { echo "--- server log ---"; adb shell "cat $DEV/server.log" 2>&1 || true; }

# shellcheck disable=SC2317 # invoked via trap
cleanup() {
	adb shell "pkill -f meowshell-e2e" >/dev/null 2>&1 || true
	[ -n "${keyfeed_pid:-}" ] && kill "$keyfeed_pid" 2>/dev/null
	[ -n "${SSH_AGENT_PID:-}" ] && ssh-agent -k > /dev/null 2>&1
	true
}
trap cleanup EXIT

echo "== pushing binaries =="
adb shell "rm -rf $DEV; mkdir -p $DEV/home"
adb push "$DIST/tailcat_android_$ABI" "$DEV/tailcat" >/dev/null
adb push "$DIST/meowshell_android_$ABI" "$DEV/meowshell" >/dev/null
adb shell "chmod 755 $DEV/tailcat $DEV/meowshell"

echo "== 0. wait for the device to reach the network =="
# Every other invocation below sets HOME=$DEV/home too: with none set,
# os.UserConfigDir() falls back to "$HOME/.config" with HOME empty, i.e.
# "/.config" -- and tailcat fails trying to create that on Android's
# read-only root, not because the network isn't up yet.
online=
for _ in $(seq 60); do
	if adb shell "HOME=$DEV/home $DEV/tailcat genkey --region=list" 2>&1 | tr -d '\r' | grep -q .; then
		online=1
		break
	fi
	sleep 3
done
if [ -n "$online" ]; then
	pass "the device can fetch the DERP map"
else
	echo "--- last attempt ---"
	adb shell "HOME=$DEV/home $DEV/tailcat genkey --region=list" 2>&1 | tail -3
	adb shell "ls -l /etc/resolv.conf; getprop | grep -i dns | head -5" 2>&1 || true
	fail "the device never reached the network"; exit 1
fi

# 1. The binaries execute on Android at all -- the one thing an ELF header
# check cannot prove, and everything below depends on it.
echo "== 1. binaries run on device =="
if adb shell "$DEV/tailcat version" | tr -d '\r' | grep -q .; then
	pass "tailcat runs on device"
else
	fail "tailcat did not run on device"; exit 1
fi

# 2. meowshell resolves a usable Android environment.
echo "== 2. environment resolution =="
env_out=$(adb shell "TAILCAT_BIN=$DEV/tailcat HOME=$DEV/home $DEV/meowshell env" | tr -d '\r')
indent "$env_out"
shell=$(printf '%s\n' "$env_out" | awk '/^shell /{print $2}')
path=$(printf '%s\n' "$env_out" | awk '/^path /{print $2}')

if adb shell "[ -x '$shell' ] && echo yes" | tr -d '\r' | grep -q yes; then
	pass "resolved shell is executable on device: $shell"
else
	fail "resolved shell is not executable on device: $shell"
fi
assert_grep     "PATH contains /system/bin"                ":/system/bin:"      ":$path:"
assert_not_grep "PATH has no dirs absent on Android"      ":/usr/[a-z/]*bin:" ":$path:"
assert_grep     "resolved tailcat via TAILCAT_BIN"         "^tailcat $DEV/tailcat" "$env_out"

# 3. The shim replaces a broken PATH. This is the bug meowshell exists for:
# tailcat hands the session /usr/local/bin:/usr/bin:/bin, none of which are
# on Android.
echo "== 3. shim repairs the session environment =="
shim_out=$(adb shell "PATH=/nonexistent HOME=$DEV/home $DEV/meowshell -c \
	'echo P=\$PATH; echo S=\$SHELL; id -u >/dev/null && echo RAN_A_REAL_SHELL'" | tr -d '\r')
indent "$shim_out"
assert_grep     "shim exec'd a working shell"        "RAN_A_REAL_SHELL"   "$shim_out"
assert_grep     "shim repaired PATH"                 "^P=.*/system/bin"   "$shim_out"
assert_not_grep "shim replaced the inherited PATH"   "^P=/nonexistent$"   "$shim_out"
assert_grep     "SHELL points at a shell, not meowshell" "^S=.*sh$"       "$shim_out"

# 4. A full session: server on the device, client on the host.
echo "== 4. end-to-end shell over a tailcat address =="
adb shell "nohup env TAILCAT_BIN=$DEV/tailcat HOME=$DEV/home TAILCAT_ADDR_FILE=$DEV/addr \
	$DEV/meowshell serve --insecure-no-auth --key=new \
	> $DEV/server.log 2>&1 < /dev/null &" >/dev/null

addr=""
for _ in $(seq 60); do
	addr=$(adb shell "cat $DEV/addr 2>/dev/null" | tr -d '\r\n' || true)
	[ -n "$addr" ] && break
	sleep 2
done
if [ -z "$addr" ]; then
	server_log
	echo "--- device network context ---"
	adb shell "ls -l /etc/resolv.conf 2>&1; getprop net.dns1; ping -c1 -W2 8.8.8.8 2>&1 | tail -2" || true
	fail "server published no address"; exit 1
fi
pass "server published an address (${#addr} chars)"

# 4a. Remote command: exercises the shim's "-c" path.
if out=$(timeout 90 "$HOST_TAILCAT" ssh "$addr" "echo $MARKER; echo P=\$PATH" 2>&1); then
	indent "$out"
	assert_grep "remote command ran on the device"   "$MARKER"          "$out"
	assert_grep "remote command saw a repaired PATH" "P=.*/system/bin"  "$out"
else
	indent "$out"; server_log
	fail "could not open a session to the device"
fi

# 4b. Interactive session under a pty: exercises the shim's "-l" path and
# proves the terminal is real rather than a pipe.
# shellcheck disable=SC2016 # $PATH is for the remote shell to expand
if out=$(printf 'tty; echo I_%s; echo IP=$PATH\nexit\n' "$MARKER" \
	| timeout 90 script -qec "$HOST_TAILCAT ssh $addr" /dev/null 2>&1); then
	out=$(printf '%s\n' "$out" | tr -d '\r')
	indent "$out"
	assert_grep "interactive session ran commands" "I_$MARKER"  "$out"
	assert_grep "session has a real pty"           "/dev/pts/"  "$out"
	assert_grep "interactive session saw a repaired PATH" "IP=.*/system/bin" "$out"
else
	indent "$out"; server_log
	fail "interactive session failed"
fi

# 5. The fleet workflow: the operator generates the key, pipes it to the
# device for one session, and connects using the address they already hold.
# Nothing about the device's identity ever has to come back off the device.
echo "== 5. key supplied at runtime, never stored on the device =="
adb shell "pkill -f meowshell-e2e" >/dev/null 2>&1 || true
sleep 1

keydir=$(mktemp -d)
provisioned=$(XDG_CONFIG_HOME="$keydir" "$HOST_TAILCAT" genkey --key=fleet-e2e | tail -1)
keyfile=$keydir/tailcat/keys/fleet-e2e.private.json
pass "provisioned a key on the host (address is ${#provisioned} chars)"

# stdin carries the key; the device writes nothing.
adb shell -T "env TAILCAT_BIN=$DEV/tailcat HOME=$DEV/home \
	$DEV/meowshell serve --key-stdin --insecure-no-auth \
	> $DEV/server-key.log 2>&1" < "$keyfile" &
keyfeed_pid=$!

# Connect using the address generated on the host, never read from the device.
connected=
for _ in $(seq 30); do
	if out=$(timeout 30 "$HOST_TAILCAT" ssh "$provisioned" "echo K_$MARKER" 2>&1); then
		if printf '%s\n' "$out" | grep -q "K_$MARKER"; then
			connected=1
			break
		fi
	fi
	sleep 2
done
if [ -n "$connected" ]; then
	pass "connected using the host-generated address, with no handoff from the device"
else
	indent "${out:-}"
	echo "--- server log ---"; adb shell "cat $DEV/server-key.log" 2>&1 || true
	fail "could not connect with the provisioned key"
fi

staged=$(adb shell "ls -d /data/local/tmp/meowshell-key-* $DEV/home/meowshell-key-* 2>/dev/null | wc -l" | tr -d '\r ')
if [ "$staged" = 0 ]; then
	pass "the key was never left on the device as a named file"
else
	fail "found $staged staged key file(s) on the device"
fi
rm -rf "$keydir"

# 6. The configuration a fleet would actually run: the device gates on both
# a tailcat client key and an SSH key. Every section above ran with
# authentication switched off.
echo "== 6. an authenticated session against the device =="
adb shell "pkill -f meowshell-e2e" >/dev/null 2>&1 || true
sleep 1

authdir=$(mktemp -d)
mkdir -p "$authdir/.ssh"
ssh-keygen -t ed25519 -N '' -q -f "$authdir/.ssh/id_ed25519"
sshpub=$(cat "$authdir/.ssh/id_ed25519.pub")
# An agent, not a config file: OpenSSH resolves ~ from the passwd database
# rather than $HOME, so a config under a temporary HOME is never read, while
# SSH_AUTH_SOCK travels with the environment.
eval "$(ssh-agent -s)" > /dev/null
ssh-add "$authdir/.ssh/id_ed25519" 2>/dev/null

XDG_CONFIG_HOME=$authdir "$HOST_TAILCAT" genkey --client --key=client-default >/dev/null
clientpub=$(XDG_CONFIG_HOME="$authdir" "$HOST_TAILCAT" printpub)
authed=$(XDG_CONFIG_HOME="$authdir" "$HOST_TAILCAT" genkey --key=device-authed | tail -1)
authkey=$authdir/tailcat/keys/device-authed.private.json

adb shell -T "env TAILCAT_BIN=$DEV/tailcat HOME=$DEV/home \
	$DEV/meowshell serve --key-stdin --allow='$clientpub' --authorized-keys='$sshpub' \
	> $DEV/server-auth.log 2>&1" < "$authkey" &
keyfeed_pid=$!

authok=
for _ in $(seq 30); do
	if out=$(XDG_CONFIG_HOME=$authdir timeout 30 \
			"$HOST_TAILCAT" ssh "$authed" "echo B_$MARKER" 2>&1); then
		if printf '%s\n' "$out" | grep -q "B_$MARKER"; then
			authok=1
			break
		fi
	fi
	sleep 2
done
if [ -n "$authok" ]; then
	pass "opened a session gated on --allow and --authorized-keys"
else
	indent "${out:-}"
	echo "--- server log ---"; adb shell "cat $DEV/server-auth.log" 2>&1 || true
	fail "could not open an authenticated session to the device"
fi

# The half that proves the gate is real.
otherdir=$(mktemp -d)
XDG_CONFIG_HOME=$otherdir "$HOST_TAILCAT" genkey --client --key=client-default >/dev/null
if out=$(XDG_CONFIG_HOME=$otherdir timeout 25 \
		"$HOST_TAILCAT" ssh "$authed" "echo LEAKED_$MARKER" 2>&1); then
	indent "$out"
	fail "a client key outside --allow got a session on the device"
else
	pass "a client key outside --allow was refused by the device"
fi
rm -rf "$authdir" "$otherdir"

echo
if [ "$failed" -eq 0 ]; then
	echo "all end-to-end checks passed"
else
	echo "end-to-end checks failed" >&2
fi
exit "$failed"
