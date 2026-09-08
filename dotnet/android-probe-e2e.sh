#!/usr/bin/env bash
# Installs and runs Meowshell.AndroidProbe on a running emulator, checks
# that it reached PROBE_PASS, then -- if HOST_TAILCAT is set -- dials into
# it from a real host tailcat and runs commands over the session.
#
# This is the one thing nothing else in the suite proves: that a real
# .NET-for-Android build of an app referencing only the packed NuGet
# packages -- not this repo's source -- has its native libraries actually
# extracted into ApplicationInfo.NativeLibraryDir, that
# MeowshellOptions.Create finds and runs them from there, and that a
# session served from inside a real installed app's sandbox (as opposed
# to adb shell's much less restricted one, which is all emulator-e2e's
# own round-trip covers) actually works end to end. Invoked as the
# "script" for reactivecircus/android-emulator-runner, so adb and a
# booted device are already in scope.
set -euo pipefail

# tailcat's own diagnostics (forwarded to logcat by MainActivity's onLog)
# include the address it just published; with InsecureNoAuth that address
# alone is a live credential, so it must never reach a CI log verbatim
# (public repo, live-streamed while the job runs). $log below stays
# unredacted for internal use (extracting $addr to actually dial in); only
# what gets echoed into this script's own stdout is redacted.
redact() { sed -E 's/\btc[A-Za-z0-9_-]{10,}/tc<redacted>/g'; }
# ::add-mask:: registers a value with the runner itself, so it gets
# replaced with *** in this job's log from here on regardless of what
# prints it later -- belt and suspenders alongside redact() above, which
# only covers print sites this script already knows about.
mask() { [ -n "$1" ] && printf '::add-mask::%s\n' "$1"; }

APP_ID=com.meowshell.androidprobe
# set -e + pipefail means a "not found" from grep or find has to be
# neutralized here, or the script would abort before ever reaching the
# fallback below or the explicit "no APK" error after it.
APK=$(find dotnet/Meowshell.AndroidProbe/bin/Release -iname "*.apk" 2>/dev/null | grep -i signed | head -1 || true)
if [ -z "$APK" ]; then
	APK=$(find dotnet/Meowshell.AndroidProbe/bin/Release -iname "*.apk" 2>/dev/null | head -1 || true)
fi
if [ -z "$APK" ]; then
	echo "FAIL no built APK found under dotnet/Meowshell.AndroidProbe/bin/Release" >&2
	find dotnet/Meowshell.AndroidProbe/bin -type f >&2 || true
	exit 1
fi
echo "== installing $APK =="

adb uninstall "$APP_ID" >/dev/null 2>&1 || true
adb install -r "$APK"

echo "== launching =="
adb logcat -c
# Started by category rather than "am start -n <pkg>/<activity>": .NET for
# Android can mangle the Java-visible activity class name when the C#
# namespace does not read as a reverse-domain package, so this avoids
# having to know that name.
adb shell monkey -p "$APP_ID" -c android.intent.category.LAUNCHER 1 >/dev/null

echo "== waiting for a result =="
result=
for _ in $(seq 45); do
	log=$(adb logcat -d -s MeowshellProbe:V 2>/dev/null || true)
	if printf '%s' "$log" | grep -q PROBE_PASS; then
		result=pass
		break
	fi
	if printf '%s' "$log" | grep -q PROBE_FAIL; then
		result=fail
		break
	fi
	sleep 2
done

echo "--- probe log (redacted) ---"
adb logcat -d -s MeowshellProbe:V | redact || true
echo "-----------------"

case "$result" in
	pass) echo "ok    the packaged Android binaries were found and ran" ;;
	fail) echo "FAIL  the probe reported a failure (see log above)" >&2; exit 1 ;;
	*)    echo "FAIL  the probe never reported a result within the timeout" >&2; exit 1 ;;
esac

# MainActivity deliberately keeps the server up rather than stopping it
# once PROBE_PASS is logged, so there's something to dial into here.
if [ -z "${HOST_TAILCAT:-}" ]; then
	echo "skip  no HOST_TAILCAT set; not attempting a live round-trip"
	exit 0
fi

addr=$(printf '%s\n' "$log" | tr -d '\r' \
	| sed -n 's/.*Server listening with new address: \(tc[A-Za-z0-9_-]*\).*/\1/p' | tail -1)
if [ -z "$addr" ]; then
	echo "FAIL  PROBE_PASS but no tailcat address found in the probe's own log" >&2
	exit 1
fi
mask "$addr"
echo "== connecting from the host (${#addr} char address) =="

marker="probe-e2e-$$-$RANDOM"
roundtrip_ok=1
if out=$(timeout 60 "$HOST_TAILCAT" ssh "$addr" "echo $marker; whoami; echo PATH=\$PATH" 2>&1); then
	printf '%s\n' "$out" | sed 's/^/      /'
	printf '%s\n' "$out" | grep -q "$marker" \
		|| { echo "FAIL  remote command did not run" >&2; roundtrip_ok=0; }
	printf '%s\n' "$out" | grep -q '/system/bin' \
		|| { echo "FAIL  session PATH has no /system/bin -- meowshell's shim did not repair it" >&2; roundtrip_ok=0; }
else
	printf '%s\n' "$out" | sed 's/^/      /'
	echo "FAIL  could not open a session against the probe" >&2
	roundtrip_ok=0
fi

if [ "$roundtrip_ok" = 1 ]; then
	echo "ok    a real client ran commands over a session served from inside the app"
else
	exit 1
fi
