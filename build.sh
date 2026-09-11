#!/usr/bin/env bash
# Cross-compile tailscale/tailcat and this repo's meowshell wrapper.
#
# Targets default to every platform upstream releases for, plus Android.
# Android needs the NDK, because those binaries are built with cgo so that
# name resolution goes through bionic; point ANDROID_NDK_HOME at an NDK
# (r19+, unified toolchain). Linux and Windows are pure Go and need nothing.
#
#   ./build.sh                      # everything the toolchain allows
#   PLATFORMS=linux ./build.sh      # just one OS
set -euo pipefail

REPO_DIR=$PWD
SRC_URL=${SRC_URL:-https://github.com/tailscale/tailcat.git}
# Keep release inputs reproducible. Override deliberately for upstream testing;
# CI uses this same reviewed revision unless a workflow_dispatch input is given.
SRC_REF=${SRC_REF:-$(tr -d '[:space:]' < "$REPO_DIR/tailcat.ref")}
SRC_DIR=${SRC_DIR:-$REPO_DIR/.tailcat-src}
OUT_DIR=${OUT_DIR:-$REPO_DIR/dist}
API=${ANDROID_API_LEVEL:-21}
NDK=${ANDROID_NDK_HOME:-}
PLATFORMS=${PLATFORMS:-android linux windows}

if [ ! -d "$SRC_DIR/.git" ]; then
	git clone "$SRC_URL" "$SRC_DIR"
fi
git -C "$SRC_DIR" fetch origin "$SRC_REF"
git -C "$SRC_DIR" checkout --detach FETCH_HEAD
# A re-run against an already-cloned SRC_DIR (a plain local dev convenience;
# CI always starts from a fresh clone) would otherwise still carry the
# patch applied below from the previous run, and re-applying it would fail.
git -C "$SRC_DIR" reset --hard FETCH_HEAD

# netmon.NewStatic() (used by pickregion.go's PickBestRegion, itself called
# by ConnInfo.Expand whenever a key's RegionID is -1, the default for
# --key=new) silently leaves its interface state nil if interface
# enumeration errors, and netcheck.GetReport then dereferences that nil
# unconditionally and panics. This is a real gap upstream, not anything this
# repo introduced, and it reliably kills every ephemeral-key server session
# on Android, where sandboxed interface enumeration fails. There is no
# upstream fix to pull yet and this repo does not fork tailcat, so patch the
# clone on every build; a patch that no longer applies means upstream
# changed the surrounding code and this needs re-checking, so fail loudly
# rather than silently shipping the panic.
git -C "$SRC_DIR" apply "$REPO_DIR/patches/tailcat/pickregion-nil-ifstate.patch"

# netmon.New() (which Server.Start and Client both call unconditionally,
# separately from the PickBestRegion path above) needs a working interface
# list before anything else can happen, and hits the same Android
# netlink-permission denial. github.com/wlynxg/anet gets a working list
# without the netlink call the stdlib makes; see the patch and its target
# file's comments for the detail. Added via `go get`, which computes
# go.mod/go.sum correctly, rather than hand-patching them.
git -C "$SRC_DIR" apply "$REPO_DIR/patches/tailcat/android-netmon-interface-getter.patch"
(cd "$SRC_DIR" && go get github.com/wlynxg/anet@v0.0.5 golang.org/x/crypto@v0.56.0)

# tailcat's SSH server hardcodes /bin/sh and /usr/local/bin:/usr/bin:/bin
# for the session shell and PATH, neither of which exist on Android --
# but this repo's own cmd/meowshell already works around exactly that
# (see its package doc comment) by exporting a repaired SHELL/HOME/USER
# before exec'ing into tailcat, so no tailcat-side patch is needed here.

mkdir -p "$OUT_DIR"

# Upstream's release tags (.goreleaser.yaml). netgo is dropped for Android:
# it forces Go's pure DNS resolver, which reads /etc/resolv.conf -- a file
# Android does not have, leaving every lookup to fail against the localhost
# fallback nameservers. Go's own net/conf.go says "DNS requests don't work
# on Android, so prefer the cgo resolver". Elsewhere netgo is what upstream
# ships, and works.
ALL_TAGS=$(tr -d '[:space:]' < "$SRC_DIR/build-tags.txt")
ANDROID_TAGS=$(printf '%s' "$ALL_TAGS" | tr ',' '\n' | grep -vx netgo | paste -sd,)

VERSION=${VERSION:-$(git -C "$SRC_DIR" describe --tags --always)}
LDFLAGS="-s -w -X main.version=$VERSION"

# goenv <goos> <goarch> [goarm] echoes env assignments for one target.
# Returns 1 if the target needs a toolchain that is not installed (skip it)
# and 2 if it is installed but lacks that target's compiler (fatal).
goenv() {
	local os=$1 arch=$2 arm=${3:-} cc
	if [ "$os" = android ]; then
		case "$arch" in
			arm64) cc=aarch64-linux-android$API-clang ;;
			arm)   cc=armv7a-linux-androideabi$API-clang ;;
			amd64) cc=x86_64-linux-android$API-clang ;;
			386)   cc=i686-linux-android$API-clang ;;
		esac
		if [ -z "$NDK" ]; then
			echo "skip android/$arch: needs an NDK (set ANDROID_NDK_HOME)" >&2
			return 1
		fi
		cc=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/$cc
		if [ ! -x "$cc" ]; then
			echo "error: android/$arch: no such compiler in the NDK: $cc" >&2
			return 2
		fi
		printf 'CGO_ENABLED=1\nGOOS=android\nGOARCH=%s\nCC=%s\n' "$arch" "$cc"
	else
		printf 'CGO_ENABLED=0\nGOOS=%s\nGOARCH=%s\n' "$os" "$arch"
	fi
	[ -n "$arm" ] && printf 'GOARM=%s\n' "$arm"
	return 0
}

# build <name> <module dir> <package> <goos> <goarch> [goarm]
build() {
	local name=$1 dir=$2 pkg=$3 os=$4 arch=$5 arm=${6:-}
	local out=$OUT_DIR/${name}_${os}_${arch}${arm:+v$arm}
	[ "$os" = windows ] && out=$out.exe

	local envtext rc=0
	# Take goenv's status from the assignment, not from a pipeline or
	# process substitution: those report the reader's status, which would
	# let a skipped target build with no GOOS/GOARCH set at all and
	# quietly produce a host binary under a foreign name.
	envtext=$(goenv "$os" "$arch" "$arm") || rc=$?
	case $rc in
		0) ;;
		1) return 0 ;;
		*) exit 1 ;;
	esac
	local -a envs
	mapfile -t envs <<< "$envtext"

	local tags=$ALL_TAGS
	local ldflags=$LDFLAGS
	if [ "$os" = android ]; then
		tags=$ANDROID_TAGS
		# cmd/tailcat/netmon_android.go's github.com/wlynxg/anet dependency
		# uses go:linkname into net's internals (its way of getting a
		# working interface list despite Android's netlink sandboxing --
		# see patches/tailcat/android-netmon-interface-getter.patch), which
		# Go 1.23+'s linker refuses by default. Harmless on meowshell, which
		# doesn't use go:linkname at all.
		ldflags="$ldflags -checklinkname=0"
	fi

	echo "building $name $os/$arch${arm:+v$arm} -> $(basename "$out")"
	(cd "$dir" && env "${envs[@]}" go build -tags="$tags" -ldflags "$ldflags" -o "$out" "$pkg")
}

targets_for() {
	case "$1" in
		android) echo "arm64 . arm 7 amd64 . 386 ." ;;
		linux)   echo "amd64 . arm64 . arm 7 386 ." ;;
		windows) echo "amd64 . arm64 ." ;;
		*) echo "unknown platform: $1" >&2; exit 1 ;;
	esac
}

for os in $PLATFORMS; do
	# shellcheck disable=SC2046 # deliberate word split into arch/goarm pairs
	set -- $(targets_for "$os")
	while [ $# -gt 0 ]; do
		arm=$2; [ "$arm" = "." ] && arm=""
		build tailcat   "$SRC_DIR"  ./cmd/tailcat   "$os" "$1" "$arm"
		build meowshell "$REPO_DIR" ./cmd/meowshell "$os" "$1" "$arm"
		shift 2
	done
done

cd "$OUT_DIR"
sha256sum tailcat_* meowshell_* > SHA256SUMS.txt
cat SHA256SUMS.txt
