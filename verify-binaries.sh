#!/usr/bin/env bash
# Sanity-check that each binary really targets the platform its name claims:
# right format, right machine, and for Android the platform's own loader
# rather than a glibc one.
set -euo pipefail

OUT_DIR=${OUT_DIR:-$PWD/dist}
BINARIES=${BINARIES:-tailcat meowshell}
status=0

# elf_check <file> <machine substring> [interpreter]
elf_check() {
	local f=$1 machine=$2 interp=${3:-}
	local got_machine got_interp errs=()
	got_machine=$(readelf -h "$f" | sed -n 's/.*Machine: *//p')
	got_interp=$(readelf -l "$f" | sed -n 's/.*program interpreter: \(.*\)\]/\1/p')

	[[ $got_machine == *"$machine"* ]] || errs+=("machine=$got_machine want *$machine*")
	if [ -n "$interp" ]; then
		# Android binaries are position-independent and use Android's loader.
		[[ $(readelf -h "$f" | sed -n 's/.*Type: *\([A-Z]*\).*/\1/p') == DYN ]] \
			|| errs+=("not position-independent")
		[[ $got_interp == "$interp" ]] || errs+=("interp=$got_interp want $interp")
	else
		# Everything else must NOT be looking for Android's loader.
		[[ $got_interp == /system/bin/* ]] && errs+=("unexpectedly uses Android's loader")
	fi
	printf '%s' "${errs[*]}"
}

# pe_check <file>
pe_check() {
	local f=$1 out
	out=$(file -b "$f")
	case "$out" in
		PE32+*|PE32*) : ;;
		*) printf 'not a Windows executable: %s' "$out" ;;
	esac
}

check() { # check <filename> <kind> <machine> [interpreter]
	local f=$OUT_DIR/$1 kind=$2 machine=$3 interp=${4:-} errs
	if [ ! -f "$f" ]; then
		printf 'MISSING  %s\n' "$1"; status=1; return
	fi
	case "$kind" in
		elf) errs=$(elf_check "$f" "$machine" "$interp") ;;
		pe)  errs=$(pe_check "$f") ;;
	esac
	if [ -z "$errs" ]; then
		printf 'OK       %-34s %s\n' "$1" "$machine"
	else
		printf 'BAD      %-34s %s\n' "$1" "$errs"; status=1
	fi
}

for b in $BINARIES; do
	check "${b}_android_arm64" elf "AArch64"     /system/bin/linker64
	check "${b}_android_armv7" elf "ARM"         /system/bin/linker
	check "${b}_android_amd64" elf "X86-64"      /system/bin/linker64
	check "${b}_android_386"   elf "Intel 80386" /system/bin/linker

	check "${b}_linux_amd64"   elf "X86-64"
	check "${b}_linux_arm64"   elf "AArch64"
	check "${b}_linux_armv7"   elf "ARM"
	check "${b}_linux_386"     elf "Intel 80386"

	check "${b}_windows_amd64.exe" pe "x86-64"
	check "${b}_windows_arm64.exe" pe "aarch64"
done

exit $status
