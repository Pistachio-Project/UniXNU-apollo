#!/usr/bin/env bash
# One boot test from RAM: Android -> fastboot -> "fastboot boot" of the built image -> wait for Android to come back
# (the kernel resets itself: bootlog-reset=N, a panic, or the entry probe) -> save the kernel's console from
# /sys/fs/pstore/console-ramoops-0. Nothing is written to the phone's storage.
# usage: scripts/bootcycle.sh [NAME] [IMAGE]     WAIT=seconds to wait for Android (default 240)
set -euo pipefail
DEVICE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
NAME=${1:-run}
IMAGE=${2:-$DEVICE/../UniXNU/out/apollo/ios-27.0.1-24A446/apollo/boot/boot.img}
LOGS=$DEVICE/.cache/bootlogs
WAIT=${WAIT:-240}
mkdir -p "$LOGS"
stamp=$(date +%Y%m%d-%H%M%S)
out=$LOGS/$stamp-$NAME
say() { echo "bootcycle: $*" >&2; }

if adb get-state >/dev/null 2>&1; then
	adb root >/dev/null 2>&1 || true
	sleep 2
	adb reboot bootloader
fi
say "waiting for fastboot"
for _ in $(seq 60); do fastboot devices | grep -q fastboot && break; sleep 1; done
fastboot devices | grep -q fastboot || { say "no fastboot device"; exit 2; }
sleep 4          # apollo's ABL drops the first command when it comes too early
sha256sum "$IMAGE" | cut -c1-16 > "$out.image"
fastboot boot "$IMAGE" 2>&1 | tail -3 >&2
started=$(date +%s)
say "booted $(basename "$IMAGE"); waiting up to $WAIT s for Android"
while :; do
	if adb get-state 2>/dev/null | grep -q device; then break; fi
	if [ $(( $(date +%s) - started )) -ge "$WAIT" ]; then
		say "Android did not come back in $WAIT s: the kernel did not reset (hold Power + Volume Down)"
		exit 3
	fi
	sleep 2
done
say "Android is back after $(( $(date +%s) - started )) s"
adb wait-for-device
adb root >/dev/null 2>&1 || true
sleep 3
adb wait-for-device
adb shell 'cat /sys/fs/pstore/console-ramoops-0 2>/dev/null' > "$out.log" || true
say "$(wc -c < "$out.log") bytes in $out.log"
echo "$out.log"
