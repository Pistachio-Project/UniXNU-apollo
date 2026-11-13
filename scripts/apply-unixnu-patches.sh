#!/usr/bin/env bash
# Apply patches/unixnu/*.patch to the UniXNU checkout: what its Linux kernel step needs for an arm64e profile and is
# not upstream yet (made against UniXNU 7d85ede). Applied patches are skipped, so re-running is harmless.
# usage: scripts/apply-unixnu-patches.sh [UNIXNU_CHECKOUT]
set -euo pipefail
DEVICE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
UNIXNU=${1:-$DEVICE/../UniXNU}
for patch in "$DEVICE"/patches/unixnu/*.patch; do
	if git -C "$UNIXNU" apply --reverse --check "$patch" 2>/dev/null; then
		echo "already applied: $(basename "$patch")"
	else
		git -C "$UNIXNU" apply "$patch"
		echo "applied: $(basename "$patch")"
	fi
done
