#!/usr/bin/env bash
# The iOS 27.0.1 profile links the kexts of the iPad17,3 24A446 kernelcache (os-profiles/ios-27.0.1-24A446/profile.toml).
# Fetch it through UniXNU's own iPadOS profile; both IPSWs share out/ipsw/24A446.
# usage: scripts/fetch-kernelcache.sh [UNIXNU_CHECKOUT]
set -euo pipefail
DEVICE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
UNIXNU=${1:-$DEVICE/../UniXNU}
cd "$UNIXNU"
./unixnu ipsw fetch --os ipados-27.0.1-24A446 -D "$DEVICE" KernelCache
