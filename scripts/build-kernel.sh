#!/usr/bin/env bash
# The kernel for apollo, from sources to the image the payload step packs:
#   1. ./unixnu build kernel       XNU, the component archives, UniXNU's RELEASE reference (when board.toml lists it)
#   2. merge_fileset_maps.py       pair Apple's kernel with ours through the KDK kernel and that reference
#   3. ./unixnu prelink            emit the kernel collection with Apple's kexts from the merged pairing
#   4. scripts/nopac-kernel.py     rewrite it for CPUs without pointer authentication, store the integrity HMACs again
# usage: scripts/build-kernel.sh        UNIXNU_LLVM_LTO=llvm-lto of the toolchain's LLVM (for the reference)
set -euo pipefail
DEVICE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
UNIXNU=$(cd "$DEVICE/../UniXNU" && pwd)
OUT=$UNIXNU/out/apollo/ios-27.0.1-24A446/apollo
export UNIXNU_LLVM_LTO=${UNIXNU_LLVM_LTO:-$DEVICE/.cache/toolchain/llvm-build/bin/llvm-lto}
NATIVE=$OUT/tree/build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/mach.development.bcm2837.unstripped.noctf
REFERENCE=$OUT/tree/build/xnu/fileset-reference/mach.release.bcm2837.unstripped.noctf
KDK=$("$DEVICE/scripts/fetch-kdk-kernel.sh" "$UNIXNU")
[ -f "$KDK.reference" ] || python3 "$DEVICE/scripts/kdk-reference.py" "$KDK" "$KDK.dwarf" "$KDK.reference"
cd "$UNIXNU"
before=$(sha256sum "$NATIVE" 2>/dev/null | cut -d' ' -f1 || true)
# The build runs the prelink itself at its end; with a new kernel the pairing of step 2 is stale and that run
# stops there, which is expected.
./unixnu build kernel > "$OUT/build-kernel.log" 2>&1 || true
[ -f "$NATIVE" ] || { tail -5 "$OUT/build-kernel.log" >&2; exit 1; }
grep -q ' error: ' "$OUT/logs/kernel.log" && { grep ' error: ' "$OUT/logs/kernel.log" | head -5 >&2; exit 1; }
[ -f "$REFERENCE" ] || { echo "no RELEASE reference at $REFERENCE: list build-fileset-release-reference.py in board.toml [kernel] archives once" >&2; exit 1; }
mkdir -p "$OUT/prelink"
python3 "$DEVICE/package/prelink/merge_fileset_maps.py" --kit "$OUT/tree/kits/XnuPrelink" \
	--kernelcache "$UNIXNU/out/ipsw/24A446/kernelcache.decompressed" --native "$NATIVE" \
	--reference "$KDK.reference" --reference "$REFERENCE" --output "$OUT/prelink/merged.map.json"
./unixnu prelink > "$OUT/prelink/prelink.log" 2>&1 || { tail -5 "$OUT/logs/prelink.log" >&2; exit 1; }
grep 'unresolved closure' "$OUT/logs/prelink.log"
rm -f "$OUT/kernel/kernel.macho.arm64e"
python3 "$DEVICE/scripts/nopac-kernel.py"
