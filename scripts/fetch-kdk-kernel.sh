#!/usr/bin/env bash
# The symbol-bearing reference kernel for the prelink: kernel.release.t8142 of the macOS 27.0.1 Kernel Debug Kit
# (build 26A434, xnu-13432.1.9), the same XNU and the same SoC configuration as the kernel inside the iPad17,3
# 24A446 kernelcache (xnu-13432.2.10, RELEASE_ARM64_T8142) whose kexts this port links.
#
# UniXNU names the functions of that stripped kernel by comparing it with a RELEASE build of its own source, which
# works when the build uses Xcode. Built on Linux with upstream clang the comparison names far fewer functions
# (porting.toml, area "packaging"); Apple's own symbols do not depend on the host compiler.
#
# The kit is fetched from the dortania/KdkSupportPkg mirror of Apple's download. Nothing of it is redistributed.
# usage: scripts/fetch-kdk-kernel.sh [UNIXNU_CHECKOUT]     -> out/kdk/26A434/kernel.release.t8142 (and .dwarf, its dSYM)
set -euo pipefail
DEVICE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
UNIXNU=${1:-$DEVICE/../UniXNU}
BUILD=26A434
KERNEL=kernel.release.t8142
OUT=$UNIXNU/out/kdk/$BUILD
URL=https://github.com/dortania/KdkSupportPkg/releases/download/$BUILD/Kernel_Debug_Kit_27.0.1_build_$BUILD.dmg
mkdir -p "$OUT"
cd "$OUT"
[ -f "$KERNEL" ] && { echo "$OUT/$KERNEL"; exit 0; }
[ -f kdk.dmg.done ] || { curl -fL -A curl -C - -o kdk.dmg "$URL"; touch kdk.dmg.done; }
rm -rf dmg pkg
7z x -y -odmg kdk.dmg >/dev/null || true          # 7-Zip reports the HFS+ resource forks it cannot place
PKG=$(find dmg -name 'KernelDebugKit.pkg' | head -1)
7z x -y -opkg "$PKG" >/dev/null
PAYLOAD=$(find pkg -name Payload | head -1)
# The payload is pbzx: a header, then chunks of (flags, length) + xz stream (or raw bytes when length is the chunk size).
python3 - "$PAYLOAD" <<'PY' | bsdtar -xf - "./System/Library/Kernels/$KERNEL" "./System/Library/Kernels/$KERNEL.dSYM/Contents/Resources/DWARF/$KERNEL"
import lzma, struct, sys
with open(sys.argv[1], 'rb') as stream:
    if stream.read(4) != b'pbzx':
        sys.exit('Payload is not pbzx')
    flags, = struct.unpack('>Q', stream.read(8))
    while flags & (1 << 24):
        flags, length = struct.unpack('>QQ', stream.read(16))
        data = stream.read(length)
        sys.stdout.buffer.write(lzma.decompress(data) if data[:6] == b'\xfd7zXZ\x00' else data)
PY
mv "System/Library/Kernels/$KERNEL" "$KERNEL"
mv "System/Library/Kernels/$KERNEL.dSYM/Contents/Resources/DWARF/$KERNEL" "$KERNEL.dwarf"
rm -rf dmg pkg System
echo "$OUT/$KERNEL"
