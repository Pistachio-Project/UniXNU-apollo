#!/usr/bin/env bash
# One entry-probe question: does the kernel get past the call to SYMBOL (in FUNCTION, default _arm_init)?
# Builds a payload from KERNEL (default: the kernel step output) with the reset placed after that call, boots it from
# RAM and reports whether the phone reset by itself. usage: scripts/probe.sh SYMBOL [FUNCTION [OCCURRENCE]]
#   KERNEL=file  TRUST=bundle  DELAY=seconds (default 3)  WAIT=seconds (default 120)
set -euo pipefail
DEVICE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
UNIXNU=$DEVICE/../UniXNU
OUT=$UNIXNU/out/apollo/ios-27.0.1-24A446/apollo
SYMBOL=$1 FUNCTION=${2:-_arm_init} OCCURRENCE=${3:-1}
KERNEL=${KERNEL:-$OUT/kernel/kernel.macho}
TRUST=${TRUST:-$UNIXNU/out/ipsw/24A446/trustcache-iphone13.bundle}
board=$(mktemp)
cp "$DEVICE/board.toml" "$board"
trap 'cp "$board" "$DEVICE/board.toml"; rm -f "$board"' EXIT
python3 - "$DEVICE/board.toml" "$SYMBOL" "$FUNCTION" "$OCCURRENCE" "${DELAY:-3}" <<'PY'
import re, sys
path, symbol, function, occurrence, delay = sys.argv[1:]
text = re.sub(r'^entry_probe_\w+ = .*\n', '', open(path).read(), flags=re.M)
text = text.replace('[payload.adt]', f'entry_probe_reset_delay = {delay}\nentry_probe_reset_after = "{symbol}"\n'
                    f'entry_probe_reset_in = "{function}"\nentry_probe_reset_occurrence = {occurrence}\n\n[payload.adt]', 1)
open(path, 'w').write(text)
PY
cd "$UNIXNU"
./unixnu payload --kernel "$KERNEL" --trust-cache "$TRUST" >/dev/null 2>&1 || { tail -3 "$OUT/logs/payload-patch.log" >&2; exit 1; }
tail -1 "$OUT/logs/payload-patch.log" >&2
./unixnu bootimg >/dev/null 2>&1
WAIT=${WAIT:-120} "$DEVICE/scripts/bootcycle.sh" "probe-${SYMBOL#_}" >/dev/null && echo "PASSED: reset after $SYMBOL in $FUNCTION" || { echo "STUCK before the reset after $SYMBOL in $FUNCTION"; exit 3; }
