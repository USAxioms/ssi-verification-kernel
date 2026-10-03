#!/usr/bin/env bash
# PURE WAD18 enforcement, three independent layers.
#  1. Compiler: every C file is built with -mgeneral-regs-only, which forbids floating-point code generation.
#  2. Source:   no floating-point type, header, or literal in any C or TypeScript source.
#  3. Binary:   the disassembly of every compiled kernel object contains no floating-point or vector register.
#     Fail closed (R3 1.1): on an architecture with no scan pattern the binary layer is reported UNVERIFIED and the
#     check fails, unless SSI_ALLOW_UNVERIFIED_BINARY=1, in which case the verdict is PARTIAL, never VERIFIED.
set -uo pipefail
cd "$(dirname "$0")"
. ./binscan.sh
status=0; partial=0
CFLAGS="-std=c11 -O2 -Wall -Wextra -Werror -mgeneral-regs-only -Iinclude"

echo "[1] compiler: build all C sources with -mgeneral-regs-only"
tmp=$(mktemp -d)
for f in src/*.c tests/*.c; do
  if gcc $CFLAGS -c "$f" -o "$tmp/$(basename "$f" .c).o"; then echo "    ok  $f"; else echo "    FAIL $f"; status=1; fi
done

echo "[2] source scan (comments and strings removed): float, double, math.h, Math., decimal literals"
if python3 scan_sources.py; then echo "    ok"; else status=1; fi

echo "[3] binary scan ($(binscan_arch)): disassembly of kernel objects for floating-point or vector registers"
fp=$(binscan_count "$tmp"/*.o)
if [ "$fp" = "0" ]; then echo "    ok  0 floating-point or vector instructions"
elif [ "$fp" = "UNSUPPORTED" ]; then
  echo "    UNVERIFIED  no scan pattern for architecture $(binscan_arch)"
  if [ "${SSI_ALLOW_UNVERIFIED_BINARY:-0}" = "1" ]; then partial=1; else status=1; fi
else echo "    FAIL $fp floating-point or vector instructions"; status=1; fi
rm -rf "$tmp"

if [ $status -ne 0 ]; then echo "PURE WAD18: FAILED"
elif [ $partial -eq 1 ]; then echo "PURE WAD18: PARTIAL (binary layer unverified)"
else echo "PURE WAD18: VERIFIED"; fi
exit $status
