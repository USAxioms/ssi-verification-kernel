#!/usr/bin/env bash
# Tests of the checks themselves (R3 1.1). The README of v1.0 stated that injected violations are caught; this script
# makes that claim executable. Each negative control must be detected, or this script fails.
set -uo pipefail
cd "$(dirname "$0")"
. ./binscan.sh
status=0
inject_src() {   # name file line-to-append
  local t; t=$(mktemp -d); cp -r src include tests ts scan_sources.py "$t/"
  printf '%s\n' "$3" >> "$t/$2"
  if (cd "$t" && python3 scan_sources.py >/dev/null 2>&1); then echo "    MISSED   source scan: $1"; status=1
  else echo "    caught   source scan: $1"; fi
  rm -rf "$t"
}
echo "[A] source scanner negative controls"
inject_src "double in C"            src/ssi.c   'double zz;'
inject_src "float in C"             src/ssi.c   'float zz;'
inject_src "decimal literal in C"   src/ssi.c   'static int zz = 1.5;'
inject_src "exponent literal in C"  src/ssi.c   'static int zz = 1e5;'
inject_src "math.h include"         src/ssi.c   '#include <math.h>'
inject_src "Math.sqrt in TS"        ts/ssi_crosscheck.ts 'const zz = Math.sqrt(4);'
inject_src "decimal literal in TS"  ts/ssi_crosscheck.ts 'const zz = 0.25;'
echo "[B] source scanner positive control (clean tree must pass)"
if python3 scan_sources.py >/dev/null; then echo "    ok       clean tree passes"; else echo "    FAIL     clean tree rejected"; status=1; fi

echo "[C] compiler layer negative control: floating point must not compile under -mgeneral-regs-only"
t=$(mktemp -d)
cat > "$t/fp.c" <<'EOC'
volatile double a = 3; volatile double b = 7;
double f(void) { return a * b / (a + b); }
EOC
if [ "$(binscan_arch)" = "x86_64" ] || [ "$(binscan_arch)" = "aarch64" ]; then
  if gcc -std=c11 -O2 -mgeneral-regs-only -c "$t/fp.c" -o "$t/fp_bad.o" 2>/dev/null; then echo "    MISSED   -mgeneral-regs-only accepted double arithmetic"; status=1
  else echo "    caught   -mgeneral-regs-only rejects double arithmetic"; fi
  echo "[D] binary scanner negative control: a double-using object compiled WITHOUT the flag must be flagged"
  gcc -std=c11 -O2 -c "$t/fp.c" -o "$t/fp_ok.o" && n=$(binscan_count "$t/fp_ok.o")
  if [ "$n" != "0" ] && [ "$n" != "UNSUPPORTED" ]; then echo "    caught   binary scan flags $n floating-point instructions"; else echo "    MISSED   binary scan result: $n"; status=1; fi
else
  echo "    SKIPPED  architecture $(binscan_arch): no binary scan pattern, so no control can run"; status=1
fi
rm -rf "$t"
[ $status -eq 0 ] && echo "SELF-TESTS: ALL NEGATIVE CONTROLS CAUGHT" || echo "SELF-TESTS: FAILED"
exit $status
