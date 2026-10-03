#!/usr/bin/env bash
# Shared binary-layer scanner for PURE WAD18. Usage: source binscan.sh; binscan_count obj...
# Prints the number of floating-point or vector instructions, or the word UNSUPPORTED when the
# architecture has no scan pattern. Fail closed: UNSUPPORTED is never reported as zero.
binscan_arch() { uname -m; }
binscan_count() {
  case "$(binscan_arch)" in
    x86_64|amd64)
      for o in "$@"; do objdump -d --no-show-raw-insn "$o"; done | grep -ciE '%(x|y|z)mm|%st\(|\bf(ld|st|add|mul|div|sub)' ;;
    aarch64|arm64)   # patterns for A64 FP/SIMD registers and mnemonics; not exercised by the author's x86_64 runs
      for o in "$@"; do objdump -d --no-show-raw-insn "$o"; done | sed 's/<[^>]*>//g' | grep -ciE '\b[vqdsh][0-9]{1,2}\b|\bf(add|sub|mul|div|mov|cmp|cvt|sqrt|abs|neg)' ;;
    *) echo UNSUPPORTED ;;
  esac
}
