#!/usr/bin/env bash
# Mutation check: break the kernel in ways that violate the specifications and confirm the test suite catches each one.
set -uo pipefail
cd "$(dirname "$0")"
CFLAGS="-std=c11 -O2 -Wall -Wextra -Werror -mgeneral-regs-only -Iinclude"
declare -a NAMES SRC FROM TO
add() { NAMES+=("$1"); SRC+=("$2"); FROM+=("$3"); TO+=("$4"); }
add "unknown treated as safe (violates Axiom S2)"        src/ssi.c   'if (inv[i] != SSI_TT) return 0;'        'if (inv[i] == SSI_FF) return 0;'
add "empty invariant set treated as safe (violates S1)"  src/ssi.c   'if (n == 0) return 0;'                   'if (n == 0) return 1;'
add "revocation ignored by Permit (violates §13)"        src/ssi.c   '!c->revoked && c->within_scope'          'c->within_scope'
add "UNKNOWN verification executes (violates §14)"       src/ssi.c   'if (v == VER_UNKNOWN) return DEC_DEFER;' 'if (v == VER_UNKNOWN) return DEC_EXECUTE;'
add "invariant checked after commit (violates §31)"      src/ssi.c   'if (!inv_next) return GATE_REJECT;'      ''
add "untyped action permitted (violates §9)"             src/ssi.c   'if (kind < ACT_READ || kind > ACT_POLICY_CHANGE) return 0;' ''
add "inexact multiply silently rounds (violates W2)"     src/wad18.c 'if (rem != 0) return WAD_NON_EXACT;' ''
add "expired CSL still authorizes (violates C1)"         src/ssi.c   'return sig && !revoked && now <= until && env;' 'return sig && !revoked && env;'
add "capability escalation allowed (violates §17)"       src/ssi.c   'return (next & ~authorized) == 0 || gov;' 'return 1;'
add "deployment binding ignored (violates §16)"          src/ssi.c   'return valid && cert_dep && dep && strcmp(cert_dep, dep) == 0;' 'return valid;'
# --- added by R3 refinement 1.1 (the ten v1.0 mutations above are unchanged in name and intent) ---
add "wide product truncated to 128 bits (v1.0 false overflow)" src/wad18.c 'r.hi = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);' 'r.hi = 0;'
add "quotient range check dropped (violates W2)"         src/wad18.c 'if (q.hi != 0 || q.lo > (u128)WAD_MAX) return WAD_OVERFLOW;' ''
add "division remainder discarded (silent truncation)"   src/wad18.c '*rem = r;' '*rem = 0;'
add "result sign lost"                                   src/wad18.c '*out = neg ? -r : r;' '*out = r;'
add "R3 adoption ignores kernel equality (violates K1)"  src/ssi.c   'return k && s && a && d && n && c; }' 'return s && a && d && n && c; }'
caught=0
for i in "${!NAMES[@]}"; do
  tmp=$(mktemp -d); cp -r src include tests "$tmp/"
  python3 - "$tmp/${SRC[$i]}" "${FROM[$i]}" "${TO[$i]}" <<'PY'
import sys
p, a, b = sys.argv[1:]
s = open(p).read()
assert s.count(a) == 1, "mutation anchor not found: " + a
open(p, "w").write(s.replace(a, b))
PY
  if gcc $CFLAGS -I"$tmp/include" "$tmp"/src/wad18.c "$tmp"/src/sha256.c "$tmp"/src/ssi.c "$tmp"/tests/test_ssi.c -o "$tmp/t" 2>/dev/null && "$tmp/t" >/dev/null; then
    echo "    SURVIVED  ${NAMES[$i]}"
  else
    echo "    caught    ${NAMES[$i]}"; caught=$((caught+1))
  fi
  rm -rf "$tmp"
done
echo "MUTATIONS CAUGHT: $caught / ${#NAMES[@]}"
[ "$caught" -eq "${#NAMES[@]}" ]
