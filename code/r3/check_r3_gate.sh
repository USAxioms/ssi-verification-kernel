#!/usr/bin/env bash
# Negative controls for the R3 adoption gate: refinements that MUST be rejected. A gate that only ever says yes proves nothing.
# Usage: check_r3_gate.sh <results_dir>      (run from the code directory, after the R3 step has produced r3_evidence.txt)
set -uo pipefail
cd "$(dirname "$0")/.."
RES="$1"; status=0
tmp=$(mktemp -d)
expect_reject() {   # name evidence directive
  if build/r3_adopt "$2" "$3" "$tmp/rec.txt" >/dev/null 2>&1; then echo "    ADOPTED (WRONG)  $1"; status=1
  else echo "    rejected         $1"; fi
}
applied() { cmp -s "$1" "$2" && { echo "    INVALID CONTROL  mutation changed nothing: $3"; status=1; }; }
mutate_ev() { sed "$1" "$RES/r3_evidence.txt" > "$tmp/ev.txt"; applied "$tmp/ev.txt" "$RES/r3_evidence.txt" "$1"; }
mutate_dv() { sed "$1" r3/directive.txt > "$tmp/dv.txt"; applied "$tmp/dv.txt" r3/directive.txt "$1"; }

echo "[0] positive control: the unmodified evidence and directive are adopted"
if build/r3_adopt "$RES/r3_evidence.txt" r3/directive.txt "$tmp/rec.txt" >/dev/null 2>&1; then echo "    adopted          unmodified refinement"; else echo "    REJECTED (WRONG) unmodified refinement"; status=1; fi

if [ $status -ne 0 ]; then echo "    baseline not adopted: negative controls are meaningless, stopping"; rm -rf "$tmp"; echo "R3 GATE: FAILED"; exit 1; fi

echo "[1] evidence-level violations"
mutate_ev 's/^kernel_equal=1/kernel_equal=0/';            expect_reject "kernel changed" "$tmp/ev.txt" r3/directive.txt
mutate_ev 's/^safety_proof_valid=1/safety_proof_valid=0/'; expect_reject "safety evidence invalid" "$tmp/ev.txt" r3/directive.txt
mutate_ev 's/^deployment_valid=1/deployment_valid=0/';     expect_reject "deployment certificate invalid" "$tmp/ev.txt" r3/directive.txt
mutate_ev 's/^parent_reproduced=1/parent_reproduced=0/';   expect_reject "parent not reproduced" "$tmp/ev.txt" r3/directive.txt
mutate_ev '0,/^\(after\.test\.[^=]*\)=T/s//\1=F/'; expect_reject "a parent test regressed (T -> F)" "$tmp/ev.txt" r3/directive.txt
mutate_ev '0,/^\(after\.mutation\.[^=]*\)=T/s//\1=F/';     expect_reject "a parent mutation no longer caught" "$tmp/ev.txt" r3/directive.txt
mutate_ev '/^after\.table\.oracle_agrees/d';               expect_reject "a parent check is missing (UNKNOWN is not TT)" "$tmp/ev.txt" r3/directive.txt
mutate_ev 's/^observed_caps=.*/observed_caps=31/';         expect_reject "gate logic changed (bit 4, not authorized)" "$tmp/ev.txt" r3/directive.txt
mutate_ev 's/^observed_caps=.*/observed_caps=47/';         expect_reject "decision lines changed (bit 5, not authorized)" "$tmp/ev.txt" r3/directive.txt
mutate_ev 's/^observed_caps=.*/observed_caps=79/';         expect_reject "undisclosed behavior change (bit 6, not authorized)" "$tmp/ev.txt" r3/directive.txt

echo "[2] directive-level violations"
mutate_dv 's/^attested=1/attested=0/';                     expect_reject "directive not attested" "$RES/r3_evidence.txt" "$tmp/dv.txt"
mutate_dv 's/^scope=.*/scope=something-else/';             expect_reject "directive out of scope" "$RES/r3_evidence.txt" "$tmp/dv.txt"
mutate_dv 's/^current_epoch=1/current_epoch=2/';           expect_reject "revocation epoch passed" "$RES/r3_evidence.txt" "$tmp/dv.txt"
mutate_dv "s/^evaluation_epoch=.*/evaluation_epoch=$(awk -F= '/^expiry_epoch/{print $2+1}' r3/directive.txt)/"; expect_reject "directive expired at evaluation time" "$RES/r3_evidence.txt" "$tmp/dv.txt"
mutate_dv "s/^evaluation_epoch=.*/evaluation_epoch=$(awk -F= '/^issue_epoch/{print $2-1}' r3/directive.txt)/";   expect_reject "directive not yet issued" "$RES/r3_evidence.txt" "$tmp/dv.txt"
mutate_dv 's/^authorized_caps=.*/authorized_caps=0/';       expect_reject "envelope authorizes nothing" "$RES/r3_evidence.txt" "$tmp/dv.txt"

echo "[3] end-to-end: really tamper with the kernel source and re-derive the evidence"
mkdir -p "$tmp/code" "$tmp/res"; cp -r src include r3 "$tmp/code/"; cp "$RES"/*.txt "$tmp/res/"
printf '\n/* tampered */\nint ssi_tamper(void) { return 1; }\n' >> "$tmp/code/src/ssi.c"
python3 r3/r3_evidence.py "$tmp/res" "$tmp/code" >/dev/null
expect_reject "ssi.c modified, evidence re-derived from disk" "$tmp/res/r3_evidence.txt" r3/directive.txt
grep -q '^kernel_equal=0' "$tmp/res/r3_evidence.txt" && echo "    confirmed        evidence pass itself reported kernel_equal=0" || { echo "    MISSED           evidence pass did not detect the tampered kernel"; status=1; }

rm -rf "$tmp"
[ $status -eq 0 ] && echo "R3 GATE: ALL NEGATIVE CONTROLS REJECTED" || echo "R3 GATE: FAILED"
exit $status
