# SSI Verification Kernel v1.1 — R³-refined Code Ocean Reproducibility Capsule

**PURE WAD¹⁸** executable reference for the Safe Super Intelligence specification family by Michael Aaron Russell:
***ZONODO: DOI https://doi.org/10.5281/zenodo.23103333***
- **Specification I:** *Safe Super Intelligence: Definition, Architecture, and Verification Standard v1.0*
- **Specification II:** *Safe Super Intelligence Axiomatic System v1.0*

This capsule implements what Specification III, the WAD-18 SSI Verification Kernel, would describe; that specification document has not yet been written. It makes the decision procedures of Specifications I and II **executable** (Conformance Level 1) and is designed to demonstrate **reproducibility** (Level 2): an independent environment reproduces the reference fingerprint below.

**v1.1 is a refinement of v1.0 produced by applying Russell Recursive Refinement (R³) to the capsule itself.** The capsule carries its parent, re-derives the parent's results, and lets its own kernel decide whether the refinement is admissible. See [R³ self-refinement](#r3-self-refinement).

## What changed from v1.0, and why

An independent review of v1.0 found that `wad_mul` and `wad_div` rejected a result whenever the **raw 128-bit intermediate** overflowed, even when the final result was representable: `14 × 14`, `100 × 2` and `171 / 2` all returned `OVERFLOW`. The defect was fail-closed, so it was not a safety hole, but it was a correctness defect: "overflow" did not mean what Axiom W2 says. The v1.0 TypeScript cross-check carried the same check, so the two implementations agreed with each other and could not reveal it. In v1.0's own decision table, 163 mul/div lines were false overflows.

| # | Change | Disclosed capability bit |
|---|---|---|
| 1 | `wad_mul`/`wad_div` compute exact 256-bit intermediates; `OVERFLOW` now means the exact result is outside [WAD_MIN, WAD_MAX] | 0, 1 |
| 2 | TypeScript cross-check uses unrestricted exact BigInt arithmetic (a genuinely different method from the C code) | 0, 1 |
| 3 | A third implementation (`code/r3/oracle.py`, pure Python integers) recomputes every WAD line of the table | 3 |
| 4 | 628 table lines appended (wide-range boundary and seeded cases); no v1.0 line moves | 2 |
| 5 | 3 new tests, 5 new mutations, and `check_selftests.sh`: executable negative controls for the scanner, the compiler layer and the binary layer | 3 |
| 6 | Binary scan fails closed on an architecture with no scan pattern (v1.0 passed vacuously off x86) | 3 |
| 7 | R³ layer: `src/r3_adopt.c`, `r3/` (pinned parent, directive, evidence pass, gate negative controls) | 3 |

Unchanged and verified byte-identical to v1.0: `src/ssi.c`, `include/ssi.h`, `src/sha256.c`, `include/sha256.h` (the assurance kernel **K**).

## PURE WAD¹⁸

Every normative value is a signed 128-bit integer z representing z × 10⁻¹⁸ (Weak Arithmetic Decidability, 18-decimal integer exact fixed point). Overflow, division by zero, excess precision, invalid encoding, and inexact results are rejected explicitly; nothing is silently rounded (Axiom W2). Enforced at three independent layers on every run:

1. **Compiler.** Every C file is built with `-mgeneral-regs-only`, which makes floating-point code impossible to compile.
2. **Source.** After comments and strings are removed, no C or TypeScript source may contain `float`, `double`, `math.h`, `Math.`, or a decimal or exponent literal.
3. **Binary.** The disassembly of every compiled object must contain zero floating-point or vector instructions. On x86_64 this is exercised on every run. An aarch64 pattern is included but has not been exercised by the author. On any other architecture the layer reports **UNVERIFIED** and the run fails (or reports PARTIAL if `SSI_ALLOW_UNVERIFIED_BINARY=1`); it never reports VERIFIED vacuously.

**The checks are themselves tested on every run** (`code/check_selftests.sh`): seven injected violations (`double`, `float`, `1.5`, `1e5`, `math.h`, `Math.sqrt`, `0.25`) must be caught by the source scan, a clean tree must pass, the compiler must refuse double arithmetic, and a double-using object built without the flag must be flagged by the binary scan.

## Layout

| Path | Contents |
|---|---|
| `code/run` | Code Ocean entry point |
| `code/include/`, `code/src/` | C11 kernel: `wad18.c`, `sha256.c`, `ssi.c`; the decision-table generator; the scenario verifier; `r3_adopt.c` |
| `code/tests/test_ssi.c` | C test suite: 30 tests, 17,206 checks |
| `code/ts/ssi_crosscheck.ts` | Independent TypeScript (exact BigInt) implementation |
| `code/r3/` | R³ layer: `parent/` (shipped v1.0 kernel sources), `parent.txt` (pinned facts), `directive.txt`, `r3_evidence.py`, `oracle.py`, `check_r3_gate.sh` |
| `code/check_pure_wad18.sh`, `code/binscan.sh`, `code/scan_sources.py` | PURE WAD¹⁸ enforcement |
| `code/check_selftests.sh` | Negative controls for the PURE WAD¹⁸ checks |
| `code/check_mutations.sh` | Mutation check (15 mutations) |
| `data/wad_literals.txt`, `data/scenarios.txt` | Shared parsing cases; eight decision scenarios |
| `environment/Dockerfile` | Reference environment (**not built or tested by the author**) |
| `reference/` | Outputs of the reference run, for comparison |

## What each run checks

1. **Test suite:** 30 tests, 17,206 checks: the 27 v1.0 tests unchanged, plus wide-intermediate regressions, exact-boundary cases (including `WAD_MAX ÷ WAD_MAX = 1`, which exercises the 256-by-128-bit division), and a 3,000-pair property test (`div(mul(a,b), b) = a`, commutativity) over operands up to 10⁹. The 20,000-step gate simulation remains a consistency test, not independent evidence for Theorem 5, because the gate performs the invariant check itself.
2. **PURE WAD¹⁸:** the three layers above. **Self-tests:** their negative controls.
3. **Mutation check:** fifteen deliberate violations (the ten from v1.0, unchanged in name and intent, and five new ones aimed at the new arithmetic and at R³ kernel equality). The suite must catch every one. The mutations are chosen by the author, so this shows the tests guard these rules, not that they would catch arbitrary defects.
4. **Decision table:** 13,058 canonical decisions (12,430 from v1.0 plus 628 appended).
5. **Cross-check:** TypeScript reproduces the table byte for byte. Its arithmetic is exact BigInt with no width limit, so it no longer shares the C code's method. It still shares the author's reading of the specifications.
6. **Oracle:** pure-Python integer arithmetic recomputes all 1,034 WAD/WADX lines (see R³ evidence).
7. **Scenarios:** eight decisions with their state IDs.
8. **Reproducibility:** a clean rebuild reproduces the table's SHA-256.
9. **R³ self-adoption:** see below. The adoption record is included in the run fingerprint.

## R³ self-refinement

R³ (Standard I, *Russell Recursive Refinement*) says a refinement `q' = R³(q)` is not adopted because it looks better; it is adopted only if

`Adopt(q,q') ⇔ KernelEqual ∧ SafetyProofValid ∧ AuthorizationValid ∧ DeploymentValid ∧ NonRegression ∧ CapabilityDisclosureValid`.

The capsule applies exactly this to itself. `run` rebuilds the pinned parent v1.0 from `r3/parent/`, re-derives its 12,430-line table and checks it against the published hash, derives each condition from artifacts on disk (`r3/r3_evidence.py`, which writes `results/r3_evidence.txt`), and then `src/r3_adopt.c` decides using the capsule's **own** kernel functions: `ssi_directive_valid`, `ssi_capability_ok`, `ssi_non_regression`, `ssi_adopt6`, `ssi_decide`, and `ssi_state_id`.

| Condition | Derived from | Reference result |
|---|---|---|
| KernelEqual | SHA-256 of K (`ssi.c`, `ssi.h`, `sha256.c`, `sha256.h`) equals the pinned parent hash **and** the shipped parent copy | 1 |
| SafetyProofValid | tests pass ∧ TS cross-check identical ∧ oracle agrees ∧ PURE WAD¹⁸ verified ∧ all mutations caught ∧ self-tests pass ∧ parent reproduced. **This is empirical evidence, not a formal proof.** | 1 |
| AuthorizationValid | the kernel's directive rule over `r3/directive.txt`, evaluated as of the directive's fixed `evaluation_epoch` | 1 (see caveat) |
| DeploymentValid | this deployment's clean rebuild reproduced the table and matched the independent TS implementation | 1 |
| NonRegression | 40 parent checks true in v1.0 (27 tests, 10 mutations, 3 table properties) all still true; judged by `ssi_non_regression` | 1 |
| CapabilityDisclosureValid | observed behavioural change (bitmask derived from the table diff) lies inside the envelope the directive authorizes | 1 (observed 15, authorized 15) |

**Capability disclosure** (`results/capability_diff.txt`, produced, not hand-written): of v1.0's 12,430 lines, 163 changed. All 163 are v1.0 false overflows: 67 `mul` lines `ERR OVERFLOW → OK`, 18 `mul` and 78 `div` lines `ERR OVERFLOW → ERR NON_EXACT`. **Zero** gate, permit, decision, CSL, directive, capability, lifecycle or verify lines changed, and zero WAD lines changed outside that class. Every changed line is confirmed by the Python oracle.

**Negative controls for the gate** (`r3/check_r3_gate.sh`, run every time): a gate that only says yes proves nothing, so 17 refinements that must be rejected are tried and are: changed kernel, invalid safety evidence, invalid deployment, unreproduced parent, a regressed parent test, an uncaught parent mutation, a missing parent check (UNKNOWN is not TT), unauthorized gate-logic / decision / undisclosed changes, an unattested / out-of-scope / revoked / expired / not-yet-issued directive, an empty envelope, and an end-to-end case that really appends code to `ssi.c` and re-derives the evidence from disk.

**Lineage.** `P0 = ID(parent state)` and `P1 = ID(child state ‖ P0 ‖ directive nonce ‖ SHA-256 of the evidence file)`, both computed with the kernel's `ssi_state_id` (canonical encoding, SHA-256). The record contains no clock and no environment data, so it is reproducible and is part of the run fingerprint: reproducing the fingerprint reproduces the adoption verdict.

**On the words "asynchronous" and "retro-causal."** They are implemented as engineering, not as physics. *Asynchronous*: the adoption pass is separate from the run that produced the results; it reads only artifacts and pinned facts and can be re-run alone. *Retro-causal*: the child is judged against, and cryptographically bound back to, a pinned parent that the capsule rebuilds and re-verifies itself. Nothing is evaluated against a future state.

## Run

**On Code Ocean:** upload `code/`, `data/`, and `environment/`. Use an environment with gcc, binutils, python3 and Node.js 22.6 or later. The provided Dockerfile describes one such environment but has **not been built and tested by the author** (no container daemon was available). Click **Reproducible Run**. **Node.js is required for adoption:** without it the independent cross-check is skipped, `DeploymentValid` is 0, R³ rejects, and the run exits non-zero. That is deliberate (fail closed).

**Locally:** `cd code && ./run` (results go to `../results`).

## Reference run

| Item | Result |
|---|---|
| Test suite | 30 tests, 17,206 checks, 0 failures |
| PURE WAD¹⁸ | Verified: 0 violations in source, 0 floating-point or vector instructions (x86_64) |
| Self-tests of the checks | 9 negative controls caught, 1 positive control passed |
| Mutation check | 15 / 15 caught |
| Decision table SHA-256 (C) | `9e180bc9a6aba7bb58813b0ee24e7ae99722786aa655d801aa96bf010ca221b7` |
| TypeScript cross-check | Identical, 13,058 lines |
| Python oracle | 1,034 WAD/WADX lines, 0 disagreements |
| Parent v1.0 rebuilt in the run | `ebca8ba900f72b94212bc6d952b85c2c4d96628371492903184e3e54e97c9b7e` (matches the published v1.0 hash) |
| R³ decision | ADOPT (6 of 6 conditions) |
| R³ gate negative controls | 17 / 17 rejected |
| Lineage `child_id` | `932c0acd3e2a5f6f9f06180c4ef072520137468f0c7a3a47706c7124f1f47bd0` |
| Run fingerprint | `e1527a9760ed0c6fff4221ac7d06e93e9ae013d2717fca4fe284a4968463701a` |

Reproduced on Ubuntu 24.04, gcc 13.3.0, Node 22.22.0, x86_64, from a pristine copy at a different path: identical decision-table hash, fingerprint and `child_id`. A rerun with the same `data/` files should reproduce all three exactly.

## Interpretation choices

The specifications leave the following open; this kernel resolves them as stated, and a different resolution would change results:

| Question | Resolution in this kernel |
|---|---|
| Rounding (Standard §7 requires it be defined) | No rounding: an inexact multiply or divide is rejected as `NON_EXACT` |
| Range | Symmetric: [−(2¹²⁷−1), 2¹²⁷−1] |
| **mul/div precedence (v1.1)** | `DIV_ZERO`; else `OVERFLOW` if the exact quotient's magnitude exceeds the range; else `NON_EXACT` if the remainder is non-zero; else `OK`. Identical in C, TypeScript and Python. |
| CSL and directive expiry | Inclusive: valid at the expiry instant, invalid after |
| Revocation epochs (Standard §10) | A directive is revoked once the current epoch exceeds its revocation epoch |
| Permit | Thirteen conditions as in §13; verification is a separate input to `ssi_decide`, whereas the Specification I text lists fourteen terms including `VerificationPass` |
| Precedence among failures | Invalid arithmetic → SAFE_STOP; else UNKNOWN verification → DEFER; else FAIL or ¬Permit → REJECT |
| Empty invariant set | Not safe (Axiom S1) |
| Missing or malformed scenario or evidence field | Fails closed: read as the unsafe value |

## Scope and honest limits

The kernel verifies that the *decision procedures* of Specifications I and II behave exactly as specified, in three independent implementations of the arithmetic and two of the decision logic. Its inputs, such as whether an invariant holds or a signature is valid, are supplied as declared values; the kernel does not evaluate a real AI system, establish the superintelligence criterion SI, or measure E_m, V_r, T_m, or R_v. Passing this capsule is evidence of a correct verification kernel, not of a Safe Super Intelligence.

Specific limits of the R³ adoption:

1. **The authorization is attested, not signed.** `r3/directive.txt` records an in-session directive by the author; there is no cryptographic signature. `AuthorizationValid` therefore rests on a declared input, exactly as every authorization in `data/scenarios.txt` does. Before publishing, replace the attestation with a real signature (for example a signed git tag over the commit) and record it.
2. **The capability envelope (`authorized_caps=15`) was drafted by the assistant that built v1.1**, from the author's instruction to refine the capsule. The author should review it; widening or narrowing it changes the verdict.
3. **`evaluation_epoch` is a fixed declared value** (adoption time), not the wall clock. That keeps the record reproducible forever, at the price that the directive's 30-day expiry is never re-tested against the real date.
4. **Kernel scope.** K is `ssi.c`, `ssi.h`, `sha256.*`. `wad18.c` is treated as the governed arithmetic substrate and was changed under disclosure, even though the specification family calls WAD-18 the "normative kernel." A reviewer who defines K to include WAD-18 would read this refinement as a kernel change; the disclosure above is meant to make that judgement easy.
5. **Shared reading.** The C and TypeScript decision logic were still written from the same reading of the specifications, so a shared misreading would not be caught. The arithmetic is now cross-checked by genuinely different methods; the decision logic is not.
6. **Open from v1.0, not addressed in v1.1:** the Lean 4 golden vectors the tests cite are not shipped here (add repository URLs and commit hashes); the Dockerfile is unbuilt; no license is chosen; no DOI is assigned yet (record the Code Ocean DOI here once published); Specification III does not exist yet.

## Naming

This work is by Michael Aaron Russell and is not affiliated with any company of a similar name. Choose and add a license before publishing.
