"""R3 evidence pass: derives every input of Adopt(q, q') from artifacts on disk. Nothing here is hand-set.
Usage: python3 r3_evidence.py <results_dir> <code_dir>
Reads : results/{decision_table_c,parent_table_regen,test_report,mutation_report,pure_wad18_report,selftest_report,
                 cross_check,reproducibility}.txt, r3/parent.txt, r3/parent_tests.txt, r3/parent_mutations.txt, r3/oracle.py
Writes: results/r3_evidence.txt, results/capability_diff.txt (and results/environment.txt is written by `run`)."""
import hashlib, os, re, sys
res, code = sys.argv[1], sys.argv[2]
sys.path.insert(0, os.path.join(code, "r3"))
import oracle

def sha(path): return hashlib.sha256(open(path, "rb").read()).hexdigest()
def lines(path): return open(path, encoding="utf-8").read().split("\n")[:-1]
def rd(name): return open(os.path.join(res, name), encoding="utf-8").read()
def r3(name): return os.path.join(code, "r3", name)

# ---- pinned parent facts
parent = {}; pk = {}
for ln in lines(r3("parent.txt")):
    if ln.startswith("#") or not ln: continue
    if ln.startswith("kernel_sha256 "): _, f, h = ln.split(" "); pk[f] = h
    else: k, v = ln.split("=", 1); parent[k] = v

ev = []            # (key, value) in a fixed order: the file is hashed into the lineage
def put(k, v): ev.append((k, str(v)))

# ---- KernelEqual: the immutable assurance kernel K = decision logic + hash. Compared three ways.
kernel_equal = 1
for f, h in pk.items():
    if sha(os.path.join(code, f)) != h: kernel_equal = 0                     # v2 vs pinned parent hash
    if sha(os.path.join(code, f)) != sha(os.path.join(code, "r3/parent", f)): kernel_equal = 0   # v2 vs shipped parent copy
    if sha(os.path.join(code, "r3/parent", f)) != h: kernel_equal = 0         # shipped parent copy vs pinned hash
put("kernel_equal", kernel_equal)

# ---- Parent reproduced inside this deployment (the capsule rebuilt its own parent and re-derived its table)
parent_tab = lines(os.path.join(res, "parent_table_regen.txt"))
parent_hash_regen = hashlib.sha256(("\n".join(parent_tab) + "\n").encode()).hexdigest()
parent_reproduced = int(parent_hash_regen == parent["parent_table_sha256"] and len(parent_tab) == int(parent["parent_table_lines"]))
put("parent_reproduced", parent_reproduced)

# ---- Table diff: parent vs child, line-aligned (new cases are appended after every parent line)
child_tab = lines(os.path.join(res, "decision_table_c.txt"))
aligned_prefix = len(child_tab) >= len(parent_tab)
changed = []       # (index, parent_line, child_line)
if aligned_prefix:
    for i, (p, c) in enumerate(zip(parent_tab, child_tab)):
        if p != c: changed.append((i, p, c))
appended = len(child_tab) - len(parent_tab)

def split(l): return l.split(" ")
n_nonwad_changed = 0; n_other_wad_changed = 0
n_mul_widened = n_div_widened = 0
cls = {}           # (op, parent_status, child_status) -> count
for i, p, c in changed:
    fp, fc = split(p), split(c)
    if fp[0] != "WAD":
        n_nonwad_changed += 1; continue
    same_operands = fp[:4] == fc[:4]
    widened = same_operands and fp[4] == "ERR" and fp[5] == "OVERFLOW" and fp[1] in ("mul", "div") and \
              (fc[4] == "OK" or (fc[4] == "ERR" and fc[5] == "NON_EXACT"))
    if widened:
        if fp[1] == "mul": n_mul_widened += 1
        else: n_div_widened += 1
        key = (fp[1], "ERR OVERFLOW", "OK" if fc[4] == "OK" else "ERR NON_EXACT"); cls[key] = cls.get(key, 0) + 1
    else:
        n_other_wad_changed += 1

# ---- Independent oracle (pure Python integers) over every WAD/WADX line of the child table
oracle_checked = oracle_bad = 0
for l in child_tab:
    if l.startswith(("WAD ", "WADX ")):
        oracle_checked += 1
        if oracle.check_line(l): oracle_bad += 1
# every widened line is, by the oracle check above, an exact result; a parent OK line that changed would be other_wad_changed

# ---- Parent checks, before -> after, as ssi_truth for the kernel's own ssi_non_regression()
test_rep = rd("test_report.txt"); mut_rep = rd("mutation_report.txt")
passed = set(re.findall(r"^PASS (\S+)", test_rep, re.M))
caught = set(re.findall(r"^    caught    (.+)$", mut_rep, re.M))
tests_summary = re.search(r"(\d+) tests, (\d+) checks, (\d+) failures", test_rep)
for t in lines(r3("parent_tests.txt")):
    put("before.test." + t, "T"); put("after.test." + t, "T" if t in passed else "F")
for m in lines(r3("parent_mutations.txt")):
    put("before.mutation." + m, "T"); put("after.mutation." + m, "T" if m in caught else "F")
put("before.table.non_wad_lines_identical", "T"); put("after.table.non_wad_lines_identical", "T" if n_nonwad_changed == 0 and aligned_prefix else "F")
put("before.table.no_other_wad_change", "T");     put("after.table.no_other_wad_change", "T" if n_other_wad_changed == 0 else "F")
put("before.table.oracle_agrees", "T");           put("after.table.oracle_agrees", "T" if oracle_bad == 0 and oracle_checked > 0 else "F")

# ---- SafetyProofValid: empirical evidence, conjunction of independent layers (not a formal proof)
mut_total = len(re.findall(r"^    (caught|SURVIVED)", mut_rep, re.M))
checks = {
  "tests_all_pass": bool(tests_summary) and tests_summary.group(3) == "0",
  "cross_check_identical": rd("cross_check.txt").startswith("IDENTICAL"),
  "oracle_agrees": oracle_bad == 0 and oracle_checked > 0,
  "pure_wad18_verified": "PURE WAD18: VERIFIED" in rd("pure_wad18_report.txt"),
  "all_mutations_caught": mut_total > 0 and len(caught) == mut_total,
  "selftests_pass": "SELF-TESTS: ALL NEGATIVE CONTROLS CAUGHT" in rd("selftest_report.txt"),
  "parent_reproduced": bool(parent_reproduced),
}
for k, v in checks.items(): put("safety." + k, int(v))
put("safety_proof_valid", int(all(checks.values())))

# ---- DeploymentValid: this deployment reproduced its own table from a clean rebuild AND matched the independent TS implementation
put("deployment_valid", int(rd("reproducibility.txt").startswith("MATCH") and checks["cross_check_identical"]))

# ---- Capability disclosure: observed behavioural deltas as a bitmask the kernel compares with the directive's envelope
obs = 0
if n_mul_widened: obs |= 1 << 0
if n_div_widened: obs |= 1 << 1
if appended > 0: obs |= 1 << 2
if tests_summary and int(tests_summary.group(1)) > len(lines(r3("parent_tests.txt"))) or mut_total > len(lines(r3("parent_mutations.txt"))): obs |= 1 << 3
if not kernel_equal: obs |= 1 << 4
if n_nonwad_changed: obs |= 1 << 5
if n_other_wad_changed or not aligned_prefix: obs |= 1 << 6
put("observed_caps", obs)
put("parent_table_sha256", parent["parent_table_sha256"]); put("parent_run_fingerprint", parent["parent_run_fingerprint"])
put("parent_kernel_sha256", hashlib.sha256("\n".join(f"{f} {h}" for f, h in sorted(pk.items())).encode()).hexdigest())
put("child_table_sha256", hashlib.sha256(("\n".join(child_tab) + "\n").encode()).hexdigest())
put("child_kernel_sha256", hashlib.sha256("\n".join(f"{f} {sha(os.path.join(code, f))}" for f in sorted(pk)).encode()).hexdigest())

with open(os.path.join(res, "r3_evidence.txt"), "w") as f:
    for k, v in ev: f.write(f"{k}={v}\n")

# ---- Capability disclosure document (human-readable; produced, not written by hand)
with open(os.path.join(res, "capability_diff.txt"), "w") as f:
    f.write("R3 capability disclosure: behavioural difference between parent v1.0 and child v1.1\n")
    f.write(f"parent table lines            : {len(parent_tab)}\nchild table lines             : {len(child_tab)}  (appended: {appended})\n")
    f.write(f"parent lines changed          : {len(changed)}\n")
    for (op, a, b), n in sorted(cls.items()): f.write(f"  WAD {op}: {a} -> {b}: {n}\n")
    f.write(f"non-WAD lines changed (gate, permit, decision, CSL, directive, capability, ...): {n_nonwad_changed}\n")
    f.write(f"WAD lines changed outside the widened class                                    : {n_other_wad_changed}\n")
    f.write(f"oracle (pure Python): {oracle_checked} WAD/WADX lines checked, {oracle_bad} disagreements\n")
    f.write(f"observed capability bits: {obs}\n")
print(f"evidence: kernel_equal={kernel_equal} parent_reproduced={parent_reproduced} widened(mul={n_mul_widened}, div={n_div_widened}) "
      f"nonwad_changed={n_nonwad_changed} other_wad_changed={n_other_wad_changed} oracle={oracle_checked}/{oracle_bad} obs={obs}")
