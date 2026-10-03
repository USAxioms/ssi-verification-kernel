// SSI Verification Kernel — independent TypeScript implementation (cross-check).
// PURE WAD¹⁸: every normative value is a BigInt z representing z × 10⁻¹⁸.
// Written separately from the C kernel; it must reproduce the C decision table byte for byte.
// Run: node --experimental-strip-types ssi_crosscheck.ts <wad_literals.txt>
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const SCALE = 10n ** 18n;
const I128_MAX = (1n << 127n) - 1n;
const WAD_MAX = I128_MAX;
const WAD_MIN = -WAD_MAX;

type Res = { ok: true; v: bigint } | { ok: false; e: string };
const ok = (v: bigint): Res => ({ ok: true, v });
const err = (e: string): Res => ({ ok: false, e });
const inRange = (x: bigint) => x >= WAD_MIN && x <= WAD_MAX;

function parse(s: string): Res {
  if (s.length === 0) return err("INVALID_ENCODING");
  let i = 0, neg = false;
  if (s[i] === "-" || s[i] === "+") { neg = s[i] === "-"; i++; }
  const isDigit = (c: string | undefined) => c !== undefined && c >= "0" && c <= "9";
  if (!isDigit(s[i])) return err("INVALID_ENCODING");
  let ip = 0n;
  while (isDigit(s[i])) {
    ip = ip * 10n; if (ip > I128_MAX) return err("OVERFLOW");
    ip = ip + BigInt(s.charCodeAt(i) - 48); if (ip > I128_MAX) return err("OVERFLOW");
    i++;
  }
  let fp = 0n, nd = 0;
  if (s[i] === ".") {
    i++;
    if (!isDigit(s[i])) return err("INVALID_ENCODING");
    while (isDigit(s[i])) {
      if (nd === 18) return err("EXCESS_PRECISION");
      fp = fp * 10n + BigInt(s.charCodeAt(i) - 48); nd++; i++;
    }
  }
  if (i !== s.length) return err("INVALID_ENCODING");
  for (let k = nd; k < 18; k++) fp *= 10n;
  let z = ip * SCALE; if (z > I128_MAX) return err("OVERFLOW");
  z = z + fp; if (z > I128_MAX) return err("OVERFLOW");
  if (neg) z = -z;
  if (!inRange(z)) return err("OVERFLOW");
  return ok(z);
}

function format(x: bigint): string {
  const neg = x < 0n, u = neg ? -x : x;
  return (neg ? "-" : "") + (u / SCALE).toString() + "." + (u % SCALE).toString().padStart(18, "0");
}

function add(a: bigint, b: bigint): Res { const r = a + b; return inRange(r) ? ok(r) : err("OVERFLOW"); }
function sub(a: bigint, b: bigint): Res { const r = a - b; return inRange(r) ? ok(r) : err("OVERFLOW"); }
// Exact BigInt arithmetic: no intermediate width limit. Precedence (matches C kernel and Python oracle):
// DIV_ZERO; else OVERFLOW if |quotient| > WAD_MAX; else NON_EXACT if remainder != 0; else OK.
const abs = (x: bigint) => (x < 0n ? -x : x);
function finish(n: bigint, d: bigint): Res {
  const q = abs(n) / abs(d), r = abs(n) % abs(d);
  if (q > WAD_MAX) return err("OVERFLOW");
  if (r !== 0n) return err("NON_EXACT");
  return ok(n < 0n !== d < 0n ? -q : q);
}
function mul(a: bigint, b: bigint): Res { return finish(a * b, SCALE); }
function div(a: bigint, b: bigint): Res {
  if (b === 0n) return err("DIV_ZERO");
  return finish(a * SCALE, b);
}

// ---------------------------------------------------------------- SSI rules
const b = (x: boolean) => (x ? 1 : 0);
const vs = (inv: string[]) => b(inv.length > 0 && inv.every((t) => t === "T"));
const member = (si: number, v: number, hg: number, a: number, ve: number) => b(!!(si && v && hg && a && ve));
const gate = (a: number, s: number, v: number, c: number, i: number) => (a && s && v && c && i ? "COMMIT" : "REJECT");
const PERMIT_REVOKED_BIT = 10;
function permit13(bits: number): number {
  for (let k = 0; k < 13; k++) {
    const set = (bits >> k) & 1;
    if (k === PERMIT_REVOKED_BIT ? set === 1 : set === 0) return 0;
  }
  return 1;
}
function decide(arith: number, v: number, p: number): string {
  if (!arith) return "SAFE_STOP";
  if (v === 2) return "DEFER";
  if (v === 1) return "REJECT";
  return p ? "EXECUTE" : "REJECT";
}
const mediate = (k: number, p: number) => b(k >= 0 && k <= 9 && p === 1);
const STATUS = ["PROPOSED", "VERIFIED", "ACTIVE", "REVALIDATION", "REVOKED", "REJECTED"];
const TRANSITIONS = new Set(["0>1", "0>5", "1>2", "2>3", "3>2", "3>4", "2>4"]);
const canTransition = (f: number, t: number) => b(TRANSITIONS.has(`${f}>${t}`));
const VERIFY_ORDER = ["TYPE_VALID", "WAD18_VALID", "KERNEL_VALID", "CSL_VALID", "AUTHORIZATION_VALID",
  "SAFETY_INVARIANTS_VALID", "CAPABILITY_VALID", "CERTIFICATE_VALID", "CERTIFICATE_BINDS_TO",
  "PROVENANCE_VALID", "SUPERINTELLIGENCE_CRITERION"];
function verify(bits: number): string {
  for (let k = 0; k < VERIFY_ORDER.length; k++) if (((bits >> k) & 1) === 0) return VERIFY_ORDER[k];
  return "PASS";
}
const allBits = (x: number, n: number) => { for (let k = 0; k < n; k++) if (((x >> k) & 1) === 0) return 0; return 1; };

// ---------------------------------------------------------------- seeded generator (xorshift64)
const M64 = (1n << 64n) - 1n;
let state = 0x9E3779B97F4A7C15n;
function rnd(): bigint {
  state ^= (state << 13n) & M64;
  state ^= state >> 7n;
  state ^= (state << 17n) & M64;
  return state;
}

// ---------------------------------------------------------------- emit the table
const hash = createHash("sha256");
const out: string[] = [];
const emit = (line: string) => { out.push(line); hash.update(line + "\n"); };

const litPath = process.argv[2] ?? "../data/wad_literals.txt";
const lits = readFileSync(litPath, "utf8").replace(/\r/g, "").split("\n");
if (lits.length && lits[lits.length - 1] === "") lits.pop();
for (const lit of lits) {
  const r = parse(lit);
  emit(r.ok ? `PARSE [${lit}] OK ${r.v} ${format(r.v)}` : `PARSE [${lit}] ERR ${r.e}`);
}

const opName = ["add", "sub", "mul", "div"];
const opFn = [add, sub, mul, div];
let wadTag = "WAD";
function wadCase(op: number, a: bigint, bb: bigint) {
  const r = opFn[op](a, bb);
  emit(r.ok ? `${wadTag} ${opName[op]} ${a} ${bb} OK ${r.v}` : `${wadTag} ${opName[op]} ${a} ${bb} ERR ${r.e}`);
}
for (let i = 0; i < 400; i++) {
  const ia = (rnd() % 2000001n) - 1000000n, ib = (rnd() % 2000001n) - 1000000n;
  let fa = (rnd() % 100n) * 10n ** 16n;
  const fb = (rnd() % 100n) * 10n ** 16n;
  if (rnd() % 4n === 0n) fa = rnd() % 10n ** 18n;
  const a = ia * SCALE + (ia < 0n ? -fa : fa);
  let bb = ib * SCALE + (ib < 0n ? -fb : fb);
  if (rnd() % 10n === 0n) bb = 0n;
  wadCase(Number(rnd() % 4n), a, bb);
}
wadCase(0, WAD_MAX, 1n); wadCase(1, WAD_MIN, 1n); wadCase(2, WAD_MAX, 2n * SCALE);
wadCase(3, WAD_MAX, 1n); wadCase(3, 1n, 0n); wadCase(2, 1n, SCALE / 2n);

for (let n = 0; n <= 4; n++) {
  for (let c = 0; c < 3 ** n; c++) {
    const inv: string[] = []; let x = BigInt(c);
    for (let i = 0; i < n; i++) { inv.push("TFU"[Number(x % 3n)]); x = x / 3n; }
    emit(`VS [${inv.join("")}] ${vs(inv)}`);
  }
}

for (let k = 0; k < 64; k++) {
  const bit = (i: number) => (k >> i) & 1;
  emit(`MEMBER ${k & 31} ${member(bit(0), bit(1), bit(2), bit(3), bit(4))} ${b(!!(member(bit(0), bit(1), bit(2), bit(3), bit(4)) && bit(5)))}`);
  emit(`GATE ${k & 31} ${gate(bit(0), bit(1), bit(2), bit(3), bit(4))}`);
  emit(`ADOPT6 ${k} ${allBits(k, 6)}`);
  emit(`SAC ${k} ${b(allBits(k & 31, 5) === 1 && bit(5) === 0)}`);
}
for (let k = 0; k < 16; k++) emit(`ADOPT4 ${k} ${allBits(k, 4)}`);
for (let k = 0; k < 8192; k++) emit(`P13 ${k} ${permit13(k)}`);
for (let a = 0; a < 2; a++) for (let v = 0; v < 3; v++) for (let p = 0; p < 2; p++) emit(`DECIDE ${a} ${v} ${p} ${decide(a, v, p)}`);
for (let k = -1; k <= 9; k++) for (let p = 0; p < 2; p++) emit(`MEDIATE ${k} ${p} ${mediate(k, p)}`);
for (let s = 0; s < 6; s++) for (let t = 0; t < 6; t++) emit(`LIFE ${STATUS[s]} ${STATUS[t]} ${canTransition(s, t)}`);
for (let k = 0; k < 16; k++) for (let s = 0; s < 6; s++) emit(`SACA ${k} ${STATUS[s]} ${b(allBits(k, 4) === 1 && s === 2)}`);
for (let k = 0; k < 2048; k++) emit(`VERIFY ${k} ${verify(k)}`);

for (let i = 0; i < 400; i++) {
  const until = rnd() % 5000n, now = rnd() % 6000n;
  const sig = b(rnd() % 8n !== 0n), rev = b(rnd() % 8n === 0n), env = b(rnd() % 7n !== 0n);
  emit(`CSL ${sig} ${rev} ${until} ${now} ${env} ${b(!!sig && !rev && now <= until && !!env)}`);
}
for (let i = 0; i < 400; i++) {
  const issue = rnd() % 500n, expiry = issue + 1n + rnd() % 2000n, now = rnd() % 3000n, ep = 1n + rnd() % 9n;
  const cur = ep + (rnd() % 5n === 0n ? 1n + rnd() % 2n : 0n);
  const sig = b(rnd() % 10n !== 0n), scope = b(rnd() % 8n !== 0n);
  const valid = b(!!sig && issue <= now && now <= expiry && cur <= ep && !!scope);
  emit(`DIRECTIVE ${sig} ${issue} ${expiry} ${ep} ${now} ${cur} ${scope} ${valid}`);
}
for (let i = 0; i < 400; i++) {
  const nx = rnd() & 0x3FFn, au = rnd() & 0x3FFn, gov = b(rnd() % 5n === 0n);
  emit(`CAP ${nx} ${au} ${gov} ${b((nx & ~au & 0x3FFn) === 0n || gov === 1)}`);
}

// R3 refinement 1.1: wide-intermediate arithmetic cases, appended after every v1.0 line.
wadTag = "WADX";
let state2 = 0xD1B54A32D192ED03n;
function rnd2(): bigint {
  state2 ^= (state2 << 13n) & M64;
  state2 ^= state2 >> 7n;
  state2 ^= (state2 << 17n) & M64;
  return state2;
}
const L = (s: string): bigint => { const r = parse(s); if (!r.ok) throw new Error("bad literal " + s); return r.v; };
const fx: [number, string, string][] = [
  [2, "14", "14"], [2, "100", "2"], [2, "1000000", "1000000"], [2, "-100", "2"], [2, "100", "-2"],
  [2, "170141183460469231731", "1"], [3, "171", "2"], [3, "1000", "10"], [3, "-1000", "10"],
  [3, "1000000000000", "1000000"], [2, "0.5", "170141183460469231731"], [3, "170141183460469231731", "0.5"],
];
for (const [o, x, y] of fx) wadCase(o, L(x), L(y));
wadCase(2, WAD_MAX, SCALE); wadCase(2, WAD_MIN, SCALE); wadCase(3, WAD_MAX, SCALE); wadCase(3, WAD_MIN, SCALE);
wadCase(2, WAD_MAX, 1n); wadCase(2, WAD_MAX, 2n * SCALE); wadCase(3, WAD_MAX, 1n); wadCase(2, 0n, WAD_MAX);
wadCase(3, 0n, WAD_MAX); wadCase(3, 1n, WAD_MAX); wadCase(2, WAD_MAX, WAD_MAX); wadCase(2, WAD_MIN, WAD_MIN);
wadCase(3, WAD_MAX, WAD_MAX); wadCase(3, WAD_MIN, WAD_MAX); wadCase(2, WAD_MIN, WAD_MAX); wadCase(3, WAD_MAX, WAD_MIN);
for (let i = 0; i < 600; i++) {
  const ia = (rnd2() % 2000000001n) - 1000000000n, ib = (rnd2() % 2000000001n) - 1000000000n;
  let a = ia * SCALE; let bb = ib * SCALE;
  if (rnd2() % 4n === 0n) { const fr = rnd2() % 10n ** 18n; a += ia < 0n ? -fr : fr; }
  if (rnd2() % 10n === 0n) bb = 0n;
  wadCase(rnd2() % 2n === 1n ? 2 : 3, a, bb);
}

process.stdout.write(out.join("\n") + "\n");
process.stderr.write(`TABLE_SHA256 ${hash.digest("hex")}\n`);
