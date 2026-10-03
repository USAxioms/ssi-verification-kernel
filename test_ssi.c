/* SSI Verification Kernel — test suite. PURE WAD¹⁸: integer-only.
 * Includes every golden vector of the Lean 4 repositories for Specifications I and II. */
#include <stdio.h>
#include <string.h>
#include "wad18.h"
#include "ssi.h"
#include "sha256.h"

static int tests = 0, failures = 0, checks = 0;
static const char *current = "";
#define TEST(name) static void name(void)
#define RUN(name) do { current = #name; int before = failures; name(); tests++; \
    printf("%s %s\n", failures == before ? "PASS" : "FAIL", #name); } while (0)
#define CHECK(cond) do { checks++; if (!(cond)) { failures++; \
    printf("  check failed in %s (line %d): %s\n", current, __LINE__, #cond); } } while (0)

static wad_t W(const char *s) { wad_t z = 0; wad_err e = wad_parse(s, &z); if (e != WAD_OK) { failures++; printf("  bad literal %s\n", s); } return z; }
static int eqfmt(wad_t x, const char *expect) { char b[64]; wad_format(x, b, sizeof b); return strcmp(b, expect) == 0; }

/* ------------------------------------------------------------ WAD-18 */
TEST(wad_paper_example) {          /* SAC Finance §6: 1000.10 + 0.20 = 1000.30 */
    wad_t r; CHECK(wad_add(W("1000.10"), W("0.20"), &r) == WAD_OK); CHECK(r == W("1000.30"));
    CHECK(eqfmt(r, "1000.300000000000000000"));
}
TEST(wad_exact_mul_div) {
    wad_t r;
    CHECK(wad_mul(W("12.5"), W("3"), &r) == WAD_OK && r == W("37.5"));
    CHECK(wad_mul(W("0.5"), W("0.5"), &r) == WAD_OK && r == W("0.25"));
    CHECK(wad_mul(W("-4.25"), W("8"), &r) == WAD_OK && r == W("-34"));
    CHECK(wad_div(W("10"), W("4"), &r) == WAD_OK && r == W("2.5"));
    CHECK(wad_div(W("7.5"), W("2.5"), &r) == WAD_OK && r == W("3"));
    CHECK(wad_div(W("-9"), W("3"), &r) == WAD_OK && r == W("-3"));
}
TEST(wad_explicit_failures) {      /* Axiom W2: no failure silently yields a value */
    wad_t r = 12345;
    CHECK(wad_div(W("10"), W("3"), &r) == WAD_NON_EXACT && r == 12345);
    CHECK(wad_mul(1, WAD_SCALE / 2, &r) == WAD_NON_EXACT && r == 12345);
    CHECK(wad_div(WAD_SCALE, 0, &r) == WAD_DIV_ZERO && r == 12345);
    CHECK(wad_add(WAD_MAX, 1, &r) == WAD_OVERFLOW && r == 12345);
    CHECK(wad_sub(WAD_MIN, 1, &r) == WAD_OVERFLOW && r == 12345);
    CHECK(wad_mul(WAD_MAX, 2 * WAD_SCALE, &r) == WAD_OVERFLOW && r == 12345);
}
TEST(wad_parse_rejections) {
    wad_t r;
    CHECK(wad_parse("0.1234567890123456789", &r) == WAD_EXCESS_PRECISION);
    CHECK(wad_parse("1.", &r) == WAD_INVALID_ENCODING);
    CHECK(wad_parse(".5", &r) == WAD_INVALID_ENCODING);
    CHECK(wad_parse("1e5", &r) == WAD_INVALID_ENCODING);
    CHECK(wad_parse("--1", &r) == WAD_INVALID_ENCODING);
    CHECK(wad_parse("", &r) == WAD_INVALID_ENCODING);
    CHECK(wad_parse("170141183460469231731.687303715884105728", &r) == WAD_OVERFLOW);
}
TEST(wad_bounds_and_smallest_unit) {
    CHECK(W("0.000000000000000001") == 1);
    CHECK(W("-0.000000000000000001") == -1);
    CHECK(W("170141183460469231731.687303715884105727") == WAD_MAX);
    CHECK(eqfmt(WAD_MIN, "-170141183460469231731.687303715884105727"));
}
TEST(wad_roundtrip_seeded) {       /* parse(format(x)) == x over 5,000 seeded values */
    uint64_t s = 0xD1B54A32D192ED03ULL;
    for (int i = 0; i < 5000; i++) {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        wad_t x = (wad_t)(int64_t)s * (wad_t)(int64_t)(s >> 11 | 1);
        char b[64]; wad_format(x, b, sizeof b);
        wad_t y; CHECK(wad_parse(b, &y) == WAD_OK && y == x);
    }
}
TEST(wad_comparison_integer_only) {
    CHECK(wad_cmp(W("1.000000000000000001"), W("1")) == 1);
    CHECK(wad_cmp(W("-0.5"), W("0.5")) == -1);
    CHECK(wad_cmp(W("2.50"), W("2.5")) == 0);
}

/* ------------------------------------------------------------ Axiomatic System (Spec II) */
TEST(vs_fail_closed) {             /* Axioms S1, S2 */
    ssi_truth all_t[3] = {SSI_TT, SSI_TT, SSI_TT}, one_f[3] = {SSI_TT, SSI_FF, SSI_TT}, one_u[2] = {SSI_TT, SSI_UNKNOWN};
    CHECK(ssi_vs(all_t, 3) == 1);
    CHECK(ssi_vs(one_f, 3) == 0);
    CHECK(ssi_vs(one_u, 2) == 0);
    CHECK(ssi_vs(NULL, 0) == 0);
}
TEST(membership_requires_every_component) {   /* Def. 21, §33, §38 */
    CHECK(ssi_member(1, 1, 1, 1, 1) == 1);
    for (int k = 0; k < 5; k++) {
        int v[5] = {1, 1, 1, 1, 1}; v[k] = 0;
        CHECK(ssi_member(v[0], v[1], v[2], v[3], v[4]) == 0);
    }
    CHECK(ssi_member_prov(1, 1, 1, 1, 1, 0) == 0);
    CHECK(ssi_member_prov(1, 1, 1, 1, 1, 1) == 1);
}
TEST(execution_gate_exhaustive) {  /* Theorems 1, 2; Axiom A2; §31 */
    for (int b = 0; b < 32; b++) {
        gate_outcome g = ssi_execute(b & 1, b >> 1 & 1, b >> 2 & 1, b >> 3 & 1, b >> 4 & 1);
        CHECK((g == GATE_COMMIT) == (b == 31));
    }
    CHECK(ssi_execute(0, 1, 1, 1, 1) == GATE_REJECT);   /* ¬AUTH ⇒ ¬EXECUTE */
    CHECK(ssi_execute(1, 1, 0, 1, 1) == GATE_REJECT);   /* ¬VER ⇒ ¬EXECUTE */
    CHECK(ssi_execute(1, 1, 1, 1, 0) == GATE_REJECT);   /* invariant check before commit */
}
TEST(csl_authorization_golden) {   /* Axiom C1; Lean golden vectors */
    CHECK(ssi_csl_auth(1, 0, 100, 50, 1) == 1);
    CHECK(ssi_csl_auth(1, 0, 100, 101, 1) == 0);
    CHECK(ssi_csl_auth(1, 1, 100, 50, 1) == 0);
    CHECK(ssi_csl_auth(0, 0, 100, 50, 1) == 0);
    CHECK(ssi_csl_auth(1, 0, 100, 50, 0) == 0);
}
TEST(adoption_and_non_regression) {  /* Def. 23–24 */
    CHECK(ssi_adopt4(1, 1, 1, 1) == 1);
    CHECK(ssi_adopt4(0, 1, 1, 1) == 0);
    ssi_truth before[3] = {SSI_TT, SSI_TT, SSI_UNKNOWN}, ok_after[3] = {SSI_TT, SSI_TT, SSI_FF},
              bad_after[3] = {SSI_TT, SSI_FF, SSI_TT};
    CHECK(ssi_non_regression(before, ok_after, 3) == 1);   /* only satisfied invariants are protected */
    CHECK(ssi_non_regression(before, bad_after, 3) == 0);
}
TEST(kernel_immutability) {        /* Axiom K1 / PO-7: a refinement that changes K fails KernelEqual */
    kv kernel[] = {{"arith", "WAD-18"}, {"gate", "fail-closed"}, {"unknown", "not-safe"}};
    char before[65], after[65], tampered[65];
    CHECK(ssi_state_id(kernel, 3, before) == 0);
    CHECK(ssi_state_id(kernel, 3, after) == 0);           /* refinement touched only M and G */
    kv changed[] = {{"arith", "WAD-18"}, {"gate", "fail-open"}, {"unknown", "not-safe"}};
    CHECK(ssi_state_id(changed, 3, tampered) == 0);
    CHECK(ssi_adopt4(strcmp(before, after) == 0, 1, 1, 1) == 1);
    CHECK(ssi_adopt4(strcmp(before, tampered) == 0, 1, 1, 1) == 0);
}
TEST(sac_axiomatic) {              /* Def. 27; §28; Axioms P1, V1 */
    CHECK(ssi_sac_current(1, 1, 1, 1, 1, 0) == 1);
    CHECK(ssi_sac_current(0, 1, 1, 1, 1, 0) == 0);        /* SAC ⊆ SSI */
    CHECK(ssi_sac_current(1, 1, 0, 1, 1, 0) == 0);        /* no provenance */
    CHECK(ssi_sac_current(1, 1, 1, 0, 1, 0) == 0);        /* certificate not bound */
    CHECK(ssi_sac_current(1, 1, 1, 1, 1, 1) == 0);        /* revoked */
}
TEST(verify_ssi_order) {           /* §31 minimal verification kernel */
    ssi_verify_input all = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    CHECK(ssi_verify(&all) == NULL);
    ssi_verify_input x = all; x.type_valid = 0; x.provenance_valid = 0;
    CHECK(strcmp(ssi_verify(&x), "TYPE_VALID") == 0);     /* first failure in kernel order */
    x = all; x.superintelligence_criterion = 0;
    CHECK(strcmp(ssi_verify(&x), "SUPERINTELLIGENCE_CRITERION") == 0);
    x = all; x.certificate_binds = 0;
    CHECK(strcmp(ssi_verify(&x), "CERTIFICATE_BINDS_TO") == 0);
    int passes = 0;
    for (uint32_t b = 0; b < 2048; b++) {
        ssi_verify_input y = { (int)(b&1), (int)(b>>1&1), (int)(b>>2&1), (int)(b>>3&1), (int)(b>>4&1), (int)(b>>5&1),
                               (int)(b>>6&1), (int)(b>>7&1), (int)(b>>8&1), (int)(b>>9&1), (int)(b>>10&1) };
        passes += ssi_verify(&y) == NULL;
    }
    CHECK(passes == 1);
}
TEST(canonical_encoding) {         /* §29: deterministic ENC(X), ID_X = H(ENC(X)) */
    kv a[] = {{"vs", "1"}, {"si", "1"}, {"hg", "1"}}, b[] = {{"hg", "1"}, {"vs", "1"}, {"si", "1"}};
    char ida[65], idb[65], buf[128];
    CHECK(ssi_state_id(a, 3, ida) == 0 && ssi_state_id(b, 3, idb) == 0 && strcmp(ida, idb) == 0);
    CHECK(ssi_encode(a, 3, buf, sizeof buf) > 0 && strcmp(buf, "hg=1\nsi=1\nvs=1\n") == 0);
    kv dup[] = {{"si", "1"}, {"si", "0"}};
    CHECK(ssi_state_id(dup, 2, ida) == -1);
    kv c[] = {{"vs", "0"}, {"si", "1"}, {"hg", "1"}};
    CHECK(ssi_state_id(c, 3, idb) == 0 && strcmp(ida, idb) != 0);
}
TEST(reachable_state_safety) {     /* Theorem 5, by exhaustive simulation of 20,000 attempted transitions */
    wad_t balance = W("100");
    uint64_t s = 0xA0761D6478BD642FULL;
    int committed = 0, violations = 0;
    for (int i = 0; i < 20000; i++) {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        wad_t delta = (wad_t)((int64_t)(s % 4000001) - 2000000) * (WAD_SCALE / 100);
        wad_t next; int arith_ok = wad_add(balance, delta, &next) == WAD_OK;
        int inv_next = arith_ok && next >= 0;                  /* invariant: balance never negative */
        int auth = (s >> 20) % 10 != 0, ver = (s >> 30) % 12 != 0;
        if (ssi_execute(auth, arith_ok, ver, 1, inv_next) == GATE_COMMIT) { balance = next; committed++; }
        if (balance < 0) violations++;
    }
    CHECK(committed > 1000);
    CHECK(violations == 0);
}

/* ------------------------------------------------------------ Standard (Spec I) */
static permit13 all_good(void) { permit13 c = {1,1,1,1,1,1,1,1,1,1,0,1,1}; return c; }
TEST(permit13_every_condition_necessary) {   /* §13 */
    permit13 c = all_good();
    CHECK(ssi_permit13(&c) == 1);
    int *f[] = {&c.type_ok, &c.action_well_typed, &c.csl_valid, &c.authorized, &c.capability_valid, &c.safety_inv,
                &c.action_safe, &c.evidence_valid, &c.deployment_bound, &c.current, &c.within_scope, &c.fresh};
    for (int i = 0; i < 12; i++) { c = all_good(); *f[i] = 0; CHECK(ssi_permit13(&c) == 0); }
    c = all_good(); c.revoked = 1; CHECK(ssi_permit13(&c) == 0);
    int permitted = 0;
    for (uint32_t b = 0; b < 8192; b++) permitted += ssi_permit13_from_bits(b);
    CHECK(permitted == 1);
}
TEST(decision_golden) {            /* §7, §14, §23; Lean golden vectors */
    CHECK(ssi_decide(1, VER_PASS, 1) == DEC_EXECUTE);
    CHECK(ssi_decide(1, VER_UNKNOWN, 1) == DEC_DEFER);     /* UNKNOWN ≠ PASS */
    CHECK(ssi_decide(1, VER_FAIL, 1) == DEC_REJECT);
    CHECK(ssi_decide(1, VER_PASS, 0) == DEC_REJECT);
    CHECK(ssi_decide(0, VER_PASS, 1) == DEC_SAFE_STOP);    /* invalid arithmetic */
    for (int a = 0; a < 2; a++) for (int v = 0; v < 3; v++) for (int p = 0; p < 2; p++)
        CHECK((ssi_decide(a, (ver_result)v, p) == DEC_EXECUTE) == (a && v == VER_PASS && p));
}
TEST(mediation_and_typing) {       /* §3, §8, §9, §32 */
    CHECK(ssi_mediate(ACT_COMMUNICATE, 1) == 1);
    CHECK(ssi_mediate(ACT_NONE, 1) == 0);                  /* untyped: no implicit permission */
    CHECK(ssi_mediate(ACT_SELF_MODIFY, 0) == 0);           /* capability is not authority */
    for (int k = ACT_READ; k <= ACT_POLICY_CHANGE; k++) CHECK(ssi_mediate((action_type)k, 0) == 0);
}
TEST(directive_golden) {           /* §10; Lean golden vectors: issued 10, expires 100, epoch 3 */
    CHECK(ssi_directive_valid(1, 10, 100, 3, 50, 3, 1) == 1);
    CHECK(ssi_directive_valid(1, 10, 100, 3, 101, 3, 1) == 0);
    CHECK(ssi_directive_valid(1, 10, 100, 3, 50, 4, 1) == 0);
    CHECK(ssi_directive_valid(1, 10, 100, 3, 5, 3, 1) == 0);
    CHECK(ssi_directive_valid(0, 10, 100, 3, 50, 3, 1) == 0);
    CHECK(ssi_directive_valid(1, 10, 100, 3, 50, 3, 0) == 0);
}
TEST(capability_non_escalation) {  /* §17 */
    uint32_t c12 = 1u << 1 | 1u << 2, c123 = c12 | 1u << 3, c14 = 1u << 1 | 1u << 4;
    CHECK(ssi_capability_ok(c12, c123, 0) == 1);
    CHECK(ssi_capability_ok(c14, c123, 0) == 0);
    CHECK(ssi_capability_ok(c14, c123, 1) == 1);
}
TEST(deployment_binding) {         /* §16 */
    CHECK(ssi_certifies(1, "deployment-A", "deployment-A") == 1);
    CHECK(ssi_certifies(1, "deployment-A", "deployment-B") == 0);
    CHECK(ssi_certifies(0, "deployment-A", "deployment-A") == 0);
}
TEST(adoption_six_conditions) {    /* §18 */
    CHECK(ssi_adopt6(1, 1, 1, 1, 1, 1) == 1);
    CHECK(ssi_adopt6(1, 1, 1, 1, 0, 1) == 0);
    CHECK(ssi_adopt6(0, 1, 1, 1, 1, 1) == 0);
}
TEST(safety_asset_lifecycle) {     /* §21–§22 */
    CHECK(ssi_sac_active(1, 1, 1, 1, ST_ACTIVE) == 1);
    CHECK(ssi_sac_active(1, 1, 1, 1, ST_REVALIDATION) == 0);
    CHECK(ssi_sac_active(1, 1, 1, 0, ST_ACTIVE) == 0);
    CHECK(ssi_can_transition(ST_ACTIVE, ST_REVOKED) == 1);
    CHECK(ssi_can_transition(ST_PROPOSED, ST_ACTIVE) == 0);
    for (int t = 0; t < 6; t++) {
        CHECK(ssi_can_transition(ST_REVOKED, (asset_status)t) == 0);
        CHECK(ssi_can_transition(ST_REJECTED, (asset_status)t) == 0);
    }
}
TEST(hash_integrity_is_not_truth) { /* §15: a sealed false claim still verifies its integrity */
    const char *claim = "safety_invariants_valid=1";   /* suppose this claim is false */
    char h1[65], h2[65];
    sha256_hex((const uint8_t *)claim, strlen(claim), h1);
    sha256_hex((const uint8_t *)claim, strlen(claim), h2);
    CHECK(strcmp(h1, h2) == 0);   /* integrity holds; the truth of the claim is a separate question */
}
TEST(sha256_reference_vectors) {
    char h[65];
    sha256_hex((const uint8_t *)"", 0, h);
    CHECK(strcmp(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
    sha256_hex((const uint8_t *)"abc", 3, h);
    CHECK(strcmp(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
}

/* ------------------------------------------------------------ R3 refinement 1.1: exact wide intermediates */
TEST(wad_wide_intermediate_regressions) {   /* v1.0 rejected each of these although the exact result is representable */
    wad_t r;
    CHECK(wad_mul(W("14"), W("14"), &r) == WAD_OK && r == W("196"));
    CHECK(wad_mul(W("100"), W("2"), &r) == WAD_OK && r == W("200"));
    CHECK(wad_mul(W("1000000"), W("1000000"), &r) == WAD_OK && r == W("1000000000000"));
    CHECK(wad_mul(W("-100"), W("2"), &r) == WAD_OK && r == W("-200"));
    CHECK(wad_div(W("171"), W("2"), &r) == WAD_OK && r == W("85.5"));
    CHECK(wad_div(W("1000"), W("10"), &r) == WAD_OK && r == W("100"));
    CHECK(wad_div(W("1000000000000"), W("1000000"), &r) == WAD_OK && r == W("1000000"));
}
TEST(wad_wide_boundaries) {                 /* overflow now means exactly: the exact result is outside [WAD_MIN, WAD_MAX] */
    wad_t r = 777;
    CHECK(wad_mul(WAD_MAX, WAD_SCALE, &r) == WAD_OK && r == WAD_MAX);
    CHECK(wad_mul(WAD_MIN, WAD_SCALE, &r) == WAD_OK && r == WAD_MIN);
    CHECK(wad_div(WAD_MAX, WAD_SCALE, &r) == WAD_OK && r == WAD_MAX);
    CHECK(wad_div(WAD_MAX, WAD_MAX, &r) == WAD_OK && r == WAD_SCALE);
    CHECK(wad_div(WAD_MIN, WAD_MAX, &r) == WAD_OK && r == -WAD_SCALE);
    r = 777; CHECK(wad_mul(WAD_MAX, 2 * WAD_SCALE, &r) == WAD_OVERFLOW && r == 777);
    r = 777; CHECK(wad_mul(WAD_MAX, WAD_MAX, &r) == WAD_OVERFLOW && r == 777);
    r = 777; CHECK(wad_div(WAD_MAX, 1, &r) == WAD_OVERFLOW && r == 777);
    r = 777; CHECK(wad_div(WAD_MAX, WAD_SCALE / 2, &r) == WAD_OVERFLOW && r == 777);
    r = 777; CHECK(wad_mul(WAD_MAX, 1, &r) == WAD_NON_EXACT && r == 777);
    r = 777; CHECK(wad_div(1, WAD_MAX, &r) == WAD_NON_EXACT && r == 777);
    r = 777; CHECK(wad_div(WAD_MAX, 0, &r) == WAD_DIV_ZERO && r == 777);
    CHECK(wad_mul(0, WAD_MAX, &r) == WAD_OK && r == 0);
}
TEST(wad_wide_properties_seeded) {          /* div(mul(a,b), b) == a over large integer-valued operands; failures stay explicit */
    uint64_t s = 0xA0761D6478BD642FULL;
    for (int i = 0; i < 3000; i++) {
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        int64_t ia = (int64_t)(s % 2000000001ULL) - 1000000000;
        s ^= s << 13; s ^= s >> 7; s ^= s << 17;
        int64_t ib = (int64_t)(s % 2000000001ULL) - 1000000000;
        if (ib == 0) ib = 1;
        wad_t a = (wad_t)ia * WAD_SCALE, b = (wad_t)ib * WAD_SCALE, p, q;
        CHECK(wad_mul(a, b, &p) == WAD_OK);
        CHECK(p == (wad_t)ia * ib * WAD_SCALE);
        CHECK(wad_div(p, b, &q) == WAD_OK && q == a);
        CHECK(wad_mul(a, b, &p) == WAD_OK && wad_mul(b, a, &q) == WAD_OK && p == q);   /* commutative */
    }
}

int main(void) {
    printf("SSI Verification Kernel test suite (PURE WAD18)\n");
    RUN(wad_paper_example); RUN(wad_exact_mul_div); RUN(wad_explicit_failures); RUN(wad_parse_rejections);
    RUN(wad_bounds_and_smallest_unit); RUN(wad_roundtrip_seeded); RUN(wad_comparison_integer_only);
    RUN(vs_fail_closed); RUN(membership_requires_every_component); RUN(execution_gate_exhaustive);
    RUN(csl_authorization_golden); RUN(adoption_and_non_regression); RUN(kernel_immutability);
    RUN(sac_axiomatic); RUN(verify_ssi_order); RUN(canonical_encoding); RUN(reachable_state_safety);
    RUN(permit13_every_condition_necessary); RUN(decision_golden); RUN(mediation_and_typing);
    RUN(directive_golden); RUN(capability_non_escalation); RUN(deployment_binding);
    RUN(adoption_six_conditions); RUN(safety_asset_lifecycle); RUN(hash_integrity_is_not_truth);
    RUN(sha256_reference_vectors);
    RUN(wad_wide_intermediate_regressions); RUN(wad_wide_boundaries); RUN(wad_wide_properties_seeded);
    printf("\n%d tests, %d checks, %d failures\n", tests, checks, failures);
    return failures ? 1 : 0;
}
