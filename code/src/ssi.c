#include "ssi.h"
#include "sha256.h"
#include <string.h>

int ssi_vs(const ssi_truth *inv, size_t n) {
    if (n == 0) return 0;                       /* S1: safety requires declared invariants */
    for (size_t i = 0; i < n; i++)
        if (inv[i] != SSI_TT) return 0;         /* S2: FALSE or UNKNOWN is not safe */
    return 1;
}

int ssi_member(int si, int vs, int hg, int a, int v) { return si && vs && hg && a && v; }
int ssi_member_prov(int si, int vs, int hg, int a, int v, int p) { return ssi_member(si, vs, hg, a, v) && p; }

int ssi_permit4(int auth, int safe, int ver, int cap) { return auth && safe && ver && cap; }

gate_outcome ssi_execute(int auth, int safe, int ver, int cap, int inv_next) {
    /* EXECUTE → VERIFY → TRANSITION → INVARIANT CHECK → COMMIT, never check-afterward */
    if (!auth) return GATE_REJECT;
    if (!safe) return GATE_REJECT;
    if (!ver) return GATE_REJECT;
    if (!cap) return GATE_REJECT;
    if (!inv_next) return GATE_REJECT;
    return GATE_COMMIT;
}

int ssi_csl_auth(int sig, int revoked, uint64_t until, uint64_t now, int env) {
    return sig && !revoked && now <= until && env;
}

int ssi_permit13(const permit13 *c) {
    return c->type_ok && c->action_well_typed && c->csl_valid && c->authorized && c->capability_valid &&
           c->safety_inv && c->action_safe && c->evidence_valid && c->deployment_bound && c->current &&
           !c->revoked && c->within_scope && c->fresh;
}

int ssi_permit13_from_bits(uint32_t b) {
    permit13 c = { (int)(b >> 0 & 1), (int)(b >> 1 & 1), (int)(b >> 2 & 1), (int)(b >> 3 & 1),
                   (int)(b >> 4 & 1), (int)(b >> 5 & 1), (int)(b >> 6 & 1), (int)(b >> 7 & 1),
                   (int)(b >> 8 & 1), (int)(b >> 9 & 1), (int)(b >> 10 & 1), (int)(b >> 11 & 1),
                   (int)(b >> 12 & 1) };
    return ssi_permit13(&c);
}

decision ssi_decide(int arith_valid, ver_result v, int permit) {
    if (!arith_valid) return DEC_SAFE_STOP;     /* §7: invalid arithmetic → safe stop */
    if (v == VER_UNKNOWN) return DEC_DEFER;     /* §14: UNKNOWN ≠ PASS */
    if (v == VER_FAIL) return DEC_REJECT;
    if (!permit) return DEC_REJECT;             /* §13: only Permit = 1 executes */
    return DEC_EXECUTE;
}

const char *decision_name(decision d) {
    switch (d) {
    case DEC_EXECUTE: return "EXECUTE";
    case DEC_REJECT: return "REJECT";
    case DEC_DEFER: return "DEFER";
    case DEC_SAFE_STOP: return "SAFE_STOP";
    }
    return "INVALID";
}

int ssi_mediate(action_type kind, int permit) {
    if (kind < ACT_READ || kind > ACT_POLICY_CHANGE) return 0;   /* §9: untyped → no implicit permission */
    return permit ? 1 : 0;                                       /* §32: ¬Permit ⇒ ¬ExternalEffect */
}

int ssi_directive_valid(int sig, uint64_t issue, uint64_t expiry, uint64_t rev_epoch,
                        uint64_t now, uint64_t epoch, int scope) {
    return sig && issue <= now && now <= expiry && epoch <= rev_epoch && scope;
}

int ssi_capability_ok(uint32_t next, uint32_t authorized, int gov) {
    return (next & ~authorized) == 0 || gov;     /* Cap(q') ⊆ Cap_authorized(q), unless governance */
}

int ssi_certifies(int valid, const char *cert_dep, const char *dep) {
    return valid && cert_dep && dep && strcmp(cert_dep, dep) == 0;
}

int ssi_adopt4(int k, int p, int a, int n) { return k && p && a && n; }
int ssi_adopt6(int k, int s, int a, int d, int n, int c) { return k && s && a && d && n && c; }

int ssi_non_regression(const ssi_truth *before, const ssi_truth *after, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (before[i] == SSI_TT && after[i] != SSI_TT) return 0;
    return 1;
}

int ssi_sac_current(int ssi, int c, int p, int b, int a, int revoked) {
    return ssi && c && p && b && a && !revoked;
}

int ssi_can_transition(asset_status f, asset_status t) {
    return (f == ST_PROPOSED && t == ST_VERIFIED) || (f == ST_PROPOSED && t == ST_REJECTED) ||
           (f == ST_VERIFIED && t == ST_ACTIVE) || (f == ST_ACTIVE && t == ST_REVALIDATION) ||
           (f == ST_REVALIDATION && t == ST_ACTIVE) || (f == ST_REVALIDATION && t == ST_REVOKED) ||
           (f == ST_ACTIVE && t == ST_REVOKED);
}

int ssi_sac_active(int ssi, int p, int s, int fresh, asset_status st) {
    return ssi && p && s && fresh && st == ST_ACTIVE;
}

const char *status_name(asset_status s) {
    static const char *n[] = {"PROPOSED", "VERIFIED", "ACTIVE", "REVALIDATION", "REVOKED", "REJECTED"};
    return (s >= ST_PROPOSED && s <= ST_REJECTED) ? n[s] : "INVALID";
}

const char *ssi_verify(const ssi_verify_input *x) {
    if (!x->type_valid) return "TYPE_VALID";
    if (!x->wad18_valid) return "WAD18_VALID";
    if (!x->kernel_valid) return "KERNEL_VALID";
    if (!x->csl_valid) return "CSL_VALID";
    if (!x->authorization_valid) return "AUTHORIZATION_VALID";
    if (!x->safety_invariants_valid) return "SAFETY_INVARIANTS_VALID";
    if (!x->capability_valid) return "CAPABILITY_VALID";
    if (!x->certificate_valid) return "CERTIFICATE_VALID";
    if (!x->certificate_binds) return "CERTIFICATE_BINDS_TO";
    if (!x->provenance_valid) return "PROVENANCE_VALID";
    if (!x->superintelligence_criterion) return "SUPERINTELLIGENCE_CRITERION";
    return NULL;
}

int ssi_encode(const kv *f, size_t n, char *out, size_t cap) {
    /* insertion sort of indices by key: deterministic, no allocation */
    size_t idx[64];
    if (n > 64) return -1;
    for (size_t i = 0; i < n; i++) idx[i] = i;
    for (size_t i = 1; i < n; i++)
        for (size_t j = i; j > 0 && strcmp(f[idx[j-1]].key, f[idx[j]].key) > 0; j--) {
            size_t t = idx[j]; idx[j] = idx[j-1]; idx[j-1] = t;
        }
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        if (i > 0 && strcmp(f[idx[i-1]].key, f[idx[i]].key) == 0) return -1;   /* duplicate key */
        const char *parts[3] = { f[idx[i]].key, "=", f[idx[i]].value };
        for (int p = 0; p < 3; p++)
            for (const char *s = parts[p]; *s; s++) { if (k + 1 >= cap) return -1; out[k++] = *s; }
        if (k + 1 >= cap) return -1;
        out[k++] = '\n';
    }
    out[k] = '\0';
    return (int)k;
}

int ssi_state_id(const kv *f, size_t n, char hex[65]) {
    char buf[8192];
    int len = ssi_encode(f, n, buf, sizeof buf);
    if (len < 0) return -1;
    sha256_hex((const uint8_t *)buf, (size_t)len, hex);
    return 0;
}
