/* R3 adoption of the capsule onto itself. PURE WAD18: integer-only. The decision is made by the capsule's OWN kernel
 * functions: ssi_directive_valid, ssi_capability_ok, ssi_non_regression, ssi_adopt6, ssi_decide, ssi_state_id.
 * Inputs are the evidence file and the directive. A missing or malformed key fails closed (read as the unsafe value).
 * Output: the adoption record, deterministic (no clock, no environment data), included in the run fingerprint. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ssi.h"
#include "sha256.h"

#define MAXKV 512
typedef struct { char k[160]; char v[320]; } pair;
typedef struct { pair p[MAXKV]; int n; } table;

static int load(const char *path, table *t) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[600];
    t->n = 0;
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '#' || !line[0]) continue;
        char *eq = strchr(line, '=');
        if (!eq || t->n >= MAXKV) continue;
        *eq = '\0';
        size_t kl = strlen(line), vl = strlen(eq + 1);
        if (kl >= sizeof t->p[0].k || vl >= sizeof t->p[0].v) continue;   /* oversized: skipped, so read as unset (fail closed) */
        memcpy(t->p[t->n].k, line, kl + 1);
        memcpy(t->p[t->n].v, eq + 1, vl + 1);
        t->n++;
    }
    fclose(f);
    return 0;
}
static const char *get(const table *t, const char *k) {
    for (int i = 0; i < t->n; i++) if (strcmp(t->p[i].k, k) == 0) return t->p[i].v;
    return NULL;
}
static uint64_t num(const table *t, const char *k) { const char *v = get(t, k); return v ? strtoull(v, NULL, 10) : 0; }
static int flag(const table *t, const char *k) { return num(t, k) == 1; }

static int file_sha(const char *path, char hex[65]) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    static uint8_t buf[1 << 20];
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    sha256_hex(buf, n, hex);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4) { fputs("usage: r3_adopt evidence directive out\n", stderr); return 2; }
    table ev, dv;
    if (load(argv[1], &ev) || load(argv[2], &dv)) { puts("decision=REJECT\nreason=missing evidence or directive"); return 1; }

    /* KernelEqual, SafetyProofValid, DeploymentValid: derived by r3_evidence.py from artifacts */
    int kernel_equal = flag(&ev, "kernel_equal");
    int safety_valid = flag(&ev, "safety_proof_valid");
    int deployment_valid = flag(&ev, "deployment_valid");

    /* AuthorizationValid: the kernel's own directive rule, evaluated as of the directive's evaluation epoch. */
    const char *scope = get(&dv, "scope");
    int in_scope = scope && strcmp(scope, "capsule-refinement") == 0;
    int authorization_valid = ssi_directive_valid(flag(&dv, "attested"), num(&dv, "issue_epoch"), num(&dv, "expiry_epoch"),
                                                  num(&dv, "revocation_epoch"), num(&dv, "evaluation_epoch"),
                                                  num(&dv, "current_epoch"), in_scope);

    /* CapabilityDisclosureValid: observed behavioural change must lie inside the authorized envelope (Cap(q') subset of Cap_auth(q)). */
    uint32_t observed = (uint32_t)num(&ev, "observed_caps"), authorized = (uint32_t)num(&dv, "authorized_caps");
    int capability_valid = ssi_capability_ok(observed, authorized, 0);

    /* NonRegression (Def. 24): every named check true in the parent stays true in the child. */
    static ssi_truth before[MAXKV], after[MAXKV];
    size_t nb = 0;
    for (int i = 0; i < ev.n && nb < MAXKV; i++) {
        if (strncmp(ev.p[i].k, "before.", 7) != 0) continue;
        char ak[200]; snprintf(ak, sizeof ak, "after.%s", ev.p[i].k + 7);
        const char *av = get(&ev, ak);
        before[nb] = ev.p[i].v[0] == 'T' ? SSI_TT : ev.p[i].v[0] == 'F' ? SSI_FF : SSI_UNKNOWN;
        after[nb] = !av ? SSI_UNKNOWN : av[0] == 'T' ? SSI_TT : av[0] == 'F' ? SSI_FF : SSI_UNKNOWN;
        nb++;
    }
    int non_regression = nb > 0 && ssi_non_regression(before, after, nb) && flag(&ev, "parent_reproduced");

    int adopt = ssi_adopt6(kernel_equal, safety_valid, authorization_valid, deployment_valid, non_regression, capability_valid);
    decision d = ssi_decide(1, VER_PASS, adopt);

    /* Lineage: P0 = ID(parent state); P1 = ID(child state bound to P0, the directive and the evidence). */
    char p0[65], p1[65], evh[65];
    kv f0[] = { {"kernel_sha256", get(&ev, "parent_kernel_sha256") ? get(&ev, "parent_kernel_sha256") : ""},
                {"run_fingerprint", get(&ev, "parent_run_fingerprint") ? get(&ev, "parent_run_fingerprint") : ""},
                {"table_sha256", get(&ev, "parent_table_sha256") ? get(&ev, "parent_table_sha256") : ""},
                {"version", "1.0"} };
    if (ssi_state_id(f0, 4, p0) != 0 || file_sha(argv[1], evh) != 0) { puts("decision=REJECT\nreason=lineage failure"); return 1; }
    kv f1[] = { {"adopt6", adopt ? "1" : "0"}, {"directive_nonce", get(&dv, "nonce") ? get(&dv, "nonce") : ""},
                {"evidence_sha256", evh}, {"kernel_sha256", get(&ev, "child_kernel_sha256") ? get(&ev, "child_kernel_sha256") : ""},
                {"parent_id", p0}, {"table_sha256", get(&ev, "child_table_sha256") ? get(&ev, "child_table_sha256") : ""},
                {"version", "1.1"} };
    if (ssi_state_id(f1, 7, p1) != 0) { puts("decision=REJECT\nreason=lineage failure"); return 1; }

    FILE *o = fopen(argv[3], "w");
    if (!o) return 2;
    fprintf(o, "R3 adoption record: SSI Verification Kernel capsule v1.0 -> v1.1, evaluated as of epoch %llu\n", (unsigned long long)num(&dv, "evaluation_epoch"));
    fprintf(o, "kernel_equal=%d\nsafety_proof_valid=%d\nauthorization_valid=%d\ndeployment_valid=%d\nnon_regression=%d (%zu parent checks)\ncapability_disclosure_valid=%d (observed %u within authorized %u)\n",
            kernel_equal, safety_valid, authorization_valid, deployment_valid, non_regression, nb, capability_valid, observed, authorized);
    fprintf(o, "adopt6=%d\ndecision=%s\nauthorization_basis=%s\nparent_id=%s\nchild_id=%s\n", adopt, adopt && d == DEC_EXECUTE ? "ADOPT" : "REJECT",
            get(&dv, "attestation") ? get(&dv, "attestation") : "none", p0, p1);
    fclose(o);
    return adopt && d == DEC_EXECUTE ? 0 : 1;
}
