/* Run the Standard's decision procedure on each scenario in data/scenarios.txt.
 * Output is deterministic: decision, failing Permit conditions, mediation result, and state ID. */
#include <stdio.h>
#include <string.h>
#include "ssi.h"

#define MAXF 32
typedef struct { char key[48]; char val[96]; } field;

static const char *PERMIT_KEYS[13] = {"type_ok", "action_well_typed", "csl_valid", "authorized", "capability_valid",
    "safety_inv", "action_safe", "evidence_valid", "deployment_bound", "current", "revoked", "within_scope", "fresh"};
static const char *ACTIONS[10] = {"READ", "COMPUTE", "COMMUNICATE", "WRITE", "PURCHASE", "DEPLOY", "CREDENTIAL",
    "PHYSICAL", "SELF_MODIFY", "POLICY_CHANGE"};

static const char *get(field *f, int n, const char *k) {
    for (int i = 0; i < n; i++) if (strcmp(f[i].key, k) == 0) return f[i].val;
    return NULL;
}

/* Missing or malformed values fail closed: they count as the unsafe reading. */
static int flag(field *f, int n, const char *k, int unsafe_default) {
    const char *v = get(f, n, k);
    if (!v) return unsafe_default;
    if (strcmp(v, "1") == 0) return 1;
    if (strcmp(v, "0") == 0) return 0;
    return unsafe_default;
}

static void run(field *f, int n) {
    if (n == 0) return;
    uint32_t bits = 0;
    for (int i = 0; i < 13; i++) {
        int unsafe = (i == 10) ? 1 : 0;                     /* missing "revoked" is treated as revoked */
        if (flag(f, n, PERMIT_KEYS[i], unsafe)) bits |= 1u << i;
    }
    int permit = ssi_permit13_from_bits(bits);
    const char *vs = get(f, n, "verification");
    ver_result v = !vs ? VER_UNKNOWN : strcmp(vs, "PASS") == 0 ? VER_PASS : strcmp(vs, "FAIL") == 0 ? VER_FAIL : VER_UNKNOWN;
    int arith = flag(f, n, "arithmetic_valid", 0);
    decision d = ssi_decide(arith, v, permit);

    const char *an = get(f, n, "action");
    action_type at = ACT_NONE;
    for (int i = 0; an && i < 10; i++) if (strcmp(an, ACTIONS[i]) == 0) at = (action_type)i;
    int effect = d == DEC_EXECUTE && ssi_mediate(at, permit);

    kv fields[MAXF];
    for (int i = 0; i < n; i++) { fields[i].key = f[i].key; fields[i].value = f[i].val; }
    char id[65];
    if (ssi_state_id(fields, (size_t)n, id) != 0) strcpy(id, "ENCODING_ERROR");

    printf("scenario: %s\n  decision: %s\n  external effect: %s\n", get(f, n, "name") ? get(f, n, "name") : "(unnamed)",
           decision_name(d), effect ? "EMITTED via mediated interface" : "none");
    printf("  failing permit conditions:");
    int any = 0;
    for (int i = 0; i < 13; i++) {
        int set = (bits >> i) & 1;
        if ((i == 10 && set) || (i != 10 && !set)) { printf(" %s", i == 10 ? "revoked" : PERMIT_KEYS[i]); any = 1; }
    }
    printf("%s\n  state id: %s\n\n", any ? "" : " none", id);
}

int main(int argc, char **argv) {
    FILE *in = fopen(argc > 1 ? argv[1] : "../data/scenarios.txt", "r");
    if (!in) { fputs("cannot open scenarios\n", stderr); return 2; }
    field f[MAXF]; int n = 0; char line[256];
    while (fgets(line, sizeof line, in)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '#') continue;
        if (line[0] == '\0') { run(f, n); n = 0; continue; }
        char *eq = strchr(line, '=');
        if (!eq || n >= MAXF) continue;
        *eq = '\0';
        size_t kl = strlen(line), vl = strlen(eq + 1);
        if (kl >= sizeof f[n].key || vl >= sizeof f[n].val) {   /* reject, never truncate */
            fprintf(stderr, "rejected over-long field '%.20s...'\n", line);
            continue;
        }
        memcpy(f[n].key, line, kl + 1);
        memcpy(f[n].val, eq + 1, vl + 1);
        n++;
    }
    run(f, n);
    fclose(in);
    return 0;
}
