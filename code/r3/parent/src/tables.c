/* Canonical decision table: every result the kernel produces over a fixed, seeded domain.
 * The TypeScript implementation must reproduce this table byte for byte. */
#include <stdio.h>
#include <string.h>
#include "ssi.h"
#include "sha256.h"

static sha256_ctx H;
static void emit(const char *line) {
    fputs(line, stdout); fputc('\n', stdout);
    sha256_update(&H, (const uint8_t *)line, strlen(line));
    sha256_update(&H, (const uint8_t *)"\n", 1);
}

static uint64_t rs = 0x9E3779B97F4A7C15ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }

static void wad_case(const char *op, wad_t a, wad_t b) {
    wad_t r = 0; wad_err e;
    if (op[0] == 'a') e = wad_add(a, b, &r);
    else if (op[0] == 's') e = wad_sub(a, b, &r);
    else if (op[0] == 'm') e = wad_mul(a, b, &r);
    else e = wad_div(a, b, &r);
    char sa[48], sb[48], sr[64], line[256];
    wad_int_to_string(a, sa, sizeof sa); wad_int_to_string(b, sb, sizeof sb);
    if (e == WAD_OK) { wad_int_to_string(r, sr, sizeof sr); snprintf(line, sizeof line, "WAD %s %s %s OK %s", op, sa, sb, sr); }
    else snprintf(line, sizeof line, "WAD %s %s %s ERR %s", op, sa, sb, wad_err_name(e));
    emit(line);
}

int main(int argc, char **argv) {
    sha256_init(&H);
    char line[512];

    /* WAD-18 parse and format of shared literals */
    FILE *f = fopen(argc > 1 ? argv[1] : "../data/wad_literals.txt", "r");
    if (!f) { fputs("cannot open literals\n", stderr); return 2; }
    char lit[256];
    while (fgets(lit, sizeof lit, f)) {
        lit[strcspn(lit, "\r\n")] = '\0';
        wad_t z; wad_err e = wad_parse(lit, &z);
        if (e == WAD_OK) { char s[64], fm[64]; wad_int_to_string(z, s, sizeof s); wad_format(z, fm, sizeof fm);
            snprintf(line, sizeof line, "PARSE [%s] OK %s %s", lit, s, fm); }
        else snprintf(line, sizeof line, "PARSE [%s] ERR %s", lit, wad_err_name(e));
        emit(line);
    }
    fclose(f);

    /* WAD-18 arithmetic over seeded operands */
    static const char *ops[] = {"add", "sub", "mul", "div"};
    for (int i = 0; i < 400; i++) {
        wad_t ia = (wad_t)(int64_t)(rnd() % 2000001) - 1000000, ib = (wad_t)(int64_t)(rnd() % 2000001) - 1000000;
        wad_t fa = (wad_t)(rnd() % 100) * 10000000000000000LL, fb = (wad_t)(rnd() % 100) * 10000000000000000LL;
        if (rnd() % 4 == 0) fa = (wad_t)(rnd() % 1000000000000000000ULL);
        wad_t a = ia * WAD_SCALE + (ia < 0 ? -fa : fa), b = ib * WAD_SCALE + (ib < 0 ? -fb : fb);
        if (rnd() % 10 == 0) b = 0;
        wad_case(ops[rnd() % 4], a, b);
    }
    wad_case("add", WAD_MAX, 1); wad_case("sub", WAD_MIN, 1); wad_case("mul", WAD_MAX, 2 * WAD_SCALE);
    wad_case("div", WAD_MAX, 1); wad_case("div", 1, 0); wad_case("mul", 1, WAD_SCALE / 2);

    /* VS over every invariant list up to length 4 */
    for (int n = 0; n <= 4; n++) {
        int total = 1; for (int i = 0; i < n; i++) total *= 3;
        for (int c = 0; c < total; c++) {
            ssi_truth v[4]; int x = c; char s[16]; int k = 0;
            for (int i = 0; i < n; i++) { v[i] = (ssi_truth)(x % 3); s[k++] = "TFU"[x % 3]; x /= 3; }
            s[k] = '\0';
            snprintf(line, sizeof line, "VS [%s] %d", s, ssi_vs(v, (size_t)n)); emit(line);
        }
    }

    for (int b = 0; b < 64; b++) {
        snprintf(line, sizeof line, "MEMBER %d %d %d", b & 31, ssi_member(b&1, b>>1&1, b>>2&1, b>>3&1, b>>4&1),
                 ssi_member_prov(b&1, b>>1&1, b>>2&1, b>>3&1, b>>4&1, b>>5&1)); emit(line);
        snprintf(line, sizeof line, "GATE %d %s", b & 31,
                 ssi_execute(b&1, b>>1&1, b>>2&1, b>>3&1, b>>4&1) == GATE_COMMIT ? "COMMIT" : "REJECT"); emit(line);
        snprintf(line, sizeof line, "ADOPT6 %d %d", b, ssi_adopt6(b&1, b>>1&1, b>>2&1, b>>3&1, b>>4&1, b>>5&1)); emit(line);
        snprintf(line, sizeof line, "SAC %d %d", b, ssi_sac_current(b&1, b>>1&1, b>>2&1, b>>3&1, b>>4&1, b>>5&1)); emit(line);
    }
    for (int b = 0; b < 16; b++) { snprintf(line, sizeof line, "ADOPT4 %d %d", b, ssi_adopt4(b&1, b>>1&1, b>>2&1, b>>3&1)); emit(line); }

    for (uint32_t b = 0; b < 8192; b++) { snprintf(line, sizeof line, "P13 %u %d", b, ssi_permit13_from_bits(b)); emit(line); }

    for (int a = 0; a < 2; a++) for (int v = 0; v < 3; v++) for (int p = 0; p < 2; p++) {
        snprintf(line, sizeof line, "DECIDE %d %d %d %s", a, v, p, decision_name(ssi_decide(a, (ver_result)v, p))); emit(line); }

    for (int k = -1; k <= 9; k++) for (int p = 0; p < 2; p++) {
        snprintf(line, sizeof line, "MEDIATE %d %d %d", k, p, ssi_mediate((action_type)k, p)); emit(line); }

    for (int s = 0; s < 6; s++) for (int t = 0; t < 6; t++) {
        snprintf(line, sizeof line, "LIFE %s %s %d", status_name((asset_status)s), status_name((asset_status)t),
                 ssi_can_transition((asset_status)s, (asset_status)t)); emit(line); }
    for (int b = 0; b < 16; b++) for (int s = 0; s < 6; s++) {
        snprintf(line, sizeof line, "SACA %d %s %d", b, status_name((asset_status)s),
                 ssi_sac_active(b&1, b>>1&1, b>>2&1, b>>3&1, (asset_status)s)); emit(line); }

    for (uint32_t b = 0; b < 2048; b++) {
        ssi_verify_input x = { (int)(b&1), (int)(b>>1&1), (int)(b>>2&1), (int)(b>>3&1), (int)(b>>4&1), (int)(b>>5&1),
                               (int)(b>>6&1), (int)(b>>7&1), (int)(b>>8&1), (int)(b>>9&1), (int)(b>>10&1) };
        const char *r = ssi_verify(&x);
        snprintf(line, sizeof line, "VERIFY %u %s", b, r ? r : "PASS"); emit(line);
    }

    for (int i = 0; i < 400; i++) {
        uint64_t until = rnd() % 5000, now = rnd() % 6000; int sig = rnd() % 8 != 0, rev = rnd() % 8 == 0, env = rnd() % 7 != 0;
        snprintf(line, sizeof line, "CSL %d %d %llu %llu %d %d", sig, rev, (unsigned long long)until, (unsigned long long)now, env,
                 ssi_csl_auth(sig, rev, until, now, env)); emit(line);
    }
    for (int i = 0; i < 400; i++) {
        uint64_t issue = rnd() % 500, expiry = issue + 1 + rnd() % 2000, now = rnd() % 3000, ep = 1 + rnd() % 9,
                 cur = ep + (rnd() % 5 == 0 ? 1 + rnd() % 2 : 0);
        int sig = rnd() % 10 != 0, scope = rnd() % 8 != 0;
        snprintf(line, sizeof line, "DIRECTIVE %d %llu %llu %llu %llu %llu %d %d", sig, (unsigned long long)issue,
                 (unsigned long long)expiry, (unsigned long long)ep, (unsigned long long)now, (unsigned long long)cur, scope,
                 ssi_directive_valid(sig, issue, expiry, ep, now, cur, scope)); emit(line);
    }
    for (int i = 0; i < 400; i++) {
        uint32_t nx = (uint32_t)(rnd() & 0x3FF), au = (uint32_t)(rnd() & 0x3FF); int gov = rnd() % 5 == 0;
        snprintf(line, sizeof line, "CAP %u %u %d %d", nx, au, gov, ssi_capability_ok(nx, au, gov)); emit(line);
    }

    char hex[65]; sha256_final(&H, hex);
    fprintf(stderr, "TABLE_SHA256 %s\n", hex);
    return 0;
}
