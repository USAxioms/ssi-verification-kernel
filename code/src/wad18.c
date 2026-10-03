#include "wad18.h"

const char *wad_err_name(wad_err e) {
    switch (e) {
    case WAD_OK: return "OK";
    case WAD_OVERFLOW: return "OVERFLOW";
    case WAD_DIV_ZERO: return "DIV_ZERO";
    case WAD_NON_EXACT: return "NON_EXACT";
    case WAD_EXCESS_PRECISION: return "EXCESS_PRECISION";
    case WAD_INVALID_ENCODING: return "INVALID_ENCODING";
    }
    return "UNKNOWN_ERROR";
}

static int in_range(wad_t x) { return x >= WAD_MIN && x <= WAD_MAX; }

wad_err wad_parse(const char *s, wad_t *out) {
    if (!s || !*s) return WAD_INVALID_ENCODING;
    int neg = 0;
    if (*s == '-' || *s == '+') { neg = (*s == '-'); s++; }
    if (*s < '0' || *s > '9') return WAD_INVALID_ENCODING;   /* a leading digit is required */
    wad_t ip = 0;
    while (*s >= '0' && *s <= '9') {
        if (__builtin_mul_overflow(ip, (wad_t)10, &ip)) return WAD_OVERFLOW;
        if (__builtin_add_overflow(ip, (wad_t)(*s - '0'), &ip)) return WAD_OVERFLOW;
        s++;
    }
    wad_t fp = 0;
    int nd = 0;
    if (*s == '.') {
        s++;
        if (*s < '0' || *s > '9') return WAD_INVALID_ENCODING;
        while (*s >= '0' && *s <= '9') {
            if (nd == WAD_DECIMALS) return WAD_EXCESS_PRECISION;
            fp = fp * 10 + (*s - '0');
            nd++;
            s++;
        }
    }
    if (*s != '\0') return WAD_INVALID_ENCODING;
    for (int i = nd; i < WAD_DECIMALS; i++) fp *= 10;
    wad_t z;
    if (__builtin_mul_overflow(ip, WAD_SCALE, &z)) return WAD_OVERFLOW;
    if (__builtin_add_overflow(z, fp, &z)) return WAD_OVERFLOW;
    if (neg) z = -z;
    if (!in_range(z)) return WAD_OVERFLOW;
    *out = z;
    return WAD_OK;
}

void wad_int_to_string(wad_t x, char *buf, size_t n) {
    char tmp[48];
    int i = 0, neg = x < 0;
    unsigned __int128 u = neg ? (unsigned __int128)(-(x + 1)) + 1 : (unsigned __int128)x;
    do { tmp[i++] = (char)('0' + (int)(u % 10)); u /= 10; } while (u);
    size_t k = 0;
    if (neg && k + 1 < n) buf[k++] = '-';
    while (i > 0 && k + 1 < n) buf[k++] = tmp[--i];
    buf[k] = '\0';
}

void wad_format(wad_t x, char *buf, size_t n) {
    int neg = x < 0;
    unsigned __int128 u = neg ? (unsigned __int128)(-(x + 1)) + 1 : (unsigned __int128)x;
    unsigned __int128 ip = u / (unsigned __int128)WAD_SCALE, fp = u % (unsigned __int128)WAD_SCALE;
    char ib[48];
    wad_int_to_string((wad_t)ip, ib, sizeof ib);
    char fb[WAD_DECIMALS + 1];
    for (int i = WAD_DECIMALS - 1; i >= 0; i--) { fb[i] = (char)('0' + (int)(fp % 10)); fp /= 10; }
    fb[WAD_DECIMALS] = '\0';
    size_t k = 0;
    if (neg && k + 1 < n) buf[k++] = '-';
    for (const char *p = ib; *p && k + 1 < n; p++) buf[k++] = *p;
    if (k + 1 < n) buf[k++] = '.';
    for (const char *p = fb; *p && k + 1 < n; p++) buf[k++] = *p;
    buf[k] = '\0';
}

wad_err wad_add(wad_t a, wad_t b, wad_t *out) {
    wad_t r;
    if (__builtin_add_overflow(a, b, &r) || !in_range(r)) return WAD_OVERFLOW;
    *out = r;
    return WAD_OK;
}

wad_err wad_sub(wad_t a, wad_t b, wad_t *out) {
    wad_t r;
    if (__builtin_sub_overflow(a, b, &r) || !in_range(r)) return WAD_OVERFLOW;
    *out = r;
    return WAD_OK;
}

/* ---- exact wide arithmetic (R3 refinement 1.1) -------------------------------------------------
 * The v1.0 kernel rejected a product whenever the RAW 128-bit intermediate overflowed, even when the
 * final result was representable (for example 100 * 2). Intermediates are now computed exactly in 256
 * bits, so OVERFLOW means only that the exact result lies outside [WAD_MIN, WAD_MAX].
 * Error precedence (identical in the TypeScript implementation and the Python oracle):
 *   DIV_ZERO; else OVERFLOW if |quotient| > WAD_MAX; else NON_EXACT if remainder != 0; else OK.      */
typedef unsigned __int128 u128;
typedef struct { u128 lo, hi; } u256;

static u128 mag(wad_t x) { return x < 0 ? (u128)(-(x + 1)) + 1 : (u128)x; }

static u256 mul_u128(u128 a, u128 b) {
    const u128 M = (u128)0xFFFFFFFFFFFFFFFFULL;
    u128 a0 = a & M, a1 = a >> 64, b0 = b & M, b1 = b >> 64;
    u128 p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
    u128 mid = (p00 >> 64) + (p01 & M) + (p10 & M);
    u256 r;
    r.lo = ((mid & M) << 64) | (p00 & M);
    r.hi = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
    return r;
}

/* Restoring division of a 256-bit numerator by a non-zero divisor of at most 2^127. */
static u256 divmod_u256(u256 n, u128 d, u128 *rem) {
    u256 q = {0, 0};
    u128 r = 0;
    for (int i = 255; i >= 0; i--) {
        u128 bit = i >= 128 ? (n.hi >> (i - 128)) & 1 : (n.lo >> i) & 1;
        r = (r << 1) | bit;
        if (r >= d) {
            r -= d;
            if (i >= 128) q.hi |= (u128)1 << (i - 128); else q.lo |= (u128)1 << i;
        }
    }
    *rem = r;
    return q;
}

static wad_err finish(u256 q, u128 rem, int neg, wad_t *out) {
    if (q.hi != 0 || q.lo > (u128)WAD_MAX) return WAD_OVERFLOW;
    if (rem != 0) return WAD_NON_EXACT;
    wad_t r = (wad_t)q.lo;
    *out = neg ? -r : r;
    return WAD_OK;
}

wad_err wad_mul(wad_t a, wad_t b, wad_t *out) {
    u128 rem;
    u256 q = divmod_u256(mul_u128(mag(a), mag(b)), (u128)WAD_SCALE, &rem);
    return finish(q, rem, (a < 0) != (b < 0), out);
}

wad_err wad_div(wad_t a, wad_t b, wad_t *out) {
    if (b == 0) return WAD_DIV_ZERO;
    u128 rem;
    u256 q = divmod_u256(mul_u128(mag(a), (u128)WAD_SCALE), mag(b), &rem);
    return finish(q, rem, (a < 0) != (b < 0), out);
}

int wad_cmp(wad_t a, wad_t b) { return (a > b) - (a < b); }
