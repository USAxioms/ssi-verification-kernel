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

wad_err wad_mul(wad_t a, wad_t b, wad_t *out) {
    wad_t p;
    if (__builtin_mul_overflow(a, b, &p)) return WAD_OVERFLOW;
    if (p % WAD_SCALE != 0) return WAD_NON_EXACT;
    wad_t r = p / WAD_SCALE;
    if (!in_range(r)) return WAD_OVERFLOW;
    *out = r;
    return WAD_OK;
}

wad_err wad_div(wad_t a, wad_t b, wad_t *out) {
    if (b == 0) return WAD_DIV_ZERO;
    wad_t n;
    if (__builtin_mul_overflow(a, WAD_SCALE, &n)) return WAD_OVERFLOW;
    if (n % b != 0) return WAD_NON_EXACT;
    wad_t r = n / b;
    if (!in_range(r)) return WAD_OVERFLOW;
    *out = r;
    return WAD_OK;
}

int wad_cmp(wad_t a, wad_t b) { return (a > b) - (a < b); }
