/*
 * WAD-18 — Weak Arithmetic Decidability, 18-decimal integer exact fixed point.
 * PURE WAD¹⁸: every normative value is a signed 128-bit integer z representing z × 10⁻¹⁸.
 * No floating-point type, operation, or instruction is used anywhere in this kernel.
 * Every arithmetic failure is explicit (SSI Axiom W2); none silently yields a value.
 */
#ifndef WAD18_H
#define WAD18_H

#include <stddef.h>

typedef __int128 wad_t;

#define WAD_DECIMALS 18
#define WAD_SCALE ((wad_t)1000000000000000000LL)            /* 10^18 */
#define WAD_MAX ((wad_t)(((unsigned __int128)1 << 127) - 1))  /* 2^127 - 1 */
#define WAD_MIN (-WAD_MAX)                                     /* symmetric range */

typedef enum {
    WAD_OK = 0,
    WAD_OVERFLOW,          /* result outside [WAD_MIN, WAD_MAX] */
    WAD_DIV_ZERO,          /* division by zero */
    WAD_NON_EXACT,         /* result not representable at 18 decimals: no silent rounding */
    WAD_EXCESS_PRECISION,  /* input has more than 18 decimal places */
    WAD_INVALID_ENCODING   /* malformed decimal literal */
} wad_err;

const char *wad_err_name(wad_err e);

/* Parse an exact decimal literal such as "-1000.10" into WAD-18. */
wad_err wad_parse(const char *text, wad_t *out);

/* Format exactly; buf must hold at least 64 bytes. Trailing zeros are kept to 18 places. */
void wad_format(wad_t x, char *buf, size_t n);

/* Format an integer (no scaling) in base 10; buf must hold at least 48 bytes. */
void wad_int_to_string(wad_t x, char *buf, size_t n);

wad_err wad_add(wad_t a, wad_t b, wad_t *out);
wad_err wad_sub(wad_t a, wad_t b, wad_t *out);
wad_err wad_mul(wad_t a, wad_t b, wad_t *out);   /* exact or WAD_NON_EXACT */
wad_err wad_div(wad_t a, wad_t b, wad_t *out);   /* exact or WAD_NON_EXACT */
int wad_cmp(wad_t a, wad_t b);                   /* -1, 0, 1: integer comparison only */

#endif
