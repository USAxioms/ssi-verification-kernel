/* SHA-256 (FIPS 180-4), integer-only. Used for canonical state identity ID_X = H(ENC(X)). */
#ifndef SHA256_H
#define SHA256_H
#include <stddef.h>
#include <stdint.h>
void sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void sha256_hex(const uint8_t *data, size_t len, char hex[65]);

typedef struct { uint32_t h[8]; uint64_t len; uint8_t buf[64]; size_t n; } sha256_ctx;
void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *c, char hex[65]);
#endif
