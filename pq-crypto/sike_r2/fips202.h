#ifndef FIPS202_H
#define FIPS202_H

#define SHAKE256_RATE 136

/** Data structure for the state of the SHAKE-256 non-incremental hashing API. */
typedef struct {
/** Internal state. */
    uint64_t ctx[25];
} shake256_ctx;

void shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen);

#endif // FIPS202_H
