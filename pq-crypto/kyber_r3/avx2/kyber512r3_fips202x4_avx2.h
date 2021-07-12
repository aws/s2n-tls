#pragma once

#include <stddef.h>
#include <stdint.h>
#include <immintrin.h>

#define keccakx4_state S2N_KYBER_512_R3_NAMESPACE(keccakx4_state)
typedef struct {
  __m256i s[25];
} keccakx4_state;

#define shake128x4_absorb S2N_KYBER_512_R3_NAMESPACE(_shake128x4_absorb)
void shake128x4_absorb(keccakx4_state *state,
                       const uint8_t *in0,
                       const uint8_t *in1,
                       const uint8_t *in2,
                       const uint8_t *in3,
                       size_t inlen);

#define shake128x4_squeezeblocks S2N_KYBER_512_R3_NAMESPACE(_shake128x4_squeezeblocks)
void shake128x4_squeezeblocks(uint8_t *out0,
                              uint8_t *out1,
                              uint8_t *out2,
                              uint8_t *out3,
                              size_t nblocks,
                              keccakx4_state *state);

#define shake256x4_absorb S2N_KYBER_512_R3_NAMESPACE(_shake256x4_absorb)
void shake256x4_absorb(keccakx4_state *state,
                       const uint8_t *in0,
                       const uint8_t *in1,
                       const uint8_t *in2,
                       const uint8_t *in3,
                       size_t inlen);

#define shake256x4_squeezeblocks S2N_KYBER_512_R3_NAMESPACE(_shake256x4_squeezeblocks)
void shake256x4_squeezeblocks(uint8_t *out0,
                              uint8_t *out1,
                              uint8_t *out2,
                              uint8_t *out3,
                              size_t nblocks,
                              keccakx4_state *state);

#define shake128x4 S2N_KYBER_512_R3_NAMESPACE(_shake128x4)
void shake128x4(uint8_t *out0,
                uint8_t *out1,
                uint8_t *out2,
                uint8_t *out3,
                size_t outlen,
                const uint8_t *in0,
                const uint8_t *in1,
                const uint8_t *in2,
                const uint8_t *in3,
                size_t inlen);

#define shake256x4 S2N_KYBER_512_R3_NAMESPACE(_shake256x4)
void shake256x4(uint8_t *out0,
                uint8_t *out1,
                uint8_t *out2,
                uint8_t *out3,
                size_t outlen,
                const uint8_t *in0,
                const uint8_t *in1,
                const uint8_t *in2,
                const uint8_t *in3,
                size_t inlen);
