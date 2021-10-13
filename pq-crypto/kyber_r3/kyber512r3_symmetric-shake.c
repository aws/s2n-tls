#include "kyber512r3_params.h"
#include "kyber512r3_fips202.h"
#include "kyber512r3_symmetric.h"
#include <stdlib.h>

/*************************************************
* Name:        kyber_shake128_absorb
*
* Description: Absorb step of the SHAKE128 specialized for the Kyber context.

* Arguments:   - keccak_state *s:           pointer to (uninitialized) output Keccak state
*              - const uint8_t *input:      pointer to S2N_KYBER_512_R3_SYMBYTES input to be absorbed into s
*              - uint8_t i                  additional byte of input
*              - uint8_t j                  additional byte of input
**************************************************/
void kyber_shake128_absorb(keccak_state *s, const uint8_t *input, uint8_t x, uint8_t y) {
    size_t i;
    uint8_t extseed[S2N_KYBER_512_R3_SYMBYTES + 2];

    for (i = 0; i < S2N_KYBER_512_R3_SYMBYTES; i++) {
        extseed[i] = input[i];
    }
    extseed[i++] = x;
    extseed[i]   = y;
    shake128_absorb(s, extseed, S2N_KYBER_512_R3_SYMBYTES + 2);
}

/*************************************************
* Name:        shake256_prf
*
* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SHAKE256 output
*
* Arguments:   - uint8_t *output:      pointer to output
*              - size_t outlen:        number of requested output bytes
*              - const uint8_t * key:  pointer to the key (of length S2N_KYBER_512_R3_SYMBYTES)
*              - uint8_t nonce:  single-byte nonce (public PRF input)
**************************************************/
void shake256_prf(uint8_t *output, size_t outlen, const uint8_t *key, uint8_t nonce) {
    uint8_t extkey[S2N_KYBER_512_R3_SYMBYTES + 1];
    size_t i;

    for (i = 0; i < S2N_KYBER_512_R3_SYMBYTES; i++) {
        extkey[i] = key[i];
    }
    extkey[i] = nonce;

    shake256(output, outlen, extkey, S2N_KYBER_512_R3_SYMBYTES + 1);
}
