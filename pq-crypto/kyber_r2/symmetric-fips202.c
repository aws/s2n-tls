#include "fips202.h"
#include "symmetric.h"

#include <stdlib.h>
/*************************************************
* Name:        kyber_shake128_absorb
*
* Description: Absorb step of the SHAKE128 specialized for the Kyber context.

* Arguments:   - keccak_state *s:           pointer to (uninitialized) output Keccak state
*              - const uint8_t *input:      pointer to KYBER_SYMBYTES input to be absorbed into s
*              - uint8_t i                  additional byte of input
*              - uint8_t j                  additional byte of input
**************************************************/
void PQCLEAN_KYBER512_CLEAN_kyber_shake128_absorb(keccak_state *s, const uint8_t *input, uint8_t x, uint8_t y) {
    size_t i;
    uint8_t extseed[KYBER_SYMBYTES + 2];

    for (i = 0; i < KYBER_SYMBYTES; i++) {
        extseed[i] = input[i];
    }
    extseed[i++] = x;
    extseed[i]   = y;
    shake128_absorb(s, extseed, KYBER_SYMBYTES + 2);
}

/*************************************************
* Name:        kyber_shake128_squeezeblocks
*
* Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of SHAKE128_RATE bytes each.
*              Modifies the state. Can be called multiple times to keep squeezing,
*              i.e., is incremental.
*
* Arguments:   - uint8_t *output:            pointer to output blocks
*              - unsigned long long nblocks: number of blocks to be squeezed (written to output)
*              - keccak_state *s:            pointer to in/output Keccak state
**************************************************/
void PQCLEAN_KYBER512_CLEAN_kyber_shake128_squeezeblocks(uint8_t *output, size_t nblocks, keccak_state *s) {
    shake128_squeezeblocks(output, nblocks, s);
}

/*************************************************
* Name:        shake256_prf
*
* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SHAKE256 output
*
* Arguments:   - uint8_t *output:      pointer to output
*              - size_t outlen:        number of requested output bytes
*              - const uint8_t * key:  pointer to the key (of length KYBER_SYMBYTES)
*              - const uint8_t nonce:  single-byte nonce (public PRF input)
**************************************************/
void PQCLEAN_KYBER512_CLEAN_shake256_prf(uint8_t *output, size_t outlen, const uint8_t *key, uint8_t nonce) {
    uint8_t extkey[KYBER_SYMBYTES + 1];
    size_t i;

    for (i = 0; i < KYBER_SYMBYTES; i++) {
        extkey[i] = key[i];
    }
    extkey[i] = nonce;

    shake256(output, outlen, extkey, KYBER_SYMBYTES + 1);
}
