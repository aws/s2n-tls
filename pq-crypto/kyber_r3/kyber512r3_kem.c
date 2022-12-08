#include <stddef.h>
#include <stdint.h>
#include "kyber512r3_params.h"
#include "kyber512r3_symmetric.h"
#include "kyber512r3_indcpa.h"
#include "kyber512r3_indcpa_avx2.h"
#include "tls/s2n_kem.h"
#include "utils/s2n_safety.h"
#include "pq-crypto/s2n_pq_random.h"
#include "pq-crypto/s2n_pq.h"

S2N_ENSURE_PORTABLE_OPTIMIZATIONS

/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - unsigned char *pk: pointer to output public key
*                (an already allocated array of S2N_KYBER_512_R3_PUBLIC_KEY_BYTES bytes)
*              - unsigned char *sk: pointer to output private key
*                (an already allocated array of S2N_KYBER_512_R3_SECRET_KEY_BYTES bytes)
*
* Returns 0 (success)
**************************************************/
int s2n_kyber_512_r3_crypto_kem_keypair(uint8_t *pk, uint8_t *sk)
{
    POSIX_ENSURE(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);
#if defined(S2N_KYBER512R3_AVX2_BMI2)
    if (s2n_kyber512r3_is_avx2_bmi2_enabled()) {
        POSIX_GUARD(indcpa_keypair_avx2(pk, sk));
    }else
#endif
    {
        POSIX_GUARD(indcpa_keypair(pk, sk));
    }
    
    for(size_t i = 0; i < S2N_KYBER_512_R3_INDCPA_PUBLICKEYBYTES; i++) {
        sk[i + S2N_KYBER_512_R3_INDCPA_SECRETKEYBYTES] = pk[i];
    }
    sha3_256(sk+S2N_KYBER_512_R3_SECRET_KEY_BYTES-2*S2N_KYBER_512_R3_SYMBYTES, pk, S2N_KYBER_512_R3_PUBLIC_KEY_BYTES);
    /* Value z for pseudo-random output on reject */
    POSIX_GUARD_RESULT(s2n_get_random_bytes(sk+S2N_KYBER_512_R3_SECRET_KEY_BYTES-S2N_KYBER_512_R3_SYMBYTES, S2N_KYBER_512_R3_SYMBYTES));
    return S2N_SUCCESS;
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - unsigned char *ct: pointer to output cipher text
*                (an already allocated array of S2N_KYBER_512_R3_CIPHERTEXT_BYTES bytes)
*              - unsigned char *ss: pointer to output shared secret
*                (an already allocated array of S2N_KYBER_512_R3_SHARED_SECRET_BYTES bytes)
*              - const unsigned char *pk: pointer to input public key
*                (an already allocated array of S2N_KYBER_512_R3_PUBLIC_KEY_BYTES bytes)
*
* Returns 0 (success)
**************************************************/
int s2n_kyber_512_r3_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    POSIX_ENSURE(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);
    uint8_t buf[2*S2N_KYBER_512_R3_SYMBYTES];
    /* Will contain key, coins */
    uint8_t kr[2*S2N_KYBER_512_R3_SYMBYTES];

    POSIX_GUARD_RESULT(s2n_get_random_bytes(buf, S2N_KYBER_512_R3_SYMBYTES));
    /* Don't release system RNG output */
    sha3_256(buf, buf, S2N_KYBER_512_R3_SYMBYTES);

    /* Multitarget countermeasure for coins + contributory KEM */
    sha3_256(buf+S2N_KYBER_512_R3_SYMBYTES, pk, S2N_KYBER_512_R3_PUBLIC_KEY_BYTES);
    sha3_512(kr, buf, 2*S2N_KYBER_512_R3_SYMBYTES);

    /* coins are in kr+S2N_KYBER_512_R3_SYMBYTES */
#if defined(S2N_KYBER512R3_AVX2_BMI2)
    if (s2n_kyber512r3_is_avx2_bmi2_enabled()) {
        indcpa_enc_avx2(ct, buf, pk, kr+S2N_KYBER_512_R3_SYMBYTES);
    }else
#endif
    {
        indcpa_enc(ct, buf, pk, kr+S2N_KYBER_512_R3_SYMBYTES);
    }
    
    /* overwrite coins in kr with H(c) */
    sha3_256(kr+S2N_KYBER_512_R3_SYMBYTES, ct, S2N_KYBER_512_R3_CIPHERTEXT_BYTES);
    /* hash concatenation of pre-k and H(c) to k */
    shake256(ss, S2N_KYBER_512_R3_SSBYTES, kr, 2*S2N_KYBER_512_R3_SYMBYTES);
    return S2N_SUCCESS;
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - unsigned char *ss: pointer to output shared secret
*                (an already allocated array of S2N_KYBER_512_R3_SHARED_SECRET_BYTES bytes)
*              - const unsigned char *ct: pointer to input cipher text
*                (an already allocated array of S2N_KYBER_512_R3_CIPHERTEXT_BYTES bytes)
*              - const unsigned char *sk: pointer to input private key
*                (an already allocated array of S2N_KYBER_512_R3_SECRET_KEY_BYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int s2n_kyber_512_r3_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    POSIX_ENSURE(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);
    uint8_t buf[2*S2N_KYBER_512_R3_SYMBYTES];
    /* Will contain key, coins */
    uint8_t kr[2*S2N_KYBER_512_R3_SYMBYTES];
    uint8_t cmp[S2N_KYBER_512_R3_CIPHERTEXT_BYTES];
    const uint8_t *pk = sk+S2N_KYBER_512_R3_INDCPA_SECRETKEYBYTES;

#if defined(S2N_KYBER512R3_AVX2_BMI2)
    if (s2n_kyber512r3_is_avx2_bmi2_enabled()) {
        indcpa_dec_avx2(buf, ct, sk);
    }else
#endif
    {
        indcpa_dec(buf, ct, sk);
    }
    
    /* Multitarget countermeasure for coins + contributory KEM */
    for(size_t i = 0; i < S2N_KYBER_512_R3_SYMBYTES; i++) {
        buf[S2N_KYBER_512_R3_SYMBYTES + i] = sk[S2N_KYBER_512_R3_SECRET_KEY_BYTES - 2 * S2N_KYBER_512_R3_SYMBYTES + i];
    }
    sha3_512(kr, buf, 2*S2N_KYBER_512_R3_SYMBYTES);

    /* coins are in kr+S2N_KYBER_512_R3_SYMBYTES */
#if defined(S2N_KYBER512R3_AVX2_BMI2)
    if (s2n_kyber512r3_is_avx2_bmi2_enabled()) {
        indcpa_enc_avx2(cmp, buf, pk, kr+S2N_KYBER_512_R3_SYMBYTES);
    }else
#endif
    {
        indcpa_enc(cmp, buf, pk, kr+S2N_KYBER_512_R3_SYMBYTES);
    }
    
    /* If ct and cmp are equal (dont_copy = 1), decryption has succeeded and we do NOT overwrite pre-k below.
     * If ct and cmp are not equal (dont_copy = 0), decryption fails and we do overwrite pre-k. */
    int dont_copy = s2n_constant_time_equals(ct, cmp, S2N_KYBER_512_R3_CIPHERTEXT_BYTES);

    /* overwrite coins in kr with H(c) */
    sha3_256(kr+S2N_KYBER_512_R3_SYMBYTES, ct, S2N_KYBER_512_R3_CIPHERTEXT_BYTES);

    /* Overwrite pre-k with z on re-encryption failure */
    POSIX_GUARD(s2n_constant_time_copy_or_dont(kr, sk+S2N_KYBER_512_R3_SECRET_KEY_BYTES-S2N_KYBER_512_R3_SYMBYTES,
            S2N_KYBER_512_R3_SYMBYTES, dont_copy));

    /* hash concatenation of pre-k and H(c) to k */
    shake256(ss, S2N_KYBER_512_R3_SSBYTES, kr, 2*S2N_KYBER_512_R3_SYMBYTES);
    return S2N_SUCCESS;
}
