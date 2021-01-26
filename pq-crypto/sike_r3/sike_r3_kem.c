/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: supersingular isogeny key encapsulation (SIKE) protocol
*********************************************************************************************/ 

#include <string.h>
#include "fips202.h"
#include "utils/s2n_safety.h"
#include "tls/s2n_kem.h"
#include "pq-crypto/s2n_pq.h"
#include "pq-crypto/s2n_pq_random.h"
#include "sikep434r3.h"
#include "fpx.h"
#include "api.h"

/* SIKE's key generation
 * Outputs: secret key sk (CRYPTO_SECRETKEYBYTES = MSG_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes)
 *          public key pk (CRYPTO_PUBLICKEYBYTES bytes) */
int sike_p434_r3_crypto_kem_keypair(unsigned char *pk, unsigned char *sk)
{
    ENSURE_POSIX(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);

    // Generate lower portion of secret key sk <- s||SK
    GUARD_AS_POSIX(s2n_get_random_bytes(sk, MSG_BYTES));
    GUARD(random_mod_order_B(sk + MSG_BYTES));

    // Generate public key pk
    EphemeralKeyGeneration_B(sk + MSG_BYTES, pk);

    // Append public key pk to secret key sk
    memcpy(&sk[MSG_BYTES + SECRETKEY_B_BYTES], pk, CRYPTO_PUBLICKEYBYTES);

    return 0;
}

/* SIKE's encapsulation
 * Input:   public key pk         (CRYPTO_PUBLICKEYBYTES bytes)
 * Outputs: shared secret ss      (CRYPTO_BYTES bytes)
 *          ciphertext message ct (CRYPTO_CIPHERTEXTBYTES = CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes) */
int sike_p434_r3_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{
    ENSURE_POSIX(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);

    unsigned char ephemeralsk[SECRETKEY_A_BYTES];
    unsigned char jinvariant[FP2_ENCODED_BYTES];
    unsigned char h[MSG_BYTES];
    unsigned char temp[CRYPTO_CIPHERTEXTBYTES+MSG_BYTES];

    // Generate ephemeralsk <- G(m||pk) mod oA 
    GUARD_AS_POSIX(s2n_get_random_bytes(temp, MSG_BYTES));
    memcpy(&temp[MSG_BYTES], pk, CRYPTO_PUBLICKEYBYTES);
    shake256(ephemeralsk, SECRETKEY_A_BYTES, temp, CRYPTO_PUBLICKEYBYTES+MSG_BYTES);
    ephemeralsk[SECRETKEY_A_BYTES - 1] &= MASK_ALICE;

    // Encrypt
    EphemeralKeyGeneration_A(ephemeralsk, ct);
    EphemeralSecretAgreement_A(ephemeralsk, pk, jinvariant);
    shake256(h, MSG_BYTES, jinvariant, FP2_ENCODED_BYTES);
    for (int i = 0; i < MSG_BYTES; i++) {
        ct[i + CRYPTO_PUBLICKEYBYTES] = temp[i] ^ h[i];
    }

    // Generate shared secret ss <- H(m||ct)
    memcpy(&temp[MSG_BYTES], ct, CRYPTO_CIPHERTEXTBYTES);
    shake256(ss, CRYPTO_BYTES, temp, CRYPTO_CIPHERTEXTBYTES+MSG_BYTES);

    return 0;
}

/* SIKE's decapsulation
 * Input:   secret key sk         (CRYPTO_SECRETKEYBYTES = MSG_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes)
 *          ciphertext message ct (CRYPTO_CIPHERTEXTBYTES = CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes)
 * Outputs: shared secret ss      (CRYPTO_BYTES bytes) */
int sike_p434_r3_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{
    ENSURE_POSIX(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);

    unsigned char ephemeralsk_[SECRETKEY_A_BYTES];
    unsigned char jinvariant_[FP2_ENCODED_BYTES];
    unsigned char h_[MSG_BYTES];
    unsigned char c0_[CRYPTO_PUBLICKEYBYTES];
    unsigned char temp[CRYPTO_CIPHERTEXTBYTES+MSG_BYTES];

    // Decrypt
    EphemeralSecretAgreement_B(sk + MSG_BYTES, ct, jinvariant_);
    shake256(h_, MSG_BYTES, jinvariant_, FP2_ENCODED_BYTES);
    for (int i = 0; i < MSG_BYTES; i++) {
        temp[i] = ct[i + CRYPTO_PUBLICKEYBYTES] ^ h_[i];
    }

    // Generate ephemeralsk_ <- G(m||pk) mod oA
    memcpy(&temp[MSG_BYTES], &sk[MSG_BYTES + SECRETKEY_B_BYTES], CRYPTO_PUBLICKEYBYTES);
    shake256(ephemeralsk_, SECRETKEY_A_BYTES, temp, CRYPTO_PUBLICKEYBYTES+MSG_BYTES);
    ephemeralsk_[SECRETKEY_A_BYTES - 1] &= MASK_ALICE;
    
    // Generate shared secret ss <- H(m||ct), or output ss <- H(s||ct) in case of ct verification failure
    EphemeralKeyGeneration_A(ephemeralsk_, c0_);
    // If selector = 0 then do ss = H(m||ct), else if selector = -1 load s to do ss = H(s||ct)
    int8_t selector = ct_compare(c0_, ct, CRYPTO_PUBLICKEYBYTES);
    ct_cmov(temp, sk, MSG_BYTES, selector);
    memcpy(&temp[MSG_BYTES], ct, CRYPTO_CIPHERTEXTBYTES);
    shake256(ss, CRYPTO_BYTES, temp, CRYPTO_CIPHERTEXTBYTES+MSG_BYTES);

    return 0;
}
