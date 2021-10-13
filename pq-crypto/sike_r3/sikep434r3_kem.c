/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: supersingular isogeny key encapsulation (SIKE) protocol
*********************************************************************************************/ 

#include <string.h>
#include "sikep434r3.h"
#include "sikep434r3_fips202.h"
#include "utils/s2n_safety.h"
#include "tls/s2n_kem.h"
#include "pq-crypto/s2n_pq.h"
#include "pq-crypto/s2n_pq_random.h"
#include "sikep434r3_fpx.h"
#include "sikep434r3_api.h"

/* SIKE's key generation
 * Outputs: secret key sk (S2N_SIKE_P434_R3_SECRET_KEY_BYTES = S2N_SIKE_P434_R3_MSG_BYTES + S2N_SIKE_P434_R3_SECRETKEY_B_BYTES + S2N_SIKE_P434_R3_PUBLIC_KEY_BYTES bytes)
 *          public key pk (S2N_SIKE_P434_R3_PUBLIC_KEY_BYTES bytes) */
int s2n_sike_p434_r3_crypto_kem_keypair(unsigned char *pk, unsigned char *sk)
{
    POSIX_ENSURE(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);

    /* Generate lower portion of secret key sk <- s||SK */
    POSIX_GUARD_RESULT(s2n_get_random_bytes(sk, S2N_SIKE_P434_R3_MSG_BYTES));
    POSIX_GUARD(random_mod_order_B(sk + S2N_SIKE_P434_R3_MSG_BYTES));

    /* Generate public key pk */
    EphemeralKeyGeneration_B(sk + S2N_SIKE_P434_R3_MSG_BYTES, pk);

    /* Append public key pk to secret key sk */
    memcpy(&sk[S2N_SIKE_P434_R3_MSG_BYTES + S2N_SIKE_P434_R3_SECRETKEY_B_BYTES], pk, S2N_SIKE_P434_R3_PUBLIC_KEY_BYTES);

    return S2N_SUCCESS;
}

/* SIKE's encapsulation
 * Input:   public key pk         (S2N_SIKE_P434_R3_PUBLIC_KEY_BYTES bytes)
 * Outputs: shared secret ss      (S2N_SIKE_P434_R3_SHARED_SECRET_BYTES bytes)
 *          ciphertext message ct (S2N_SIKE_P434_R3_CIPHERTEXT_BYTES = S2N_SIKE_P434_R3_PUBLIC_KEY_BYTES + S2N_SIKE_P434_R3_MSG_BYTES bytes) */
int s2n_sike_p434_r3_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{
    POSIX_ENSURE(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);

    unsigned char ephemeralsk[S2N_SIKE_P434_R3_SECRETKEY_A_BYTES];
    unsigned char jinvariant[S2N_SIKE_P434_R3_FP2_ENCODED_BYTES];
    unsigned char h[S2N_SIKE_P434_R3_MSG_BYTES];
    unsigned char temp[S2N_SIKE_P434_R3_CIPHERTEXT_BYTES+S2N_SIKE_P434_R3_MSG_BYTES];

    /* Generate ephemeralsk <- G(m||pk) mod oA */
    POSIX_GUARD_RESULT(s2n_get_random_bytes(temp, S2N_SIKE_P434_R3_MSG_BYTES));
    memcpy(&temp[S2N_SIKE_P434_R3_MSG_BYTES], pk, S2N_SIKE_P434_R3_PUBLIC_KEY_BYTES);
    shake256(ephemeralsk, S2N_SIKE_P434_R3_SECRETKEY_A_BYTES, temp, S2N_SIKE_P434_R3_PUBLIC_KEY_BYTES+S2N_SIKE_P434_R3_MSG_BYTES);
    ephemeralsk[S2N_SIKE_P434_R3_SECRETKEY_A_BYTES - 1] &= S2N_SIKE_P434_R3_MASK_ALICE;

    /* Encrypt */
    EphemeralKeyGeneration_A(ephemeralsk, ct);
    EphemeralSecretAgreement_A(ephemeralsk, pk, jinvariant);
    shake256(h, S2N_SIKE_P434_R3_MSG_BYTES, jinvariant, S2N_SIKE_P434_R3_FP2_ENCODED_BYTES);
    for (int i = 0; i < S2N_SIKE_P434_R3_MSG_BYTES; i++) {
        ct[i + S2N_SIKE_P434_R3_PUBLIC_KEY_BYTES] = temp[i] ^ h[i];
    }

    /* Generate shared secret ss <- H(m||ct) */
    memcpy(&temp[S2N_SIKE_P434_R3_MSG_BYTES], ct, S2N_SIKE_P434_R3_CIPHERTEXT_BYTES);
    shake256(ss, S2N_SIKE_P434_R3_SHARED_SECRET_BYTES, temp, S2N_SIKE_P434_R3_CIPHERTEXT_BYTES+S2N_SIKE_P434_R3_MSG_BYTES);

    return S2N_SUCCESS;
}

/* SIKE's decapsulation
 * Input:   secret key sk         (S2N_SIKE_P434_R3_SECRET_KEY_BYTES = S2N_SIKE_P434_R3_MSG_BYTES + S2N_SIKE_P434_R3_SECRETKEY_B_BYTES + S2N_SIKE_P434_R3_PUBLIC_KEY_BYTES bytes)
 *          ciphertext message ct (S2N_SIKE_P434_R3_CIPHERTEXT_BYTES = S2N_SIKE_P434_R3_PUBLIC_KEY_BYTES + S2N_SIKE_P434_R3_MSG_BYTES bytes)
 * Outputs: shared secret ss      (S2N_SIKE_P434_R3_SHARED_SECRET_BYTES bytes) */
int s2n_sike_p434_r3_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{
    POSIX_ENSURE(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);

    unsigned char ephemeralsk_[S2N_SIKE_P434_R3_SECRETKEY_A_BYTES];
    unsigned char jinvariant_[S2N_SIKE_P434_R3_FP2_ENCODED_BYTES];
    unsigned char h_[S2N_SIKE_P434_R3_MSG_BYTES];
    unsigned char c0_[S2N_SIKE_P434_R3_PUBLIC_KEY_BYTES];
    unsigned char temp[S2N_SIKE_P434_R3_CIPHERTEXT_BYTES+S2N_SIKE_P434_R3_MSG_BYTES];

    /* Decrypt */
    EphemeralSecretAgreement_B(sk + S2N_SIKE_P434_R3_MSG_BYTES, ct, jinvariant_);
    shake256(h_, S2N_SIKE_P434_R3_MSG_BYTES, jinvariant_, S2N_SIKE_P434_R3_FP2_ENCODED_BYTES);
    for (int i = 0; i < S2N_SIKE_P434_R3_MSG_BYTES; i++) {
        temp[i] = ct[i + S2N_SIKE_P434_R3_PUBLIC_KEY_BYTES] ^ h_[i];
    }

    /* Generate ephemeralsk_ <- G(m||pk) mod oA */
    memcpy(&temp[S2N_SIKE_P434_R3_MSG_BYTES], &sk[S2N_SIKE_P434_R3_MSG_BYTES + S2N_SIKE_P434_R3_SECRETKEY_B_BYTES], S2N_SIKE_P434_R3_PUBLIC_KEY_BYTES);
    shake256(ephemeralsk_, S2N_SIKE_P434_R3_SECRETKEY_A_BYTES, temp, S2N_SIKE_P434_R3_PUBLIC_KEY_BYTES+S2N_SIKE_P434_R3_MSG_BYTES);
    ephemeralsk_[S2N_SIKE_P434_R3_SECRETKEY_A_BYTES - 1] &= S2N_SIKE_P434_R3_MASK_ALICE;

    /* Generate shared secret ss <- H(m||ct), or output ss <- H(s||ct) in case of ct verification failure */
    EphemeralKeyGeneration_A(ephemeralsk_, c0_);

    /* Verify ciphertext.
     * If c0_ and ct are NOT equal, decaps failed and we overwrite the shared secret
     * with pseudorandom noise (ss = H(s||ct)) by performing the copy (dont_copy = false).
     *
     * If c0_ and ct are equal, then decaps succeeded and we skip the overwrite and output
     * the actual shared secret: ss = H(m||ct) (dont_copy = true). */
    bool dont_copy = s2n_constant_time_equals(c0_, ct, S2N_SIKE_P434_R3_PUBLIC_KEY_BYTES);
    POSIX_GUARD(s2n_constant_time_copy_or_dont(temp, sk, S2N_SIKE_P434_R3_MSG_BYTES, dont_copy));
    memcpy(&temp[S2N_SIKE_P434_R3_MSG_BYTES], ct, S2N_SIKE_P434_R3_CIPHERTEXT_BYTES);
    shake256(ss, S2N_SIKE_P434_R3_SHARED_SECRET_BYTES, temp, S2N_SIKE_P434_R3_CIPHERTEXT_BYTES+S2N_SIKE_P434_R3_MSG_BYTES);

    return S2N_SUCCESS;
}
