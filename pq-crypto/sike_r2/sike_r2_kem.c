/********************************************************************************************
* SIDH: an efficient supersingular isogeny cryptography library
*
* Abstract: supersingular isogeny key encapsulation (SIKE) protocol
*********************************************************************************************/

#include <string.h>
#include "../s2n_pq_random.h"
#include "fips202.h"
#include "utils/s2n_safety.h"
#include "tls/s2n_kem.h"
#include "pq-crypto/s2n_pq.h"

int SIKE_P434_r2_crypto_kem_keypair(unsigned char *pk, unsigned char *sk) {
    // SIKE's key generation
    // Outputs: secret key sk (CRYPTO_SECRETKEYBYTES = MSG_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes)
    //          public key pk (CRYPTO_PUBLICKEYBYTES bytes)
    POSIX_ENSURE(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);

    digit_t _sk[(SECRETKEY_B_BYTES / sizeof(digit_t)) + 1];

    // Generate lower portion of secret key sk <- s||SK
    POSIX_GUARD_RESULT(s2n_get_random_bytes(sk, MSG_BYTES));
    POSIX_GUARD(random_mod_order_B((unsigned char *)_sk));

    // Generate public key pk
    EphemeralKeyGeneration_B(_sk, pk);

    memcpy(sk + MSG_BYTES, _sk, SECRETKEY_B_BYTES);

    // Append public key pk to secret key sk
    memcpy(&sk[MSG_BYTES + SECRETKEY_B_BYTES], pk, CRYPTO_PUBLICKEYBYTES);

    return 0;
}

int SIKE_P434_r2_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk) {
    // SIKE's encapsulation
    // Input:   public key pk         (CRYPTO_PUBLICKEYBYTES bytes)
    // Outputs: shared secret ss      (CRYPTO_BYTES bytes)
    //          ciphertext message ct (CRYPTO_CIPHERTEXTBYTES = CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes)
    POSIX_ENSURE(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);

    union {
        unsigned char b[SECRETKEY_A_BYTES];
        digit_t       d[SECRETKEY_A_BYTES/sizeof(digit_t)];
    } ephemeralsk;
    unsigned char jinvariant[FP2_ENCODED_BYTES];
    unsigned char h[MSG_BYTES];
    unsigned char temp[CRYPTO_CIPHERTEXTBYTES + MSG_BYTES];

    // Generate ephemeralsk <- G(m||pk) mod oA
    POSIX_GUARD_RESULT(s2n_get_random_bytes(temp, MSG_BYTES));
    memcpy(&temp[MSG_BYTES], pk, CRYPTO_PUBLICKEYBYTES);
    shake256(ephemeralsk.b, SECRETKEY_A_BYTES, temp, CRYPTO_PUBLICKEYBYTES + MSG_BYTES);

    /* ephemeralsk is a union; the memory set here through .b will get accessed through the .d member later */
    /* cppcheck-suppress unreadVariable */
    /* cppcheck-suppress unmatchedSuppression */
    ephemeralsk.b[SECRETKEY_A_BYTES - 1] &= MASK_ALICE;

    // Encrypt
    EphemeralKeyGeneration_A(ephemeralsk.d, ct);
    EphemeralSecretAgreement_A(ephemeralsk.d, pk, jinvariant);
    shake256(h, MSG_BYTES, jinvariant, FP2_ENCODED_BYTES);
    for (int i = 0; i < MSG_BYTES; i++) {
        ct[i + CRYPTO_PUBLICKEYBYTES] = temp[i] ^ h[i];
    }
    // Generate shared secret ss <- H(m||ct)
    memcpy(&temp[MSG_BYTES], ct, CRYPTO_CIPHERTEXTBYTES);
    shake256(ss, CRYPTO_BYTES, temp, CRYPTO_CIPHERTEXTBYTES + MSG_BYTES);

    return 0;
}

int SIKE_P434_r2_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk) {
    // SIKE's decapsulation
    // Input:   secret key sk         (CRYPTO_SECRETKEYBYTES = MSG_BYTES + SECRETKEY_B_BYTES + CRYPTO_PUBLICKEYBYTES bytes)
    //          ciphertext message ct (CRYPTO_CIPHERTEXTBYTES = CRYPTO_PUBLICKEYBYTES + MSG_BYTES bytes)
    // Outputs: shared secret ss      (CRYPTO_BYTES bytes)
    POSIX_ENSURE(s2n_pq_is_enabled(), S2N_ERR_PQ_DISABLED);

    union {
        unsigned char b[SECRETKEY_A_BYTES];
        digit_t       d[SECRETKEY_A_BYTES/sizeof(digit_t)];
    } ephemeralsk_;
    unsigned char jinvariant_[FP2_ENCODED_BYTES];
    unsigned char h_[MSG_BYTES];
    unsigned char c0_[CRYPTO_PUBLICKEYBYTES];
    unsigned char temp[CRYPTO_CIPHERTEXTBYTES + MSG_BYTES];

    digit_t _sk[(SECRETKEY_B_BYTES / sizeof(digit_t)) + 1];
    memcpy(_sk, sk + MSG_BYTES, SECRETKEY_B_BYTES);

    // Decrypt
    EphemeralSecretAgreement_B(_sk, ct, jinvariant_);
    shake256(h_, MSG_BYTES, jinvariant_, FP2_ENCODED_BYTES);
    for (int i = 0; i < MSG_BYTES; i++) {
        temp[i] = ct[i + CRYPTO_PUBLICKEYBYTES] ^ h_[i];
    }
    // Generate ephemeralsk_ <- G(m||pk) mod oA
    memcpy(&temp[MSG_BYTES], &sk[MSG_BYTES + SECRETKEY_B_BYTES], CRYPTO_PUBLICKEYBYTES);
    shake256(ephemeralsk_.b, SECRETKEY_A_BYTES, temp, CRYPTO_PUBLICKEYBYTES + MSG_BYTES);

    /* ephemeralsk_ is a union; the memory set here through .b will get accessed through the .d member later */
    /* cppcheck-suppress unreadVariable */
    /* cppcheck-suppress uninitvar */
    /* cppcheck-suppress unmatchedSuppression */
    ephemeralsk_.b[SECRETKEY_A_BYTES - 1] &= MASK_ALICE;

    // Generate shared secret ss <- H(m||ct) or output ss <- H(s||ct)
    EphemeralKeyGeneration_A(ephemeralsk_.d, c0_);

    // Note: This step deviates from the NIST supplied code by using constant time operations.
    // We only want to copy the data if c0_ and ct are different
    bool dont_copy = s2n_constant_time_equals(c0_, ct, CRYPTO_PUBLICKEYBYTES);
    // The last argument to s2n_constant_time_copy_or_dont is dont and thus prevents the copy when non-zero/true
    s2n_constant_time_copy_or_dont(temp, sk, MSG_BYTES, dont_copy);

    memcpy(&temp[MSG_BYTES], ct, CRYPTO_CIPHERTEXTBYTES);
    shake256(ss, CRYPTO_BYTES, temp, CRYPTO_CIPHERTEXTBYTES + MSG_BYTES);

    return 0;
}
