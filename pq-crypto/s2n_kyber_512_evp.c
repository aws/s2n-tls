/*
* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License").
* You may not use this file except in compliance with the License.
* A copy of the License is located at
*
*  http://aws.amazon.com/apache2.0
*
* or in the "license" file accompanying this file. This file is distributed
* on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
* express or implied. See the License for the specific language governing
* permissions and limitations under the License.
*/

#include "s2n_kyber_512_evp.h"

#include <openssl/evp.h>
#include <stddef.h>

#include "error/s2n_errno.h"
#include "tls/s2n_kem.h"
#include "utils/s2n_safety_macros.h"

#if defined(S2N_LIBCRYPTO_SUPPORTS_KYBER512)
int s2n_kyber_512_evp_generate_keypair(uint8_t *public_key, uint8_t *private_key) {
    EVP_PKEY_CTX *kyber_pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_KYBER512, NULL);
    POSIX_GUARD_PTR(kyber_pkey_ctx);
    POSIX_ENSURE(EVP_PKEY_keygen_init(kyber_pkey_ctx), S2N_FAILURE);

    EVP_PKEY *kyber_pkey = NULL;
    POSIX_ENSURE(EVP_PKEY_keygen(kyber_pkey_ctx, &kyber_pkey), S2N_FAILURE);

    size_t public_key_size = S2N_KYBER_512_R3_PUBLIC_KEY_BYTES;
    size_t private_key_size = S2N_KYBER_512_R3_SECRET_KEY_BYTES;
    POSIX_ENSURE(EVP_PKEY_get_raw_public_key(kyber_pkey, public_key, &public_key_size), S2N_FAILURE);
    POSIX_ENSURE(EVP_PKEY_get_raw_private_key(kyber_pkey, private_key, &private_key_size), S2N_FAILURE);

    return S2N_SUCCESS;
}

int s2n_kyber_512_evp_encapsulate(uint8_t *ciphertext, uint8_t *shared_secret,
                                  const uint8_t *public_key) {
    size_t public_key_size = S2N_KYBER_512_R3_PUBLIC_KEY_BYTES;
    EVP_PKEY *kyber_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_KYBER512, NULL, public_key, public_key_size);
    POSIX_GUARD_PTR(kyber_pkey);

    EVP_PKEY_CTX *kyber_pkey_ctx = EVP_PKEY_CTX_new(kyber_pkey, NULL);
    POSIX_GUARD_PTR(kyber_pkey_ctx);

    size_t cipher_text_size = S2N_KYBER_512_R3_CIPHERTEXT_BYTES;
    size_t shared_secret_size = S2N_KYBER_512_R3_SHARED_SECRET_BYTES;
    POSIX_ENSURE(EVP_PKEY_encapsulate(kyber_pkey_ctx, ciphertext, &cipher_text_size, shared_secret,
                                      &shared_secret_size), S2N_FAILURE);
    return S2N_SUCCESS;
}

int s2n_kyber_512_evp_decapsulate(uint8_t *shared_secret, const uint8_t *ciphertext,
                                  const uint8_t *private_key) {
    size_t private_key_size = S2N_KYBER_512_R3_SECRET_KEY_BYTES;
    EVP_PKEY *kyber_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_KYBER512, NULL, private_key, private_key_size);
    POSIX_GUARD_PTR(kyber_pkey);

    EVP_PKEY_CTX *kyber_pkey_ctx = EVP_PKEY_CTX_new(kyber_pkey, NULL);
    POSIX_GUARD_PTR(kyber_pkey_ctx);

    size_t shared_secret_size = S2N_KYBER_512_R3_SHARED_SECRET_BYTES;
    POSIX_ENSURE(EVP_PKEY_decapsulate(kyber_pkey_ctx, shared_secret, &shared_secret_size, (uint8_t *) ciphertext,
                                      S2N_KYBER_512_R3_CIPHERTEXT_BYTES), S2N_FAILURE);
    return S2N_SUCCESS;
}
#else
int s2n_kyber_512_evp_generate_keypair(OUT uint8_t *public_key, OUT uint8_t *private_key) {
    POSIX_BAIL(S2N_ERR_UNIMPLEMENTED);
}

int s2n_kyber_512_evp_encapsulate(OUT uint8_t *ciphertext, OUT uint8_t *shared_secret,
                                  IN const uint8_t *public_key) {
    POSIX_BAIL(S2N_ERR_UNIMPLEMENTED);
}

int s2n_kyber_512_evp_decapsulate(OUT uint8_t *shared_secret, IN const uint8_t *ciphertext,
                                  IN const uint8_t *private_key) {
    POSIX_BAIL(S2N_ERR_UNIMPLEMENTED);
}
#endif
