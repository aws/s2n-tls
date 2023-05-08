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

#include <openssl/rc4.h>

#include "crypto/s2n_cipher.h"
#include "crypto/s2n_fips.h"
#include "crypto/s2n_openssl.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"

#if S2N_OPENSSL_VERSION_AT_LEAST(3, 0, 0)
    #include "openssl/provider.h"
DEFINE_POINTER_CLEANUP_FUNC(OSSL_LIB_CTX *, OSSL_LIB_CTX_free);
#endif

static EVP_CIPHER *s2n_rc4_cipher = NULL;

S2N_RESULT s2n_rc4_init()
{
    /* In Openssl-3.0, RC4 is only available from the "legacy" provider,
     * which is not loaded in the default library context.
     */
#if defined(S2N_LIBCRYPTO_SUPPORTS_EVP_RC4) && S2N_OPENSSL_VERSION_AT_LEAST(3, 0, 0)
    DEFER_CLEANUP(OSSL_LIB_CTX *lib_ctx = OSSL_LIB_CTX_new(), OSSL_LIB_CTX_free_pointer);
    RESULT_ENSURE_REF(lib_ctx);
    RESULT_ENSURE_REF(OSSL_PROVIDER_load(lib_ctx, "legacy"));
    s2n_rc4_cipher = EVP_CIPHER_fetch(lib_ctx, "rc4", "provider=legacy");
    RESULT_ENSURE_REF(s2n_rc4_cipher);
#endif
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_rc4_cleanup()
{
#if S2N_OPENSSL_VERSION_AT_LEAST(3, 0, 0)
    EVP_CIPHER_free(s2n_rc4_cipher);
#endif
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_get_rc4_cipher(const EVP_CIPHER **cipher)
{
    RESULT_ENSURE_REF(cipher);
    *cipher = NULL;
    if (s2n_is_in_fips_mode()) {
        *cipher = NULL;
    } else if (s2n_rc4_cipher) {
        *cipher = s2n_rc4_cipher;
#if S2N_LIBCRYPTO_SUPPORTS_EVP_RC4
    } else {
        *cipher = EVP_rc4();
#endif
    }
    RESULT_ENSURE(*cipher, S2N_ERR_UNIMPLEMENTED);
    return S2N_RESULT_OK;
}

static uint8_t s2n_stream_cipher_rc4_available()
{
    const EVP_CIPHER *cipher = NULL;
    if (s2n_result_is_ok(s2n_get_rc4_cipher(&cipher)) && cipher) {
        return 1;
    }
    return 0;
}

static int s2n_stream_cipher_rc4_encrypt(struct s2n_session_key *key, struct s2n_blob *in, struct s2n_blob *out)
{
    POSIX_ENSURE_GTE(out->size, in->size);

    /* len is set by EVP_EncryptUpdate and checked post operation */
    int len = 0;
    POSIX_GUARD_OSSL(EVP_EncryptUpdate(key->evp_cipher_ctx, out->data, &len, in->data, in->size), S2N_ERR_ENCRYPT);

    POSIX_ENSURE((int64_t) len == (int64_t) in->size, S2N_ERR_DECRYPT);

    return 0;
}

static int s2n_stream_cipher_rc4_decrypt(struct s2n_session_key *key, struct s2n_blob *in, struct s2n_blob *out)
{
    POSIX_ENSURE_GTE(out->size, in->size);

    /* len is set by EVP_DecryptUpdate and checked post operation */
    int len = 0;
    POSIX_GUARD_OSSL(EVP_DecryptUpdate(key->evp_cipher_ctx, out->data, &len, in->data, in->size), S2N_ERR_DECRYPT);

    POSIX_ENSURE((int64_t) len == (int64_t) in->size, S2N_ERR_DECRYPT);

    return 0;
}

static int s2n_stream_cipher_rc4_set_encryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    POSIX_ENSURE_EQ(in->size, 16);

    const EVP_CIPHER *evp_rc4 = NULL;
    POSIX_GUARD_RESULT(s2n_get_rc4_cipher(&evp_rc4));

    POSIX_GUARD_OSSL(EVP_EncryptInit_ex(key->evp_cipher_ctx, evp_rc4, NULL, in->data, NULL), S2N_ERR_KEY_INIT);

    return S2N_SUCCESS;
}

static int s2n_stream_cipher_rc4_set_decryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    POSIX_ENSURE_EQ(in->size, 16);

    const EVP_CIPHER *evp_rc4 = NULL;
    POSIX_GUARD_RESULT(s2n_get_rc4_cipher(&evp_rc4));

    POSIX_GUARD_OSSL(EVP_DecryptInit_ex(key->evp_cipher_ctx, evp_rc4, NULL, in->data, NULL), S2N_ERR_KEY_INIT);

    return S2N_SUCCESS;
}

static int s2n_stream_cipher_rc4_init(struct s2n_session_key *key)
{
    s2n_evp_ctx_init(key->evp_cipher_ctx);

    return 0;
}

static int s2n_stream_cipher_rc4_destroy_key(struct s2n_session_key *key)
{
    EVP_CIPHER_CTX_cleanup(key->evp_cipher_ctx);

    return 0;
}

const struct s2n_cipher s2n_rc4 = {
    .type = S2N_STREAM,
    .key_material_size = 16,
    .io.stream = {
            .decrypt = s2n_stream_cipher_rc4_decrypt,
            .encrypt = s2n_stream_cipher_rc4_encrypt },
    .is_available = s2n_stream_cipher_rc4_available,
    .init = s2n_stream_cipher_rc4_init,
    .set_decryption_key = s2n_stream_cipher_rc4_set_decryption_key,
    .set_encryption_key = s2n_stream_cipher_rc4_set_encryption_key,
    .destroy_key = s2n_stream_cipher_rc4_destroy_key,
};
