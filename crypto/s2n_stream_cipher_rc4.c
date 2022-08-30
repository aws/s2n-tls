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

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

static uint8_t s2n_stream_cipher_rc4_available()
{
#ifdef S2N_LIBCRYPTO_SUPPORTS_EVP_RC4
    if (s2n_is_in_fips_mode()) {
        return 0;
    } else {
        return (EVP_rc4() ? 1 : 0);
    }
#else
    return 0;
#endif /* S2N_LIBCRYPTO_SUPPORTS_EVP_RC4 */
}

#ifdef S2N_LIBCRYPTO_SUPPORTS_EVP_RC4
static int s2n_stream_cipher_rc4_encrypt(struct s2n_session_key *key, struct s2n_blob *in, struct s2n_blob *out)
{
    POSIX_ENSURE_GTE(out->size, in->size);

    /* len is set by EVP_EncryptUpdate and checked post operation */
    int len = 0;
    POSIX_GUARD_OSSL(EVP_EncryptUpdate(key->evp_cipher_ctx, out->data, &len, in->data, in->size), S2N_ERR_ENCRYPT);

    S2N_ERROR_IF(len != in->size, S2N_ERR_ENCRYPT);

    return 0;
}

static int s2n_stream_cipher_rc4_decrypt(struct s2n_session_key *key, struct s2n_blob *in, struct s2n_blob *out)
{
    POSIX_ENSURE_GTE(out->size, in->size);

    /* len is set by EVP_DecryptUpdate and checked post operation */
    int len = 0;
    POSIX_GUARD_OSSL(EVP_DecryptUpdate(key->evp_cipher_ctx, out->data, &len, in->data, in->size), S2N_ERR_DECRYPT);

    S2N_ERROR_IF(len != in->size, S2N_ERR_DECRYPT);

    return 0;
}

static int s2n_stream_cipher_rc4_set_encryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    POSIX_ENSURE_EQ(in->size, 16);
    POSIX_GUARD_OSSL(EVP_EncryptInit_ex(key->evp_cipher_ctx, EVP_rc4(), NULL, in->data, NULL), S2N_ERR_KEY_INIT);

    return 0;
}

static int s2n_stream_cipher_rc4_set_decryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    POSIX_ENSURE_EQ(in->size, 16);
    POSIX_GUARD_OSSL(EVP_DecryptInit_ex(key->evp_cipher_ctx, EVP_rc4(), NULL, in->data, NULL), S2N_ERR_KEY_INIT);

    return 0;
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
#else

static int s2n_stream_cipher_rc4_encrypt(struct s2n_session_key *key, struct s2n_blob *in, struct s2n_blob *out)
{
    POSIX_BAIL(S2N_ERR_UNIMPLEMENTED);
}

static int s2n_stream_cipher_rc4_decrypt(struct s2n_session_key *key, struct s2n_blob *in, struct s2n_blob *out)
{
    POSIX_BAIL(S2N_ERR_UNIMPLEMENTED);
}

static int s2n_stream_cipher_rc4_set_encryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    POSIX_BAIL(S2N_ERR_UNIMPLEMENTED);
}

static int s2n_stream_cipher_rc4_set_decryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    POSIX_BAIL(S2N_ERR_UNIMPLEMENTED);
}

static int s2n_stream_cipher_rc4_init(struct s2n_session_key *key)
{
    POSIX_BAIL(S2N_ERR_UNIMPLEMENTED);
}

static int s2n_stream_cipher_rc4_destroy_key(struct s2n_session_key *key)
{
    POSIX_BAIL(S2N_ERR_UNIMPLEMENTED);
}

#endif /* S2N_LIBCRYPTO_SUPPORTS_EVP_RC4 */

struct s2n_cipher s2n_rc4 = {
    .type = S2N_STREAM,
    .key_material_size = 16,
    .io.stream = {
                  .decrypt = s2n_stream_cipher_rc4_decrypt,
                  .encrypt = s2n_stream_cipher_rc4_encrypt},
    .is_available = s2n_stream_cipher_rc4_available,
    .init = s2n_stream_cipher_rc4_init,
    .set_decryption_key = s2n_stream_cipher_rc4_set_decryption_key,
    .set_encryption_key = s2n_stream_cipher_rc4_set_encryption_key,
    .destroy_key = s2n_stream_cipher_rc4_destroy_key,
};
