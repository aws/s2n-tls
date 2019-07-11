/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "crypto/s2n_cipher.h"
#include "crypto/s2n_fips.h"
#include "crypto/s2n_openssl.h"

#include "tls/s2n_crypto.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

/* Silly accessors, but we avoid using version macro guards in multiple places */
static const EVP_CIPHER *s2n_evp_aes_128_cbc_hmac_sha1(void)
{
    /* Symbols for AES-SHA1-CBC composite ciphers were added in Openssl 1.0.1:
     * See https://www.openssl.org/news/cl101.txt.
     */
    #if S2N_OPENSSL_VERSION_AT_LEAST(1,0,1) && !defined LIBRESSL_VERSION_NUMBER
        return EVP_aes_128_cbc_hmac_sha1();
    #else
        return NULL;
    #endif
}

static const EVP_CIPHER *s2n_evp_aes_256_cbc_hmac_sha1(void)
{
    #if S2N_OPENSSL_VERSION_AT_LEAST(1,0,1) && !defined LIBRESSL_VERSION_NUMBER
        return EVP_aes_256_cbc_hmac_sha1();
    #else
        return NULL;
    #endif
}

static const EVP_CIPHER *s2n_evp_aes_128_cbc_hmac_sha256(void)
{
    /* Symbols for AES-SHA256-CBC composite ciphers were added in Openssl 1.0.2:
     * See https://www.openssl.org/news/cl102.txt. Not supported in any LibreSSL releases.
     */
    #if S2N_OPENSSL_VERSION_AT_LEAST(1,0,2) && !defined LIBRESSL_VERSION_NUMBER
        return EVP_aes_128_cbc_hmac_sha256();
    #else
        return NULL;
    #endif
}

static const EVP_CIPHER *s2n_evp_aes_256_cbc_hmac_sha256(void)
{
    #if S2N_OPENSSL_VERSION_AT_LEAST(1,0,2) && !defined LIBRESSL_VERSION_NUMBER
        return EVP_aes_256_cbc_hmac_sha256();
    #else
        return NULL;
    #endif
}

static uint8_t s2n_composite_cipher_aes128_sha_available(void)
{
    /* EVP_aes_128_cbc_hmac_sha1() returns NULL if the implementations aren't available.
     * See https://github.com/openssl/openssl/blob/master/crypto/evp/e_aes_cbc_hmac_sha1.c#L952
     *
     * Composite ciphers cannot be used when FIPS mode is set. Ciphers require the
     * EVP_CIPH_FLAG_FIPS OpenSSL flag to be set for use when in FIPS mode, and composite
     * ciphers cause OpenSSL errors due to the lack of the flag.
     */
    return (!s2n_is_in_fips_mode() && s2n_evp_aes_128_cbc_hmac_sha1() ? 1 : 0);
}

static uint8_t s2n_composite_cipher_aes256_sha_available(void)
{
    /* Composite ciphers cannot be used when FIPS mode is set. Ciphers require the
     * EVP_CIPH_FLAG_FIPS OpenSSL flag to be set for use when in FIPS mode, and composite
     * ciphers cause OpenSSL errors due to the lack of the flag.
     */
    return (!s2n_is_in_fips_mode() && s2n_evp_aes_256_cbc_hmac_sha1() ? 1 : 0);
}

static uint8_t s2n_composite_cipher_aes128_sha256_available(void)
{
    /* Composite ciphers cannot be used when FIPS mode is set. Ciphers require the
     * EVP_CIPH_FLAG_FIPS OpenSSL flag to be set for use when in FIPS mode, and composite
     * ciphers cause OpenSSL errors due to the lack of the flag.
     */
    return (!s2n_is_in_fips_mode() && s2n_evp_aes_128_cbc_hmac_sha256() ? 1 : 0);
}

static uint8_t s2n_composite_cipher_aes256_sha256_available(void)
{
    /* Composite ciphers cannot be used when FIPS mode is set. Ciphers require the
     * EVP_CIPH_FLAG_FIPS OpenSSL flag to be set for use when in FIPS mode, and composite
     * ciphers cause OpenSSL errors due to the lack of the flag.
     */
    return (!s2n_is_in_fips_mode() && s2n_evp_aes_256_cbc_hmac_sha256() ? 1 : 0);
}

static int s2n_composite_cipher_aes_sha_initial_hmac(struct s2n_session_key *key, uint8_t *sequence_number, uint8_t content_type,
                                                     uint16_t protocol_version, uint16_t payload_and_eiv_len, int *extra)
{
    uint8_t ctrl_buf[S2N_TLS12_AAD_LEN];
    struct s2n_blob ctrl_blob = { .data = ctrl_buf, .size = S2N_TLS12_AAD_LEN };
    struct s2n_stuffer ctrl_stuffer = {0};
    GUARD(s2n_stuffer_init(&ctrl_stuffer, &ctrl_blob));

    GUARD(s2n_stuffer_write_bytes(&ctrl_stuffer, sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));
    GUARD(s2n_stuffer_write_uint8(&ctrl_stuffer, content_type));
    GUARD(s2n_stuffer_write_uint8(&ctrl_stuffer, protocol_version / 10));
    GUARD(s2n_stuffer_write_uint8(&ctrl_stuffer, protocol_version % 10));
    GUARD(s2n_stuffer_write_uint16(&ctrl_stuffer, payload_and_eiv_len));

    /* This will unnecessarily mangle the input buffer, which is fine since it's temporary
     * Return value will be length of digest, padding, and padding length byte.
     * See https://github.com/openssl/openssl/blob/master/crypto/evp/e_aes_cbc_hmac_sha1.c#L814
     * and https://github.com/openssl/openssl/blob/4f0c475719defd7c051964ef9964cc6e5b3a63bf/ssl/record/ssl3_record.c#L743
     */
    int ctrl_ret = EVP_CIPHER_CTX_ctrl(key->evp_cipher_ctx, EVP_CTRL_AEAD_TLS1_AAD, S2N_TLS12_AAD_LEN, ctrl_buf);

    S2N_ERROR_IF(ctrl_ret < 0, S2N_ERR_INITIAL_HMAC);

    *extra = ctrl_ret;
    return 0;
}

static int s2n_composite_cipher_aes_sha_encrypt(struct s2n_session_key *key, struct s2n_blob *iv, struct s2n_blob *in, struct s2n_blob *out)
{
    eq_check(out->size, in->size);

    GUARD_OSSL(EVP_EncryptInit_ex(key->evp_cipher_ctx, NULL, NULL, NULL, iv->data), S2N_ERR_KEY_INIT);
    GUARD_OSSL(EVP_Cipher(key->evp_cipher_ctx, out->data, in->data, in->size), S2N_ERR_ENCRYPT);

    return 0;
}

static int s2n_composite_cipher_aes_sha_decrypt(struct s2n_session_key *key, struct s2n_blob *iv, struct s2n_blob *in, struct s2n_blob *out)
{
    eq_check(out->size, in->size);

    GUARD_OSSL(EVP_DecryptInit_ex(key->evp_cipher_ctx, NULL, NULL, NULL, iv->data), S2N_ERR_KEY_INIT);
    GUARD_OSSL(EVP_Cipher(key->evp_cipher_ctx, out->data, in->data, in->size), S2N_ERR_DECRYPT);

    return 0;
}

static int s2n_composite_cipher_aes_sha_set_mac_write_key(struct s2n_session_key *key, uint8_t *mac_key, uint32_t mac_size)
{
    eq_check(mac_size, SHA_DIGEST_LENGTH);

    EVP_CIPHER_CTX_ctrl(key->evp_cipher_ctx, EVP_CTRL_AEAD_SET_MAC_KEY, mac_size, mac_key);

    return 0;
}

static int s2n_composite_cipher_aes_sha256_set_mac_write_key(struct s2n_session_key *key, uint8_t *mac_key, uint32_t mac_size)
{
    eq_check(mac_size, SHA256_DIGEST_LENGTH);

    EVP_CIPHER_CTX_ctrl(key->evp_cipher_ctx, EVP_CTRL_AEAD_SET_MAC_KEY, mac_size, mac_key);

    return 0;
}


static int s2n_composite_cipher_aes128_sha_set_encryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    eq_check(in->size, 16);

    EVP_CIPHER_CTX_set_padding(key->evp_cipher_ctx, EVP_CIPH_NO_PADDING);
    EVP_EncryptInit_ex(key->evp_cipher_ctx, s2n_evp_aes_128_cbc_hmac_sha1(), NULL, in->data, NULL);

    return 0;
}

static int s2n_composite_cipher_aes128_sha_set_decryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    eq_check(in->size, 16);

    EVP_CIPHER_CTX_set_padding(key->evp_cipher_ctx, EVP_CIPH_NO_PADDING);
    EVP_DecryptInit_ex(key->evp_cipher_ctx, s2n_evp_aes_128_cbc_hmac_sha1(), NULL, in->data, NULL);

    return 0;
}

static int s2n_composite_cipher_aes256_sha_set_encryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    eq_check(in->size, 32);

    EVP_CIPHER_CTX_set_padding(key->evp_cipher_ctx, EVP_CIPH_NO_PADDING);
    EVP_EncryptInit_ex(key->evp_cipher_ctx, s2n_evp_aes_256_cbc_hmac_sha1(), NULL, in->data, NULL);

    return 0;
}

static int s2n_composite_cipher_aes256_sha_set_decryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    eq_check(in->size, 32);

    EVP_CIPHER_CTX_set_padding(key->evp_cipher_ctx, EVP_CIPH_NO_PADDING);
    EVP_DecryptInit_ex(key->evp_cipher_ctx, s2n_evp_aes_256_cbc_hmac_sha1(), NULL, in->data, NULL);

    return 0;
}

static int s2n_composite_cipher_aes128_sha256_set_encryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    eq_check(in->size, 16);

    EVP_CIPHER_CTX_set_padding(key->evp_cipher_ctx, EVP_CIPH_NO_PADDING);
    EVP_EncryptInit_ex(key->evp_cipher_ctx, s2n_evp_aes_128_cbc_hmac_sha256(), NULL, in->data, NULL);

    return 0;
}

static int s2n_composite_cipher_aes128_sha256_set_decryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    eq_check(in->size, 16);

    EVP_CIPHER_CTX_set_padding(key->evp_cipher_ctx, EVP_CIPH_NO_PADDING);
    EVP_DecryptInit_ex(key->evp_cipher_ctx, s2n_evp_aes_128_cbc_hmac_sha256(), NULL, in->data, NULL);

    return 0;
}

static int s2n_composite_cipher_aes256_sha256_set_encryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    eq_check(in->size, 32);

    EVP_CIPHER_CTX_set_padding(key->evp_cipher_ctx, EVP_CIPH_NO_PADDING);
    EVP_EncryptInit_ex(key->evp_cipher_ctx, s2n_evp_aes_256_cbc_hmac_sha256(), NULL, in->data, NULL);

    return 0;
}

static int s2n_composite_cipher_aes256_sha256_set_decryption_key(struct s2n_session_key *key, struct s2n_blob *in)
{
    eq_check(in->size, 32);

    EVP_CIPHER_CTX_set_padding(key->evp_cipher_ctx, EVP_CIPH_NO_PADDING);
    EVP_DecryptInit_ex(key->evp_cipher_ctx, s2n_evp_aes_256_cbc_hmac_sha256(), NULL, in->data, NULL);

    return 0;
}

static int s2n_composite_cipher_aes_sha_init(struct s2n_session_key *key)
{
    s2n_evp_ctx_init(key->evp_cipher_ctx);

    return 0;
}

static int s2n_composite_cipher_aes_sha_destroy_key(struct s2n_session_key *key)
{
    EVP_CIPHER_CTX_cleanup(key->evp_cipher_ctx);

    return 0;
}

struct s2n_cipher s2n_aes128_sha = {
    .key_material_size = 16,
    .type = S2N_COMPOSITE,
    .io.comp = {
                .block_size = 16,
                .record_iv_size = 16,
                .mac_key_size = SHA_DIGEST_LENGTH,
                .decrypt = s2n_composite_cipher_aes_sha_decrypt,
                .encrypt = s2n_composite_cipher_aes_sha_encrypt,
                .set_mac_write_key = s2n_composite_cipher_aes_sha_set_mac_write_key,
                .initial_hmac = s2n_composite_cipher_aes_sha_initial_hmac },
    .is_available = s2n_composite_cipher_aes128_sha_available,
    .init = s2n_composite_cipher_aes_sha_init,
    .set_encryption_key = s2n_composite_cipher_aes128_sha_set_encryption_key,
    .set_decryption_key = s2n_composite_cipher_aes128_sha_set_decryption_key,
    .destroy_key = s2n_composite_cipher_aes_sha_destroy_key,
};

struct s2n_cipher s2n_aes256_sha = {
    .key_material_size = 32,
    .type = S2N_COMPOSITE,
    .io.comp = {
                .block_size = 16,
                .record_iv_size = 16,
                .mac_key_size = SHA_DIGEST_LENGTH,
                .decrypt = s2n_composite_cipher_aes_sha_decrypt,
                .encrypt = s2n_composite_cipher_aes_sha_encrypt,
                .set_mac_write_key = s2n_composite_cipher_aes_sha_set_mac_write_key,
                .initial_hmac = s2n_composite_cipher_aes_sha_initial_hmac },
    .is_available = s2n_composite_cipher_aes256_sha_available,
    .init = s2n_composite_cipher_aes_sha_init,
    .set_encryption_key = s2n_composite_cipher_aes256_sha_set_encryption_key,
    .set_decryption_key = s2n_composite_cipher_aes256_sha_set_decryption_key,
    .destroy_key = s2n_composite_cipher_aes_sha_destroy_key,
};

struct s2n_cipher s2n_aes128_sha256 = {
    .key_material_size = 16,
    .type = S2N_COMPOSITE,
    .io.comp = {
                .block_size = 16,
                .record_iv_size = 16,
                .mac_key_size = SHA256_DIGEST_LENGTH,
                .decrypt = s2n_composite_cipher_aes_sha_decrypt,
                .encrypt = s2n_composite_cipher_aes_sha_encrypt,
                .set_mac_write_key = s2n_composite_cipher_aes_sha256_set_mac_write_key,
                .initial_hmac = s2n_composite_cipher_aes_sha_initial_hmac },
    .is_available = s2n_composite_cipher_aes128_sha256_available,
    .init = s2n_composite_cipher_aes_sha_init,
    .set_encryption_key = s2n_composite_cipher_aes128_sha256_set_encryption_key,
    .set_decryption_key = s2n_composite_cipher_aes128_sha256_set_decryption_key,
    .destroy_key = s2n_composite_cipher_aes_sha_destroy_key,
};

struct s2n_cipher s2n_aes256_sha256 = {
    .key_material_size = 32,
    .type = S2N_COMPOSITE,
    .io.comp = {
                .block_size = 16,
                .record_iv_size = 16,
                .mac_key_size = SHA256_DIGEST_LENGTH,
                .decrypt = s2n_composite_cipher_aes_sha_decrypt,
                .encrypt = s2n_composite_cipher_aes_sha_encrypt,
                .set_mac_write_key = s2n_composite_cipher_aes_sha256_set_mac_write_key,
                .initial_hmac = s2n_composite_cipher_aes_sha_initial_hmac },
    .is_available = s2n_composite_cipher_aes256_sha256_available,
    .init = s2n_composite_cipher_aes_sha_init,
    .set_encryption_key = s2n_composite_cipher_aes256_sha256_set_encryption_key,
    .set_decryption_key = s2n_composite_cipher_aes256_sha256_set_decryption_key,
    .destroy_key = s2n_composite_cipher_aes_sha_destroy_key,
};
