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

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

S2N_RESULT helper_generate_test_data(struct s2n_blob *test_data)
{
    struct s2n_stuffer test_data_stuffer = { 0 };
    EXPECT_SUCCESS(s2n_stuffer_init(&test_data_stuffer, test_data));
    for (int i = 0; i < S2N_MAX_KEY_BLOCK_LEN; i++) {
        RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(&test_data_stuffer, i));
    }
    return S2N_RESULT_OK;
}

S2N_RESULT helper_validate_key_material(struct s2n_key_material *key_material, struct s2n_blob *test_data_blob,
        uint8_t mac_size, uint8_t key_size, uint8_t iv_size)
{
    /* confirm that the data is copied to key_material */
    RESULT_ENSURE_EQ(memcmp(test_data_blob->data, key_material->key_block, test_data_blob->size), 0);

    uint8_t *test_ptr = test_data_blob->data;
    RESULT_ENSURE_REF(test_ptr);
    /* client MAC */
    RESULT_ENSURE_EQ(memcmp(test_ptr, key_material->client_mac.data, mac_size), 0);
    test_ptr += mac_size;
    RESULT_ENSURE_REF(test_ptr);
    /* server MAC */
    RESULT_ENSURE_EQ(memcmp(test_ptr, key_material->server_mac.data, mac_size), 0);
    test_ptr += mac_size;
    RESULT_ENSURE_REF(test_ptr);

    /* client KEY */
    RESULT_ENSURE_EQ(memcmp(test_ptr, key_material->client_key.data, key_size), 0);
    test_ptr += key_size;
    RESULT_ENSURE_REF(test_ptr);
    /* server KEY */
    RESULT_ENSURE_EQ(memcmp(test_ptr, key_material->server_key.data, key_size), 0);
    test_ptr += key_size;
    RESULT_ENSURE_REF(test_ptr);

    /* client IV */
    RESULT_ENSURE_EQ(memcmp(test_ptr, key_material->client_iv.data, iv_size), 0);
    test_ptr += iv_size;
    RESULT_ENSURE_REF(test_ptr);

    /* server IV */
    RESULT_ENSURE_EQ(memcmp(test_ptr, key_material->server_iv.data, iv_size), 0);

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* prepare test data */
    uint8_t test_data[S2N_MAX_KEY_BLOCK_LEN] = { 0 };
    struct s2n_blob test_data_blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&test_data_blob, test_data, sizeof(test_data)));
    EXPECT_OK(helper_generate_test_data(&test_data_blob));

    /* fuzz s2n_key_material_init with different mac, key, iv sizes */
    {
        for (uint8_t mac_size = 0; mac_size < 16; mac_size++) {
            for (uint8_t key_size = 0; key_size < 32; key_size++) {
                for (uint8_t iv_size = 0; iv_size < 32; iv_size++) {
                    EXPECT_TRUE((mac_size * 2 + key_size * 2 + iv_size * 2 <= S2N_MAX_KEY_BLOCK_LEN));

                    DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                            s2n_connection_ptr_free);
                    conn->actual_protocol_version = S2N_TLS10;

                    /* test varying size of mac, key and iv */
                    struct s2n_cipher temp_cipher = {
                        .type = S2N_COMPOSITE,
                        .key_material_size = key_size,
                        .io.comp = {
                                /* interpreted as iv size for composite ciphers.. which makes
                                 * it easy for testing */
                                .block_size = iv_size,
                                .mac_key_size = mac_size,
                        },
                    };
                    struct s2n_record_algorithm temp_record_alg = {
                        .cipher = &temp_cipher,
                    };
                    struct s2n_cipher_suite temp_cipher_suite = {
                        .record_alg = &temp_record_alg,
                    };
                    conn->secure->cipher_suite = &temp_cipher_suite;

                    /* set the record_alg on connection and init key_material */
                    struct s2n_key_material key_material = { 0 };
                    EXPECT_OK(s2n_key_material_init(&key_material, conn));

                    /* assert that sizes match */
                    EXPECT_EQUAL(key_material.client_mac.size, mac_size);
                    EXPECT_EQUAL(key_material.client_key.size, key_size);
                    EXPECT_EQUAL(key_material.client_iv.size, iv_size);
                    EXPECT_EQUAL(key_material.server_mac.size, mac_size);
                    EXPECT_EQUAL(key_material.server_key.size, key_size);
                    EXPECT_EQUAL(key_material.server_iv.size, iv_size);

                    /* copy data into key_material and validate key_material matches test_data */
                    POSIX_CHECKED_MEMCPY(key_material.key_block, test_data, s2n_array_len(key_material.key_block));
                    EXPECT_OK(helper_validate_key_material(&key_material, &test_data_blob, mac_size, key_size, iv_size));
                }
            }
        }
    }

    /* AEAD cipher
     * assert same IV size regardless of protocol version
     */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
        EXPECT_EQUAL(conn->secure->cipher_suite->record_alg->cipher->type, S2N_AEAD);

        struct s2n_key_material key_material = { 0 };

        uint32_t mac = 0;
        uint32_t key = S2N_TLS_AES_128_GCM_KEY_LEN;
        uint32_t iv = S2N_TLS13_FIXED_IV_LEN;

        /* assert IV of size == 0 if protocol version > S2N_TLS10 */
        conn->actual_protocol_version = S2N_TLS10;
        EXPECT_OK(s2n_key_material_init(&key_material, conn));

        EXPECT_EQUAL(key_material.client_mac.size, mac);
        EXPECT_EQUAL(key_material.client_key.size, key);
        EXPECT_EQUAL(key_material.client_iv.size, iv);
        EXPECT_EQUAL(key_material.server_mac.size, mac);
        EXPECT_EQUAL(key_material.server_key.size, key);
        EXPECT_EQUAL(key_material.server_iv.size, iv);

        /* assert IV of size == 0 if protocol version > S2N_TLS10 */
        conn->actual_protocol_version = S2N_TLS11;
        EXPECT_OK(s2n_key_material_init(&key_material, conn));
        /* assert same IV size regardless of protocol version */
        EXPECT_EQUAL(key_material.client_mac.size, mac);
        EXPECT_EQUAL(key_material.client_key.size, key);
        EXPECT_EQUAL(key_material.client_iv.size, iv);
        EXPECT_EQUAL(key_material.server_mac.size, mac);
        EXPECT_EQUAL(key_material.server_key.size, key);
        EXPECT_EQUAL(key_material.server_iv.size, iv);
    }

    /* NON AEAD cipher
     * IV size depends on protocol version
     */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);

        conn->secure->cipher_suite = &s2n_rsa_with_aes_128_cbc_sha256;
        const struct s2n_cipher *cipher = conn->secure->cipher_suite->record_alg->cipher;
        /* assert that the cipher chosen is non AEAD */
        EXPECT_TRUE(
                cipher->type == S2N_COMPOSITE || cipher->type == S2N_CBC);

        struct s2n_key_material key_material = { 0 };

        uint32_t mac = SHA256_DIGEST_LENGTH;
        uint32_t key = S2N_TLS_AES_128_GCM_KEY_LEN;
        uint32_t iv = 16;

        /* assert IV of non 0 if protocol version <= S2N_TLS10 */
        conn->actual_protocol_version = S2N_TLS10;
        EXPECT_OK(s2n_key_material_init(&key_material, conn));

        EXPECT_EQUAL(key_material.client_mac.size, mac);
        EXPECT_EQUAL(key_material.client_key.size, key);
        EXPECT_EQUAL(key_material.client_iv.size, iv);
        EXPECT_EQUAL(key_material.server_mac.size, mac);
        EXPECT_EQUAL(key_material.server_key.size, key);
        EXPECT_EQUAL(key_material.server_iv.size, iv);

        /* assert IV of size == 0 if protocol version > S2N_TLS10 */
        conn->actual_protocol_version = S2N_TLS11;
        EXPECT_OK(s2n_key_material_init(&key_material, conn));
        iv = 0;

        EXPECT_EQUAL(key_material.client_mac.size, mac);
        EXPECT_EQUAL(key_material.client_key.size, key);
        EXPECT_EQUAL(key_material.client_iv.size, iv);
        EXPECT_EQUAL(key_material.server_mac.size, mac);
        EXPECT_EQUAL(key_material.server_key.size, key);
        EXPECT_EQUAL(key_material.server_iv.size, iv);
    }

    END_TEST();
}
