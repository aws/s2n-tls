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

#include <openssl/evp.h>
#include <string.h>

#include "api/s2n.h"
#include "crypto/s2n_cipher.h"
#include "crypto/s2n_hash.h"
#include "crypto/s2n_hmac.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_record.h"
#include "utils/s2n_random.h"

/* Explicit IV starts after the TLS record header. */
#define EXPLICIT_IV_OFFSET S2N_TLS_RECORD_HEADER_LENGTH

/* IVs should never be repeated with the same session key. */
static int ensure_explicit_iv_is_unique(uint8_t existing_explicit_ivs[S2N_DEFAULT_FRAGMENT_LENGTH][S2N_TLS_MAX_IV_LEN],
        size_t num_existing_ivs,
        const uint8_t *candidate_iv,
        uint16_t iv_len)
{
    for (size_t i = 0; i < num_existing_ivs; i++) {
        if (memcmp(existing_explicit_ivs[i], candidate_iv, iv_len) == 0) {
            return S2N_FAILURE;
        }
    }

    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    struct s2n_connection *conn;
    uint8_t random_data[S2N_DEFAULT_FRAGMENT_LENGTH + 1];
    uint8_t mac_key_sha[20] = "server key shaserve";
    uint8_t mac_key_sha256[32] = "server key sha256server key sha";
    uint8_t aes128_key[] = "123456789012345";
    uint8_t aes256_key[] = "1234567890123456789012345678901";
    struct s2n_blob aes128 = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&aes128, aes128_key, sizeof(aes128_key)));
    struct s2n_blob aes256 = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&aes256, aes256_key, sizeof(aes256_key)));
    struct s2n_blob r = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&r, random_data, sizeof(random_data)));
    /* Stores explicit IVs used in each test case to validate uniqueness. */
    uint8_t existing_explicit_ivs[S2N_DEFAULT_FRAGMENT_LENGTH + 2][S2N_TLS_MAX_IV_LEN];

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Skip test if we can't use the ciphers */
    if (!s2n_aes128_sha.is_available()
            || !s2n_aes256_sha.is_available()
            || !s2n_aes128_sha256.is_available()
            || !s2n_aes256_sha256.is_available()) {
        END_TEST();
    }

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    EXPECT_OK(s2n_get_public_random_data(&r));

    /* Peer and we are in sync */
    conn->server = conn->initial;
    conn->client = conn->initial;

    const int max_aligned_fragment = S2N_DEFAULT_FRAGMENT_LENGTH;
    const uint8_t proto_versions[3] = { S2N_TLS10, S2N_TLS11, S2N_TLS12 };

    /* test the composite AES128_SHA1 cipher  */
    conn->initial->cipher_suite->record_alg = &s2n_record_alg_aes128_sha_composite;

    /* It's important to verify all TLS versions for the composite implementation.
     * There are a few gotchas with respect to explicit IV length and payload length
     */
    for (int j = 0; j < 3; j++) {
        for (size_t i = 0; i <= max_aligned_fragment + 1; i++) {
            struct s2n_blob in = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&in, random_data, i));
            int bytes_written;

            EXPECT_SUCCESS(s2n_connection_wipe(conn));

            EXPECT_SUCCESS(conn->initial->cipher_suite->record_alg->cipher->set_encryption_key(&conn->initial->server_key, &aes128));
            EXPECT_SUCCESS(conn->initial->cipher_suite->record_alg->cipher->set_decryption_key(&conn->initial->client_key, &aes128));
            EXPECT_SUCCESS(conn->initial->cipher_suite->record_alg->cipher->io.comp.set_mac_write_key(&conn->initial->server_key, mac_key_sha, sizeof(mac_key_sha)));
            EXPECT_SUCCESS(conn->initial->cipher_suite->record_alg->cipher->io.comp.set_mac_write_key(&conn->initial->client_key, mac_key_sha, sizeof(mac_key_sha)));

            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));
            conn->actual_protocol_version = proto_versions[j];

            int explicit_iv_len;
            if (conn->actual_protocol_version > S2N_TLS10) {
                explicit_iv_len = 16;
            } else {
                explicit_iv_len = 0;
            }

            s2n_result result = s2n_record_write(conn, TLS_APPLICATION_DATA, &in);
            if (i <= max_aligned_fragment) {
                EXPECT_OK(result);
                bytes_written = i;
            } else {
                EXPECT_ERROR_WITH_ERRNO(result, S2N_ERR_FRAGMENT_LENGTH_TOO_LARGE);
                bytes_written = max_aligned_fragment;
            }

            uint16_t predicted_length = bytes_written + 1 + SHA_DIGEST_LENGTH + explicit_iv_len;
            if (predicted_length % 16) {
                predicted_length += (16 - (predicted_length % 16));
            }
            EXPECT_EQUAL(conn->out.blob.data[0], TLS_APPLICATION_DATA);
            uint8_t record_version = conn->out.blob.data[1] * 10 + conn->out.blob.data[2];
            EXPECT_EQUAL(record_version, conn->actual_protocol_version);
            EXPECT_EQUAL(conn->out.blob.data[3], (predicted_length >> 8) & 0xff);
            EXPECT_EQUAL(conn->out.blob.data[4], predicted_length & 0xff);

            /* The data should be encrypted */
            if (bytes_written > 10) {
                EXPECT_NOT_EQUAL(memcmp(conn->out.blob.data + EXPLICIT_IV_OFFSET + explicit_iv_len, random_data, bytes_written), 0);
            }

            if (explicit_iv_len > 0) {
                /* The explicit IV for every record written should be random */
                uint8_t *explicit_iv = conn->out.blob.data + EXPLICIT_IV_OFFSET;
                EXPECT_SUCCESS(ensure_explicit_iv_is_unique(existing_explicit_ivs, i, explicit_iv, explicit_iv_len));
                /* Record this IV */
                EXPECT_MEMCPY_SUCCESS(existing_explicit_ivs[i], explicit_iv, explicit_iv_len);
            }

            /* Copy the encrypted out data to the in data */
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, S2N_TLS_RECORD_HEADER_LENGTH));
            EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));

            /* Let's decrypt it */
            uint8_t content_type;
            uint16_t fragment_length;
            EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
            EXPECT_SUCCESS(s2n_record_parse(conn));
            EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);
            EXPECT_EQUAL(fragment_length, predicted_length);

            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        }
    }

    /* test the composite AES256_SHA1 cipher  */
    conn->initial->cipher_suite->record_alg = &s2n_record_alg_aes256_sha_composite;
    for (int j = 0; j < 3; j++) {
        for (int i = 0; i <= max_aligned_fragment + 1; i++) {
            struct s2n_blob in = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&in, random_data, i));
            int bytes_written;

            EXPECT_SUCCESS(s2n_connection_wipe(conn));

            EXPECT_SUCCESS(conn->initial->cipher_suite->record_alg->cipher->set_encryption_key(&conn->initial->server_key, &aes256));
            EXPECT_SUCCESS(conn->initial->cipher_suite->record_alg->cipher->set_decryption_key(&conn->initial->client_key, &aes256));
            EXPECT_SUCCESS(conn->initial->cipher_suite->record_alg->cipher->io.comp.set_mac_write_key(&conn->initial->server_key, mac_key_sha, sizeof(mac_key_sha)));
            EXPECT_SUCCESS(conn->initial->cipher_suite->record_alg->cipher->io.comp.set_mac_write_key(&conn->initial->client_key, mac_key_sha, sizeof(mac_key_sha)));

            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));
            conn->actual_protocol_version = proto_versions[j];

            int explicit_iv_len;
            if (conn->actual_protocol_version > S2N_TLS10) {
                explicit_iv_len = 16;
            } else {
                explicit_iv_len = 0;
            }

            s2n_result result = s2n_record_write(conn, TLS_APPLICATION_DATA, &in);
            if (i <= max_aligned_fragment) {
                EXPECT_OK(result);
                bytes_written = i;
            } else {
                EXPECT_ERROR_WITH_ERRNO(result, S2N_ERR_FRAGMENT_LENGTH_TOO_LARGE);
                bytes_written = max_aligned_fragment;
            }

            uint16_t predicted_length = bytes_written + 1 + SHA_DIGEST_LENGTH + explicit_iv_len;
            if (predicted_length % 16) {
                predicted_length += (16 - (predicted_length % 16));
            }
            EXPECT_EQUAL(conn->out.blob.data[0], TLS_APPLICATION_DATA);
            uint8_t record_version = conn->out.blob.data[1] * 10 + conn->out.blob.data[2];
            EXPECT_EQUAL(record_version, conn->actual_protocol_version);
            EXPECT_EQUAL(conn->out.blob.data[3], (predicted_length >> 8) & 0xff);
            EXPECT_EQUAL(conn->out.blob.data[4], predicted_length & 0xff);

            /* The data should be encrypted */
            if (bytes_written > 10) {
                EXPECT_NOT_EQUAL(memcmp(conn->out.blob.data + EXPLICIT_IV_OFFSET + explicit_iv_len, random_data, bytes_written), 0);
            }

            if (explicit_iv_len > 0) {
                /* The explicit IV for every record written should be random */
                uint8_t *explicit_iv = conn->out.blob.data + EXPLICIT_IV_OFFSET;
                EXPECT_SUCCESS(ensure_explicit_iv_is_unique(existing_explicit_ivs, i, explicit_iv, explicit_iv_len));
                /* Record this IV */
                EXPECT_MEMCPY_SUCCESS(existing_explicit_ivs[i], explicit_iv, explicit_iv_len);
            }

            /* Copy the encrypted out data to the in data */
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, S2N_TLS_RECORD_HEADER_LENGTH));
            EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));

            /* Let's decrypt it */
            uint8_t content_type;
            uint16_t fragment_length;
            EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
            EXPECT_SUCCESS(s2n_record_parse(conn));
            EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);
            EXPECT_EQUAL(fragment_length, predicted_length);

            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        }
    }

    /* test the composite AES128_SHA256 cipher  */
    conn->initial->cipher_suite->record_alg = &s2n_record_alg_aes128_sha256_composite;
    for (int j = 0; j < 3; j++) {
        for (int i = 0; i < max_aligned_fragment + 1; i++) {
            struct s2n_blob in = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&in, random_data, i));
            int bytes_written;

            EXPECT_SUCCESS(s2n_connection_wipe(conn));

            EXPECT_SUCCESS(conn->initial->cipher_suite->record_alg->cipher->set_encryption_key(&conn->initial->server_key, &aes128));
            EXPECT_SUCCESS(conn->initial->cipher_suite->record_alg->cipher->set_decryption_key(&conn->initial->client_key, &aes128));
            EXPECT_SUCCESS(conn->initial->cipher_suite->record_alg->cipher->io.comp.set_mac_write_key(&conn->initial->server_key, mac_key_sha256, sizeof(mac_key_sha256)));
            EXPECT_SUCCESS(conn->initial->cipher_suite->record_alg->cipher->io.comp.set_mac_write_key(&conn->initial->client_key, mac_key_sha256, sizeof(mac_key_sha256)));

            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));
            conn->actual_protocol_version = proto_versions[j];

            int explicit_iv_len;
            if (conn->actual_protocol_version > S2N_TLS10) {
                explicit_iv_len = 16;
            } else {
                explicit_iv_len = 0;
            }

            s2n_result result = s2n_record_write(conn, TLS_APPLICATION_DATA, &in);
            if (i <= max_aligned_fragment) {
                EXPECT_OK(result);
                bytes_written = i;
            } else {
                EXPECT_ERROR_WITH_ERRNO(result, S2N_ERR_FRAGMENT_LENGTH_TOO_LARGE);
                bytes_written = max_aligned_fragment;
            }

            uint16_t predicted_length = bytes_written + 1 + SHA256_DIGEST_LENGTH + explicit_iv_len;
            if (predicted_length % 16) {
                predicted_length += (16 - (predicted_length % 16));
            }
            EXPECT_EQUAL(conn->out.blob.data[0], TLS_APPLICATION_DATA);
            uint8_t record_version = conn->out.blob.data[1] * 10 + conn->out.blob.data[2];
            EXPECT_EQUAL(record_version, conn->actual_protocol_version);
            EXPECT_EQUAL(conn->out.blob.data[3], (predicted_length >> 8) & 0xff);
            EXPECT_EQUAL(conn->out.blob.data[4], predicted_length & 0xff);

            /* The data should be encrypted */
            if (bytes_written > 10) {
                EXPECT_NOT_EQUAL(memcmp(conn->out.blob.data + EXPLICIT_IV_OFFSET + explicit_iv_len, random_data, bytes_written), 0);
            }

            if (explicit_iv_len > 0) {
                /* The explicit IV for every record written should be random */
                uint8_t *explicit_iv = conn->out.blob.data + EXPLICIT_IV_OFFSET;
                EXPECT_SUCCESS(ensure_explicit_iv_is_unique(existing_explicit_ivs, i, explicit_iv, explicit_iv_len));
                /* Record this IV */
                EXPECT_MEMCPY_SUCCESS(existing_explicit_ivs[i], explicit_iv, explicit_iv_len);
            }

            /* Copy the encrypted out data to the in data */
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, S2N_TLS_RECORD_HEADER_LENGTH));
            EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));

            /* Let's decrypt it */
            uint8_t content_type;
            uint16_t fragment_length;
            EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
            EXPECT_SUCCESS(s2n_record_parse(conn));
            EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);
            EXPECT_EQUAL(fragment_length, predicted_length);

            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        }
    }

    /* test the composite AES256_SHA256 cipher  */
    conn->initial->cipher_suite->record_alg = &s2n_record_alg_aes256_sha256_composite;
    for (int j = 0; j < 3; j++) {
        for (int i = 0; i <= max_aligned_fragment + 1; i++) {
            struct s2n_blob in = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&in, random_data, i));
            int bytes_written;

            EXPECT_SUCCESS(s2n_connection_wipe(conn));

            EXPECT_SUCCESS(conn->initial->cipher_suite->record_alg->cipher->set_encryption_key(&conn->initial->server_key, &aes256));
            EXPECT_SUCCESS(conn->initial->cipher_suite->record_alg->cipher->set_decryption_key(&conn->initial->client_key, &aes256));
            EXPECT_SUCCESS(conn->initial->cipher_suite->record_alg->cipher->io.comp.set_mac_write_key(&conn->initial->server_key, mac_key_sha256, sizeof(mac_key_sha256)));
            EXPECT_SUCCESS(conn->initial->cipher_suite->record_alg->cipher->io.comp.set_mac_write_key(&conn->initial->client_key, mac_key_sha256, sizeof(mac_key_sha256)));

            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));
            conn->actual_protocol_version = proto_versions[j];

            int explicit_iv_len;
            if (conn->actual_protocol_version > S2N_TLS10) {
                explicit_iv_len = 16;
            } else {
                explicit_iv_len = 0;
            }

            s2n_result result = s2n_record_write(conn, TLS_APPLICATION_DATA, &in);
            if (i <= max_aligned_fragment) {
                EXPECT_OK(result);
                bytes_written = i;
            } else {
                EXPECT_ERROR_WITH_ERRNO(result, S2N_ERR_FRAGMENT_LENGTH_TOO_LARGE);
                bytes_written = max_aligned_fragment;
            }

            uint16_t predicted_length = bytes_written + 1 + SHA256_DIGEST_LENGTH + explicit_iv_len;
            if (predicted_length % 16) {
                predicted_length += (16 - (predicted_length % 16));
            }
            EXPECT_EQUAL(conn->out.blob.data[0], TLS_APPLICATION_DATA);
            uint8_t record_version = conn->out.blob.data[1] * 10 + conn->out.blob.data[2];
            EXPECT_EQUAL(record_version, conn->actual_protocol_version);
            EXPECT_EQUAL(conn->out.blob.data[3], (predicted_length >> 8) & 0xff);
            EXPECT_EQUAL(conn->out.blob.data[4], predicted_length & 0xff);

            /* The data should be encrypted */
            if (bytes_written > 10) {
                EXPECT_NOT_EQUAL(memcmp(conn->out.blob.data + EXPLICIT_IV_OFFSET + explicit_iv_len, random_data, bytes_written), 0);
            }

            if (explicit_iv_len > 0) {
                /* The explicit IV for every record written should be random */
                uint8_t *explicit_iv = conn->out.blob.data + EXPLICIT_IV_OFFSET;
                EXPECT_SUCCESS(ensure_explicit_iv_is_unique(existing_explicit_ivs, i, explicit_iv, explicit_iv_len));
                /* Record this IV */
                EXPECT_MEMCPY_SUCCESS(existing_explicit_ivs[i], explicit_iv, explicit_iv_len);
            }

            /* Copy the encrypted out data to the in data */
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, S2N_TLS_RECORD_HEADER_LENGTH));
            EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));

            /* Let's decrypt it */
            uint8_t content_type;
            uint16_t fragment_length;
            EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
            EXPECT_SUCCESS(s2n_record_parse(conn));
            EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);
            EXPECT_EQUAL(fragment_length, predicted_length);

            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        }
    }

    EXPECT_SUCCESS(s2n_connection_free(conn));

    END_TEST();
}
