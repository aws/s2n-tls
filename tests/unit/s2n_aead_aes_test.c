/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <string.h>
#include <stdio.h>

#include <s2n.h>

#include "testlib/s2n_testlib.h"

#include "tls/s2n_cipher_suites.h"
#include "stuffer/s2n_stuffer.h"
#include "crypto/s2n_cipher.h"
#include "utils/s2n_random.h"
#include "crypto/s2n_hmac.h"
#include "tls/s2n_record.h"
#include "tls/s2n_prf.h"

int main(int argc, char **argv)
{
    struct s2n_connection *conn;
    uint8_t random_data[S2N_SMALL_FRAGMENT_LENGTH + 1];
    uint8_t mac_key[] = "sample mac key";
    uint8_t aes128_key[] = "123456789012345";
    uint8_t aes256_key[] = "1234567890123456789012345678901";
    struct s2n_blob aes128 = {.data = aes128_key,.size = sizeof(aes128_key) };
    struct s2n_blob aes256 = {.data = aes256_key,.size = sizeof(aes256_key) };
    struct s2n_blob r = {.data = random_data, .size = sizeof(random_data)};

    BEGIN_TEST();

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    EXPECT_SUCCESS(s2n_get_urandom_data(&r));

    /* Peer and we are in sync */
    conn->server = &conn->active;
    conn->client = &conn->active;

    /* test the AES128 cipher with a SHA1 hash */
    conn->active.cipher_suite->cipher = &s2n_aes128_gcm;
    conn->active.cipher_suite->hmac_alg = S2N_HMAC_SHA1;
    EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_encryption_key(&conn->active.server_key, &aes128));
    EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_decryption_key(&conn->active.client_key, &aes128));
    EXPECT_SUCCESS(s2n_hmac_init(&conn->active.client_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
    EXPECT_SUCCESS(s2n_hmac_init(&conn->active.server_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
    conn->actual_protocol_version = S2N_TLS12;

    int max_fragment = S2N_SMALL_FRAGMENT_LENGTH;
    for (int i = 0; i < max_fragment; i++) {
        struct s2n_blob in = {.data = random_data,.size = i };
        int bytes_written;

        EXPECT_SUCCESS(s2n_connection_wipe(conn));
        EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_encryption_key(&conn->active.server_key, &aes128));
        EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_decryption_key(&conn->active.client_key, &aes128));
        EXPECT_SUCCESS(s2n_hmac_init(&conn->active.client_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
        EXPECT_SUCCESS(s2n_hmac_init(&conn->active.server_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
        EXPECT_SUCCESS(bytes_written = s2n_record_write(conn, TLS_APPLICATION_DATA, &in));

        static const int overhead = 20 /* TLS header */
            + 8   /* IV */
            + 16; /* TAG */
        if (i < max_fragment - overhead) {
            EXPECT_EQUAL(bytes_written, i);
        } else {
            EXPECT_EQUAL(bytes_written, max_fragment - overhead);
        }

        uint16_t predicted_length = bytes_written + 20;
        predicted_length += conn->active.cipher_suite->cipher->io.aead.record_iv_size;
        predicted_length += conn->active.cipher_suite->cipher->io.aead.tag_size;

        EXPECT_EQUAL(conn->out.blob.data[0], TLS_APPLICATION_DATA);
        EXPECT_EQUAL(conn->out.blob.data[1], 3);
        EXPECT_EQUAL(conn->out.blob.data[2], 3);
        EXPECT_EQUAL(conn->out.blob.data[3], (predicted_length >> 8) & 0xff);
        EXPECT_EQUAL(conn->out.blob.data[4], predicted_length & 0xff);

        /* The data should be encrypted */
        if (bytes_written > 10) {
            EXPECT_NOT_EQUAL(memcmp(conn->out.blob.data + 5, random_data, bytes_written), 0);
        }

        /* Copy the encrypted out data to the in data */
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, 5));
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

        /* Start over */
        EXPECT_SUCCESS(s2n_connection_wipe(conn));
        EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_encryption_key(&conn->active.server_key, &aes128));
        EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_decryption_key(&conn->active.client_key, &aes128));
        EXPECT_SUCCESS(s2n_hmac_init(&conn->active.client_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
        EXPECT_SUCCESS(s2n_hmac_init(&conn->active.server_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
        EXPECT_SUCCESS(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));

        /* Now lets corrupt some data and ensure the tests pass */
        /* Copy the encrypted out data to the in data */
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, 5));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));

        /* Tamper the protocol version in the header, and ensure decryption fails, as we use this in the AAD */
        conn->in.blob.data[2] = 2;
        EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
        EXPECT_FAILURE(s2n_record_parse(conn));
        EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);

        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));

        /* Tamper with the IV and ensure decryption fails */
        for (int j = 0; j < S2N_TLS_GCM_IV_LEN; j++) {
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
            EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_encryption_key(&conn->active.server_key, &aes128));
            EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_decryption_key(&conn->active.client_key, &aes128));
            EXPECT_SUCCESS(s2n_hmac_init(&conn->active.client_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
            EXPECT_SUCCESS(s2n_hmac_init(&conn->active.server_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
            EXPECT_SUCCESS(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));

            /* Copy the encrypted out data to the in data */
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, 5));
            EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));
            conn->in.blob.data[5 + j] ++;
            EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
            EXPECT_FAILURE(s2n_record_parse(conn));
            EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);

            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        }

        /* Tamper with the TAG and ensure decryption fails */
        for (int j = 0; j < S2N_TLS_GCM_TAG_LEN; j++) {
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
            EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_encryption_key(&conn->active.server_key, &aes128));
            EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_decryption_key(&conn->active.client_key, &aes128));
            EXPECT_SUCCESS(s2n_hmac_init(&conn->active.client_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
            EXPECT_SUCCESS(s2n_hmac_init(&conn->active.server_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
            EXPECT_SUCCESS(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));

            /* Copy the encrypted out data to the in data */
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, 5));
            EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));
            conn->in.blob.data[s2n_stuffer_data_available(&conn->in) - j - 1] ++;
            EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
            EXPECT_FAILURE(s2n_record_parse(conn));
            EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);

            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        }

        /* Tamper with the ciphertext and ensure decryption fails */
        for (int j = 0; j < i - S2N_TLS_GCM_TAG_LEN; j++) {
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
            EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_encryption_key(&conn->active.server_key, &aes128));
            EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_decryption_key(&conn->active.client_key, &aes128));
            EXPECT_SUCCESS(s2n_hmac_init(&conn->active.client_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
            EXPECT_SUCCESS(s2n_hmac_init(&conn->active.server_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
            EXPECT_SUCCESS(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));

            /* Copy the encrypted out data to the in data */
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, 5));
            EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));
            conn->in.blob.data[S2N_TLS_GCM_IV_LEN + j]++;
            EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
            EXPECT_FAILURE(s2n_record_parse(conn));
            EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);

            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        }
    }
    EXPECT_SUCCESS(conn->active.cipher_suite->cipher->destroy_key(&conn->active.server_key));
    EXPECT_SUCCESS(conn->active.cipher_suite->cipher->destroy_key(&conn->active.client_key));
    EXPECT_SUCCESS(s2n_connection_free(conn));

    /* test the AES256 cipher with a SHA1 hash */
    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    conn->active.cipher_suite->cipher = &s2n_aes256_gcm;
    conn->active.cipher_suite->hmac_alg = S2N_HMAC_SHA1;
    EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_encryption_key(&conn->active.server_key, &aes256));
    EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_decryption_key(&conn->active.client_key, &aes256));
    EXPECT_SUCCESS(s2n_hmac_init(&conn->active.client_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
    EXPECT_SUCCESS(s2n_hmac_init(&conn->active.server_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
    conn->actual_protocol_version = S2N_TLS12;

    for (int i = 0; i <= max_fragment + 1; i++) {
        struct s2n_blob in = {.data = random_data,.size = i };
        int bytes_written;

        EXPECT_SUCCESS(s2n_connection_wipe(conn));
        conn->active.cipher_suite->cipher = &s2n_aes256_gcm;
        conn->active.cipher_suite->cipher = &s2n_aes256_gcm;
        EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_encryption_key(&conn->active.server_key, &aes256));
        EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_decryption_key(&conn->active.client_key, &aes256));
        EXPECT_SUCCESS(s2n_hmac_init(&conn->active.client_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
        EXPECT_SUCCESS(s2n_hmac_init(&conn->active.server_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
        conn->actual_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(bytes_written = s2n_record_write(conn, TLS_APPLICATION_DATA, &in));

        static const int overhead = 20 /* TLS header */
            + 8   /* IV */
            + 16; /* TAG */
        if (i < max_fragment - overhead) {
            EXPECT_EQUAL(bytes_written, i);
        } else {
            EXPECT_EQUAL(bytes_written, max_fragment - overhead);
        }

        uint16_t predicted_length = bytes_written + 20;
        predicted_length += conn->active.cipher_suite->cipher->io.aead.record_iv_size;
        predicted_length += conn->active.cipher_suite->cipher->io.aead.tag_size;

        EXPECT_EQUAL(conn->out.blob.data[0], TLS_APPLICATION_DATA);
        EXPECT_EQUAL(conn->out.blob.data[1], 3);
        EXPECT_EQUAL(conn->out.blob.data[2], 3);
        EXPECT_EQUAL(conn->out.blob.data[3], (predicted_length >> 8) & 0xff);
        EXPECT_EQUAL(conn->out.blob.data[4], predicted_length & 0xff);

        /* The data should be encrypted */
        if (bytes_written > 10) {
            EXPECT_NOT_EQUAL(memcmp(conn->out.blob.data + 5, random_data, bytes_written), 0);
        }

        /* Copy the encrypted out data to the in data */
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, 5));
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

        EXPECT_SUCCESS(s2n_connection_wipe(conn));
        conn->active.cipher_suite->cipher = &s2n_aes256_gcm;
        conn->active.cipher_suite->cipher = &s2n_aes256_gcm;
        EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_encryption_key(&conn->active.server_key, &aes256));
        EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_decryption_key(&conn->active.client_key, &aes256));
        EXPECT_SUCCESS(s2n_hmac_init(&conn->active.client_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
        EXPECT_SUCCESS(s2n_hmac_init(&conn->active.server_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
        conn->actual_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));

        /* Now lets corrupt some data and ensure the tests pass */
        /* Copy the encrypted out data to the in data */
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, 5));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));

        /* Tamper with the protocol version in the header, and ensure decryption fails, as we use this in the AAD */
        conn->in.blob.data[2] = 2;
        EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
        EXPECT_FAILURE(s2n_record_parse(conn));
        EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);

        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));

        /* Tamper with the IV and ensure decryption fails */
        for (int j = 0; j < S2N_TLS_GCM_IV_LEN; j++) {
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
            conn->active.cipher_suite->cipher = &s2n_aes256_gcm;
            conn->active.cipher_suite->cipher = &s2n_aes256_gcm;
            EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_encryption_key(&conn->active.server_key, &aes256));
            EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_decryption_key(&conn->active.client_key, &aes256));
            EXPECT_SUCCESS(s2n_hmac_init(&conn->active.client_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
            EXPECT_SUCCESS(s2n_hmac_init(&conn->active.server_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));

            /* Copy the encrypted out data to the in data */
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, 5));
            EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));
            conn->in.blob.data[5 + j] ++;
            EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
            EXPECT_FAILURE(s2n_record_parse(conn));
            EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);

            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        }

        /* Tamper with the TAG and ensure decryption fails */
        for (int j = 0; j < S2N_TLS_GCM_TAG_LEN; j++) {
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
            conn->active.cipher_suite->cipher = &s2n_aes256_gcm;
            conn->active.cipher_suite->cipher = &s2n_aes256_gcm;
            EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_encryption_key(&conn->active.server_key, &aes256));
            EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_decryption_key(&conn->active.client_key, &aes256));
            EXPECT_SUCCESS(s2n_hmac_init(&conn->active.client_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
            EXPECT_SUCCESS(s2n_hmac_init(&conn->active.server_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));

            /* Copy the encrypted out data to the in data */
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, 5));
            EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));
            conn->in.blob.data[s2n_stuffer_data_available(&conn->in) - j - 1] ++;
            EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
            EXPECT_FAILURE(s2n_record_parse(conn));
            EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);

            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        }

        /* Tamper with the ciphertext and ensure decryption fails */
        for (int j = S2N_TLS_GCM_IV_LEN; j < i - S2N_TLS_GCM_TAG_LEN; j++) {
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
            conn->active.cipher_suite->cipher = &s2n_aes256_gcm;
            conn->active.cipher_suite->cipher = &s2n_aes256_gcm;
            EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_encryption_key(&conn->active.server_key, &aes256));
            EXPECT_SUCCESS(conn->active.cipher_suite->cipher->get_decryption_key(&conn->active.client_key, &aes256));
            EXPECT_SUCCESS(s2n_hmac_init(&conn->active.client_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
            EXPECT_SUCCESS(s2n_hmac_init(&conn->active.server_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));

            /* Copy the encrypted out data to the in data */
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, 5));
            EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));
            conn->in.blob.data[j]++;
            EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
            EXPECT_FAILURE(s2n_record_parse(conn));
            EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);

            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
            EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        }
    }
    EXPECT_SUCCESS(conn->active.cipher_suite->cipher->destroy_key(&conn->active.server_key));
    EXPECT_SUCCESS(conn->active.cipher_suite->cipher->destroy_key(&conn->active.client_key));
    EXPECT_SUCCESS(s2n_connection_free(conn));

    END_TEST();
}

