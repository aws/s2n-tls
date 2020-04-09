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

#include <string.h>
#include <stdio.h>

#include <s2n.h>

#include "testlib/s2n_testlib.h"

#include "tls/s2n_cipher_suites.h"
#include "stuffer/s2n_stuffer.h"
#include "crypto/s2n_cipher.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"
#include "crypto/s2n_hmac.h"
#include "tls/s2n_crypto.h"
#include "tls/s2n_record.h"
#include "tls/s2n_prf.h"

static int destroy_server_keys(struct s2n_connection *server_conn)
{
    GUARD(server_conn->initial.cipher_suite->record_alg->cipher->destroy_key(&server_conn->initial.server_key));
    GUARD(server_conn->initial.cipher_suite->record_alg->cipher->destroy_key(&server_conn->initial.client_key));
    return 0;
}

static int setup_server_keys(struct s2n_connection *server_conn, struct s2n_blob *key)
{
    GUARD(server_conn->initial.cipher_suite->record_alg->cipher->init(&server_conn->initial.server_key));
    GUARD(server_conn->initial.cipher_suite->record_alg->cipher->init(&server_conn->initial.client_key));
    GUARD(server_conn->initial.cipher_suite->record_alg->cipher->set_encryption_key(&server_conn->initial.server_key, key));
    GUARD(server_conn->initial.cipher_suite->record_alg->cipher->set_decryption_key(&server_conn->initial.client_key, key));

    return 0;
}

int main(int argc, char **argv)
{
    struct s2n_connection *conn;
    uint8_t random_data[S2N_SMALL_FRAGMENT_LENGTH + 1];
    uint8_t chacha20_poly1305_key_data[] = "1234567890123456789012345678901";
    struct s2n_blob chacha20_poly1305_key = { .data = chacha20_poly1305_key_data, sizeof(chacha20_poly1305_key_data) };
    struct s2n_blob r = { .data = random_data, .size = sizeof(random_data)};

    BEGIN_TEST();

    /* Skip test if librcrypto doesn't support the cipher */
    if(!s2n_chacha20_poly1305.is_available()) {
        END_TEST();
    }

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    EXPECT_SUCCESS(s2n_get_urandom_data(&r));

    /* Peer and we are in sync */
    conn->server = &conn->initial;
    conn->client = &conn->initial;

    /* test the chacha20_poly1305 cipher */
    conn->initial.cipher_suite->record_alg = &s2n_record_alg_chacha20_poly1305;
    GUARD(setup_server_keys(conn, &chacha20_poly1305_key));

    int max_fragment = S2N_SMALL_FRAGMENT_LENGTH;
    for (int i = 0; i < max_fragment; i++) {
        struct s2n_blob in = {.data = random_data,.size = i };
        int bytes_written;

        EXPECT_SUCCESS(s2n_connection_wipe(conn));
        EXPECT_SUCCESS(s2n_connection_prefer_low_latency(conn));
        conn->actual_protocol_version_established = 1;
        conn->server_protocol_version = S2N_TLS12;
        conn->client_protocol_version = S2N_TLS12;
        conn->actual_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(destroy_server_keys(conn));
        EXPECT_SUCCESS(setup_server_keys(conn, &chacha20_poly1305_key));
        EXPECT_SUCCESS(bytes_written = s2n_record_write(conn, TLS_APPLICATION_DATA, &in));

        static const int overhead = S2N_TLS_CHACHA20_POLY1305_EXPLICIT_IV_LEN   /* Should be 0 */
            + S2N_TLS_GCM_TAG_LEN; /* TAG */
        if (i < max_fragment - overhead) {
            EXPECT_EQUAL(bytes_written, i);
        } else {
            EXPECT_EQUAL(bytes_written, max_fragment - overhead);
        }

        uint16_t predicted_length = bytes_written;
        predicted_length += conn->initial.cipher_suite->record_alg->cipher->io.aead.record_iv_size;
        predicted_length += conn->initial.cipher_suite->record_alg->cipher->io.aead.tag_size;

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
        conn->actual_protocol_version_established = 1;
        conn->server_protocol_version = S2N_TLS12;
        conn->client_protocol_version = S2N_TLS12;
        conn->actual_protocol_version = S2N_TLS12;
        EXPECT_SUCCESS(destroy_server_keys(conn));
        EXPECT_SUCCESS(setup_server_keys(conn, &chacha20_poly1305_key));
        EXPECT_SUCCESS(s2n_record_write(conn, TLS_APPLICATION_DATA, &in));

        /* Now lets corrupt some data and ensure the tests pass */
        /* Copy the encrypted out data to the in data */
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, 5));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));

        /* Tamper the protocol version in the header, and ensure decryption fails, as we use this in the AAD */
        EXPECT_EQUAL(conn->header_in.blob.data[0], TLS_APPLICATION_DATA);
        conn->header_in.blob.data[0] ^= 1; /* Flip a bit in the content_type of the TLS Record Header */

        EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
        EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA ^ 1);

        /**
         * We are trying to test the case when the Additional Authenticated Data in AEAD ciphers is tampered with.
         *
         * AEAD Ciphers authenticate several fields, including the TLS Record content_type, so this should fail since
         * we flipped a bit. See s2n_aead_aad_init() for which fields are added to the additional authenticated data.
         *
         * We can't flip the TLS Protocol Version bits here because s2n_record_header_parse() will error before we
         * attempt decryption with ChaCha because the Protocol version doesn't match "conn->actual_protocol_version".
         */
        EXPECT_FAILURE(s2n_record_parse(conn));


        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        GUARD(conn->initial.cipher_suite->record_alg->cipher->destroy_key(&conn->initial.server_key));
        GUARD(conn->initial.cipher_suite->record_alg->cipher->destroy_key(&conn->initial.client_key));

        /* Tamper with the TAG and ensure decryption fails */
        for (int j = 0; j < S2N_TLS_CHACHA20_POLY1305_TAG_LEN; j++) {
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
            conn->actual_protocol_version_established = 1;
            conn->server_protocol_version = S2N_TLS12;
            conn->client_protocol_version = S2N_TLS12;
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(destroy_server_keys(conn));
            EXPECT_SUCCESS(setup_server_keys(conn, &chacha20_poly1305_key));
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
            GUARD(conn->initial.cipher_suite->record_alg->cipher->destroy_key(&conn->initial.server_key));
            GUARD(conn->initial.cipher_suite->record_alg->cipher->destroy_key(&conn->initial.client_key));
        }

        /* Tamper with the ciphertext and ensure decryption fails */
        for (int j = 0; j < i - S2N_TLS_CHACHA20_POLY1305_TAG_LEN; j++) {
            EXPECT_SUCCESS(s2n_connection_wipe(conn));
            conn->actual_protocol_version_established = 1;
            conn->server_protocol_version = S2N_TLS12;
            conn->client_protocol_version = S2N_TLS12;
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(destroy_server_keys(conn));
            EXPECT_SUCCESS(setup_server_keys(conn, &chacha20_poly1305_key));
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
            GUARD(conn->initial.cipher_suite->record_alg->cipher->destroy_key(&conn->initial.server_key));
            GUARD(conn->initial.cipher_suite->record_alg->cipher->destroy_key(&conn->initial.client_key));
        }
    }

    EXPECT_SUCCESS(destroy_server_keys(conn));
    EXPECT_SUCCESS(s2n_connection_free(conn));
    END_TEST();
}
