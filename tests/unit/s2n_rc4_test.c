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
#include "crypto/s2n_fips.h"
#include "utils/s2n_random.h"
#include "crypto/s2n_hmac.h"
#include "tls/s2n_record.h"
#include "tls/s2n_prf.h"

int main(int argc, char **argv)
{
    struct s2n_connection *conn;
    uint8_t mac_key[] = "sample mac key";
    uint8_t rc4_key[] = "123456789012345";
    struct s2n_blob key_iv = {.data = rc4_key,.size = sizeof(rc4_key) };
    uint8_t random_data[S2N_DEFAULT_FRAGMENT_LENGTH + 1];
    struct s2n_blob r = {.data = random_data, .size = sizeof(random_data)};

    BEGIN_TEST();

    if (s2n_is_in_fips_mode()) {
        /* Skip when FIPS mode is set as FIPS mode does not support RC4 */
        END_TEST();
    }

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    EXPECT_SUCCESS(s2n_get_urandom_data(&r));

    /* Peer and we are in sync */
    conn->server = &conn->secure;
    conn->client = &conn->secure;

    /* test the RC4 cipher with a SHA1 hash */
    conn->secure.cipher_suite->record_alg = &s2n_record_alg_rc4_sha;
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->init(&conn->secure.server_key));
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->init(&conn->secure.client_key));
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->set_decryption_key(&conn->secure.client_key, &key_iv));
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->set_encryption_key(&conn->secure.server_key, &key_iv));
    EXPECT_SUCCESS(s2n_hmac_init(&conn->secure.client_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
    EXPECT_SUCCESS(s2n_hmac_init(&conn->secure.server_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
    conn->actual_protocol_version = S2N_TLS11;

    for (int i = 0; i <= S2N_DEFAULT_FRAGMENT_LENGTH + 1; i++) {
        struct s2n_blob in = {.data = random_data,.size = i };
        int bytes_written;

        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));
        EXPECT_SUCCESS(bytes_written = s2n_record_write(conn, TLS_APPLICATION_DATA, &in));

        if (i <= S2N_DEFAULT_FRAGMENT_LENGTH - 20) {
            EXPECT_EQUAL(bytes_written, i);
        } else {
            EXPECT_EQUAL(bytes_written, S2N_DEFAULT_FRAGMENT_LENGTH - 20);
        }

        uint16_t predicted_length = bytes_written + 20;
        EXPECT_EQUAL(conn->out.blob.data[0], TLS_APPLICATION_DATA);
        EXPECT_EQUAL(conn->out.blob.data[1], 3);
        EXPECT_EQUAL(conn->out.blob.data[2], 2);
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

        /* Check that the data looks right */
        EXPECT_EQUAL(bytes_written + 20, s2n_stuffer_data_available(&conn->in));

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

    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->destroy_key(&conn->secure.server_key));
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->destroy_key(&conn->secure.client_key));
    EXPECT_SUCCESS(s2n_connection_free(conn));

    END_TEST();
}
