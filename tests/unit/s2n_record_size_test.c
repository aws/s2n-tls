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
    uint8_t mac_key[] = "sample mac key";
    uint8_t aes128_key[] = "123456789012345";
    struct s2n_blob aes128 = {.data = aes128_key,.size = sizeof(aes128_key) };
    uint8_t random_data[S2N_LARGE_RECORD_LENGTH + 1];
    struct s2n_blob r = {.data = random_data, .size = sizeof(random_data)};

    BEGIN_TEST();

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    EXPECT_SUCCESS(s2n_get_urandom_data(&r));

    /* Peer and we are in sync */
    conn->server = &conn->secure;
    conn->client = &conn->secure;

    /* test the AES128 cipher with a SHA1 hash */
    conn->secure.cipher_suite->record_alg = &s2n_record_alg_aes128_sha;
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->init(&conn->secure.server_key));
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->init(&conn->secure.client_key));
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->set_encryption_key(&conn->secure.server_key, &aes128));
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->set_decryption_key(&conn->secure.client_key, &aes128));
    EXPECT_SUCCESS(s2n_hmac_init(&conn->secure.client_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
    EXPECT_SUCCESS(s2n_hmac_init(&conn->secure.server_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
    conn->actual_protocol_version = S2N_TLS11;

    /* Align the record size, then subtract 20 bytes for the HMAC, 16 bytes for the explicit IV, and one byte
     * for the padding length byte.
     */
    int small_aligned_payload = S2N_SMALL_FRAGMENT_LENGTH - (S2N_SMALL_FRAGMENT_LENGTH % 16) - 20 - 16 - 1;
    int large_aligned_payload = S2N_LARGE_FRAGMENT_LENGTH - (S2N_LARGE_FRAGMENT_LENGTH % 16) - 20 - 16 - 1;
    int medium_aligned_payload = S2N_DEFAULT_FRAGMENT_LENGTH - (S2N_DEFAULT_FRAGMENT_LENGTH % 16) - 20 - 16 - 1;
    int bytes_written;

    /* Check the default: medium records */
    EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));
    EXPECT_SUCCESS(bytes_written = s2n_record_write(conn, TLS_APPLICATION_DATA, &r));
    EXPECT_EQUAL(bytes_written, medium_aligned_payload);

    /* Check explicitly small records */
    EXPECT_SUCCESS(s2n_connection_prefer_low_latency(conn));
    EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));
    EXPECT_SUCCESS(bytes_written = s2n_record_write(conn, TLS_APPLICATION_DATA, &r));
    EXPECT_EQUAL(bytes_written, small_aligned_payload);

    /* Check explicitly large records */
    EXPECT_SUCCESS(s2n_connection_prefer_throughput(conn));
    EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));
    EXPECT_SUCCESS(bytes_written = s2n_record_write(conn, TLS_APPLICATION_DATA, &r));
    EXPECT_EQUAL(bytes_written, large_aligned_payload);

    /* Clean up */
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->destroy_key(&conn->secure.server_key));
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->destroy_key(&conn->secure.client_key));
    EXPECT_SUCCESS(s2n_connection_free(conn));

    END_TEST();
}
