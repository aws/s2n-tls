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

#include <stdio.h>
#include <string.h>

#include "crypto/s2n_fips.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_prf.h"

/*

 * Grabbed from gnutls-cli --insecure -d 9 www.example.com --ciphers AES --macs SHA --protocols SSLv3
 *
 * |<9>| INT: PREMASTER SECRET[48]: 03009e8e006a7f1451d32164088a8cba5077d1b819160662a97e90a765cec244b5f8f98fd50cfe8e4fba97994a7a4843
 * |<9>| INT: CLIENT RANDOM[32]: 537fb7fdddc05090774e55f8ef8564c2b5b238819703409bfdabe14e4cf1897d
 * |<9>| INT: SERVER RANDOM[32]: 537fb7fe649225c9f37904b24916452d51794b3b5735fc7e628b6090db52209f
 * |<9>| INT: MASTER SECRET: 02b811717e3aa29e6b0526d7e9ae2b74496d461564401f47498e9cdbdf54c8afa69c25a648b360de2004c74850e8f7db
 */
int main(int argc, char **argv)
{
    uint8_t master_secret_hex_pad[96];
    char premaster_secret_hex_in[] = "03009e8e006a7f1451d32164088a8cba5077d1b819160662a97e90a765cec244b5f8f98fd50cfe8e4fba97994a7a4843";
    char client_random_hex_in[] = "537fb7fdddc05090774e55f8ef8564c2b5b238819703409bfdabe14e4cf1897d";
    char server_random_hex_in[] = "537fb7fe649225c9f37904b24916452d51794b3b5735fc7e628b6090db52209f";
    char master_secret_hex_in[] = "02b811717e3aa29e6b0526d7e9ae2b74496d461564401f47498e9cdbdf54c8afa69c25a648b360de2004c74850e8f7db";

    struct s2n_stuffer client_random_in = { 0 };
    struct s2n_stuffer server_random_in = { 0 };
    struct s2n_stuffer premaster_secret_in = { 0 };
    struct s2n_stuffer master_secret_hex_out = { 0 };
    struct s2n_blob master_secret = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&master_secret, master_secret_hex_pad, sizeof(master_secret_hex_pad)));
    struct s2n_blob pms = { 0 };

    struct s2n_connection *conn = NULL;

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    if (s2n_is_in_fips_mode()) {
        /* Skip when FIPS mode is set as FIPS mode does not support SSLv3 */
        END_TEST();
    }

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_string(&client_random_in, client_random_hex_in));
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_string(&server_random_in, server_random_hex_in));
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_string(&premaster_secret_in, premaster_secret_hex_in));

    EXPECT_SUCCESS(s2n_stuffer_init(&master_secret_hex_out, &master_secret));

    /* Parse the hex */
    for (int i = 0; i < 48; i++) {
        uint8_t c = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8_hex(&premaster_secret_in, &c));
        conn->secrets.version.tls12.rsa_premaster_secret[i] = c;
    }
    for (int i = 0; i < 32; i++) {
        uint8_t c = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8_hex(&client_random_in, &c));
        conn->handshake_params.client_random[i] = c;
    }
    for (int i = 0; i < 32; i++) {
        uint8_t c = 0;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8_hex(&server_random_in, &c));
        conn->handshake_params.server_random[i] = c;
    }

    /* Set the protocol version to sslv3 */
    conn->actual_protocol_version = S2N_SSLv3;
    pms.data = conn->secrets.version.tls12.rsa_premaster_secret;
    pms.size = sizeof(conn->secrets.version.tls12.rsa_premaster_secret);
    EXPECT_SUCCESS(s2n_tls_prf_master_secret(conn, &pms));

    /* Convert the master secret to hex */
    for (int i = 0; i < 48; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&master_secret_hex_out, conn->secrets.version.tls12.master_secret[i]));
    }

    EXPECT_EQUAL(memcmp(master_secret_hex_pad, master_secret_hex_in, sizeof(master_secret_hex_pad)), 0);

    EXPECT_SUCCESS(s2n_connection_free(conn));
    EXPECT_SUCCESS(s2n_stuffer_free(&client_random_in));
    EXPECT_SUCCESS(s2n_stuffer_free(&server_random_in));
    EXPECT_SUCCESS(s2n_stuffer_free(&premaster_secret_in));

    END_TEST();
}
