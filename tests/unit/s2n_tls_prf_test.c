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
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_prf.h"

/*
 * Grabbed from gnutls-cli --insecure -d 9 www.example.com --ciphers AES --macs SHA --protocols TLS1.0
 *
 * |<9>| INT: PREMASTER SECRET[48]: 0301bebf2a5707c7bda6bfe5a8971a351a9ebd019de412212da021fd802e03f49f231d4e959c7352679f892f9d7f9748
 * |<9>| INT: CLIENT RANDOM[32]: 537eefc1e720b311ff8483d057ae750a3667af9d5b496cc0d2edfb0dd309a286
 * |<9>| INT: SERVER RANDOM[32]: 537eefc29f337c5eedacd00a1889b031261701872d666a74fa999dc13bcd8821
 * |<9>| INT: MASTER SECRET: c8c610686237cd024a2d8e0391f61a8a4464c2c9576ea2b5ccf3af68139ec07c6a1720097063de968f2341f77b837120
 */
int main(int argc, char **argv)
{
    uint8_t master_secret_hex_pad[96];
    char premaster_secret_hex_in[] = "0301bebf2a5707c7bda6bfe5a8971a351a9ebd019de412212da021fd802e03f49f231d4e959c7352679f892f9d7f9748";
    char client_random_hex_in[] = "537eefc1e720b311ff8483d057ae750a3667af9d5b496cc0d2edfb0dd309a286";
    char server_random_hex_in[] = "537eefc29f337c5eedacd00a1889b031261701872d666a74fa999dc13bcd8821";
    char master_secret_hex_in[] = "c8c610686237cd024a2d8e0391f61a8a4464c2c9576ea2b5ccf3af68139ec07c6a1720097063de968f2341f77b837120";

    struct s2n_stuffer client_random_in;
    struct s2n_stuffer server_random_in;
    struct s2n_stuffer premaster_secret_in;
    struct s2n_stuffer master_secret_hex_out;
    struct s2n_blob master_secret = {.data = master_secret_hex_pad,.size = sizeof(master_secret_hex_pad) };
    struct s2n_blob pms;

    struct s2n_connection *conn;

    BEGIN_TEST();

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

    /* Check the most common PRF */
    conn->actual_protocol_version = S2N_TLS11;

    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_string(&client_random_in, client_random_hex_in));
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_string(&server_random_in, server_random_hex_in));
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_string(&premaster_secret_in, premaster_secret_hex_in));

    EXPECT_SUCCESS(s2n_stuffer_init(&master_secret_hex_out, &master_secret));

    /* Parse the hex */
    for (int i = 0; i < 48; i++) {
        uint8_t c;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8_hex(&premaster_secret_in, &c));
        conn->secure.rsa_premaster_secret[i] = c;
    }
    for (int i = 0; i < 32; i++) {
        uint8_t c;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8_hex(&client_random_in, &c));
        conn->secure.client_random[i] = c;
    }
    for (int i = 0; i < 32; i++) {
        uint8_t c;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8_hex(&server_random_in, &c));
        conn->secure.server_random[i] = c;
    }

    pms.data = conn->secure.rsa_premaster_secret;
    pms.size = sizeof(conn->secure.rsa_premaster_secret);
    EXPECT_SUCCESS(s2n_tls_prf_master_secret(conn, &pms));

    /* Convert the master secret to hex */
    for (int i = 0; i < 48; i++) {
        EXPECT_SUCCESS(s2n_stuffer_write_uint8_hex(&master_secret_hex_out, conn->secure.master_secret[i]));
    }

    EXPECT_EQUAL(memcmp(master_secret_hex_pad, master_secret_hex_in, sizeof(master_secret_hex_pad)), 0);

    EXPECT_SUCCESS(s2n_connection_free(conn));
    EXPECT_SUCCESS(s2n_stuffer_free(&client_random_in));
    EXPECT_SUCCESS(s2n_stuffer_free(&server_random_in));
    EXPECT_SUCCESS(s2n_stuffer_free(&premaster_secret_in));

    END_TEST();
}
