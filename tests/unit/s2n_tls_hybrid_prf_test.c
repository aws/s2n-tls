/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <tls/s2n_cipher_suites.h>

#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_prf.h"
#include "utils/s2n_safety.h"
#include "tests/testlib/s2n_nist_kats.h"

#define KAT_FILE_NAME "kats/hybrid_prf.kat"

/* The lengths for premaster_kem_secret and client_key_exchange_message must be defined in the KAT file,
 * since they vary based on which KEM is being used. The other lengths are fixed and can be defined here. */
#define PREMASTER_CLASSIC_SECRET_LENGTH 48
#define CLIENT_RANDOM_LENGTH 32
#define SERVER_RANDOM_LENGTH 32
#define MASTER_SECRET_LENGTH 48

#define NUM_TEST_VECTORS 6

int main(int argc, char **argv)
{
    BEGIN_TEST();

    FILE *kat_file = fopen(KAT_FILE_NAME, "r");
    EXPECT_NOT_NULL(kat_file);

    uint8_t premaster_classic_secret[PREMASTER_CLASSIC_SECRET_LENGTH];
    uint8_t client_random[CLIENT_RANDOM_LENGTH];
    uint8_t server_random[SERVER_RANDOM_LENGTH];
    uint8_t expected_master_secret[MASTER_SECRET_LENGTH];

    for (uint32_t i = 0; i < NUM_TEST_VECTORS; i++) {
        /* Verify test index */
        uint32_t count = 0;
        GUARD(FindMarker(kat_file, "count = "));
        gt_check(fscanf(kat_file, "%u", &count), 0);
        eq_check(count, i);

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        conn->actual_protocol_version = S2N_TLS12;
        /* Really only need for the hash function in the PRF */
        conn->secure.cipher_suite = &s2n_ecdhe_rsa_with_aes_256_gcm_sha384;

        /* Read test vector from KAT file */
        uint32_t premaster_kem_secret_length = 0;
        uint32_t client_key_exchange_message_length = 0;

        GUARD(ReadHex(kat_file, premaster_classic_secret, PREMASTER_CLASSIC_SECRET_LENGTH, "premaster_classic_secret = "));

        GUARD(FindMarker(kat_file, "premaster_kem_secret_length = "));
        gt_check(fscanf(kat_file, "%u", &premaster_kem_secret_length), 0);

        uint8_t *premaster_kem_secret;
        notnull_check(premaster_kem_secret = malloc(premaster_kem_secret_length));
        GUARD(ReadHex(kat_file, premaster_kem_secret, premaster_kem_secret_length, "premaster_kem_secret = "));

        GUARD(ReadHex(kat_file, client_random, CLIENT_RANDOM_LENGTH, "client_random = "));
        GUARD(ReadHex(kat_file, server_random, SERVER_RANDOM_LENGTH, "server_random = "));

        GUARD(FindMarker(kat_file, "client_key_exchange_message_length = "));
        gt_check(fscanf(kat_file, "%u", &client_key_exchange_message_length), 0);

        uint8_t *client_key_exchange_message;
        notnull_check(client_key_exchange_message = malloc(client_key_exchange_message_length));
        GUARD(ReadHex(kat_file, client_key_exchange_message, client_key_exchange_message_length, "client_key_exchange_message = "));

        GUARD(ReadHex(kat_file, expected_master_secret, MASTER_SECRET_LENGTH, "master_secret = "));

        struct s2n_blob classic_pms = {.data = premaster_classic_secret, .size = PREMASTER_CLASSIC_SECRET_LENGTH};
        struct s2n_blob kem_pms = {.data = premaster_kem_secret, .size = premaster_kem_secret_length};

        /* In the future the hybrid_kex client_key_send (client side) and client_key_receive (server side) will concatenate the two parts */
        DEFER_CLEANUP(struct s2n_blob combined_pms = {0}, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&combined_pms, classic_pms.size + kem_pms.size));
        struct s2n_stuffer combined_stuffer = {0};
        s2n_stuffer_init(&combined_stuffer, &combined_pms);
        s2n_stuffer_write(&combined_stuffer, &classic_pms);
        s2n_stuffer_write(&combined_stuffer, &kem_pms);

        memcpy_check(conn->secure.client_random, client_random, CLIENT_RANDOM_LENGTH);
        memcpy_check(conn->secure.server_random, server_random, SERVER_RANDOM_LENGTH);

        EXPECT_SUCCESS(s2n_alloc(&conn->secure.client_key_exchange_message, client_key_exchange_message_length));

        memcpy_check(conn->secure.client_key_exchange_message.data, client_key_exchange_message, client_key_exchange_message_length);

        EXPECT_SUCCESS(s2n_hybrid_prf_master_secret(conn, &combined_pms));
        EXPECT_BYTEARRAY_EQUAL(expected_master_secret, conn->secure.master_secret, S2N_TLS_SECRET_LEN);
        EXPECT_SUCCESS(s2n_free(&conn->secure.client_key_exchange_message));
        EXPECT_SUCCESS(s2n_connection_free(conn));

        free(premaster_kem_secret);
        free(client_key_exchange_message);
    }

    if (FindMarker(kat_file, "count = ") == 0) {
        FAIL_MSG("Found unexpected test vectors in the KAT file. Has the KAT file been changed? Did you update NUM_TEST_VECTORS?");
    }

    END_TEST();
}
