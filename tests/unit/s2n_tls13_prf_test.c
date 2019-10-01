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

#include "testlib/s2n_testlib.h"
#include "stuffer/s2n_stuffer.h"
#include "crypto/s2n_hkdf.h"
#include "utils/s2n_safety.h"

/*
 * Test vectors from https://datatracker.ietf.org/doc/draft-ietf-tls-tls13-vectors/?include_text=1
 */
int main(int argc, char **argv)
{
    char client_handshake_message_hex_in[] = "010000c003032724c0ba613abd59"
                                             "4894f19ff6d59cde8364549555119b96ec1158fb9ac"
                                             "ba397000006130113031302010000910000000b0009"
                                             "000006736572766572ff01000100000a00140012001"
                                             "d001700180019010001010102010301040023000000"
                                             "3300260024001d00207e74fe9d31f2bb96f4f553465"
                                             "b92ea8210971e71e258d6cf622c3b086db26104002b"
                                             "0003027f1c000d0020001e040305030603020308040"
                                             "805080604010501060102010402050206020202002d"
                                             "00020101001c00024001";

    char server_handshake_message_hex_in[] = "020000560303b9206e3d30c43c8a"
                                             "cb1c234f9d004c6a2fecb84c6811ca285c1bbce322"
                                             "bed16000130100002e00330024001d0020bba1ffe6"
                                             "d10f92d4a8444aa51913fea27c3d2bfdf24489da40"
                                             "92dfbfbfd67c53002b00027f1c";

    char expected_secret_hex_in[] ="33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a";
    char expected_expanded_hex_in[] ="6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba";

    DEFER_CLEANUP(struct s2n_stuffer client_handshake_message_in = {0}, s2n_stuffer_free);
    DEFER_CLEANUP(struct s2n_stuffer server_handshake_message_in = {0}, s2n_stuffer_free);
    DEFER_CLEANUP(struct s2n_stuffer expected_secret_in = {0}, s2n_stuffer_free);
    DEFER_CLEANUP(struct s2n_stuffer expected_expanded_in = {0}, s2n_stuffer_free);

    char client_handshake_message[ sizeof(client_handshake_message_hex_in) / 2 ] = { 0 };
    char server_handshake_message[ sizeof(server_handshake_message_hex_in) / 2 ] = { 0 };
    char expected_secret[ sizeof(expected_secret_hex_in) / 2 ] = { 0 };
    char expected_expanded[ sizeof(expected_expanded_hex_in) / 2 ] = { 0 };

    uint8_t digest_buf[SHA256_DIGEST_LENGTH];
    uint8_t secret_buf[SHA256_DIGEST_LENGTH];
    struct s2n_blob digest;
    struct s2n_blob secret;

    struct s2n_hash_state transcript_hash, transcript_hash_snapshot;

    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_string(&client_handshake_message_in, client_handshake_message_hex_in));
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_string(&server_handshake_message_in, server_handshake_message_hex_in));
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_string(&expected_secret_in, expected_secret_hex_in));
    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_string(&expected_expanded_in, expected_expanded_hex_in));

    /* Parse the hex */
    for (int i = 0; i < sizeof(client_handshake_message); i++) {
        uint8_t c;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8_hex(&client_handshake_message_in, &c));
        client_handshake_message[i] = c;
    }

    for (int i = 0; i < sizeof(server_handshake_message); i++) {
        uint8_t c;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8_hex(&server_handshake_message_in, &c));
        server_handshake_message[i] = c;
    }

    for (int i = 0; i < sizeof(expected_secret); i++) {
        uint8_t c;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8_hex(&expected_secret_in, &c));
        expected_secret[i] = c;
    }

    for (int i = 0; i < sizeof(expected_expanded); i++) {
        uint8_t c;
        EXPECT_SUCCESS(s2n_stuffer_read_uint8_hex(&expected_expanded_in, &c));
        expected_expanded[i] = c;
    }

    EXPECT_SUCCESS(s2n_hash_new(&transcript_hash));
    EXPECT_SUCCESS(s2n_hash_new(&transcript_hash_snapshot));
    EXPECT_SUCCESS(s2n_hash_init(&transcript_hash, S2N_HASH_SHA256));
    EXPECT_SUCCESS(s2n_hash_copy(&transcript_hash_snapshot, &transcript_hash));
    EXPECT_SUCCESS(s2n_hash_digest(&transcript_hash_snapshot, digest_buf, SHA256_DIGEST_LENGTH));

    uint8_t salt_buf[32] = { 0 };
    struct s2n_blob salt = { 0 };

    uint8_t ikm_buf[32] = { 0 };
    struct s2n_blob ikm = { 0 };

    uint8_t output_buf[SHA256_DIGEST_LENGTH] = { 0 };
    struct s2n_blob output = { 0 };

    EXPECT_SUCCESS(s2n_blob_init(&salt, salt_buf, sizeof(salt_buf)));
    EXPECT_SUCCESS(s2n_blob_init(&ikm, ikm_buf, sizeof(ikm_buf)));
    EXPECT_SUCCESS(s2n_blob_init(&digest, digest_buf, sizeof(digest_buf)));
    EXPECT_SUCCESS(s2n_blob_init(&secret, secret_buf, sizeof(secret_buf)));
    EXPECT_SUCCESS(s2n_blob_init(&output, output_buf, sizeof(output_buf)));

    struct s2n_hmac_state throwaway;
    EXPECT_SUCCESS(s2n_hmac_new(&throwaway));

    /* Validate the early secret */
    EXPECT_SUCCESS(s2n_hkdf_extract(&throwaway, S2N_HMAC_SHA256, &salt, &ikm, &secret));
    EXPECT_EQUAL(memcmp(secret_buf, expected_secret, sizeof(secret_buf)), 0);

    /* Validate the derived secret */
    S2N_BLOB_LABEL(label, "derived");

    struct s2n_hmac_state hmac = {0};

    EXPECT_SUCCESS(s2n_hmac_new(&hmac));
    EXPECT_SUCCESS(s2n_hkdf_expand_label(&hmac, S2N_HMAC_SHA256, &secret, &label, &digest, &output));

    EXPECT_EQUAL(memcmp(output_buf, expected_expanded, sizeof(output_buf)), 0);

    EXPECT_SUCCESS(s2n_hmac_free(&throwaway));
    EXPECT_SUCCESS(s2n_hmac_free(&hmac));
    EXPECT_SUCCESS(s2n_hash_free(&transcript_hash));
    EXPECT_SUCCESS(s2n_hash_free(&transcript_hash_snapshot));

    END_TEST();
}
