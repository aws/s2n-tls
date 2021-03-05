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

/* Include source to test static methods. */
#include "tls/extensions/s2n_client_psk.c"

#define TEST_BYTES 0x01, 0xFF, 0x23
#define TEST_BYTES_SIZE 0x00, 0x03

#define TEST_BYTES_2 0x0A, 0x0B, 0x0C
#define TEST_BYTES_SIZE_2 0x00, 0x03

struct s2n_psk_test_case {
    s2n_hmac_algorithm hmac_alg;
    uint8_t hash_size;
    const uint8_t* identity;
    size_t identity_size;
};

uint16_t s2n_test_customer_wire_index_choice;
static int s2n_test_select_psk_identity_callback(struct s2n_connection *conn,
        struct s2n_offered_psk_list *psk_identity_list, uint16_t *chosen_wire_index)
{
    *chosen_wire_index = s2n_test_customer_wire_index_choice;
    return S2N_SUCCESS;
}

static int s2n_test_error_select_psk_identity_callback(struct s2n_connection *conn,
        struct s2n_offered_psk_list *psk_identity_list, uint16_t *chosen_wire_index)
{
    POSIX_BAIL(S2N_ERR_UNIMPLEMENTED);
}

static S2N_RESULT s2n_write_test_identity(struct s2n_stuffer *out, struct s2n_blob *identity)
{
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, identity->size));
    RESULT_GUARD_POSIX(s2n_stuffer_write(out, identity));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint32(out, 0));
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    uint8_t test_bytes_data[] = { TEST_BYTES };
    uint8_t test_bytes_data_2[] = { TEST_BYTES_2 };
    uint8_t test_identity[] = "test identity";
    uint8_t test_identity_2[] = "another identity";
    uint8_t test_identity_3[] = "identity 3";
    uint8_t test_secret[] = "test secret";

    uint8_t single_wire_identity[] = {
        TEST_BYTES_SIZE,        /* identity size */
        TEST_BYTES,             /* identity */
        0x00, 0x00, 0x00, 0x00, /* ticket_age */
    };

    uint8_t wire_identities[] = {
        0x00, 0x01,             /* identity size */
        0x01,                   /* identity */
        0x00, 0x00, 0x00, 0x00, /* ticket_age */

        0x00, 0x01,             /* identity size */
        0xFF,                   /* identity */
        0x00, 0x00, 0x00, 0x00, /* ticket_age */

        TEST_BYTES_SIZE,        /* identity size */
        TEST_BYTES,             /* identity */
        0x00, 0x00, 0x00, 0x00, /* ticket_age */

        TEST_BYTES_SIZE,        /* identity size */
        TEST_BYTES,             /* identity */
        0x00, 0x00, 0x00, 0x00, /* ticket_age */

        0x00, 0x02,             /* identity size */
        0x00, 0x01,             /* identity */
        0x00, 0x00, 0x00, 0x00, /* ticket_age */
    };

    /* Test: s2n_client_psk_is_missing */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        /* Okay if early data not requested */
        conn->early_data_state = S2N_EARLY_DATA_NOT_REQUESTED;
        EXPECT_SUCCESS(s2n_client_psk_extension.if_missing(conn));

        /**
         *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
         *= type=test
         *# When a PSK is used and early data is allowed for that PSK, the client
         *# can send Application Data in its first flight of messages.  If the
         *# client opts to do so, it MUST supply both the "pre_shared_key" and
         *# "early_data" extensions.
         */
        conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
        EXPECT_FAILURE_WITH_ERRNO(s2n_client_psk_extension.if_missing(conn), S2N_ERR_UNSUPPORTED_EXTENSION);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: s2n_client_psk_should_send */
    {
        struct s2n_psk *psk = NULL;

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        EXPECT_FALSE(s2n_client_psk_extension.should_send(NULL));

        conn->actual_protocol_version = S2N_TLS12;
        EXPECT_FALSE(s2n_client_psk_extension.should_send(conn));
        conn->actual_protocol_version = S2N_TLS13;
        EXPECT_FALSE(s2n_client_psk_extension.should_send(conn));

        EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &psk));

        conn->actual_protocol_version = S2N_TLS12;
        EXPECT_FALSE(s2n_client_psk_extension.should_send(conn));
        conn->actual_protocol_version = S2N_TLS13;
        EXPECT_TRUE(s2n_client_psk_extension.should_send(conn));

        /* Only send the extension after a retry if at least one PSK matches the cipher suite */
        {
            conn->secure.cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
            const s2n_hmac_algorithm matching_hmac_alg = conn->secure.cipher_suite->prf_alg;
            const s2n_hmac_algorithm different_hmac_alg = conn->secure.cipher_suite->prf_alg + 1;

            /* Do send if the PSK does NOT match the cipher suite, but this is NOT a retry */
            conn->handshake.handshake_type = INITIAL;
            psk->hmac_alg = different_hmac_alg;
            EXPECT_TRUE(s2n_client_psk_extension.should_send(conn));

            /* Do send if the PSK matches the cipher suite */
            conn->handshake.handshake_type = HELLO_RETRY_REQUEST;
            psk->hmac_alg = matching_hmac_alg;
            EXPECT_TRUE(s2n_client_psk_extension.should_send(conn));

            /* Do NOT send if the PSK does NOT match the cipher suite */
            conn->handshake.handshake_type = HELLO_RETRY_REQUEST;
            psk->hmac_alg = different_hmac_alg;
            EXPECT_FALSE(s2n_client_psk_extension.should_send(conn));

            /* Do send if there are two PSKs, and one matches the cipher suite */
            conn->handshake.handshake_type = HELLO_RETRY_REQUEST;
            psk->hmac_alg = different_hmac_alg;
            EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &psk));
            psk->hmac_alg = matching_hmac_alg;
            EXPECT_TRUE(s2n_client_psk_extension.should_send(conn));
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: s2n_client_psk_send */
    {
        /* Send a single PSK identity */
        {
            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            struct s2n_psk *psk = NULL;
            EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &psk));
            EXPECT_OK(s2n_psk_init(psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_set_identity(psk, test_identity, sizeof(test_identity)));
            psk->hmac_alg = S2N_HMAC_SHA384;

            EXPECT_SUCCESS(s2n_client_psk_extension.send(conn, &out));

            uint32_t offered_psks_size = 0;
            EXPECT_OK(s2n_psk_parameters_offered_psks_size(&conn->psk_params, &offered_psks_size));
            EXPECT_EQUAL(offered_psks_size, s2n_stuffer_data_available(&out));

            uint16_t identity_list_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&out, &identity_list_size));

            uint16_t identity_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&out, &identity_size));
            EXPECT_EQUAL(identity_size, sizeof(test_identity));

            uint8_t *identity_data;
            EXPECT_NOT_NULL(identity_data = s2n_stuffer_raw_read(&out, identity_size));
            EXPECT_BYTEARRAY_EQUAL(identity_data, test_identity, sizeof(test_identity));

            uint32_t obfuscated_ticket_age = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint32(&out, &obfuscated_ticket_age));
            EXPECT_EQUAL(obfuscated_ticket_age, 0);

            EXPECT_EQUAL(s2n_stuffer_data_available(&out),
                    SHA384_DIGEST_LENGTH /* binder size */
                    + sizeof(uint8_t) /* size of binder size */
                    + sizeof(uint16_t)) /* size of binder list size */;

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        }

        /* Send multiple PSK identities */
        {
            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            struct s2n_psk_test_case test_cases[] = {
                    { .hmac_alg = S2N_HMAC_SHA224, .hash_size = SHA224_DIGEST_LENGTH,
                            .identity = test_identity, .identity_size = sizeof(test_identity) },
                    { .hmac_alg = S2N_HMAC_SHA384, .hash_size = SHA384_DIGEST_LENGTH,
                            .identity = test_identity_2, .identity_size =  sizeof(test_identity_2)},
            };

            uint16_t binder_list_size = 0;
            for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
                struct s2n_psk *psk = NULL;
                EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &psk));
                EXPECT_OK(s2n_psk_init(psk, S2N_PSK_TYPE_EXTERNAL));
                EXPECT_SUCCESS(s2n_psk_set_identity(psk, test_cases[i].identity, test_cases[i].identity_size));
                psk->hmac_alg = test_cases[i].hmac_alg;

                binder_list_size += test_cases[i].hash_size
                        + sizeof(uint8_t) /* size of binder size */;
            }

            EXPECT_SUCCESS(s2n_client_psk_extension.send(conn, &out));

            uint32_t offered_psks_size = 0;
            EXPECT_OK(s2n_psk_parameters_offered_psks_size(&conn->psk_params, &offered_psks_size));
            EXPECT_EQUAL(offered_psks_size, s2n_stuffer_data_available(&out));

            uint16_t identity_list_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&out, &identity_list_size));

            for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
                uint16_t identity_size = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_uint16(&out, &identity_size));
                EXPECT_EQUAL(identity_size, test_cases[i].identity_size);

                uint8_t *identity_data;
                EXPECT_NOT_NULL(identity_data = s2n_stuffer_raw_read(&out, identity_size));
                EXPECT_BYTEARRAY_EQUAL(identity_data, test_cases[i].identity, test_cases[i].identity_size);

                uint32_t obfuscated_ticket_age = 0;
                EXPECT_SUCCESS(s2n_stuffer_read_uint32(&out, &obfuscated_ticket_age));
                EXPECT_EQUAL(obfuscated_ticket_age, 0);
            }

            EXPECT_EQUAL(s2n_stuffer_data_available(&out),
                    binder_list_size /* binder list size */
                    + sizeof(uint16_t)) /* size of binder list size */;

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        }

        /* On the second ClientHello after a retry request,
         * do not send any PSKs that do not match the cipher suite.
         *
         *= https://tools.ietf.org/rfc/rfc8446#section-4.1.4
         *= type=test
         *# In addition, in its updated ClientHello, the client SHOULD NOT offer
         *# any pre-shared keys associated with a hash other than that of the
         *# selected cipher suite.
         */
        {
            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            const struct s2n_psk_test_case matching_psk = {
                    .hmac_alg = S2N_HMAC_SHA384, .hash_size = SHA384_DIGEST_LENGTH,
                    .identity = test_identity, .identity_size = sizeof(test_identity)
            };
            const struct s2n_psk_test_case non_matching_psk = {
                    .hmac_alg = S2N_HMAC_SHA224, .hash_size = SHA224_DIGEST_LENGTH,
                    .identity = test_identity, .identity_size = sizeof(test_identity)
            };
            struct s2n_psk_test_case test_cases[] = { matching_psk, non_matching_psk };

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            conn->handshake.handshake_type = HELLO_RETRY_REQUEST;
            conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            EXPECT_EQUAL(conn->secure.cipher_suite->prf_alg, matching_psk.hmac_alg);

            for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
                struct s2n_psk *psk = NULL;
                EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &psk));
                EXPECT_OK(s2n_psk_init(psk, S2N_PSK_TYPE_EXTERNAL));
                EXPECT_SUCCESS(s2n_psk_set_identity(psk, test_cases[i].identity, test_cases[i].identity_size));
                psk->hmac_alg = test_cases[i].hmac_alg;
            }

            EXPECT_SUCCESS(s2n_client_psk_extension.send(conn, &out));

            /* The identity list should only contain the matching psk's identity.
             * It should NOT contain the non-matching psk. */

            uint16_t identity_list_size = 0;
            uint16_t identity_size = 0;
            uint8_t *identity_data = NULL;
            uint32_t obfuscated_ticket_age = 0;

            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&out, &identity_list_size));
            EXPECT_EQUAL(identity_list_size, sizeof(identity_size) + matching_psk.identity_size + sizeof(obfuscated_ticket_age));

            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&out, &identity_size));
            EXPECT_EQUAL(identity_size, matching_psk.identity_size);
            EXPECT_NOT_NULL(identity_data = s2n_stuffer_raw_read(&out, identity_size));
            EXPECT_BYTEARRAY_EQUAL(identity_data, matching_psk.identity, matching_psk.identity_size);

            EXPECT_SUCCESS(s2n_stuffer_read_uint32(&out, &obfuscated_ticket_age));

            /* The binder list should only reserve space for the matching psk's binder.
             * It should NOT reserve space for the binder for the non-matching psk. */
            EXPECT_EQUAL(s2n_stuffer_data_available(&out),
                    matching_psk.hash_size
                    + sizeof(uint8_t) /* size of binder size */
                    + sizeof(uint16_t)) /* size of binder list size */;

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        }
    }

    /* Test: s2n_match_psk_identity */
    {
        struct s2n_psk_parameters params = { 0 };
        EXPECT_OK(s2n_psk_parameters_init(&params));

        struct s2n_array *known_psks = &params.psk_list;

        struct s2n_blob wire_identity = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&wire_identity, test_identity, sizeof(test_identity)));

        /* Safety checks */
        {
            struct s2n_psk *match = NULL;
            EXPECT_ERROR_WITH_ERRNO(s2n_match_psk_identity(NULL, &wire_identity, &match), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_match_psk_identity(known_psks, NULL, &match), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_match_psk_identity(known_psks, &wire_identity, NULL), S2N_ERR_NULL);
        }

        /* Test: No known PSKs */
        {
            struct s2n_psk *match = NULL;
            EXPECT_OK(s2n_match_psk_identity(known_psks, &wire_identity, &match));
            EXPECT_NULL(match);
        }

        /* Test: No match exists */
        {
            struct s2n_psk *different_identity = NULL;
            EXPECT_OK(s2n_array_pushback(known_psks, (void**) &different_identity));
            EXPECT_OK(s2n_psk_init(different_identity, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_set_identity(different_identity, test_identity_2, sizeof(test_identity_2)));

            struct s2n_psk *match = NULL;
            EXPECT_OK(s2n_match_psk_identity(known_psks, &wire_identity, &match));
            EXPECT_NULL(match);
        }

        struct s2n_psk *expected_match = NULL;

        /* Test: Match exists */
        {
            EXPECT_OK(s2n_array_pushback(known_psks, (void**) &expected_match));
            EXPECT_OK(s2n_psk_init(expected_match, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_set_identity(expected_match, test_identity, sizeof(test_identity)));

            struct s2n_psk *match = NULL;
            EXPECT_OK(s2n_match_psk_identity(known_psks, &wire_identity, &match));
            EXPECT_EQUAL(match, expected_match);
        }

        /* Test: Multiple matches exist */
        {
            struct s2n_psk *another_match = NULL;
            EXPECT_OK(s2n_array_pushback(known_psks, (void**) &another_match));
            EXPECT_OK(s2n_psk_init(another_match, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_set_identity(another_match, test_identity, sizeof(test_identity)));

            struct s2n_psk *match = NULL;
            EXPECT_OK(s2n_match_psk_identity(known_psks, &wire_identity, &match));
            EXPECT_EQUAL(match, expected_match);
        }

        EXPECT_OK(s2n_psk_parameters_wipe(&params));
    }

    /* Test: s2n_select_psk_identity */
    {
        /* Safety checks */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            EXPECT_ERROR_WITH_ERRNO(s2n_select_psk_identity(conn, NULL), S2N_ERR_NULL);

            struct s2n_offered_psk_list wire_identity_list = { 0 };
            EXPECT_ERROR_WITH_ERRNO(s2n_select_psk_identity(NULL, &wire_identity_list), S2N_ERR_NULL);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        struct s2n_blob identity_1 = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&identity_1, test_identity, sizeof(test_identity)));
        struct s2n_blob identity_2 = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&identity_2, test_identity_2, sizeof(test_identity_2)));
        struct s2n_blob identity_3 = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&identity_3, test_identity_3, sizeof(test_identity_3)));

        struct s2n_blob *all_psks_list[] = { &identity_1, &identity_2, &identity_3 };
        struct s2n_blob *reverse_order_list[] = { &identity_3, &identity_2, &identity_1 };
        struct s2n_blob *list_without_psk1[] = { &identity_2, &identity_3 };
        struct s2n_blob *multiple_psk1[] = { &identity_1, &identity_1, &identity_1 };
        struct s2n_blob *multiple_psk2[] = { &identity_2, &identity_2, &identity_2 };
        struct s2n_blob *only_psk1[] = { &identity_1 };
        struct s2n_blob *only_psk2[] = { &identity_2 };
        struct s2n_blob *only_psk3[] = { &identity_3 };

        struct {
            bool match;
            struct s2n_blob **wire_identities;
            size_t wire_identities_len;
            struct s2n_blob **local_identities;
            size_t local_identities_len;
            size_t wire_match_index;
            size_t local_match_index;
        } test_cases[] = {
#define WIRE_IDENTITIES(list) .wire_identities = list, .wire_identities_len = s2n_array_len(list)
#define LOCAL_IDENTITIES(list) .local_identities = list, .local_identities_len = s2n_array_len(list)
            /* No wire or local identities */
            { .match = false },

            /* Only wire identities */
            { .match = false, WIRE_IDENTITIES(only_psk1) },
            { .match = false, WIRE_IDENTITIES(all_psks_list) },

            /* Only local identities */
            { .match = false, LOCAL_IDENTITIES(only_psk1) },
            { .match = false, LOCAL_IDENTITIES(all_psks_list) },

            /* No match with valid lists */
            { .match = false, WIRE_IDENTITIES(only_psk1), LOCAL_IDENTITIES(only_psk2) },
            { .match = false, WIRE_IDENTITIES(only_psk1), LOCAL_IDENTITIES(list_without_psk1) },
            { .match = false, WIRE_IDENTITIES(list_without_psk1), LOCAL_IDENTITIES(only_psk1) },

            /* Single option matches */
            { .match = true, WIRE_IDENTITIES(only_psk1), LOCAL_IDENTITIES(only_psk1),
                    .wire_match_index = 0, .local_match_index = 0 },

            /* Single wire option matches */
            { .match = true, WIRE_IDENTITIES(only_psk1), LOCAL_IDENTITIES(all_psks_list),
                    .wire_match_index = 0, .local_match_index = 0 },
            { .match = true, WIRE_IDENTITIES(only_psk2), LOCAL_IDENTITIES(all_psks_list),
                    .wire_match_index = 0, .local_match_index = 1 },
            { .match = true, WIRE_IDENTITIES(only_psk3), LOCAL_IDENTITIES(all_psks_list),
                    .wire_match_index = 0, .local_match_index = 2 },

            /* Single local option matches */
            { .match = true, WIRE_IDENTITIES(all_psks_list), LOCAL_IDENTITIES(only_psk1),
                    .wire_match_index = 0, .local_match_index = 0 },
            { .match = true, WIRE_IDENTITIES(all_psks_list), LOCAL_IDENTITIES(only_psk2),
                    .wire_match_index = 1, .local_match_index = 0 },
            { .match = true, WIRE_IDENTITIES(all_psks_list), LOCAL_IDENTITIES(only_psk3),
                    .wire_match_index = 2, .local_match_index = 0 },

            /* Match with multiple wire and local options: choose first local */
            { .match = true, WIRE_IDENTITIES(all_psks_list), LOCAL_IDENTITIES(all_psks_list),
                    .wire_match_index = 0, .local_match_index = 0 },
            { .match = true, WIRE_IDENTITIES(reverse_order_list), LOCAL_IDENTITIES(all_psks_list),
                    .wire_match_index = 2, .local_match_index = 0 },
            { .match = true, WIRE_IDENTITIES(all_psks_list), LOCAL_IDENTITIES(reverse_order_list),
                    .wire_match_index = 2, .local_match_index = 0 },
            { .match = true, WIRE_IDENTITIES(list_without_psk1), LOCAL_IDENTITIES(all_psks_list),
                    .wire_match_index = 0, .local_match_index = 1 },
            { .match = true, WIRE_IDENTITIES(all_psks_list), LOCAL_IDENTITIES(list_without_psk1),
                    .wire_match_index = 1, .local_match_index = 0 },
            { .match = true, WIRE_IDENTITIES(list_without_psk1), LOCAL_IDENTITIES(reverse_order_list),
                    .wire_match_index = 1, .local_match_index = 0 },
            { .match = true, WIRE_IDENTITIES(reverse_order_list), LOCAL_IDENTITIES(list_without_psk1),
                    .wire_match_index = 1, .local_match_index = 0 },

            /* Handle duplicates */
            { .match = true, WIRE_IDENTITIES(multiple_psk1), LOCAL_IDENTITIES(multiple_psk1),
                    .wire_match_index = 0, .local_match_index = 0 },
            { .match = false, WIRE_IDENTITIES(multiple_psk1), LOCAL_IDENTITIES(multiple_psk2)},
            { .match = true, WIRE_IDENTITIES(multiple_psk1), LOCAL_IDENTITIES(all_psks_list),
                    .wire_match_index = 0, .local_match_index = 0 },
            { .match = true, WIRE_IDENTITIES(all_psks_list), LOCAL_IDENTITIES(multiple_psk1),
                    .wire_match_index = 0, .local_match_index = 0 },
            { .match = true, WIRE_IDENTITIES(multiple_psk1), LOCAL_IDENTITIES(reverse_order_list),
                    .wire_match_index = 0, .local_match_index = 2 },
            { .match = true, WIRE_IDENTITIES(reverse_order_list), LOCAL_IDENTITIES(multiple_psk1),
                    .wire_match_index = 2, .local_match_index = 0 },
        };

        for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            struct s2n_offered_psk_list client_identity_list = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&client_identity_list.wire_data, 0));
            for (size_t wire_i = 0; wire_i < test_cases[i].wire_identities_len; wire_i++) {
                EXPECT_OK(s2n_write_test_identity(&client_identity_list.wire_data, test_cases[i].wire_identities[wire_i]));
            }

            struct s2n_psk *expected_chosen_psk = NULL;
            for (size_t local_i = 0; local_i < test_cases[i].local_identities_len; local_i++) {
                struct s2n_psk *server_psk = NULL;
                EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &server_psk));
                EXPECT_NOT_NULL(server_psk);
                EXPECT_SUCCESS(s2n_psk_set_identity(server_psk, test_cases[i].local_identities[local_i]->data,
                        test_cases[i].local_identities[local_i]->size));

                if (local_i == test_cases[i].local_match_index) {
                    expected_chosen_psk = server_psk;
                }
            }

            if (test_cases[i].match) {
                EXPECT_OK(s2n_select_psk_identity(conn, &client_identity_list));
                EXPECT_EQUAL(conn->psk_params.chosen_psk_wire_index, test_cases[i].wire_match_index);
                EXPECT_EQUAL(conn->psk_params.chosen_psk, expected_chosen_psk);
            } else {
                EXPECT_ERROR(s2n_select_psk_identity(conn, &client_identity_list));
                EXPECT_NULL(conn->psk_params.chosen_psk);
            }

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&client_identity_list.wire_data));
        }
    }

    /* Test: s2n_client_psk_recv_identity_list */
    {
        /* Safety checks */
        {
            struct s2n_stuffer wire_identities_in = { 0 };

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            EXPECT_ERROR_WITH_ERRNO(s2n_client_psk_recv_identity_list(conn, NULL), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_client_psk_recv_identity_list(NULL, &wire_identities_in), S2N_ERR_NULL);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Receive an empty list */
        {
            struct s2n_stuffer empty_wire_identities_in = { 0 };

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            EXPECT_ERROR(s2n_client_psk_recv_identity_list(conn, &empty_wire_identities_in));
            EXPECT_NULL(conn->psk_params.chosen_psk);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Default selection logic: receive a list without a match */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            struct s2n_stuffer wire_identities_in = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_alloc(&wire_identities_in, sizeof(wire_identities)));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&wire_identities_in, wire_identities, sizeof(wire_identities)));

            struct s2n_psk *no_match_psk = NULL;
            EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &no_match_psk));
            EXPECT_OK(s2n_psk_init(no_match_psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_set_identity(no_match_psk, test_bytes_data_2, sizeof(test_bytes_data_2)));

            EXPECT_ERROR_WITH_ERRNO(s2n_client_psk_recv_identity_list(conn, &wire_identities_in), S2N_ERR_NULL);
            EXPECT_NULL(conn->psk_params.chosen_psk);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&wire_identities_in));
        }

        /* Default selection logic: receive a list with a match */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            struct s2n_stuffer wire_identities_in = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_alloc(&wire_identities_in, sizeof(single_wire_identity)));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&wire_identities_in, single_wire_identity, sizeof(single_wire_identity)));

            struct s2n_psk *match_psk = NULL;
            EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &match_psk));
            EXPECT_OK(s2n_psk_init(match_psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_set_identity(match_psk, test_bytes_data, sizeof(test_bytes_data)));

            EXPECT_OK(s2n_client_psk_recv_identity_list(conn, &wire_identities_in));
            EXPECT_EQUAL(conn->psk_params.chosen_psk_wire_index, 0);
            EXPECT_EQUAL(conn->psk_params.chosen_psk, match_psk);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&wire_identities_in));
        }

        /* Customer selection logic: customer rejects all identities */
        {
            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_psk_selection_callback(config, s2n_test_error_select_psk_identity_callback));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            struct s2n_stuffer wire_identities_in = { 0 };
            EXPECT_ERROR_WITH_ERRNO(s2n_client_psk_recv_identity_list(conn, &wire_identities_in),
                    S2N_ERR_UNIMPLEMENTED);
            EXPECT_EQUAL(conn->psk_params.chosen_psk, NULL);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_stuffer_free(&wire_identities_in));
        }

        /* Customer selection logic: customer selects valid identity */
        {
            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_psk_selection_callback(config, s2n_test_select_psk_identity_callback));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            struct s2n_psk *match_psk = NULL;
            EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &match_psk));
            EXPECT_OK(s2n_psk_init(match_psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_set_identity(match_psk, test_bytes_data, sizeof(test_bytes_data)));

            struct s2n_stuffer wire_identities_in = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&wire_identities_in, 0));
            EXPECT_OK(s2n_write_test_identity(&wire_identities_in, &match_psk->identity));

            s2n_test_customer_wire_index_choice = 0;
            EXPECT_OK(s2n_client_psk_recv_identity_list(conn, &wire_identities_in));
            EXPECT_EQUAL(conn->psk_params.chosen_psk, match_psk);
            EXPECT_EQUAL(conn->psk_params.chosen_psk_wire_index, 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_stuffer_free(&wire_identities_in));
        }

        /* Customer selection logic: customer selects out of bounds index */
        {
            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_psk_selection_callback(config, s2n_test_select_psk_identity_callback));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            struct s2n_psk *match_psk = NULL;
            EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &match_psk));
            EXPECT_OK(s2n_psk_init(match_psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_set_identity(match_psk, test_bytes_data, sizeof(test_bytes_data)));

            struct s2n_stuffer wire_identities_in = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&wire_identities_in, 0));
            EXPECT_OK(s2n_write_test_identity(&wire_identities_in, &match_psk->identity));

            s2n_test_customer_wire_index_choice = 10;
            EXPECT_ERROR(s2n_client_psk_recv_identity_list(conn, &wire_identities_in));
            EXPECT_EQUAL(conn->psk_params.chosen_psk, NULL);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_stuffer_free(&wire_identities_in));
        }

        /* Customer selection logic: customer selects index without a local match */
        {
            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_psk_selection_callback(config, s2n_test_select_psk_identity_callback));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            struct s2n_psk *local_psk = NULL;
            EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &local_psk));
            EXPECT_OK(s2n_psk_init(local_psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_set_identity(local_psk, test_bytes_data, sizeof(test_bytes_data)));

            struct s2n_blob wire_identity = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&wire_identity, test_bytes_data_2, sizeof(test_bytes_data_2)));

            struct s2n_stuffer wire_identities_in = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&wire_identities_in, 0));
            EXPECT_OK(s2n_write_test_identity(&wire_identities_in, &wire_identity));

            s2n_test_customer_wire_index_choice = 0;
            EXPECT_ERROR(s2n_client_psk_recv_identity_list(conn, &wire_identities_in));
            EXPECT_EQUAL(conn->psk_params.chosen_psk, NULL);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_stuffer_free(&wire_identities_in));
        }
    }

    /* Test: s2n_client_psk_recv_binder_list */
    {
        const uint8_t filler_binders[] = {
                0x00, /* binder size */

                0x01, /* binder size */
                0xFF, /* binder value */
        };
        const size_t zero_length_binder_index = 0;
        const size_t valid_binder_index = 2;

        uint8_t partial_client_hello_data[] = "Hello";
        uint8_t secret_data[] = "Secret";
        uint8_t binder_hash_data[SHA256_DIGEST_LENGTH] = { 0 };
        uint8_t valid_binder_data[SHA256_DIGEST_LENGTH] = { 0 };

        struct s2n_blob partial_client_hello = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&partial_client_hello,
                partial_client_hello_data, sizeof(partial_client_hello_data)));

        struct s2n_blob binder_hash = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&binder_hash, binder_hash_data, sizeof(binder_hash_data)));

        struct s2n_blob valid_binder = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&valid_binder, valid_binder_data, sizeof(valid_binder_data)));

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        DEFER_CLEANUP(struct s2n_psk psk = { 0 }, s2n_psk_wipe);
        EXPECT_OK(s2n_psk_init(&psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_set_secret(&psk, secret_data, sizeof(secret_data)));

        EXPECT_SUCCESS(s2n_psk_calculate_binder_hash(conn, psk.hmac_alg, &partial_client_hello, &binder_hash));
        EXPECT_SUCCESS(s2n_psk_calculate_binder(&psk, &binder_hash, &valid_binder));

        struct s2n_stuffer wire_binders_in = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&wire_binders_in, sizeof(filler_binders)));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&wire_binders_in, filler_binders, sizeof(filler_binders)));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(&wire_binders_in, valid_binder.size));
        EXPECT_SUCCESS(s2n_stuffer_write(&wire_binders_in, &valid_binder));

        /* Receive an empty list */
        {
            uint8_t empty_wire_binders[] = { 0 };
            conn->psk_params.chosen_psk = &psk;
            conn->psk_params.chosen_psk_wire_index = valid_binder_index;

            struct s2n_stuffer empty_wire_binders_in = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_alloc(&empty_wire_binders_in, sizeof(empty_wire_binders)));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&empty_wire_binders_in, empty_wire_binders, sizeof(empty_wire_binders)));

            EXPECT_ERROR_WITH_ERRNO(s2n_client_psk_recv_binder_list(conn, &partial_client_hello, &empty_wire_binders_in),
                    S2N_ERR_BAD_MESSAGE);

            EXPECT_SUCCESS(s2n_stuffer_free(&empty_wire_binders_in));
        }

        /* No chosen identity */
        {
            EXPECT_SUCCESS(s2n_stuffer_reread(&wire_binders_in));
            conn->psk_params.chosen_psk = NULL;
            conn->psk_params.chosen_psk_wire_index = 0;

            EXPECT_ERROR_WITH_ERRNO(s2n_client_psk_recv_binder_list(conn, &partial_client_hello, &wire_binders_in),
                    S2N_ERR_NULL);
        }

        /* Binder list too short for chosen identity index */
        {
            EXPECT_SUCCESS(s2n_stuffer_reread(&wire_binders_in));
            conn->psk_params.chosen_psk = &psk;
            conn->psk_params.chosen_psk_wire_index = valid_binder_index + 10;

            EXPECT_ERROR_WITH_ERRNO(s2n_client_psk_recv_binder_list(conn, &partial_client_hello, &wire_binders_in),
                    S2N_ERR_BAD_MESSAGE);
        }

        /* Binder for chosen identity is zero-length */
        {
            EXPECT_SUCCESS(s2n_stuffer_reread(&wire_binders_in));
            conn->psk_params.chosen_psk = &psk;
            conn->psk_params.chosen_psk_wire_index = zero_length_binder_index;

            EXPECT_ERROR_WITH_ERRNO(s2n_client_psk_recv_binder_list(conn, &partial_client_hello, &wire_binders_in),
                    S2N_ERR_SAFETY);
        }

        /* Binder for chosen identity is invalid */
        {
            EXPECT_SUCCESS(s2n_stuffer_reread(&wire_binders_in));
            conn->psk_params.chosen_psk = &psk;
            conn->psk_params.chosen_psk_wire_index = valid_binder_index;

            /* Using a different partial client hello produces a different binder */
            struct s2n_blob *different_partial_client_hello = &valid_binder;

            EXPECT_ERROR_WITH_ERRNO(s2n_client_psk_recv_binder_list(conn, different_partial_client_hello, &wire_binders_in),
                    S2N_ERR_BAD_MESSAGE);
        }

        /* Binder for chosen identity is valid */
        {
            EXPECT_SUCCESS(s2n_stuffer_reread(&wire_binders_in));
            conn->psk_params.chosen_psk = &psk;
            conn->psk_params.chosen_psk_wire_index = valid_binder_index;

            EXPECT_OK(s2n_client_psk_recv_binder_list(conn, &partial_client_hello, &wire_binders_in));
        }

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&wire_binders_in));
    }

    /* Test: s2n_client_psk_recv */
    {
        const uint8_t client_hello_data[] = "ClientHello";
        s2n_extension_type_id key_share_id;
        s2n_extension_type_id psk_ke_mode_id;
        EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES, &psk_ke_mode_id));
        EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(TLS_EXTENSION_KEY_SHARE, &key_share_id));

        /* Receive an extension with no valid identity */
        {
            const uint8_t extension_data[] = {
                    0x00, 0x00,             /* identity list size */
                    0x00, 0x00,             /* binder list size */
            };

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->client_hello.extensions.count = 1;

            /* The psk key exchange modes and keyshare extensions need to be received to use a psk */
            conn->psk_params.psk_ke_mode = S2N_PSK_DHE_KE;
            S2N_CBIT_SET(conn->extension_requests_received, psk_ke_mode_id);
            S2N_CBIT_SET(conn->extension_requests_received, key_share_id);

            /* Setup the ClientHello */
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->handshake.io, client_hello_data, sizeof(client_hello_data)));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->handshake.io, extension_data, sizeof(extension_data)));

            /* Setup the extension */
            struct s2n_stuffer extension = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&extension, extension_data, sizeof(extension_data)));

            /* Verify it is successful, but no PSK is chosen */
            EXPECT_SUCCESS(s2n_client_psk_recv(conn, &extension));
            EXPECT_EQUAL(conn->psk_params.chosen_psk_wire_index, 0);
            EXPECT_EQUAL(conn->psk_params.chosen_psk, NULL);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&extension));
        }

        /* Receive an extension with an invalid binder */
        /* Receive an extension when running with TLS1.2 */
        {
            const uint8_t identity = 0x12;
            const uint8_t identity_bytes[] = { identity };
            const uint8_t extension_data[] = {
                    0x00, 0x07,             /* identity list size */
                    0x00, 0x01,             /* identity size */
                    identity,               /* identity */
                    0x00, 0x00, 0x00, 0x00, /* ticket_age */
                    0x00, 0x00,             /* binder list size */
            };

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->client_hello.extensions.count = 1;

            /* The psk_ke_modes and keyshare extensions need to be received to use a psk */
            conn->psk_params.psk_ke_mode = S2N_PSK_DHE_KE;
            S2N_CBIT_SET(conn->extension_requests_received, psk_ke_mode_id);
            S2N_CBIT_SET(conn->extension_requests_received, key_share_id);

            /* Setup the ClientHello */
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->handshake.io, client_hello_data, sizeof(client_hello_data)));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->handshake.io, extension_data, sizeof(extension_data)));

            /* Setup the extension */
            struct s2n_stuffer extension = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&extension, extension_data, sizeof(extension_data)));

            struct s2n_psk *psk = NULL;
            EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &psk));
            EXPECT_OK(s2n_psk_init(psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_set_identity(psk, identity_bytes, sizeof(identity_bytes)));

            /* Should be a no-op if using TLS1.2 */
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_client_psk_recv(conn, &extension));
            EXPECT_NULL(conn->psk_params.chosen_psk);
            EXPECT_EQUAL(s2n_stuffer_data_available(&extension), sizeof(extension_data));

            /* Should be a failure if using TLS1.3 */
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_FAILURE_WITH_ERRNO(s2n_client_psk_recv(conn, &extension), S2N_ERR_BAD_MESSAGE);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&extension));
        }

        /* Receive a psk extension with no psk_ke_modes extension */
        {
            const uint8_t extension_data[] = { 0 };

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->client_hello.extensions.count = 1;

            /* Setup the extension */
            struct s2n_stuffer extension = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&extension, extension_data, sizeof(extension_data)));

            EXPECT_EQUAL(conn->psk_params.psk_ke_mode, S2N_PSK_KE_UNKNOWN);

            EXPECT_FALSE(S2N_CBIT_TEST(conn->extension_requests_received, psk_ke_mode_id));

            EXPECT_FAILURE_WITH_ERRNO(s2n_client_psk_recv(conn, &extension), S2N_ERR_MISSING_EXTENSION);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&extension));
        }

        /* Receive a psk extension with an unknown psk key exchange mode */
        {
            const uint8_t extension_data[] = { 0 };
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->client_hello.extensions.count = 1;

            /* Setup the extension */
            struct s2n_stuffer extension = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&extension, extension_data, sizeof(extension_data)));

            conn->psk_params.psk_ke_mode = S2N_PSK_KE_UNKNOWN;

            S2N_CBIT_SET(conn->extension_requests_received, psk_ke_mode_id);

            EXPECT_SUCCESS(s2n_client_psk_recv(conn, &extension));
            EXPECT_NULL(conn->psk_params.chosen_psk);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&extension));
        }

        /* Receive a psk extension and a psk key exchange extension with (EC)DHE key establishment but no 
         * keyshare_extension */
        {
            const uint8_t extension_data[] = { 0 };
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->client_hello.extensions.count = 1;

            /* Setup the extension */
            struct s2n_stuffer extension = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&extension, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&extension, extension_data, sizeof(extension_data)));

            conn->psk_params.psk_ke_mode = S2N_PSK_DHE_KE;

            S2N_CBIT_SET(conn->extension_requests_received, psk_ke_mode_id);
            EXPECT_FALSE(S2N_CBIT_TEST(conn->extension_requests_received, key_share_id));

            EXPECT_FAILURE_WITH_ERRNO(s2n_client_psk_recv(conn, &extension), S2N_ERR_MISSING_EXTENSION);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&extension));
        }

        /* The extension does not appear last in the extension list */
        {
            s2n_extension_type_id psk_ext_id;
            EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(TLS_EXTENSION_PRE_SHARED_KEY, &psk_ext_id));

            struct s2n_stuffer extension = { 0 };
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            conn->client_hello.extensions.count = 2;
            conn->client_hello.extensions.parsed_extensions[psk_ext_id].wire_index = 0;
            EXPECT_FAILURE_WITH_ERRNO(s2n_client_psk_recv(conn, &extension), S2N_ERR_UNSUPPORTED_EXTENSION);

            conn->client_hello.extensions.count = 5;
            conn->client_hello.extensions.parsed_extensions[psk_ext_id].wire_index = 1;
            EXPECT_FAILURE_WITH_ERRNO(s2n_client_psk_recv(conn, &extension), S2N_ERR_UNSUPPORTED_EXTENSION);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Receive a valid extension */
        {
            const uint8_t client_hello_prefix_data[] = {
                    0x01,               /* Message Type: ClientHello */
                    0x00, 0x00, 0x00,   /* Message size: not set yet */
                    0x12, 0x34, 0x56,   /* Message: random data */
            };

            struct s2n_connection *client_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            struct s2n_stuffer *client_out = &client_conn->handshake.io;

            struct s2n_connection *server_conn;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            struct s2n_stuffer *server_in = &server_conn->handshake.io;
            server_conn->client_hello.extensions.count = 1;

            /* The psk key exchange modes and keyshare extensions need to be received to use a psk */
            server_conn->psk_params.psk_ke_mode = S2N_PSK_DHE_KE;
            S2N_CBIT_SET(server_conn->extension_requests_received, psk_ke_mode_id);
            S2N_CBIT_SET(server_conn->extension_requests_received, key_share_id);

            struct s2n_psk *shared_psk = NULL;
            EXPECT_OK(s2n_array_pushback(&client_conn->psk_params.psk_list, (void**) &shared_psk));
            EXPECT_OK(s2n_psk_init(shared_psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_set_identity(shared_psk, test_identity, sizeof(test_identity)));
            EXPECT_SUCCESS(s2n_psk_set_secret(shared_psk, test_secret, sizeof(test_secret)));
            EXPECT_OK(s2n_array_pushback(&server_conn->psk_params.psk_list, (void**) &shared_psk));
            EXPECT_OK(s2n_psk_init(shared_psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_set_identity(shared_psk, test_identity, sizeof(test_identity)));
            EXPECT_SUCCESS(s2n_psk_set_secret(shared_psk, test_secret, sizeof(test_secret)));

            struct s2n_psk *other_server_psk = NULL;
            EXPECT_OK(s2n_array_pushback(&server_conn->psk_params.psk_list, (void**) &other_server_psk));
            EXPECT_OK(s2n_psk_init(other_server_psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_set_identity(other_server_psk, test_identity_2, sizeof(test_identity_2)));

            /* Write the ClientHello prefix */
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(client_out,
                    client_hello_prefix_data, sizeof(client_hello_prefix_data)));

            EXPECT_SUCCESS(s2n_client_psk_extension.send(client_conn, client_out));
            EXPECT_OK(s2n_finish_psk_extension(client_conn));

            /* Copy the ClientHello over to the server's input buffer, but skip ClientHello prefix */
            EXPECT_SUCCESS(s2n_stuffer_copy(client_out, server_in,
                    s2n_stuffer_data_available(client_out)));
            EXPECT_SUCCESS(s2n_stuffer_skip_read(server_in, sizeof(client_hello_prefix_data)));

            EXPECT_SUCCESS(s2n_client_psk_recv(server_conn, server_in));
            EXPECT_EQUAL(server_conn->psk_params.chosen_psk_wire_index, 0);
            EXPECT_EQUAL(server_conn->psk_params.chosen_psk, shared_psk);

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        }
    }

    /* Functional test */
    {
        /* Setup connections */
        struct s2n_connection *client_conn, *server_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Setup other client PSK */
        uint8_t other_client_data[] = "other client data";
        struct s2n_psk *other_client_psk = NULL;
        EXPECT_OK(s2n_array_pushback(&client_conn->psk_params.psk_list, (void**) &other_client_psk));
        EXPECT_OK(s2n_psk_init(other_client_psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_set_identity(other_client_psk, other_client_data, sizeof(other_client_data)));
        EXPECT_SUCCESS(s2n_psk_set_secret(other_client_psk, other_client_data, sizeof(other_client_data)));

        /* Setup other server PSK */
        uint8_t other_server_data[] = "other server data";
        struct s2n_psk *other_server_psk = NULL;
        EXPECT_OK(s2n_array_pushback(&server_conn->psk_params.psk_list, (void**) &other_server_psk));
        EXPECT_OK(s2n_psk_init(other_server_psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_set_identity(other_server_psk, other_server_data, sizeof(other_server_data)));
        EXPECT_SUCCESS(s2n_psk_set_secret(other_server_psk, other_server_data, sizeof(other_server_data)));

        /* Setup shared PSK for client */
        struct s2n_psk *shared_psk = NULL;
        EXPECT_OK(s2n_array_pushback(&client_conn->psk_params.psk_list, (void**) &shared_psk));
        EXPECT_OK(s2n_psk_init(shared_psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_set_identity(shared_psk, test_identity, sizeof(test_identity)));
        EXPECT_SUCCESS(s2n_psk_set_secret(shared_psk, test_secret, sizeof(test_secret)));

        /* Setup shared PSK for server */
        EXPECT_OK(s2n_array_pushback(&server_conn->psk_params.psk_list, (void**) &shared_psk));
        EXPECT_OK(s2n_psk_init(shared_psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_set_identity(shared_psk, test_identity, sizeof(test_identity)));
        EXPECT_SUCCESS(s2n_psk_set_secret(shared_psk, test_secret, sizeof(test_secret)));

        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                s2n_stuffer_data_available(&client_conn->handshake.io)));
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

        /* Verify shared PSK chosen */
        EXPECT_EQUAL(server_conn->psk_params.chosen_psk_wire_index, 1);
        EXPECT_EQUAL(server_conn->psk_params.chosen_psk, shared_psk);
        EXPECT_EQUAL(shared_psk->secret.size, sizeof(test_secret));
        EXPECT_BYTEARRAY_EQUAL(shared_psk->secret.data, test_secret, sizeof(test_secret));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    }

    END_TEST();
}
