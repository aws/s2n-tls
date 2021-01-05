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

#include "crypto/s2n_hmac.h"
#include "tls/extensions/s2n_client_psk.h"

/* Include source to test static methods. */
#include "tls/extensions/s2n_client_psk.c"

#define TEST_BYTES 0x01, 0xFF, 0x23
#define TEST_BYTES_SIZE 0x00, 0x03

struct s2n_psk_test_case {
    s2n_hmac_algorithm hmac_alg;
    uint8_t hash_size;
    const uint8_t* identity;
    size_t identity_size;
};

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const uint8_t test_bytes_data[] = { TEST_BYTES };
    uint8_t test_identity[] = "test identity";
    uint8_t test_identity_2[] = "another identity";
    uint8_t test_secret[] = "test secret";

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
            EXPECT_SUCCESS(s2n_psk_init(psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_new_identity(psk, test_identity, sizeof(test_identity)));
            psk->hmac_alg = S2N_HMAC_SHA384;

            EXPECT_SUCCESS(s2n_client_psk_extension.send(conn, &out));

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
                EXPECT_SUCCESS(s2n_psk_init(psk, S2N_PSK_TYPE_EXTERNAL));
                EXPECT_SUCCESS(s2n_psk_new_identity(psk, test_cases[i].identity, test_cases[i].identity_size));
                psk->hmac_alg = test_cases[i].hmac_alg;

                binder_list_size += test_cases[i].hash_size
                        + sizeof(uint8_t) /* size of binder size */;
            }

            EXPECT_SUCCESS(s2n_client_psk_extension.send(conn, &out));

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
    }

    /* Test: s2n_match_psk_identity */
    {
        struct s2n_psk_parameters params = { 0 };
        EXPECT_OK(s2n_psk_parameters_init(&params));

        struct s2n_array *known_psks = &params.psk_list;

        struct s2n_blob wire_identity = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&wire_identity, test_identity, sizeof(test_identity)));

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
            EXPECT_SUCCESS(s2n_psk_init(different_identity, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_new_identity(different_identity, test_identity_2, sizeof(test_identity_2)));

            struct s2n_psk *match = NULL;
            EXPECT_OK(s2n_match_psk_identity(known_psks, &wire_identity, &match));
            EXPECT_NULL(match);
        }

        struct s2n_psk *expected_match;

        /* Test: Match exists */
        {
            EXPECT_OK(s2n_array_pushback(known_psks, (void**) &expected_match));
            EXPECT_SUCCESS(s2n_psk_init(expected_match, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_new_identity(expected_match, test_identity, sizeof(test_identity)));

            struct s2n_psk *match = NULL;
            EXPECT_OK(s2n_match_psk_identity(known_psks, &wire_identity, &match));
            EXPECT_EQUAL(match, expected_match);
        }

        /* Test: Multiple matches exist */
        {
            struct s2n_psk *another_match = NULL;
            EXPECT_OK(s2n_array_pushback(known_psks, (void**) &another_match));
            EXPECT_SUCCESS(s2n_psk_init(another_match, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_new_identity(another_match, test_identity, sizeof(test_identity)));

            struct s2n_psk *match = NULL;
            EXPECT_OK(s2n_match_psk_identity(known_psks, &wire_identity, &match));
            EXPECT_EQUAL(match, expected_match);
        }

        EXPECT_SUCCESS(s2n_psk_parameters_free(&params));
    }

    /* Test: s2n_client_psk_recv_identity_list */
    {
        const uint8_t single_wire_identity[] = {
                TEST_BYTES_SIZE,        /* identity size */
                TEST_BYTES,             /* identity */
                0x00, 0x00, 0x00, 0x00, /* ticket_age */
        };

        const uint8_t wire_identites[] = {
                0x00, 0x00,             /* identity size */
                0x00, 0x00, 0x00, 0x00, /* ticket_age */

                0x00, 0x01,             /* identity size */
                0xFF,                   /* identity */
                0x00, 0x00, 0x00, 0x00, /* ticket_age */

                TEST_BYTES_SIZE,        /* identity size */
                TEST_BYTES,             /* identity */
                0x00, 0x00, 0x00, 0x00, /* ticket_age */

                0x00, 0x02,             /* identity size */
                0x00, 0x01,             /* identity */
                0x00, 0x00, 0x00, 0x00, /* ticket_age */
        };
        const uint16_t wire_identities_match_index = 2;

        /* Receive an empty list */
        {
            struct s2n_stuffer empty_wire_identities_in = { 0 };

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            EXPECT_OK(s2n_client_psk_recv_identity_list(conn, &empty_wire_identities_in));
            EXPECT_NULL(conn->psk_params.chosen_psk);
            EXPECT_EQUAL(conn->psk_params.chosen_psk_wire_index, 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Receive a list without a match */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            struct s2n_stuffer wire_identities_in = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_alloc(&wire_identities_in, sizeof(wire_identites)));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&wire_identities_in, wire_identites, sizeof(wire_identites)));

            EXPECT_OK(s2n_client_psk_recv_identity_list(conn, &wire_identities_in));
            EXPECT_NULL(conn->psk_params.chosen_psk);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&wire_identities_in));
        }

        /* Receive a list with an immediate match */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            struct s2n_stuffer wire_identities_in = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_alloc(&wire_identities_in, sizeof(single_wire_identity)));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&wire_identities_in, single_wire_identity, sizeof(single_wire_identity)));

            struct s2n_psk *match_psk = NULL;
            EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &match_psk));
            EXPECT_SUCCESS(s2n_psk_init(match_psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_new_identity(match_psk, test_bytes_data, sizeof(test_bytes_data)));

            EXPECT_OK(s2n_client_psk_recv_identity_list(conn, &wire_identities_in));
            EXPECT_EQUAL(conn->psk_params.chosen_psk, match_psk);
            EXPECT_EQUAL(conn->psk_params.chosen_psk_wire_index, 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&wire_identities_in));
        }

        /* Receive a list with a match later in the list */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            struct s2n_stuffer wire_identities_in = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_alloc(&wire_identities_in, sizeof(wire_identites)));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&wire_identities_in, wire_identites, sizeof(wire_identites)));

            struct s2n_psk *match_psk = NULL;
            EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &match_psk));
            EXPECT_SUCCESS(s2n_psk_init(match_psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_new_identity(match_psk, test_bytes_data, sizeof(test_bytes_data)));

            EXPECT_OK(s2n_client_psk_recv_identity_list(conn, &wire_identities_in));
            EXPECT_EQUAL(conn->psk_params.chosen_psk, match_psk);
            EXPECT_EQUAL(conn->psk_params.chosen_psk_wire_index, wire_identities_match_index);

            EXPECT_SUCCESS(s2n_connection_free(conn));
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

        DEFER_CLEANUP(struct s2n_psk psk = { 0 }, s2n_psk_free);
        EXPECT_SUCCESS(s2n_psk_init(&psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_new_secret(&psk, secret_data, sizeof(secret_data)));

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
            const size_t psk_count = 10;
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

            /* Allocate some memory for the PSKs so that we can verify they're cleaned up later. */
            for (size_t i = 0; i < psk_count; i++) {
                struct s2n_psk *psk = NULL;
                EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &psk));
                EXPECT_SUCCESS(s2n_psk_init(psk, S2N_PSK_TYPE_EXTERNAL));
                EXPECT_SUCCESS(s2n_psk_new_identity(psk, test_bytes_data, sizeof(test_bytes_data)));
            }

            /* Verify it is successful, but no PSK is chosen */
            EXPECT_SUCCESS(s2n_client_psk_recv(conn, &extension));
            EXPECT_EQUAL(conn->psk_params.chosen_psk_wire_index, 0);
            EXPECT_EQUAL(conn->psk_params.chosen_psk, NULL);

            /* Verify all PSKs are cleaned up */
            for (size_t i = 0; i < psk_count; i++) {
                struct s2n_psk *psk = NULL;
                EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, i, (void**) &psk));
                EXPECT_EQUAL(psk->identity.size, 0);
                EXPECT_EQUAL(psk->identity.data, NULL);
            }

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
            EXPECT_SUCCESS(s2n_psk_init(psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_new_identity(psk, identity_bytes, sizeof(identity_bytes)));

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
            EXPECT_SUCCESS(s2n_psk_init(shared_psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_new_identity(shared_psk, test_identity, sizeof(test_identity)));
            EXPECT_SUCCESS(s2n_psk_new_secret(shared_psk, test_secret, sizeof(test_secret)));
            EXPECT_OK(s2n_array_pushback(&server_conn->psk_params.psk_list, (void**) &shared_psk));
            EXPECT_SUCCESS(s2n_psk_init(shared_psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_new_identity(shared_psk, test_identity, sizeof(test_identity)));
            EXPECT_SUCCESS(s2n_psk_new_secret(shared_psk, test_secret, sizeof(test_secret)));

            struct s2n_psk *other_server_psk = NULL;
            EXPECT_OK(s2n_array_pushback(&server_conn->psk_params.psk_list, (void**) &other_server_psk));
            EXPECT_SUCCESS(s2n_psk_init(other_server_psk, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_new_identity(other_server_psk, test_identity_2, sizeof(test_identity_2)));

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
            EXPECT_EQUAL(server_conn->psk_params.chosen_psk, shared_psk);
            EXPECT_EQUAL(server_conn->psk_params.chosen_psk_wire_index, 0);

            /* Verify the unused key is cleaned up */
            EXPECT_EQUAL(other_server_psk->identity.data, NULL);
            EXPECT_EQUAL(other_server_psk->identity.size, 0);

            /* Verify the chosen key is NOT cleaned up */
            EXPECT_NOT_EQUAL(shared_psk->identity.data, NULL);
            EXPECT_NOT_EQUAL(shared_psk->identity.size, 0);

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

        /* Setup config */
        struct s2n_cert_chain_and_key *chain_and_key = NULL;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
        struct s2n_config *config;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Setup other client PSK */
        uint8_t other_client_data[] = "other client data";
        struct s2n_psk *other_client_psk = NULL;
        EXPECT_OK(s2n_array_pushback(&client_conn->psk_params.psk_list, (void**) &other_client_psk));
        EXPECT_SUCCESS(s2n_psk_init(other_client_psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_new_identity(other_client_psk, other_client_data, sizeof(other_client_data)));
        EXPECT_SUCCESS(s2n_psk_new_secret(other_client_psk, other_client_data, sizeof(other_client_data)));

        /* Setup other server PSK */
        uint8_t other_server_data[] = "other server data";
        struct s2n_psk *other_server_psk = NULL;
        EXPECT_OK(s2n_array_pushback(&server_conn->psk_params.psk_list, (void**) &other_server_psk));
        EXPECT_SUCCESS(s2n_psk_init(other_server_psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_new_identity(other_server_psk, other_server_data, sizeof(other_server_data)));
        EXPECT_SUCCESS(s2n_psk_new_secret(other_server_psk, other_server_data, sizeof(other_server_data)));

        /* Setup shared PSK for client */
        struct s2n_psk *shared_psk = NULL;
        EXPECT_OK(s2n_array_pushback(&client_conn->psk_params.psk_list, (void**) &shared_psk));
        EXPECT_SUCCESS(s2n_psk_init(shared_psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_new_identity(shared_psk, test_identity, sizeof(test_identity)));
        EXPECT_SUCCESS(s2n_psk_new_secret(shared_psk, test_secret, sizeof(test_secret)));

        /* Setup shared PSK for server */
        EXPECT_OK(s2n_array_pushback(&server_conn->psk_params.psk_list, (void**) &shared_psk));
        EXPECT_SUCCESS(s2n_psk_init(shared_psk, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_new_identity(shared_psk, test_identity, sizeof(test_identity)));
        EXPECT_SUCCESS(s2n_psk_new_secret(shared_psk, test_secret, sizeof(test_secret)));

        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                s2n_stuffer_data_available(&client_conn->handshake.io)));
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

        /* Verify shared PSK chosen */
        EXPECT_EQUAL(server_conn->psk_params.chosen_psk, shared_psk);
        EXPECT_EQUAL(server_conn->psk_params.chosen_psk_wire_index, 1);
        EXPECT_EQUAL(shared_psk->secret.size, sizeof(test_secret));
        EXPECT_BYTEARRAY_EQUAL(shared_psk->secret.data, test_secret, sizeof(test_secret));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(config));
    }

    END_TEST();
}
