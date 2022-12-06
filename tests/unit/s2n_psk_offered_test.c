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
#include "tls/extensions/s2n_client_psk.h"

/* Include source to test static methods. */
#include "tls/s2n_psk.c"

#define MILLIS_TO_NANOS(millis) (millis * (uint64_t) ONE_MILLISEC_IN_NANOS)

static int s2n_setup_ticket_key(struct s2n_config *config)
{
    /**
     *= https://tools.ietf.org/rfc/rfc5869#appendix-A.1
     *# PRK  = 0x077709362c2e32df0ddc3f0dc47bba63
     *#        90b6c73bb50f9c3122ec844ad7c2b3e5 (32 octets)
     **/
    S2N_BLOB_FROM_HEX(ticket_key,
            "077709362c2e32df0ddc3f0dc47bba63"
            "90b6c73bb50f9c3122ec844ad7c2b3e5");

    /* Set up encryption key */
    uint64_t current_time = 0;
    uint8_t ticket_key_name[16] = "2016.07.26.15\0";

    POSIX_GUARD(s2n_config_set_session_tickets_onoff(config, 1));
    POSIX_GUARD(config->wall_clock(config->sys_clock_ctx, &current_time));
    POSIX_GUARD(s2n_config_add_ticket_crypto_key(config, ticket_key_name, strlen((char *) ticket_key_name),
            ticket_key.data, ticket_key.size, current_time / ONE_SEC_IN_NANOS));
    return S2N_SUCCESS;
}

static S2N_RESULT s2n_setup_encrypted_ticket(struct s2n_connection *conn, struct s2n_stuffer *output)
{
    conn->tls13_ticket_fields = (struct s2n_ticket_fields){ 0 };
    uint8_t test_secret_data[] = "test secret";
    RESULT_GUARD_POSIX(s2n_alloc(&conn->tls13_ticket_fields.session_secret, sizeof(test_secret_data)));
    RESULT_CHECKED_MEMCPY(conn->tls13_ticket_fields.session_secret.data, test_secret_data, sizeof(test_secret_data));

    /* Create a valid resumption psk identity */
    RESULT_GUARD_POSIX(s2n_encrypt_session_ticket(conn, output));
    output->blob.size = s2n_stuffer_data_available(output);

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_write_test_identity(struct s2n_stuffer *out, const uint8_t *identity, uint16_t identity_size)
{
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, identity_size));
    RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(out, identity, identity_size));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint32(out, 0));
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const uint8_t wire_identity_1[] = { "one" };
    const uint8_t wire_identity_2[] = { "two" };

    /* Test s2n_offered_psk_list_has_next */
    {
        struct s2n_offered_psk_list psk_list = { 0 };

        /* Safety check */
        EXPECT_FALSE(s2n_offered_psk_list_has_next(NULL));

        /* Empty list */
        EXPECT_FALSE(s2n_offered_psk_list_has_next(&psk_list));

        /* Contains data */
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&psk_list.wire_data, 0));
        EXPECT_SUCCESS(s2n_stuffer_skip_write(&psk_list.wire_data, 1));
        EXPECT_TRUE(s2n_offered_psk_list_has_next(&psk_list));

        /* Out of data */
        EXPECT_SUCCESS(s2n_stuffer_skip_read(&psk_list.wire_data, 1));
        EXPECT_FALSE(s2n_offered_psk_list_has_next(&psk_list));

        EXPECT_SUCCESS(s2n_stuffer_free(&psk_list.wire_data));
    };

    /* Test s2n_offered_psk_list_next */
    {
        /* Safety checks */
        {
            struct s2n_offered_psk_list psk_list = { 0 };
            struct s2n_offered_psk psk = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_psk_list_next(&psk_list, NULL), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_psk_list_next(NULL, &psk), S2N_ERR_NULL);
        };

        /* Empty list */
        {
            struct s2n_offered_psk_list psk_list = { 0 };
            struct s2n_offered_psk psk = { 0 };

            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_psk_list_next(&psk_list, &psk), S2N_ERR_STUFFER_OUT_OF_DATA);
            EXPECT_EQUAL(psk.identity.size, 0);
            EXPECT_EQUAL(psk.identity.data, NULL);

            /* Calling again produces same result */
            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_psk_list_next(&psk_list, &psk), S2N_ERR_STUFFER_OUT_OF_DATA);
            EXPECT_EQUAL(psk.identity.size, 0);
            EXPECT_EQUAL(psk.identity.data, NULL);
        };

        /* Parses only element in list */
        {
            struct s2n_offered_psk psk = { 0 };
            struct s2n_offered_psk_list psk_list = { 0 };
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            psk_list.conn = conn;

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&psk_list.wire_data, 0));
            EXPECT_OK(s2n_write_test_identity(&psk_list.wire_data, wire_identity_1, sizeof(wire_identity_1)));

            EXPECT_SUCCESS(s2n_offered_psk_list_next(&psk_list, &psk));
            EXPECT_EQUAL(psk.identity.size, sizeof(wire_identity_1));
            EXPECT_BYTEARRAY_EQUAL(psk.identity.data, wire_identity_1, sizeof(wire_identity_1));

            /* Trying to retrieve a second element fails */
            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_psk_list_next(&psk_list, &psk), S2N_ERR_STUFFER_OUT_OF_DATA);
            EXPECT_EQUAL(psk.identity.size, 0);
            EXPECT_EQUAL(psk.identity.data, NULL);

            EXPECT_SUCCESS(s2n_stuffer_free(&psk_list.wire_data));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Fails to parse zero-length identities */
        {
            struct s2n_offered_psk psk = { 0 };
            struct s2n_offered_psk_list psk_list = { 0 };

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&psk_list.wire_data, 0));
            EXPECT_OK(s2n_write_test_identity(&psk_list.wire_data, wire_identity_1, 0));

            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_psk_list_next(&psk_list, &psk), S2N_ERR_BAD_MESSAGE);
            EXPECT_EQUAL(psk.identity.size, 0);
            EXPECT_EQUAL(psk.identity.data, NULL);

            EXPECT_SUCCESS(s2n_stuffer_free(&psk_list.wire_data));
        };

        /* Fails to parse partial identities */
        {
            struct s2n_offered_psk psk = { 0 };
            struct s2n_offered_psk_list psk_list = { 0 };

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&psk_list.wire_data, 0));
            EXPECT_OK(s2n_write_test_identity(&psk_list.wire_data, wire_identity_1, 0));
            EXPECT_SUCCESS(s2n_stuffer_wipe_n(&psk_list.wire_data, 1));

            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_psk_list_next(&psk_list, &psk), S2N_ERR_BAD_MESSAGE);
            EXPECT_EQUAL(psk.identity.size, 0);
            EXPECT_EQUAL(psk.identity.data, NULL);

            EXPECT_SUCCESS(s2n_stuffer_free(&psk_list.wire_data));
        };

        /* Parses multiple elements from list */
        {
            struct s2n_offered_psk psk = { 0 };
            struct s2n_offered_psk_list psk_list = { 0 };
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            psk_list.conn = conn;

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&psk_list.wire_data, 0));
            EXPECT_OK(s2n_write_test_identity(&psk_list.wire_data, wire_identity_1, sizeof(wire_identity_1)));
            EXPECT_OK(s2n_write_test_identity(&psk_list.wire_data, wire_identity_2, sizeof(wire_identity_2)));

            EXPECT_SUCCESS(s2n_offered_psk_list_next(&psk_list, &psk));
            EXPECT_EQUAL(psk.identity.size, sizeof(wire_identity_1));
            EXPECT_BYTEARRAY_EQUAL(psk.identity.data, wire_identity_1, sizeof(wire_identity_1));

            EXPECT_SUCCESS(s2n_offered_psk_list_next(&psk_list, &psk));
            EXPECT_EQUAL(psk.identity.size, sizeof(wire_identity_2));
            EXPECT_BYTEARRAY_EQUAL(psk.identity.data, wire_identity_2, sizeof(wire_identity_2));

            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_psk_list_next(&psk_list, &psk), S2N_ERR_STUFFER_OUT_OF_DATA);
            EXPECT_EQUAL(psk.identity.size, 0);
            EXPECT_EQUAL(psk.identity.data, NULL);

            EXPECT_SUCCESS(s2n_stuffer_free(&psk_list.wire_data));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* Test s2n_offered_psk_list_read_next */
    {
        /* Safety check */
        {
            struct s2n_offered_psk psk = { 0 };
            struct s2n_offered_psk_list psk_list = { 0 };
            EXPECT_ERROR_WITH_ERRNO(s2n_offered_psk_list_read_next(&psk_list, NULL), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_offered_psk_list_read_next(NULL, &psk), S2N_ERR_NULL);
        };

        /**
         *= https://tools.ietf.org/rfc/rfc8446#section-4.2.11
         *= type=test
         *# For identities established externally, an obfuscated_ticket_age of 0 SHOULD be
         *# used, and servers MUST ignore the value.
         */
        {
            struct s2n_offered_psk psk = { 0 };
            struct s2n_offered_psk_list psk_list = { 0 };
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            conn->psk_params.type = S2N_PSK_TYPE_EXTERNAL;
            psk_list.conn = conn;
            uint32_t obfuscated_ticket_age = 100;

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&psk_list.wire_data, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&psk_list.wire_data, sizeof(wire_identity_1)));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&psk_list.wire_data, wire_identity_1, sizeof(wire_identity_1)));
            EXPECT_SUCCESS(s2n_stuffer_write_uint32(&psk_list.wire_data, obfuscated_ticket_age));

            EXPECT_OK(s2n_offered_psk_list_read_next(&psk_list, &psk));

            EXPECT_EQUAL(psk.obfuscated_ticket_age, 0);

            EXPECT_SUCCESS(s2n_stuffer_free(&psk_list.wire_data));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Resumption PSKs do not skip obfuscated ticket age parsing */
        {
            struct s2n_offered_psk psk = { 0 };
            struct s2n_offered_psk_list psk_list = { 0 };
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            conn->psk_params.type = S2N_PSK_TYPE_RESUMPTION;
            psk_list.conn = conn;
            uint32_t obfuscated_ticket_age = 100;

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&psk_list.wire_data, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&psk_list.wire_data, sizeof(wire_identity_1)));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&psk_list.wire_data, wire_identity_1, sizeof(wire_identity_1)));
            EXPECT_SUCCESS(s2n_stuffer_write_uint32(&psk_list.wire_data, obfuscated_ticket_age));

            EXPECT_OK(s2n_offered_psk_list_read_next(&psk_list, &psk));

            EXPECT_EQUAL(psk.obfuscated_ticket_age, obfuscated_ticket_age);

            EXPECT_SUCCESS(s2n_stuffer_free(&psk_list.wire_data));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    };

    /* Test s2n_offered_psk_list_reread */
    {
        /* Safety check */
        EXPECT_FAILURE_WITH_ERRNO(s2n_offered_psk_list_reread(NULL), S2N_ERR_NULL);

        /* No-op on empty list */
        {
            struct s2n_offered_psk psk = { 0 };
            struct s2n_offered_psk_list psk_list = { 0 };

            EXPECT_SUCCESS(s2n_offered_psk_list_reread(&psk_list));
            EXPECT_SUCCESS(s2n_offered_psk_list_reread(&psk_list));

            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_psk_list_next(&psk_list, &psk), S2N_ERR_STUFFER_OUT_OF_DATA);
        };

        /* Resets non-empty list */
        {
            struct s2n_offered_psk psk = { 0 };
            struct s2n_offered_psk_list psk_list = { 0 };
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            psk_list.conn = conn;

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&psk_list.wire_data, 0));
            EXPECT_OK(s2n_write_test_identity(&psk_list.wire_data, wire_identity_1, sizeof(wire_identity_1)));

            EXPECT_SUCCESS(s2n_offered_psk_list_next(&psk_list, &psk));
            EXPECT_EQUAL(psk.identity.size, sizeof(wire_identity_1));
            EXPECT_BYTEARRAY_EQUAL(psk.identity.data, wire_identity_1, sizeof(wire_identity_1));

            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_psk_list_next(&psk_list, &psk), S2N_ERR_STUFFER_OUT_OF_DATA);

            EXPECT_SUCCESS(s2n_offered_psk_list_reread(&psk_list));

            EXPECT_SUCCESS(s2n_offered_psk_list_next(&psk_list, &psk));
            EXPECT_EQUAL(psk.identity.size, sizeof(wire_identity_1));
            EXPECT_BYTEARRAY_EQUAL(psk.identity.data, wire_identity_1, sizeof(wire_identity_1));

            EXPECT_SUCCESS(s2n_stuffer_free(&psk_list.wire_data));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* Test s2n_offered_psk_new */
    {
        struct s2n_offered_psk zeroed_psk = { 0 };
        POSIX_CHECKED_MEMSET(&zeroed_psk, 0, sizeof(struct s2n_offered_psk));
        DEFER_CLEANUP(struct s2n_offered_psk *new_psk = s2n_offered_psk_new(), s2n_offered_psk_free);
        EXPECT_NOT_NULL(new_psk);

        /* _new equivalent to a zero-inited structure */
        EXPECT_BYTEARRAY_EQUAL(&zeroed_psk, new_psk, sizeof(struct s2n_offered_psk));
    };

    /* Test s2n_offered_psk_free */
    {
        EXPECT_SUCCESS(s2n_offered_psk_free(NULL));

        struct s2n_offered_psk *new_psk = s2n_offered_psk_new();
        EXPECT_NOT_NULL(new_psk);
        EXPECT_SUCCESS(s2n_offered_psk_free(&new_psk));
        EXPECT_NULL(new_psk);
    };

    /* Test s2n_offered_psk_get_identity */
    {
        /* Safety checks */
        {
            struct s2n_offered_psk psk = { 0 };
            uint8_t *data = NULL;
            uint16_t size = 0;
            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_psk_get_identity(NULL, &data, &size), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_psk_get_identity(&psk, NULL, &size), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_psk_get_identity(&psk, &data, NULL), S2N_ERR_NULL);
        };

        /* Empty identity */
        {
            DEFER_CLEANUP(struct s2n_offered_psk *psk = s2n_offered_psk_new(), s2n_offered_psk_free);

            uint8_t *data = NULL;
            uint16_t size = 0;
            EXPECT_SUCCESS(s2n_offered_psk_get_identity(psk, &data, &size));
            EXPECT_EQUAL(size, 0);
            EXPECT_EQUAL(data, NULL);
        };

        /* Valid identity */
        {
            uint8_t wire_identity[] = "identity";
            DEFER_CLEANUP(struct s2n_offered_psk *psk = s2n_offered_psk_new(), s2n_offered_psk_free);
            EXPECT_SUCCESS(s2n_blob_init(&psk->identity, wire_identity, sizeof(wire_identity)));

            uint8_t *data = NULL;
            uint16_t size = 0;
            EXPECT_SUCCESS(s2n_offered_psk_get_identity(psk, &data, &size));
            EXPECT_EQUAL(size, sizeof(wire_identity));
            EXPECT_BYTEARRAY_EQUAL(data, wire_identity, sizeof(wire_identity));
        };
    };

    /* Test: s2n_validate_ticket_lifetime */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(conn);
        uint32_t ticket_age_add = 0;
        uint32_t obfuscated_ticket_age = 0;

        /* Ticket age is smaller than session lifetime */
        conn->config->session_state_lifetime_in_nanos = MILLIS_TO_NANOS(100);
        EXPECT_OK(s2n_validate_ticket_lifetime(conn, obfuscated_ticket_age, ticket_age_add));

        /* Ticket age is greater than session lifetime */
        obfuscated_ticket_age = 101;
        conn->config->session_state_lifetime_in_nanos = MILLIS_TO_NANOS(100);
        EXPECT_ERROR_WITH_ERRNO(s2n_validate_ticket_lifetime(conn, obfuscated_ticket_age, ticket_age_add), S2N_ERR_INVALID_SESSION_TICKET);

        /* ticket_age_add is greater than obfuscated ticket age and ticket age
         * is smaller than session lifetime */
        obfuscated_ticket_age = 100;
        ticket_age_add = 1000;
        conn->config->session_state_lifetime_in_nanos = MILLIS_TO_NANOS(UINT32_MAX);
        EXPECT_OK(s2n_validate_ticket_lifetime(conn, obfuscated_ticket_age, ticket_age_add));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: s2n_offered_psk_list_choose_psk */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        struct s2n_array *known_psks = &conn->psk_params.psk_list;

        const uint16_t wire_index = 5;
        uint8_t wire_identity_bytes[] = "wire_identity_bytes";
        struct s2n_blob wire_identity = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&wire_identity, wire_identity_bytes, sizeof(wire_identity_bytes)));
        struct s2n_offered_psk offered_psk = { .identity = wire_identity, .wire_index = wire_index };

        struct s2n_offered_psk_list offered_psk_list = { .conn = conn };
        conn->psk_params.type = S2N_PSK_TYPE_EXTERNAL;

        /* Safety */
        EXPECT_FAILURE_WITH_ERRNO(s2n_offered_psk_list_choose_psk(NULL, &offered_psk), S2N_ERR_NULL);

        /* Test: No known PSKs */
        {
            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_psk_list_choose_psk(&offered_psk_list, &offered_psk), S2N_ERR_NULL);
            EXPECT_NULL(conn->psk_params.chosen_psk);
        };

        /* Test: No match exists */
        {
            struct s2n_psk *different_identity = NULL;
            EXPECT_OK(s2n_array_pushback(known_psks, (void **) &different_identity));
            EXPECT_OK(s2n_psk_init(different_identity, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_set_identity(different_identity, wire_identity_2, sizeof(wire_identity_2)));

            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_psk_list_choose_psk(&offered_psk_list, &offered_psk), S2N_ERR_NULL);
            EXPECT_NULL(conn->psk_params.chosen_psk);
        };

        struct s2n_psk *expected_match = NULL;

        /* Test: Match exists */
        {
            EXPECT_OK(s2n_array_pushback(known_psks, (void **) &expected_match));
            EXPECT_OK(s2n_psk_init(expected_match, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_set_identity(expected_match, wire_identity_bytes, sizeof(wire_identity_bytes)));

            EXPECT_SUCCESS(s2n_offered_psk_list_choose_psk(&offered_psk_list, &offered_psk));
            EXPECT_EQUAL(conn->psk_params.chosen_psk, expected_match);
            EXPECT_EQUAL(conn->psk_params.chosen_psk_wire_index, wire_index);
        };

        /* Test: set NULL PSK */
        {
            EXPECT_SUCCESS(s2n_offered_psk_list_choose_psk(&offered_psk_list, NULL));
            EXPECT_NULL(conn->psk_params.chosen_psk);
        };

        /* Test: Multiple matches exist */
        {
            struct s2n_psk *another_match = NULL;
            EXPECT_OK(s2n_array_pushback(known_psks, (void **) &another_match));
            EXPECT_OK(s2n_psk_init(another_match, S2N_PSK_TYPE_EXTERNAL));
            EXPECT_SUCCESS(s2n_psk_set_identity(another_match, wire_identity_bytes, sizeof(wire_identity_bytes)));

            EXPECT_SUCCESS(s2n_offered_psk_list_choose_psk(&offered_psk_list, &offered_psk));
            EXPECT_EQUAL(conn->psk_params.chosen_psk, expected_match);
            EXPECT_EQUAL(conn->psk_params.chosen_psk_wire_index, wire_index);
        };

        EXPECT_SUCCESS(s2n_connection_free(conn));

        /* Test: Valid resumption psk is received */
        {
            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);

            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_setup_ticket_key(config));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            server_conn->psk_params.type = S2N_PSK_TYPE_RESUMPTION;
            server_conn->actual_protocol_version = S2N_TLS13;
            server_conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

            DEFER_CLEANUP(struct s2n_stuffer psk_identity = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&psk_identity, 0));
            EXPECT_OK(s2n_setup_encrypted_ticket(server_conn, &psk_identity));

            struct s2n_offered_psk_list identity_list = { .conn = server_conn };

            DEFER_CLEANUP(struct s2n_stuffer test_stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&test_stuffer, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&test_stuffer, psk_identity.blob.data, psk_identity.blob.size));
            test_stuffer.blob.size = s2n_stuffer_data_available(&psk_identity);

            struct s2n_offered_psk client_psk = { .identity = test_stuffer.blob, .wire_index = wire_index };

            EXPECT_SUCCESS(s2n_offered_psk_list_choose_psk(&identity_list, &client_psk));

            EXPECT_EQUAL(server_conn->psk_params.chosen_psk_wire_index, wire_index);
            EXPECT_NOT_NULL(server_conn->psk_params.chosen_psk);

            /* Sanity check psk creation is correct */
            EXPECT_EQUAL(server_conn->psk_params.chosen_psk->hmac_alg, s2n_tls13_aes_128_gcm_sha256.prf_alg);

            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* Resumption psk has expired */
        {
            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);

            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_setup_ticket_key(config));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            server_conn->psk_params.type = S2N_PSK_TYPE_RESUMPTION;
            server_conn->actual_protocol_version = S2N_TLS13;
            server_conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

            DEFER_CLEANUP(struct s2n_stuffer psk_identity = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&psk_identity, 0));
            EXPECT_OK(s2n_setup_encrypted_ticket(server_conn, &psk_identity));

            struct s2n_offered_psk_list identity_list = { .conn = server_conn };

            DEFER_CLEANUP(struct s2n_stuffer test_stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&test_stuffer, 0));
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&test_stuffer, psk_identity.blob.data, psk_identity.blob.size));
            test_stuffer.blob.size = s2n_stuffer_data_available(&psk_identity);

            /* Obfuscated ticket age is larger than the session lifetime */
            struct s2n_offered_psk client_psk = { .identity = psk_identity.blob, .wire_index = wire_index, .obfuscated_ticket_age = 100 };
            server_conn->config->session_state_lifetime_in_nanos = 0;

            EXPECT_FAILURE_WITH_ERRNO(s2n_offered_psk_list_choose_psk(&identity_list, &client_psk), S2N_ERR_INVALID_SESSION_TICKET);

            EXPECT_EQUAL(server_conn->psk_params.chosen_psk_wire_index, 0);
            EXPECT_NULL(server_conn->psk_params.chosen_psk);

            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* Invalid resumption psk is received */
        {
            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);

            server_conn->psk_params.type = S2N_PSK_TYPE_RESUMPTION;
            server_conn->actual_protocol_version = S2N_TLS13;
            server_conn->secure->cipher_suite = &s2n_tls13_aes_128_gcm_sha256;

            struct s2n_offered_psk_list identity_list = { .conn = server_conn };
            struct s2n_offered_psk client_psk = { .identity = wire_identity, .wire_index = wire_index };

            EXPECT_FAILURE(s2n_offered_psk_list_choose_psk(&identity_list, &client_psk));

            EXPECT_EQUAL(server_conn->psk_params.chosen_psk_wire_index, 0);
            EXPECT_NULL(server_conn->psk_params.chosen_psk);

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };
    };

    /* Functional test: Process the output of sending the psk extension */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);
        conn->psk_params.type = S2N_PSK_TYPE_EXTERNAL;

        const uint8_t test_secret[] = "secret";

        struct s2n_psk *psk1 = NULL;
        EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void **) &psk1));
        EXPECT_OK(s2n_psk_init(psk1, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_set_identity(psk1, wire_identity_1, sizeof(wire_identity_1)));
        EXPECT_SUCCESS(s2n_psk_set_secret(psk1, test_secret, sizeof(test_secret)));

        struct s2n_psk *psk2 = NULL;
        EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void **) &psk2));
        EXPECT_OK(s2n_psk_init(psk2, S2N_PSK_TYPE_EXTERNAL));
        EXPECT_SUCCESS(s2n_psk_set_identity(psk2, wire_identity_2, sizeof(wire_identity_2)));
        EXPECT_SUCCESS(s2n_psk_set_secret(psk2, test_secret, sizeof(test_secret)));

        EXPECT_SUCCESS(s2n_client_psk_extension.send(conn, &conn->handshake.io));

        /* Skip identity list size */
        EXPECT_SUCCESS(s2n_stuffer_skip_read(&conn->handshake.io, sizeof(uint16_t)));

        struct s2n_offered_psk_list identity_list = { .conn = conn };
        const size_t size = s2n_stuffer_data_available(&conn->handshake.io);
        EXPECT_SUCCESS(s2n_stuffer_alloc(&identity_list.wire_data, size));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&identity_list.wire_data,
                s2n_stuffer_raw_read(&conn->handshake.io, size), size));

        uint8_t *data = NULL;
        uint16_t data_size = 0;
        struct s2n_offered_psk psk = { 0 };

        EXPECT_TRUE(s2n_offered_psk_list_has_next(&identity_list));
        EXPECT_SUCCESS(s2n_offered_psk_list_next(&identity_list, &psk));
        EXPECT_SUCCESS(s2n_offered_psk_get_identity(&psk, &data, &data_size));
        EXPECT_EQUAL(data_size, sizeof(wire_identity_1));
        EXPECT_BYTEARRAY_EQUAL(data, wire_identity_1, sizeof(wire_identity_1));

        EXPECT_TRUE(s2n_offered_psk_list_has_next(&identity_list));
        EXPECT_SUCCESS(s2n_offered_psk_list_next(&identity_list, &psk));
        EXPECT_SUCCESS(s2n_offered_psk_get_identity(&psk, &data, &data_size));
        EXPECT_EQUAL(data_size, sizeof(wire_identity_2));
        EXPECT_BYTEARRAY_EQUAL(data, wire_identity_2, sizeof(wire_identity_2));

        EXPECT_SUCCESS(s2n_offered_psk_list_choose_psk(&identity_list, &psk));
        EXPECT_EQUAL(conn->psk_params.chosen_psk, psk2);
        EXPECT_EQUAL(conn->psk_params.chosen_psk_wire_index, 1);

        EXPECT_SUCCESS(s2n_offered_psk_list_reread(&identity_list));

        EXPECT_TRUE(s2n_offered_psk_list_has_next(&identity_list));
        EXPECT_SUCCESS(s2n_offered_psk_list_next(&identity_list, &psk));
        EXPECT_SUCCESS(s2n_offered_psk_get_identity(&psk, &data, &data_size));
        EXPECT_EQUAL(data_size, sizeof(wire_identity_1));
        EXPECT_BYTEARRAY_EQUAL(data, wire_identity_1, sizeof(wire_identity_1));

        EXPECT_SUCCESS(s2n_offered_psk_list_choose_psk(&identity_list, &psk));
        EXPECT_EQUAL(conn->psk_params.chosen_psk, psk1);
        EXPECT_EQUAL(conn->psk_params.chosen_psk_wire_index, 0);

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_stuffer_free(&identity_list.wire_data));
    };

    END_TEST();
}
