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
#include "tls/extensions/s2n_server_psk.h"

/* Include source to test static methods. */
#include "tls/extensions/s2n_server_psk.c"

struct s2n_psk_test_case {
    s2n_hmac_algorithm hmac_alg;
    uint8_t hash_size;
    const uint8_t* identity;
    size_t identity_size;
    const uint8_t* secret;
    size_t secret_size;

};

uint8_t test_identity_1[] = "test identity";
uint8_t test_identity_2[] = "another identity";
uint8_t test_secret_1[] = "test secret";
uint8_t test_secret_2[] = "another secret";

struct s2n_psk_test_case test_cases[] = {
    { .hmac_alg = S2N_HMAC_SHA224, .hash_size = SHA224_DIGEST_LENGTH,
      .identity = test_identity_1, .identity_size = sizeof(test_identity_1),
      .secret = test_secret_1, .secret_size = sizeof(test_secret_1)},
    { .hmac_alg = S2N_HMAC_SHA384, .hash_size = SHA384_DIGEST_LENGTH,
      .identity = test_identity_2, .identity_size = sizeof(test_identity_2),
      .secret = test_secret_2, .secret_size = sizeof(test_secret_2)},  
};

static s2n_result validate_psk_is_wiped(struct s2n_psk *psk)
{
    ENSURE_EQ(psk->identity.data, NULL);
    ENSURE_EQ(psk->identity.size, 0);
    ENSURE_EQ(psk->secret.data, NULL);
    ENSURE_EQ(psk->secret.size, 0);
    ENSURE_EQ(psk->early_secret.data, NULL);
    ENSURE_EQ(psk->early_secret.size, 0);

    return S2N_RESULT_OK;
}

static s2n_result validate_psk_is_not_wiped(struct s2n_psk *psk)
{
    ENSURE_REF(psk->identity.data);
    ENSURE_NE(psk->identity.size, 0);
    ENSURE_REF(psk->secret.data);
    ENSURE_NE(psk->secret.size, 0);

    return S2N_RESULT_OK;
}

static s2n_result setup_psks(struct s2n_connection *conn)
{
    ENSURE_REF(conn);
    for (size_t i = 0; i < s2n_array_len(test_cases); i++) {
        struct s2n_psk *psk = NULL;
        GUARD_RESULT(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &psk));
        GUARD_AS_RESULT(s2n_psk_init(psk, S2N_PSK_TYPE_EXTERNAL));
        GUARD_AS_RESULT(s2n_psk_new_identity(psk, test_cases[i].identity, test_cases[i].identity_size));
        GUARD_AS_RESULT(s2n_psk_new_secret(psk, test_cases[i].secret, test_cases[i].secret_size));
    }

    return S2N_RESULT_OK;
}

static s2n_result setup_order_mismatch_psks(struct s2n_connection *server_conn, struct s2n_connection *client_conn, struct s2n_psk **shared_psk) 
{
    ENSURE_REF(server_conn);
    ENSURE_REF(client_conn);

    /* Setup other client PSK */
    uint8_t other_client_data[] = "other client data";
    struct s2n_psk *other_client_psk = NULL;
    GUARD_RESULT(s2n_array_pushback(&client_conn->psk_params.psk_list, (void**) &other_client_psk));
    GUARD_AS_RESULT(s2n_psk_init(other_client_psk, S2N_PSK_TYPE_EXTERNAL));
    GUARD_AS_RESULT(s2n_psk_new_identity(other_client_psk, other_client_data, sizeof(other_client_data)));
    GUARD_AS_RESULT(s2n_psk_new_secret(other_client_psk, other_client_data, sizeof(other_client_data)));

    /* Setup shared PSK for client */
    GUARD_RESULT(s2n_array_pushback(&client_conn->psk_params.psk_list, (void**) shared_psk));
    GUARD_AS_RESULT(s2n_psk_init(*shared_psk, S2N_PSK_TYPE_EXTERNAL));
    GUARD_AS_RESULT(s2n_psk_new_identity(*shared_psk, test_identity_1, sizeof(test_identity_1)));
    GUARD_AS_RESULT(s2n_psk_new_secret(*shared_psk, test_secret_1, sizeof(test_secret_1)));

    /* Setup shared PSK for server */
    GUARD_RESULT(s2n_array_pushback(&server_conn->psk_params.psk_list, (void**) shared_psk));
    GUARD_AS_RESULT(s2n_psk_init(*shared_psk, S2N_PSK_TYPE_EXTERNAL));
    GUARD_AS_RESULT(s2n_psk_new_identity(*shared_psk, test_identity_1, sizeof(test_identity_1)));
    GUARD_AS_RESULT(s2n_psk_new_secret(*shared_psk, test_secret_1, sizeof(test_secret_1)));

    /* Setup other server PSK */
    uint8_t other_server_data[] = "other server data";
    struct s2n_psk *other_server_psk = NULL;
    GUARD_RESULT(s2n_array_pushback(&server_conn->psk_params.psk_list, (void**) &other_server_psk));
    GUARD_AS_RESULT(s2n_psk_init(other_server_psk, S2N_PSK_TYPE_EXTERNAL));
    GUARD_AS_RESULT(s2n_psk_new_identity(other_server_psk, other_server_data, sizeof(other_server_data)));
    GUARD_AS_RESULT(s2n_psk_new_secret(other_server_psk, other_server_data, sizeof(other_server_data)));


    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test: s2n_server_psk_should_send */
    {
        struct s2n_psk *psk = NULL;

        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        EXPECT_FALSE(s2n_server_psk_extension.should_send(NULL));

        conn->actual_protocol_version = S2N_TLS12;
        EXPECT_FALSE(s2n_server_psk_extension.should_send(conn));
        conn->actual_protocol_version = S2N_TLS13;
        EXPECT_FALSE(s2n_server_psk_extension.should_send(conn));

        EXPECT_OK(s2n_array_pushback(&conn->psk_params.psk_list, (void**) &psk));

        conn->actual_protocol_version = S2N_TLS12;
        EXPECT_FALSE(s2n_server_psk_extension.should_send(conn));
        conn->actual_protocol_version = S2N_TLS13;
        EXPECT_FALSE(s2n_server_psk_extension.should_send(conn));

        conn->psk_params.chosen_psk_wire_index = 0;
        EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, conn->psk_params.chosen_psk_wire_index,
                                (void **)&conn->psk_params.chosen_psk));
        EXPECT_TRUE(s2n_server_psk_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test: s2n_server_psk_send */
    {
        /* Send the index of the chosen PSK that is stored on the connection. */
        {
            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            struct s2n_connection *server_conn = NULL;
            struct s2n_connection *client_conn = NULL;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

            struct s2n_psk *shared_psk = NULL;
            EXPECT_OK(setup_order_mismatch_psks(server_conn, client_conn, &shared_psk));
            EXPECT_NOT_NULL(shared_psk);

            uint16_t shared_psk_wire_index = 0;

            for (size_t i = 0; i < client_conn->psk_params.psk_list.len; i++) {
                struct s2n_psk *psk = NULL;
                EXPECT_OK(s2n_array_get(&client_conn->psk_params.psk_list, i, (void**)&psk));
                if (psk == shared_psk) {
                    shared_psk_wire_index = i;
                }
            }

            /* Valid chosen psk wire index set */
            server_conn->psk_params.chosen_psk_wire_index = shared_psk_wire_index;
            EXPECT_SUCCESS(s2n_server_psk_extension.send(server_conn, &out));

            uint16_t chosen_psk_wire_index;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&out, &chosen_psk_wire_index));
            EXPECT_EQUAL(chosen_psk_wire_index, server_conn->psk_params.chosen_psk_wire_index);
            EXPECT_TRUE(chosen_psk_wire_index < client_conn->psk_params.psk_list.len);

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        }
    }

    /* Test: s2n_server_psk_recv */
    {
        /* Test s2n_server_psk_recv for invalid TLS versions <= TLS1.2 */
        {
            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_OK(setup_psks(conn));

            uint16_t chosen_psk_wire_index = 1;
            /* Incorrect protocol version */
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&out, chosen_psk_wire_index));

            EXPECT_NULL(conn->psk_params.chosen_psk);
            EXPECT_SUCCESS(s2n_server_psk_extension.recv(conn, &out));
            EXPECT_NULL(conn->psk_params.chosen_psk);

            /* Validate that the client list of PSKs is not wiped */
            for (size_t i = 0; i < conn->psk_params.psk_list.len; i++) {
                struct s2n_psk *psk = NULL;
                EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, i, (void**)&psk));
                EXPECT_OK(validate_psk_is_not_wiped(psk));
            }

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        }

        /* Receive invalid chosen psk wire index */
        {
            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_OK(setup_psks(conn));

            /* Invalid chosen psk wire index */
            uint8_t chosen_psk_wire_index = s2n_array_len(test_cases) + 1;
            conn->actual_protocol_version = S2N_TLS13;

            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&out, chosen_psk_wire_index));

            EXPECT_NULL(conn->psk_params.chosen_psk);
            EXPECT_FAILURE_WITH_ERRNO(s2n_server_psk_extension.recv(conn, &out), S2N_ERR_INVALID_ARGUMENT);
            EXPECT_NULL(conn->psk_params.chosen_psk);

            /* Validate that the client list of PSKs is not wiped */
            for (size_t i = 0; i < conn->psk_params.psk_list.len; i++) {
                struct s2n_psk *psk = NULL;
                EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, i, (void**)&psk));
                EXPECT_OK(validate_psk_is_not_wiped(psk));
            }

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        }
        /* Receive valid server preshared extension recv */
        {
            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_OK(setup_psks(conn));

            uint16_t chosen_psk_wire_index = 0;
            conn->actual_protocol_version = S2N_TLS13;
            
            struct s2n_psk *chosen_psk = NULL;
            EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, chosen_psk_wire_index, (void**)&chosen_psk));

            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&out, chosen_psk_wire_index));

            EXPECT_NULL(conn->psk_params.chosen_psk);
            EXPECT_SUCCESS(s2n_server_psk_extension.recv(conn, &out));
            EXPECT_NOT_NULL(conn->psk_params.chosen_psk);

            /* Verify the chosen PSK pointer is set correctly */ 
            EXPECT_EQUAL(conn->psk_params.chosen_psk_wire_index, chosen_psk_wire_index);
            EXPECT_EQUAL(conn->psk_params.chosen_psk, chosen_psk);

            /* Validate that the chosen PSK is not wiped and the PSKs not chosen are wiped */
            for (size_t i = 0; i < conn->psk_params.psk_list.len; i++) {
                struct s2n_psk *psk = NULL;
                EXPECT_OK(s2n_array_get(&conn->psk_params.psk_list, i, (void**)&psk));
                if (i == conn->psk_params.chosen_psk_wire_index) {
                    EXPECT_OK(validate_psk_is_not_wiped(psk));
                } else {
                    EXPECT_OK(validate_psk_is_wiped(psk));
                }
            }

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
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

        struct s2n_psk *shared_psk = NULL;
        EXPECT_OK(setup_order_mismatch_psks(server_conn, client_conn, &shared_psk));
        EXPECT_NOT_NULL(shared_psk);

        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                s2n_stuffer_data_available(&client_conn->handshake.io)));
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

        /* Verify shared PSK chosen */
        EXPECT_EQUAL(server_conn->psk_params.chosen_psk, shared_psk);
        EXPECT_EQUAL(server_conn->psk_params.chosen_psk_wire_index, 1);
        EXPECT_EQUAL(server_conn->psk_params.chosen_psk->secret.size, sizeof(test_secret_1));
        EXPECT_BYTEARRAY_EQUAL(server_conn->psk_params.chosen_psk->secret.data, test_secret_1, sizeof(test_secret_1));

        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                s2n_stuffer_data_available(&server_conn->handshake.io)));

        EXPECT_NULL(client_conn->psk_params.chosen_psk);
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));
        EXPECT_NOT_NULL(client_conn->psk_params.chosen_psk);

        /* Verify the chosen PSK pointer is set correctly */ 
        EXPECT_EQUAL(client_conn->psk_params.chosen_psk_wire_index, server_conn->psk_params.chosen_psk_wire_index);
    
        /* Validate that the chosen PSK is not wiped and PSKs not chosen are wiped */
        for (size_t i = 0; i < client_conn->psk_params.psk_list.len; i++) {
            struct s2n_psk *psk = NULL;
            EXPECT_OK(s2n_array_get(&client_conn->psk_params.psk_list, i, (void**)&psk));
            if (i == client_conn->psk_params.chosen_psk_wire_index) {
                EXPECT_OK(validate_psk_is_not_wiped(psk));
            } else {
                EXPECT_OK(validate_psk_is_wiped(psk));
            }
        }

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(config));
    }

    END_TEST();
}
