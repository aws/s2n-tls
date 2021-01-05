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
#include "tls/s2n_tls.h"
#include "utils/s2n_bitmap.h"

#define TEST_PSK_WIRE_INDEX 1
#define TEST_PSK_HMAC S2N_HMAC_SHA384

uint8_t test_identity[] = "test identity";
uint8_t test_secret[] = "test secret";

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


static s2n_result setup_client_psks(struct s2n_connection *client_conn)
{
    ENSURE_REF(client_conn);

    /* Setup other client PSK */
    uint8_t other_client_data[] = "other client data";
    struct s2n_psk *other_client_psk = NULL;
    GUARD_RESULT(s2n_array_pushback(&client_conn->psk_params.psk_list, (void**) &other_client_psk));
    GUARD_AS_RESULT(s2n_psk_init(other_client_psk, S2N_PSK_TYPE_EXTERNAL));
    GUARD_AS_RESULT(s2n_psk_new_identity(other_client_psk, other_client_data, sizeof(other_client_data)));
    GUARD_AS_RESULT(s2n_psk_new_secret(other_client_psk, other_client_data, sizeof(other_client_data)));
    other_client_psk->hmac_alg = S2N_HMAC_SHA256;

    /* Setup shared PSK for client */
    struct s2n_psk *shared_psk = NULL;
    GUARD_RESULT(s2n_array_pushback(&client_conn->psk_params.psk_list, (void**) &shared_psk));
    GUARD_AS_RESULT(s2n_psk_init(shared_psk, S2N_PSK_TYPE_EXTERNAL));
    GUARD_AS_RESULT(s2n_psk_new_identity(shared_psk, test_identity, sizeof(test_identity)));
    GUARD_AS_RESULT(s2n_psk_new_secret(shared_psk, test_secret, sizeof(test_secret)));
    shared_psk->hmac_alg = TEST_PSK_HMAC;

    return S2N_RESULT_OK;
}

static s2n_result setup_server_psks(struct s2n_connection *server_conn)
{
    ENSURE_REF(server_conn);

    /* Setup shared PSK for server */
    struct s2n_psk *shared_psk = NULL;
    GUARD_RESULT(s2n_array_pushback(&server_conn->psk_params.psk_list, (void**) &shared_psk));
    GUARD_AS_RESULT(s2n_psk_init(shared_psk, S2N_PSK_TYPE_EXTERNAL));
    GUARD_AS_RESULT(s2n_psk_new_identity(shared_psk, test_identity, sizeof(test_identity)));
    GUARD_AS_RESULT(s2n_psk_new_secret(shared_psk, test_secret, sizeof(test_secret)));
    shared_psk->hmac_alg = TEST_PSK_HMAC;

    /* Setup other server PSK */
    uint8_t other_server_data[] = "other server data";
    struct s2n_psk *other_server_psk = NULL;
    GUARD_RESULT(s2n_array_pushback(&server_conn->psk_params.psk_list, (void**) &other_server_psk));
    GUARD_AS_RESULT(s2n_psk_init(other_server_psk, S2N_PSK_TYPE_EXTERNAL));
    GUARD_AS_RESULT(s2n_psk_new_identity(other_server_psk, other_server_data, sizeof(other_server_data)));
    GUARD_AS_RESULT(s2n_psk_new_secret(other_server_psk, other_server_data, sizeof(other_server_data)));
    other_server_psk->hmac_alg = S2N_HMAC_SHA224;

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test: s2n_server_psk_should_send */
    {
        struct s2n_psk *psk = NULL;

        struct s2n_connection *conn = NULL;
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
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

            EXPECT_OK(setup_server_psks(server_conn));

            server_conn->psk_params.chosen_psk_wire_index = TEST_PSK_WIRE_INDEX;
            EXPECT_SUCCESS(s2n_server_psk_extension.send(server_conn, &out));

            uint16_t chosen_psk_wire_index = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&out, &chosen_psk_wire_index));
            EXPECT_EQUAL(chosen_psk_wire_index, server_conn->psk_params.chosen_psk_wire_index);

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        }
    }

    /* Test: s2n_server_psk_recv */
    {
        s2n_extension_type_id key_share_ext_id;
        EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(TLS_EXTENSION_KEY_SHARE, &key_share_ext_id));

        /* Test s2n_server_psk_recv for invalid TLS versions <= TLS1.2 */
        {
            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            struct s2n_connection *conn = NULL;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_OK(setup_client_psks(conn));

            /* The keyshare extension needs to be present, as s2n currently only
             * supports pre-shared keys in (EC)DHE key exchange mode.
             */
            S2N_CBIT_SET(conn->extension_requests_received, key_share_ext_id);

            uint16_t chosen_psk_wire_index = 1;
            /* Incorrect protocol version */
            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&out, chosen_psk_wire_index));

            EXPECT_NULL(conn->psk_params.chosen_psk);
            EXPECT_SUCCESS(s2n_server_psk_extension.recv(conn, &out));
            EXPECT_NULL(conn->psk_params.chosen_psk);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        }

        /* Test s2n_server_psk_recv when server key_share extension is not present */
        {
            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            struct s2n_connection *conn = NULL;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_OK(setup_client_psks(conn));

            uint16_t chosen_psk_wire_index = TEST_PSK_WIRE_INDEX;
            conn->actual_protocol_version = S2N_TLS13;

            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&out, chosen_psk_wire_index));

            EXPECT_NULL(conn->psk_params.chosen_psk);
            EXPECT_FAILURE_WITH_ERRNO(s2n_server_psk_extension.recv(conn, &out), S2N_ERR_MISSING_EXTENSION);
            EXPECT_NULL(conn->psk_params.chosen_psk);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out)); 
        }

        /* Receive invalid chosen psk wire index */
        {
            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            struct s2n_connection *conn = NULL;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_OK(setup_client_psks(conn));

            /* The keyshare extension needs to be present, as s2n currently only
             * supports pre-shared keys in (EC)DHE key exchange mode.
             */
            S2N_CBIT_SET(conn->extension_requests_received, key_share_ext_id);

            /* Invalid chosen psk wire index */
            uint16_t chosen_psk_wire_index = 10;
            conn->actual_protocol_version = S2N_TLS13;

            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&out, chosen_psk_wire_index));

            EXPECT_NULL(conn->psk_params.chosen_psk);
            EXPECT_FAILURE_WITH_ERRNO(s2n_server_psk_extension.recv(conn, &out), S2N_ERR_INVALID_ARGUMENT);
            EXPECT_NULL(conn->psk_params.chosen_psk);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&out));
        }

        /* Receive valid server preshared extension recv */
        {
            struct s2n_stuffer out = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&out, 0));

            struct s2n_connection *conn = NULL;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_OK(setup_client_psks(conn));

            /* The keyshare extension needs to be present, as s2n currently only
             * supports pre-shared keys in (EC)DHE key exchange mode.
             */
            S2N_CBIT_SET(conn->extension_requests_received, key_share_ext_id);

            uint16_t chosen_psk_wire_index = TEST_PSK_WIRE_INDEX;
            conn->actual_protocol_version = S2N_TLS13;

            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&out, chosen_psk_wire_index));

            EXPECT_NULL(conn->psk_params.chosen_psk);
            EXPECT_SUCCESS(s2n_server_psk_extension.recv(conn, &out));

            /* Verify chosen PSK */
            EXPECT_EQUAL(conn->psk_params.psk_ke_mode, S2N_PSK_DHE_KE);
            EXPECT_EQUAL(conn->psk_params.chosen_psk_wire_index, TEST_PSK_WIRE_INDEX);
            EXPECT_EQUAL(conn->psk_params.chosen_psk->identity.size, sizeof(test_identity));
            EXPECT_BYTEARRAY_EQUAL(conn->psk_params.chosen_psk->identity.data, test_identity, sizeof(test_identity));
            EXPECT_EQUAL(conn->psk_params.chosen_psk->secret.size, sizeof(test_secret));
            EXPECT_BYTEARRAY_EQUAL(conn->psk_params.chosen_psk->secret.data, test_secret, sizeof(test_secret));
            EXPECT_EQUAL(conn->psk_params.chosen_psk->hmac_alg, TEST_PSK_HMAC);

            /* Validate that the chosen PSK is not wiped and PSKs not chosen are wiped */
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
        EXPECT_SUCCESS(s2n_enable_tls13());
        struct s2n_connection *client_conn, *server_conn;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        /* Setup config */
        struct s2n_cert_chain_and_key *chain_and_key = NULL;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
        struct s2n_config *config = NULL;
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(client_conn, S2N_TLS13));
        EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));

        EXPECT_OK(setup_client_psks(client_conn));
        EXPECT_OK(setup_server_psks(server_conn));

        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                s2n_stuffer_data_available(&client_conn->handshake.io)));
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

        /* Verify shared PSK chosen */
        EXPECT_EQUAL(server_conn->psk_params.chosen_psk_wire_index, TEST_PSK_WIRE_INDEX);

        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));

        EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                s2n_stuffer_data_available(&server_conn->handshake.io)));

        EXPECT_NULL(client_conn->psk_params.chosen_psk);
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));

        /* Verify chosen PSK received */
        EXPECT_EQUAL(client_conn->psk_params.psk_ke_mode, S2N_PSK_DHE_KE);
        EXPECT_EQUAL(client_conn->psk_params.chosen_psk_wire_index, TEST_PSK_WIRE_INDEX);
        EXPECT_EQUAL(client_conn->psk_params.chosen_psk->identity.size, sizeof(test_identity));
        EXPECT_BYTEARRAY_EQUAL(client_conn->psk_params.chosen_psk->identity.data, test_identity, sizeof(test_identity));
        EXPECT_EQUAL(client_conn->psk_params.chosen_psk->secret.size, sizeof(test_secret));
        EXPECT_BYTEARRAY_EQUAL(client_conn->psk_params.chosen_psk->secret.data, test_secret, sizeof(test_secret));
        EXPECT_EQUAL(client_conn->psk_params.chosen_psk->hmac_alg, TEST_PSK_HMAC);

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
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(config));
    }

    END_TEST();
}
