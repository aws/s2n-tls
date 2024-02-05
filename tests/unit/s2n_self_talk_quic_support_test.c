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
#include "tls/s2n_quic_support.h"

#define S2N_MODE_COUNT        2
#define S2N_SECRET_TYPE_COUNT 6

static const uint8_t CLIENT_TRANSPORT_PARAMS[] = "client transport params";
static const uint8_t SERVER_TRANSPORT_PARAMS[] = "server transport params";

static int s2n_test_secret_handler(void *context, struct s2n_connection *conn,
        s2n_secret_type_t secret_type,
        uint8_t *secret, uint8_t secret_size)
{
    /* Verify context passed through correctly */
    struct s2n_blob(*secrets)[S2N_SECRET_TYPE_COUNT] = context;
    EXPECT_NOT_NULL(secrets);

    /* Save secret for later */
    EXPECT_SUCCESS(s2n_alloc(&secrets[conn->mode][secret_type], secret_size));
    EXPECT_MEMCPY_SUCCESS(secrets[conn->mode][secret_type].data, secret, secret_size);

    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    const uint8_t *transport_params = NULL;
    uint16_t transport_params_len = 0;

    /* Setup connections */
    struct s2n_connection *client_conn, *server_conn;
    EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
    EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

    /* Setup config */
    struct s2n_cert_chain_and_key *chain_and_key;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
    struct s2n_config *config;
    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_enable_quic(config));
    EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
    EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

    /* Create nonblocking pipes */
    struct s2n_test_io_pair io_pair;
    EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
    EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
    EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

    /* Setup quic transport parameters */
    EXPECT_SUCCESS(s2n_connection_set_quic_transport_parameters(client_conn,
            CLIENT_TRANSPORT_PARAMS, sizeof(CLIENT_TRANSPORT_PARAMS)));
    EXPECT_SUCCESS(s2n_connection_set_quic_transport_parameters(server_conn,
            SERVER_TRANSPORT_PARAMS, sizeof(SERVER_TRANSPORT_PARAMS)));

    /* Set secret handler */
    struct s2n_blob secrets[S2N_MODE_COUNT][S2N_SECRET_TYPE_COUNT] = { 0 };
    EXPECT_SUCCESS(s2n_connection_set_secret_callback(client_conn, s2n_test_secret_handler, secrets));
    EXPECT_SUCCESS(s2n_connection_set_secret_callback(server_conn, s2n_test_secret_handler, secrets));

    /* Do handshake */
    EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

    /* Verify TLS1.3 */
    EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);
    EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

    /* Verify server quic_transport_parameters on client */
    EXPECT_SUCCESS(s2n_connection_get_quic_transport_parameters(client_conn,
            &transport_params, &transport_params_len));
    EXPECT_EQUAL(transport_params_len, sizeof(SERVER_TRANSPORT_PARAMS));
    EXPECT_BYTEARRAY_EQUAL(transport_params, SERVER_TRANSPORT_PARAMS, transport_params_len);

    /* Verify client quic_transport_parameters on server */
    EXPECT_SUCCESS(s2n_connection_get_quic_transport_parameters(server_conn,
            &transport_params, &transport_params_len));
    EXPECT_EQUAL(transport_params_len, sizeof(CLIENT_TRANSPORT_PARAMS));
    EXPECT_BYTEARRAY_EQUAL(transport_params, CLIENT_TRANSPORT_PARAMS, transport_params_len);

    /* Verify legacy_session_id not set (QUIC does not use middlebox compat mode) */
    EXPECT_EQUAL(client_conn->session_id_len, 0);
    EXPECT_EQUAL(server_conn->session_id_len, 0);

    /* Verify handshake not MIDDLEBOX_COMPAT (QUIC does not use middlebox compat mode) */
    EXPECT_FALSE(IS_MIDDLEBOX_COMPAT_MODE(client_conn));
    EXPECT_FALSE(IS_MIDDLEBOX_COMPAT_MODE(server_conn));

    /* Verify secret handler collected secrets */
    for (size_t i = 1; i < S2N_SECRET_TYPE_COUNT; i++) {
        EXPECT_NOT_EQUAL(secrets[S2N_CLIENT][i].size, 0);
        EXPECT_EQUAL(secrets[S2N_CLIENT][i].size, secrets[S2N_SERVER][i].size);
        EXPECT_BYTEARRAY_EQUAL(secrets[S2N_CLIENT][i].data, secrets[S2N_SERVER][i].data, secrets[S2N_SERVER][i].size);

        EXPECT_SUCCESS(s2n_free(&secrets[S2N_CLIENT][i]));
        EXPECT_SUCCESS(s2n_free(&secrets[S2N_SERVER][i]));
    }

    EXPECT_SUCCESS(s2n_connection_free(server_conn));
    EXPECT_SUCCESS(s2n_connection_free(client_conn));
    EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    EXPECT_SUCCESS(s2n_config_free(config));

    END_TEST();
}
