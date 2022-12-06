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

#define TEST_SHARED_PSK_WIRE_INDEX_1 1
#define TEST_SHARED_PSK_WIRE_INDEX_2 2
#define TEST_PSK_HMAC                S2N_PSK_HMAC_SHA256

#define ARE_FULL_HANDSHAKES(client, server) \
    (IS_FULL_HANDSHAKE(client) && IS_FULL_HANDSHAKE(server))

#define IS_CLIENT_AUTH(client, server) \
    (IS_CLIENT_AUTH_HANDSHAKE(client) && IS_CLIENT_AUTH_HANDSHAKE(server))

#define IS_HELLO_RETRY(client, server)                          \
    (((client->handshake.handshake_type) & HELLO_RETRY_REQUEST) \
            && ((server->handshake.handshake_type) & HELLO_RETRY_REQUEST))

#define s2n_set_io_pair_both_connections(client, server, io_pair) \
    EXPECT_SUCCESS(s2n_connection_set_io_pair(client, &io_pair)); \
    EXPECT_SUCCESS(s2n_connection_set_io_pair(server, &io_pair));

#define s2n_set_config_both_connections(client, server, config) \
    EXPECT_SUCCESS(s2n_connection_set_config(client, config));  \
    EXPECT_SUCCESS(s2n_connection_set_config(server, config));

uint8_t test_shared_identity[] = "test shared identity";
uint8_t test_shared_secret[] = "test shared secret";
uint8_t test_shared_identity_2[] = "test shared identity 2";
uint8_t test_shared_secret_2[] = "test shared secret 2";
uint8_t test_other_client_data[] = "test other client data";
uint8_t test_other_server_data[] = "test other server data";

static s2n_result setup_psk(struct s2n_connection *conn, const uint8_t *test_identity_data, uint16_t test_identity_size,
        const uint8_t *test_secret_data, uint16_t test_secret_size, s2n_psk_hmac test_hmac)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(test_identity_data);
    RESULT_ENSURE_REF(test_secret_data);

    struct s2n_psk *psk = s2n_external_psk_new();
    RESULT_GUARD_POSIX(s2n_psk_set_identity(psk, test_identity_data, test_identity_size));
    RESULT_GUARD_POSIX(s2n_psk_set_secret(psk, test_secret_data, test_secret_size));
    RESULT_GUARD_POSIX(s2n_psk_set_hmac(psk, test_hmac));
    RESULT_GUARD_POSIX(s2n_connection_append_psk(conn, psk));
    RESULT_GUARD_POSIX(s2n_psk_free(&psk));
    EXPECT_NULL(psk);

    return S2N_RESULT_OK;
}

static s2n_result setup_client_psks(struct s2n_connection *client_conn)
{
    RESULT_ENSURE_REF(client_conn);

    /* Setup other client PSK */
    EXPECT_OK(setup_psk(client_conn, test_other_client_data, sizeof(test_other_client_data), test_other_client_data,
            sizeof(test_other_client_data), TEST_PSK_HMAC));
    /* Setup first shared PSK for client */
    EXPECT_OK(setup_psk(client_conn, test_shared_identity, sizeof(test_shared_identity), test_shared_secret,
            sizeof(test_shared_secret), TEST_PSK_HMAC));
    /* Setup second shared PSK for client */
    EXPECT_OK(setup_psk(client_conn, test_shared_identity_2, sizeof(test_shared_identity_2), test_shared_secret_2,
            sizeof(test_shared_secret_2), TEST_PSK_HMAC));

    return S2N_RESULT_OK;
}

static s2n_result setup_server_psks(struct s2n_connection *server_conn)
{
    RESULT_ENSURE_REF(server_conn);

    /* Setup first shared PSK for server */
    EXPECT_OK(setup_psk(server_conn, test_shared_identity, sizeof(test_shared_identity), test_shared_secret,
            sizeof(test_shared_secret), TEST_PSK_HMAC));
    /* Setup other server PSK */
    EXPECT_OK(setup_psk(server_conn, test_other_server_data, sizeof(test_other_server_data), test_other_server_data,
            sizeof(test_other_server_data), S2N_PSK_HMAC_SHA384));
    /* Setup second shared PSK for server */
    EXPECT_OK(setup_psk(server_conn, test_shared_identity_2, sizeof(test_shared_identity_2), test_shared_secret_2,
            sizeof(test_shared_secret_2), TEST_PSK_HMAC));

    return S2N_RESULT_OK;
}

static s2n_result setup_psks_with_no_match(struct s2n_connection *client_conn, struct s2n_connection *server_conn)
{
    RESULT_ENSURE_REF(client_conn);
    RESULT_ENSURE_REF(server_conn);

    /* Setup other client PSK */
    EXPECT_OK(setup_psk(client_conn, test_other_client_data, sizeof(test_other_client_data), test_other_client_data,
            sizeof(test_other_client_data), S2N_PSK_HMAC_SHA256));
    /* Setup other server PSK */
    EXPECT_OK(setup_psk(server_conn, test_other_server_data, sizeof(test_other_server_data), test_other_server_data,
            sizeof(test_other_server_data), S2N_PSK_HMAC_SHA384));

    return S2N_RESULT_OK;
}

static s2n_result validate_chosen_psk(struct s2n_connection *server_conn, uint8_t *psk_identity_data,
        size_t psk_identity_size, size_t chosen_index)
{
    RESULT_ENSURE_REF(server_conn);
    RESULT_ENSURE_REF(psk_identity_data);
    RESULT_ENSURE_REF(server_conn->psk_params.chosen_psk);

    RESULT_ENSURE_EQ(server_conn->psk_params.chosen_psk->identity.size, psk_identity_size);
    RESULT_ENSURE_EQ(memcmp(server_conn->psk_params.chosen_psk->identity.data, psk_identity_data, psk_identity_size), 0);
    RESULT_ENSURE_EQ(server_conn->psk_params.chosen_psk_wire_index, chosen_index);

    return S2N_RESULT_OK;
}

static int s2n_test_select_psk_identity_callback(struct s2n_connection *conn, void *context,
        struct s2n_offered_psk_list *psk_identity_list)
{
    struct s2n_offered_psk offered_psk = { 0 };
    uint16_t idx = 0;
    while (s2n_offered_psk_list_has_next(psk_identity_list)) {
        POSIX_GUARD(s2n_offered_psk_list_next(psk_identity_list, &offered_psk));
        if (idx == TEST_SHARED_PSK_WIRE_INDEX_2) {
            POSIX_GUARD(s2n_offered_psk_list_choose_psk(psk_identity_list, &offered_psk));
            break;
        }
        idx++;
    };
    return S2N_SUCCESS;
}

static int s2n_client_hello_no_op_cb(struct s2n_connection *conn, void *ctx)
{
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    /* Setup connections */
    struct s2n_connection *client_conn = NULL;
    struct s2n_connection *server_conn = NULL;
    EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
    EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

    /* Setup config */
    struct s2n_config *config = NULL;
    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));

    /* Setup config with certificates set */
    struct s2n_config *config_with_certs = NULL;
    EXPECT_NOT_NULL(config_with_certs = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config_with_certs, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config_with_certs));
    struct s2n_cert_chain_and_key *chain_and_key = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key, S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN,
            S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config_with_certs, chain_and_key));

    /* Create nonblocking pipes */
    struct s2n_test_io_pair io_pair = { 0 };
    EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

    /* Basic PSK without callback function, without certificates and client auth not set */
    {
        s2n_set_config_both_connections(client_conn, server_conn, config);
        s2n_set_io_pair_both_connections(client_conn, server_conn, io_pair);

        /* Setup PSKs */
        EXPECT_OK(setup_client_psks(client_conn));
        EXPECT_OK(setup_server_psks(server_conn));

        /* Negotiate handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Validate handshake type */
        EXPECT_FALSE(ARE_FULL_HANDSHAKES(client_conn, server_conn));

        /* Validate chosen PSK */
        EXPECT_OK(validate_chosen_psk(server_conn, test_shared_identity, sizeof(test_shared_identity),
                TEST_SHARED_PSK_WIRE_INDEX_1));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
    };

    /* PSK with callback function */
    {
        s2n_set_config_both_connections(client_conn, server_conn, config);
        s2n_set_io_pair_both_connections(client_conn, server_conn, io_pair);

        /* Setup PSKs */
        EXPECT_OK(setup_client_psks(client_conn));
        EXPECT_OK(setup_server_psks(server_conn));

        /* Set the customer callback to select PSK identity */
        EXPECT_SUCCESS(s2n_config_set_psk_selection_callback(server_conn->config, s2n_test_select_psk_identity_callback, NULL));
        EXPECT_EQUAL(server_conn->config->psk_selection_cb, s2n_test_select_psk_identity_callback);

        /* Negotiate handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Validate handshake type */
        EXPECT_FALSE(ARE_FULL_HANDSHAKES(client_conn, server_conn));

        /* Validate chosen PSK */
        EXPECT_OK(validate_chosen_psk(server_conn, test_shared_identity_2, sizeof(test_shared_identity_2),
                TEST_SHARED_PSK_WIRE_INDEX_2));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        server_conn->config->psk_selection_cb = NULL;

        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
    };

    /* PSK with certificates set */
    {
        /* Setup certs */
        s2n_set_config_both_connections(client_conn, server_conn, config_with_certs);
        s2n_set_io_pair_both_connections(client_conn, server_conn, io_pair);

        /* Setup PSKs */
        EXPECT_OK(setup_client_psks(client_conn));
        EXPECT_OK(setup_server_psks(server_conn));

        /* Negotiate handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Validate handshake type */
        EXPECT_FALSE(ARE_FULL_HANDSHAKES(client_conn, server_conn));

        /* Validate chosen PSK */
        EXPECT_OK(validate_chosen_psk(server_conn, test_shared_identity, sizeof(test_shared_identity),
                TEST_SHARED_PSK_WIRE_INDEX_1));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
    };

    /* PSK with certificates set and client auth set as required */
    {
        /* Setup certs */
        s2n_set_config_both_connections(client_conn, server_conn, config_with_certs);
        s2n_set_io_pair_both_connections(client_conn, server_conn, io_pair);

        /* Explicitly set client_auth as required */
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_REQUIRED));
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(server_conn, S2N_CERT_AUTH_REQUIRED));

        /* Setup PSKs */
        EXPECT_OK(setup_client_psks(client_conn));
        EXPECT_OK(setup_server_psks(server_conn));

        /* Negotiate handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Validate handshake type */
        EXPECT_FALSE(IS_CLIENT_AUTH(client_conn, server_conn));
        EXPECT_FALSE(ARE_FULL_HANDSHAKES(client_conn, server_conn));

        /* Validate chosen PSK */
        EXPECT_OK(validate_chosen_psk(server_conn, test_shared_identity, sizeof(test_shared_identity),
                TEST_SHARED_PSK_WIRE_INDEX_1));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
    };

    /* Basic PSK with Client Hello async callback set */
    {
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, s2n_client_hello_no_op_cb, NULL));
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb_mode(config, S2N_CLIENT_HELLO_CB_NONBLOCKING));

        s2n_set_config_both_connections(client_conn, server_conn, config);
        s2n_set_io_pair_both_connections(client_conn, server_conn, io_pair);

        /* Setup PSKs */
        EXPECT_OK(setup_client_psks(client_conn));
        EXPECT_OK(setup_server_psks(server_conn));

        /* Handshake negotiation is successful when the Client Hello callback is marked as done */
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn), S2N_ERR_ASYNC_BLOCKED);
        EXPECT_SUCCESS(s2n_client_hello_cb_done(server_conn));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Validate handshake type */
        EXPECT_FALSE(ARE_FULL_HANDSHAKES(client_conn, server_conn));

        /* Validate chosen PSK */
        EXPECT_OK(validate_chosen_psk(server_conn, test_shared_identity, sizeof(test_shared_identity),
                TEST_SHARED_PSK_WIRE_INDEX_1));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, NULL, NULL));
    };

    /* HRR with PSK and Client Hello async callback set */
    {
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config_with_certs, s2n_client_hello_no_op_cb, NULL));
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb_mode(config_with_certs, S2N_CLIENT_HELLO_CB_NONBLOCKING));

        /* Setup certs */
        s2n_set_config_both_connections(client_conn, server_conn, config_with_certs);
        s2n_set_io_pair_both_connections(client_conn, server_conn, io_pair);

        /* Force the HRR path */
        client_conn->security_policy_override = &security_policy_test_tls13_retry;

        /* Setup PSKs */
        EXPECT_OK(setup_client_psks(client_conn));
        EXPECT_OK(setup_server_psks(server_conn));

        /* Handshake negotiation is successful when the Client Hello callback is marked as done */
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn), S2N_ERR_ASYNC_BLOCKED);
        EXPECT_SUCCESS(s2n_client_hello_cb_done(server_conn));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Validate handshake type */
        EXPECT_TRUE(IS_HELLO_RETRY(client_conn, server_conn));
        EXPECT_FALSE(ARE_FULL_HANDSHAKES(client_conn, server_conn));

        /* Validate chosen PSK */
        EXPECT_OK(validate_chosen_psk(server_conn, test_shared_identity, sizeof(test_shared_identity),
                TEST_SHARED_PSK_WIRE_INDEX_1));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config_with_certs, NULL, NULL));
    };

    /* Fallback to full handshake if no PSK is chosen and certificates are set */
    {
        /* Setup certs */
        s2n_set_config_both_connections(client_conn, server_conn, config_with_certs);
        s2n_set_io_pair_both_connections(client_conn, server_conn, io_pair);

        /* Setup no matching PSKs */
        EXPECT_OK(setup_psks_with_no_match(client_conn, server_conn));

        /* Negotiate handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Validate handshake type */
        EXPECT_TRUE(ARE_FULL_HANDSHAKES(client_conn, server_conn));

        /* Validate that a PSK is not chosen */
        EXPECT_NULL(server_conn->psk_params.chosen_psk);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
    };

    /* Fallback to full handshake uses client auth if requested */
    {
        /* Setup certs */
        s2n_set_config_both_connections(client_conn, server_conn, config_with_certs);
        s2n_set_io_pair_both_connections(client_conn, server_conn, io_pair);

        /* Explicitly set client_auth as required */
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client_conn, S2N_CERT_AUTH_REQUIRED));
        EXPECT_SUCCESS(s2n_connection_set_client_auth_type(server_conn, S2N_CERT_AUTH_REQUIRED));

        /* Setup no matching PSKs */
        EXPECT_OK(setup_psks_with_no_match(client_conn, server_conn));

        /* Negotiate handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Validate handshake type */
        EXPECT_TRUE(IS_CLIENT_AUTH(client_conn, server_conn));
        EXPECT_TRUE(ARE_FULL_HANDSHAKES(client_conn, server_conn));

        /* Validate that a PSK is not chosen */
        EXPECT_NULL(server_conn->psk_params.chosen_psk);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
    };

    /* Error Case: Fallback to full handshake if no PSK is chosen and certificates are not set */
    {
        s2n_set_config_both_connections(client_conn, server_conn, config);
        s2n_set_io_pair_both_connections(client_conn, server_conn, io_pair);
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

        /* Setup no matching PSKs */
        EXPECT_OK(setup_psks_with_no_match(client_conn, server_conn));

        /* Negotiate handshake */
        EXPECT_FAILURE(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Validate that a PSK is not chosen */
        EXPECT_NULL(server_conn->psk_params.chosen_psk);

        /* Validate handshake type is not FULL_HANDSHAKE */
        EXPECT_FALSE(ARE_FULL_HANDSHAKES(client_conn, server_conn));

        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
    };

    /* Clean-up */
    EXPECT_SUCCESS(s2n_connection_free(server_conn));
    EXPECT_SUCCESS(s2n_connection_free(client_conn));
    EXPECT_SUCCESS(s2n_config_free(config));
    EXPECT_SUCCESS(s2n_config_free(config_with_certs));
    EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

    END_TEST();
}
