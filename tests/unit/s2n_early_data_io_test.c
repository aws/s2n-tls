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

#include "tls/s2n_early_data.h"

static S2N_RESULT s2n_test_client_and_server_new(struct s2n_connection **client_conn, struct s2n_connection **server_conn)
{
    *client_conn = s2n_connection_new(S2N_CLIENT);
    EXPECT_NOT_NULL(*client_conn);
    EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(*client_conn, "default_tls13"));

    *server_conn = s2n_connection_new(S2N_SERVER);
    EXPECT_NOT_NULL(*server_conn);
    EXPECT_SUCCESS(s2n_connection_set_blinding(*server_conn, S2N_SELF_SERVICE_BLINDING));
    EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(*server_conn, "default_tls13"));

    struct s2n_test_io_pair io_pair = { 0 };
    EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
    EXPECT_SUCCESS(s2n_connections_set_io_pair(*client_conn, *server_conn, &io_pair));

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const uint8_t test_data[] = "hello world";

    DEFER_CLEANUP(struct s2n_psk *test_psk = s2n_external_psk_new(), s2n_psk_free);
    EXPECT_SUCCESS(s2n_psk_set_identity(test_psk, test_data, sizeof(test_data)));
    EXPECT_SUCCESS(s2n_psk_set_secret(test_psk, test_data, sizeof(test_data)));
    EXPECT_SUCCESS(s2n_psk_configure_early_data(test_psk, 100, 0x13, 0x01));

    DEFER_CLEANUP(struct s2n_psk *test_psk_without_early_data = s2n_external_psk_new(), s2n_psk_free);
    EXPECT_SUCCESS(s2n_psk_set_identity(test_psk_without_early_data, test_data, sizeof(test_data)));
    EXPECT_SUCCESS(s2n_psk_set_secret(test_psk_without_early_data, test_data, sizeof(test_data)));

    struct s2n_cert_chain_and_key *cert_chain = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&cert_chain,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    struct s2n_config *config_with_cert = s2n_config_new();
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config_with_cert, cert_chain));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config_with_cert));

    const struct s2n_ecc_named_curve *const curves_reversed_order[] = {
        &s2n_ecc_curve_secp384r1,
        &s2n_ecc_curve_secp256r1,
    };
    const struct s2n_ecc_preferences ecc_prefs_reversed_order = {
            .count = s2n_array_len(curves_reversed_order),
            .ecc_curves = curves_reversed_order,
    };
    struct s2n_security_policy sec_policy_reversed_order = security_policy_test_all_tls13;
    sec_policy_reversed_order.ecc_preferences = &ecc_prefs_reversed_order;
    const struct s2n_security_policy retry_policy = sec_policy_reversed_order;

    /* Test s2n_negotiate with early data */
    {
        /* Early data accepted */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_TRUE(WITH_EARLY_DATA(client_conn));
            EXPECT_TRUE(WITH_EARLY_DATA(server_conn));
            EXPECT_FALSE(IS_FULL_HANDSHAKE(client_conn));
            EXPECT_FALSE(IS_FULL_HANDSHAKE(server_conn));
            EXPECT_FALSE(IS_HELLO_RETRY_HANDSHAKE(client_conn));
            EXPECT_FALSE(IS_HELLO_RETRY_HANDSHAKE(server_conn));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), APPLICATION_DATA);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), APPLICATION_DATA);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Early data rejected */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk_without_early_data));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_FALSE(WITH_EARLY_DATA(client_conn));
            EXPECT_FALSE(WITH_EARLY_DATA(server_conn));
            EXPECT_FALSE(IS_FULL_HANDSHAKE(client_conn));
            EXPECT_FALSE(IS_FULL_HANDSHAKE(server_conn));
            EXPECT_FALSE(IS_HELLO_RETRY_HANDSHAKE(client_conn));
            EXPECT_FALSE(IS_HELLO_RETRY_HANDSHAKE(server_conn));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), APPLICATION_DATA);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), APPLICATION_DATA);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Early data rejected due to HRR */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk));
            client_conn->security_policy_override = &retry_policy;

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_FALSE(WITH_EARLY_DATA(client_conn));
            EXPECT_FALSE(WITH_EARLY_DATA(server_conn));
            EXPECT_FALSE(IS_FULL_HANDSHAKE(client_conn));
            EXPECT_FALSE(IS_FULL_HANDSHAKE(server_conn));
            EXPECT_TRUE(IS_HELLO_RETRY_HANDSHAKE(client_conn));
            EXPECT_TRUE(IS_HELLO_RETRY_HANDSHAKE(server_conn));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), APPLICATION_DATA);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), APPLICATION_DATA);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* PSK rejected altogether */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config_with_cert));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config_with_cert));
            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_FALSE(WITH_EARLY_DATA(client_conn));
            EXPECT_FALSE(WITH_EARLY_DATA(server_conn));
            EXPECT_TRUE(IS_FULL_HANDSHAKE(client_conn));
            EXPECT_TRUE(IS_FULL_HANDSHAKE(server_conn));
            EXPECT_FALSE(IS_HELLO_RETRY_HANDSHAKE(client_conn));
            EXPECT_FALSE(IS_HELLO_RETRY_HANDSHAKE(server_conn));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), APPLICATION_DATA);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), APPLICATION_DATA);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }
    }

    EXPECT_SUCCESS(s2n_config_free(config_with_cert));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(cert_chain));
    END_TEST();
}
