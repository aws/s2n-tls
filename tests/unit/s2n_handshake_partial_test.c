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
#include "tls/s2n_handshake.h"
#include "tls/s2n_record.h"
#include "tls/s2n_tls.h"

static S2N_RESULT s2n_get_test_client_and_server(struct s2n_connection **client_conn, struct s2n_connection **server_conn,
        struct s2n_config *config)
{
    *client_conn = s2n_connection_new(S2N_CLIENT);
    RESULT_ENSURE_REF(*client_conn);

    *server_conn = s2n_connection_new(S2N_SERVER);
    RESULT_GUARD_POSIX(s2n_connection_set_blinding(*server_conn, S2N_SELF_SERVICE_BLINDING));
    RESULT_ENSURE_REF(*server_conn);

    RESULT_GUARD_POSIX(s2n_connection_set_config(*client_conn, config));
    RESULT_GUARD_POSIX(s2n_connection_set_config(*server_conn, config));

    struct s2n_test_io_pair io_pair = { 0 };
    RESULT_GUARD_POSIX(s2n_io_pair_init_non_blocking(&io_pair));
    RESULT_GUARD_POSIX(s2n_connections_set_io_pair(*client_conn, *server_conn, &io_pair));

    return S2N_RESULT_OK;
}

int main()
{
    BEGIN_TEST();

    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    const uint8_t test_psk_data[] = "very secret";
    DEFER_CLEANUP(struct s2n_psk *test_psk = s2n_external_psk_new(), s2n_psk_free);
    EXPECT_SUCCESS(s2n_psk_set_identity(test_psk, test_psk_data, sizeof(test_psk_data)));
    EXPECT_SUCCESS(s2n_psk_set_secret(test_psk, test_psk_data, sizeof(test_psk_data)));
    EXPECT_SUCCESS(s2n_psk_configure_early_data(test_psk, 100, 0x13, 0x01));

    struct s2n_cert_chain_and_key *cert_chain = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&cert_chain,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    struct s2n_config *config = s2n_config_new();
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, cert_chain));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));

    /* Test s2n_negotiate_until_message */
    {
        /* Safety */
        {
            struct s2n_connection conn = { 0 };
            s2n_blocked_status blocked = 0;
            EXPECT_ERROR_WITH_ERRNO(s2n_negotiate_until_message(NULL, &blocked, CLIENT_HELLO), S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_negotiate_until_message(&conn, NULL, CLIENT_HELLO), S2N_ERR_NULL);
        };

        /* If message is never encountered, complete the handshake */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_get_test_client_and_server(&client_conn, &server_conn, config));

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    SERVER_KEY));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), APPLICATION_DATA);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), APPLICATION_DATA);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* Can stop on a given message */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_get_test_client_and_server(&client_conn, &server_conn, config));

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    SERVER_CERT_VERIFY));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_CERT_VERIFY);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), SERVER_CERT_VERIFY);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* Can be called repeatedly */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_get_test_client_and_server(&client_conn, &server_conn, config));

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    CLIENT_HELLO));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), CLIENT_HELLO);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), CLIENT_HELLO);

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    CLIENT_HELLO));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), CLIENT_HELLO);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), CLIENT_HELLO);

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    SERVER_HELLO));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_HELLO);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), SERVER_HELLO);

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    SERVER_HELLO));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_HELLO);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), SERVER_HELLO);

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    APPLICATION_DATA));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), APPLICATION_DATA);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), APPLICATION_DATA);

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    APPLICATION_DATA));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), APPLICATION_DATA);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), APPLICATION_DATA);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* Can continue as normal after stopping */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_get_test_client_and_server(&client_conn, &server_conn, config));

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    CLIENT_FINISHED));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), CLIENT_FINISHED);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), CLIENT_FINISHED);

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), APPLICATION_DATA);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), APPLICATION_DATA);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* Can stop on END_OF_EARLY_DATA when using early data, then continue.
         * (This is the non-test use case for this feature) */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_get_test_client_and_server(&client_conn, &server_conn, config));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    END_OF_EARLY_DATA));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), END_OF_EARLY_DATA);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), END_OF_EARLY_DATA);

            EXPECT_SUCCESS(s2n_connection_set_end_of_early_data(client_conn));
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), APPLICATION_DATA);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), APPLICATION_DATA);

            EXPECT_TRUE(WITH_EARLY_DATA(client_conn));
            EXPECT_TRUE(WITH_EARLY_DATA(server_conn));

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };
    };

    EXPECT_SUCCESS(s2n_config_free(config));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(cert_chain));
    END_TEST();
}
