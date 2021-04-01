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

#define TEST_MAX_EARLY_DATA_SIZE 1000

#define EXPECT_SUCCESS_S2N_SEND(conn, data, data_len, blocked) \
        EXPECT_EQUAL(s2n_send(conn, data, data_len, blocked), data_len)
#define EXPECT_SUCCESS_S2N_RECV(conn, data_buffer, data_buffer_size, blocked, data, data_len) \
        EXPECT_EQUAL(s2n_recv(conn, data_buffer, data_buffer_size, blocked), data_len); \
        EXPECT_BYTEARRAY_EQUAL(data_buffer, data, data_len)

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
    EXPECT_SUCCESS(s2n_psk_configure_early_data(test_psk, TEST_MAX_EARLY_DATA_SIZE, 0x13, 0x01));

    DEFER_CLEANUP(struct s2n_psk *test_psk_without_early_data = s2n_external_psk_new(), s2n_psk_free);
    EXPECT_SUCCESS(s2n_psk_set_identity(test_psk_without_early_data, test_data, sizeof(test_data)));
    EXPECT_SUCCESS(s2n_psk_set_secret(test_psk_without_early_data, test_data, sizeof(test_data)));

    DEFER_CLEANUP(struct s2n_psk *test_psk_to_reject = s2n_external_psk_new(), s2n_psk_free);
    EXPECT_SUCCESS(s2n_psk_set_identity(test_psk_to_reject, test_data, sizeof(test_data)));
    EXPECT_SUCCESS(s2n_psk_set_secret(test_psk_to_reject, test_data, sizeof(test_data)));
    EXPECT_SUCCESS(s2n_psk_configure_early_data(test_psk_to_reject, TEST_MAX_EARLY_DATA_SIZE, 0x13, 0x03));

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
        /* Early data not supported by server */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_FALSE(WITH_EARLY_DATA(client_conn));
            EXPECT_FALSE(WITH_EARLY_DATA(server_conn));
            EXPECT_TRUE(WITH_EARLY_CLIENT_CCS(client_conn));
            EXPECT_TRUE(WITH_EARLY_CLIENT_CCS(server_conn));
            EXPECT_FALSE(IS_FULL_HANDSHAKE(client_conn));
            EXPECT_FALSE(IS_FULL_HANDSHAKE(server_conn));
            EXPECT_FALSE(IS_HELLO_RETRY_HANDSHAKE(client_conn));
            EXPECT_FALSE(IS_HELLO_RETRY_HANDSHAKE(server_conn));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), APPLICATION_DATA);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), APPLICATION_DATA);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Early data not supported by client */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_FALSE(WITH_EARLY_DATA(client_conn));
            EXPECT_FALSE(WITH_EARLY_DATA(server_conn));
            EXPECT_FALSE(WITH_EARLY_CLIENT_CCS(client_conn));
            EXPECT_FALSE(WITH_EARLY_CLIENT_CCS(server_conn));
            EXPECT_FALSE(IS_FULL_HANDSHAKE(client_conn));
            EXPECT_FALSE(IS_FULL_HANDSHAKE(server_conn));
            EXPECT_FALSE(IS_HELLO_RETRY_HANDSHAKE(client_conn));
            EXPECT_FALSE(IS_HELLO_RETRY_HANDSHAKE(server_conn));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), APPLICATION_DATA);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), APPLICATION_DATA);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Server does not support TLS1.3 */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "test_all"));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "test_all_tls12"));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config_with_cert));

            /* Stop the TLS1.2 server before the CLIENT_KEY message. At that point, it will attempt to read
             * a CLIENT_KEY message but instead receive CLIENT_CHANGE_CIPHER_SPEC. But this error is
             * irrelevant to the test: TLS1.2 servers aren't expected to successfully handle early data.
             *
             * What we really care about is how the client reacts to the TLS1.2 SERVER_HELLO.
             */
            EXPECT_ERROR_WITH_ERRNO(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    CLIENT_KEY), S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Early data accepted */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    END_OF_EARLY_DATA));

            /* Blocked indefinitely */
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            for (size_t i = 0; i < 10; i++) {
                EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(client_conn, &blocked), S2N_ERR_EARLY_DATA_BLOCKED);
                EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_EARLY_DATA);
            }

            EXPECT_SUCCESS(s2n_connection_set_end_of_early_data(client_conn));
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_TRUE(WITH_EARLY_DATA(client_conn));
            EXPECT_TRUE(WITH_EARLY_DATA(server_conn));
            EXPECT_TRUE(WITH_EARLY_CLIENT_CCS(client_conn));
            EXPECT_TRUE(WITH_EARLY_CLIENT_CCS(server_conn));
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
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_FALSE(WITH_EARLY_DATA(client_conn));
            EXPECT_FALSE(WITH_EARLY_DATA(server_conn));
            EXPECT_TRUE(WITH_EARLY_CLIENT_CCS(client_conn));
            EXPECT_TRUE(WITH_EARLY_CLIENT_CCS(server_conn));
            EXPECT_FALSE(IS_FULL_HANDSHAKE(client_conn));
            EXPECT_FALSE(IS_FULL_HANDSHAKE(server_conn));
            EXPECT_FALSE(IS_HELLO_RETRY_HANDSHAKE(client_conn));
            EXPECT_FALSE(IS_HELLO_RETRY_HANDSHAKE(server_conn));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), APPLICATION_DATA);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), APPLICATION_DATA);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Early data rejected and ignored */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk_to_reject));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    SERVER_HELLO));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_REQUESTED);

            /* Send some early data to verify the server ignores it */
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_SUCCESS_S2N_SEND(client_conn, test_data, sizeof(test_data), &blocked);
            EXPECT_SUCCESS_S2N_SEND(client_conn, test_data, sizeof(test_data), &blocked);
            EXPECT_SUCCESS_S2N_SEND(client_conn, test_data, sizeof(test_data), &blocked);

            EXPECT_SUCCESS(s2n_connection_set_end_of_early_data(client_conn));
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

        /* Early data rejected, but too much early data received */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk_to_reject));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    SERVER_HELLO));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_REQUESTED);

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_TRUE((TEST_MAX_EARLY_DATA_SIZE / sizeof(test_data)) > 0);
            for (size_t i = 0; i < (TEST_MAX_EARLY_DATA_SIZE / sizeof(test_data)); i++) {
                EXPECT_SUCCESS_S2N_SEND(client_conn, test_data, sizeof(test_data), &blocked);
            }

            /* Trick the client into sending more early data than allowed */
            client_conn->early_data_bytes = 0;
            EXPECT_SUCCESS_S2N_SEND(client_conn, test_data, sizeof(test_data), &blocked);

            EXPECT_SUCCESS(s2n_connection_set_end_of_early_data(client_conn));
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                    S2N_ERR_MAX_EARLY_DATA_SIZE);

            EXPECT_FALSE(WITH_EARLY_DATA(client_conn));
            EXPECT_FALSE(WITH_EARLY_DATA(server_conn));
            EXPECT_FALSE(IS_FULL_HANDSHAKE(client_conn));
            EXPECT_FALSE(IS_FULL_HANDSHAKE(server_conn));
            EXPECT_FALSE(IS_HELLO_RETRY_HANDSHAKE(client_conn));
            EXPECT_FALSE(IS_HELLO_RETRY_HANDSHAKE(server_conn));

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Early data rejected due to HRR */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));
            client_conn->security_policy_override = &retry_policy;

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_FALSE(WITH_EARLY_DATA(client_conn));
            EXPECT_FALSE(WITH_EARLY_DATA(server_conn));
            EXPECT_TRUE(WITH_EARLY_CLIENT_CCS(client_conn));
            EXPECT_TRUE(WITH_EARLY_CLIENT_CCS(server_conn));
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
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));
            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_FALSE(WITH_EARLY_DATA(client_conn));
            EXPECT_FALSE(WITH_EARLY_DATA(server_conn));
            EXPECT_TRUE(WITH_EARLY_CLIENT_CCS(client_conn));
            EXPECT_TRUE(WITH_EARLY_CLIENT_CCS(server_conn));
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

    /* Test s2n_send with early data */
    {
        /* End early data after the server accepts the early data request */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;

            /* Can't send early data before negotiation begins */
            EXPECT_EQUAL(client_conn->early_data_state, S2N_UNKNOWN_EARLY_DATA_STATE);
            EXPECT_FAILURE_WITH_ERRNO(s2n_send(client_conn, test_data, sizeof(test_data), &blocked),
                    S2N_ERR_EARLY_DATA_NOT_ALLOWED);
            EXPECT_FAILURE_WITH_ERRNO(s2n_send(client_conn, test_data, 0, &blocked),
                    S2N_ERR_EARLY_DATA_NOT_ALLOWED);

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    SERVER_HELLO));

            /* Can send after early data requested */
            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_REQUESTED);
            EXPECT_SUCCESS_S2N_SEND(client_conn, test_data, sizeof(test_data), &blocked);

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    SERVER_FINISHED));

            /* Can send after early data accepted */
            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_ACCEPTED);
            EXPECT_SUCCESS_S2N_SEND(client_conn, test_data, sizeof(test_data), &blocked);

            /* Can send zero-length */
            EXPECT_SUCCESS_S2N_SEND(client_conn, NULL, 0, &blocked);

            /* Can send more */
            EXPECT_SUCCESS_S2N_SEND(client_conn, test_data, sizeof(test_data), &blocked);

            /* Can't send too much early data */
            EXPECT_FAILURE_WITH_ERRNO(s2n_send(client_conn, test_data, TEST_MAX_EARLY_DATA_SIZE, &blocked),
                    S2N_ERR_MAX_EARLY_DATA_SIZE);

            /* Can continue sending, even if a send failed */
            EXPECT_SUCCESS_S2N_SEND(client_conn, test_data, sizeof(test_data), &blocked);

            /* Can't send early data after end of early data indicated */
            EXPECT_SUCCESS(s2n_connection_set_end_of_early_data(client_conn));
            EXPECT_FAILURE_WITH_ERRNO(s2n_send(client_conn, NULL, 0, &blocked), S2N_ERR_EARLY_DATA_NOT_ALLOWED);

            /* Continue the handshake */
            EXPECT_ERROR_WITH_ERRNO(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    CLIENT_FINISHED), S2N_ERR_EARLY_DATA_BLOCKED);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), CLIENT_FINISHED);

            /* Can't send early data after END_OF_EARLY_DATA sent */
            EXPECT_EQUAL(client_conn->early_data_state, S2N_END_OF_EARLY_DATA);
            EXPECT_FAILURE_WITH_ERRNO(s2n_send(client_conn, NULL, 0, &blocked), S2N_ERR_EARLY_DATA_NOT_ALLOWED);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* End early data before the server accepts the early data request. */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    SERVER_HELLO));

            /* Can send after early data requested */
            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_REQUESTED);
            EXPECT_SUCCESS_S2N_SEND(client_conn, test_data, sizeof(test_data), &blocked);

            /* Can't send early data after end of early data indicated */
            EXPECT_SUCCESS(s2n_connection_set_end_of_early_data(client_conn));
            EXPECT_FAILURE_WITH_ERRNO(s2n_send(client_conn, NULL, 0, &blocked), S2N_ERR_EARLY_DATA_NOT_ALLOWED);

            /* Continue the handshake */
            EXPECT_ERROR_WITH_ERRNO(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    CLIENT_FINISHED), S2N_ERR_EARLY_DATA_BLOCKED);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), CLIENT_FINISHED);

            /* Still can't send early data after END_OF_EARLY_DATA sent */
            EXPECT_EQUAL(client_conn->early_data_state, S2N_END_OF_EARLY_DATA);
            EXPECT_FAILURE_WITH_ERRNO(s2n_send(client_conn, NULL, 0, &blocked), S2N_ERR_EARLY_DATA_NOT_ALLOWED);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }
    }

    /* Test s2n_recv with early data */
    {
        /* s2n_recv can read early data sent with s2n_send */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            uint8_t test_buffer[TEST_MAX_EARLY_DATA_SIZE] = { 0 };

            /* Can't recv early data before negotiation begins */
            EXPECT_EQUAL(server_conn->early_data_state, S2N_UNKNOWN_EARLY_DATA_STATE);
            EXPECT_FAILURE_WITH_ERRNO(s2n_recv(server_conn, test_buffer, sizeof(test_buffer), &blocked),
                    S2N_ERR_EARLY_DATA_NOT_ALLOWED);
            EXPECT_FAILURE_WITH_ERRNO(s2n_recv(server_conn, test_buffer, 0, &blocked),
                    S2N_ERR_EARLY_DATA_NOT_ALLOWED);

            /* Can't recv before END_OF_EARLY_DATA */
            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    SERVER_HELLO));
            EXPECT_FAILURE_WITH_ERRNO(s2n_recv(server_conn, test_buffer, 0, &blocked), S2N_ERR_EARLY_DATA_NOT_ALLOWED);

            /* Can recv on END_OF_EARLY_DATA */
            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    END_OF_EARLY_DATA));
            EXPECT_SUCCESS_S2N_RECV(server_conn, test_buffer, 0, &blocked, test_data, 0);

            /* Can recv after s2n_negotiate decrypts the record */
            EXPECT_SUCCESS_S2N_SEND(client_conn, test_data, sizeof(test_data), &blocked);
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(server_conn, &blocked), S2N_ERR_EARLY_DATA_BLOCKED);
            EXPECT_SUCCESS_S2N_RECV(server_conn, test_buffer, sizeof(test_buffer), &blocked,
                    test_data, sizeof(test_data));
            EXPECT_BYTEARRAY_EQUAL(test_buffer, test_data, sizeof(test_data));

            /* Can spread recv over multiple calls */
            EXPECT_SUCCESS_S2N_SEND(client_conn, test_data, sizeof(test_data), &blocked);
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(server_conn, &blocked), S2N_ERR_EARLY_DATA_BLOCKED);
            EXPECT_SUCCESS_S2N_RECV(server_conn, test_buffer, 0, &blocked, test_data, 0);
            EXPECT_SUCCESS_S2N_RECV(server_conn, test_buffer, 2, &blocked, test_data, 2);
            EXPECT_SUCCESS_S2N_RECV(server_conn, test_buffer, (sizeof(test_data) - 2), &blocked,
                    (test_data + 2), (sizeof(test_data) - 2));

            /* Can block + recv repeatedly on the same record */
            EXPECT_SUCCESS_S2N_SEND(client_conn, test_data, sizeof(test_data), &blocked);
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(server_conn, &blocked), S2N_ERR_EARLY_DATA_BLOCKED);
            EXPECT_SUCCESS_S2N_RECV(server_conn, test_buffer, 2, &blocked, test_data, 2);
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(server_conn, &blocked), S2N_ERR_EARLY_DATA_BLOCKED);
            EXPECT_SUCCESS_S2N_RECV(server_conn, test_buffer, 0, &blocked, test_data, 0);
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(server_conn, &blocked), S2N_ERR_EARLY_DATA_BLOCKED);
            EXPECT_SUCCESS_S2N_RECV(server_conn, test_buffer, (sizeof(test_data) - 2), &blocked,
                    (test_data + 2), (sizeof(test_data) - 2));

            /* Can't recv after END_OF_EARLY_DATA */
            EXPECT_SUCCESS(s2n_connection_set_end_of_early_data(client_conn));
            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, CLIENT_FINISHED));
            EXPECT_FAILURE_WITH_ERRNO(s2n_recv(server_conn, test_buffer, 0, &blocked), S2N_ERR_EARLY_DATA_NOT_ALLOWED);

            /* Can finish handshake */
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* s2n_recv fails if it encounters a handshake message instead of early data. */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            uint8_t test_buffer[TEST_MAX_EARLY_DATA_SIZE] = { 0 };
            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    END_OF_EARLY_DATA));

            /* Client sends the EndOfEarlyData handshake message */
            EXPECT_SUCCESS(s2n_connection_set_end_of_early_data(client_conn));
            EXPECT_SUCCESS(s2n_negotiate(client_conn, &blocked));

            /* Server fails to read the EndOfEarlyData handshake message via s2n_recv.
             * s2n_recv can only process post-handshake messages, and EndOfEarlyData is not a post-handshake
             * message.
             * We should have read the EndOfEarlyData handshake message via s2n_negotiate.
             */
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), END_OF_EARLY_DATA);
            EXPECT_FAILURE_WITH_ERRNO(s2n_recv(server_conn, test_buffer, sizeof(test_buffer), &blocked),
                    S2N_ERR_BAD_MESSAGE);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* s2n_recv fails on too much early data */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            const uint8_t large_test_data[TEST_MAX_EARLY_DATA_SIZE] = "hello";
            uint8_t test_buffer[TEST_MAX_EARLY_DATA_SIZE] = { 0 };

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                    END_OF_EARLY_DATA));

            /* Send the maximum allowed data */
            EXPECT_SUCCESS_S2N_SEND(client_conn, large_test_data, sizeof(large_test_data), &blocked);
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(server_conn, &blocked), S2N_ERR_EARLY_DATA_BLOCKED);
            EXPECT_SUCCESS_S2N_RECV(server_conn, test_buffer, sizeof(test_buffer), &blocked,
                    large_test_data, TEST_MAX_EARLY_DATA_SIZE);

            /* Trick the client into sending more */
            client_conn->early_data_bytes = 0;
            EXPECT_SUCCESS_S2N_SEND(client_conn, test_data, sizeof(test_data), &blocked);

            /* The server should fail to accept the data */
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(server_conn, &blocked), S2N_ERR_EARLY_DATA_BLOCKED);
            EXPECT_FAILURE_WITH_ERRNO(s2n_recv(server_conn, test_buffer, sizeof(test_buffer), &blocked),
                    S2N_ERR_MAX_EARLY_DATA_SIZE);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }
    }

    EXPECT_SUCCESS(s2n_config_free(config_with_cert));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(cert_chain));
    END_TEST();
}
