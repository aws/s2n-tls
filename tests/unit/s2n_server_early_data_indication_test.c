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
#include "tls/extensions/s2n_early_data_indication.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_array.h"

static S2N_RESULT s2n_exchange_hellos(struct s2n_connection *client_conn, struct s2n_connection *server_conn)
{
    RESULT_GUARD_POSIX(s2n_client_hello_send(client_conn));
    RESULT_GUARD_POSIX(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
            s2n_stuffer_data_available(&client_conn->handshake.io)));
    RESULT_GUARD_POSIX(s2n_establish_session(server_conn));

    RESULT_GUARD_POSIX(s2n_server_hello_send(server_conn));
    RESULT_GUARD_POSIX(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
            s2n_stuffer_data_available(&server_conn->handshake.io)));
    RESULT_GUARD_POSIX(s2n_server_hello_recv(client_conn));

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    const uint32_t nonzero_max_early_data = 10;

    /* Test s2n_server_early_data_indication_should_send */
    {
        /* Safety check */
        EXPECT_FALSE(s2n_server_early_data_indication_extension.should_send(NULL));

        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(conn);

        conn->early_data_state = S2N_EARLY_DATA_NOT_REQUESTED;
        EXPECT_FALSE(s2n_server_early_data_indication_extension.should_send(conn));

        conn->early_data_state = S2N_EARLY_DATA_REJECTED;
        EXPECT_FALSE(s2n_server_early_data_indication_extension.should_send(conn));

        conn->early_data_state = S2N_EARLY_DATA_ACCEPTED;
        EXPECT_TRUE(s2n_server_early_data_indication_extension.should_send(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test s2n_server_early_data_indication_is_missing */
    {
        /* No-op if early data not requested */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);

            conn->early_data_state = S2N_EARLY_DATA_NOT_REQUESTED;
            EXPECT_SUCCESS(s2n_server_early_data_indication_extension.if_missing(conn));
            EXPECT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_NOT_REQUESTED);

            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            EXPECT_SUCCESS(s2n_server_early_data_indication_extension.if_missing(conn));
            EXPECT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_REJECTED);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* Test s2n_server_early_data_indication_recv */
    {
        struct s2n_stuffer stuffer = { 0 };

        /* Fails if early data config does not match the connection */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);

            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            conn->actual_protocol_version = S2N_TLS13;
            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;

            /* No early data configured */
            EXPECT_FAILURE_WITH_ERRNO(s2n_server_early_data_indication_extension.recv(conn, &stuffer),
                    S2N_ERR_EARLY_DATA_NOT_ALLOWED);
            EXPECT_NOT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_ACCEPTED);

            /* Early data correctly configured */
            EXPECT_OK(s2n_append_test_chosen_psk_with_early_data(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_SUCCESS(s2n_server_early_data_indication_extension.recv(conn, &stuffer));
            EXPECT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_ACCEPTED);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Fails if early data not requested */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);

            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_OK(s2n_append_test_chosen_psk_with_early_data(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));

            /* Early data not requested */
            conn->early_data_state = S2N_EARLY_DATA_NOT_REQUESTED;
            EXPECT_FAILURE_WITH_ERRNO(s2n_server_early_data_indication_extension.recv(conn, &stuffer),
                    S2N_ERR_INVALID_EARLY_DATA_STATE);

            /* Early data requested */
            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            EXPECT_SUCCESS(s2n_server_early_data_indication_extension.recv(conn, &stuffer));
            EXPECT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_ACCEPTED);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* Test state transitions */
    {
        const char *security_policy = "20190801";
        struct s2n_cipher_suite *expected_cipher_suite = &s2n_tls13_aes_256_gcm_sha384;

        /* When early data not requested */
        {
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_OK(s2n_append_test_chosen_psk_with_early_data(client_conn, 0, expected_cipher_suite));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, security_policy));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_OK(s2n_append_test_chosen_psk_with_early_data(server_conn, 0, expected_cipher_suite));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, security_policy));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            EXPECT_OK(s2n_exchange_hellos(client_conn, server_conn));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_NOT_REQUESTED);
            EXPECT_EQUAL(server_conn->early_data_state, S2N_EARLY_DATA_NOT_REQUESTED);

            EXPECT_SUCCESS(s2n_encrypted_extensions_send(server_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                    s2n_stuffer_data_available(&server_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_encrypted_extensions_recv(client_conn));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_NOT_REQUESTED);
            EXPECT_EQUAL(server_conn->early_data_state, S2N_EARLY_DATA_NOT_REQUESTED);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /** When early data accepted.
         *
         *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
         *= type=test
         *# A server which receives an "early_data" extension MUST behave in one
         *# of three ways:
         *
         *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
         *= type=test
         *# -  Return its own "early_data" extension in EncryptedExtensions,
         *#    indicating that it intends to process the early data.
         **/
        {
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_OK(s2n_append_test_chosen_psk_with_early_data(client_conn, nonzero_max_early_data, expected_cipher_suite));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, security_policy));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_OK(s2n_append_test_chosen_psk_with_early_data(server_conn, nonzero_max_early_data, expected_cipher_suite));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, security_policy));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            EXPECT_OK(s2n_exchange_hellos(client_conn, server_conn));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_REQUESTED);
            EXPECT_EQUAL(server_conn->early_data_state, S2N_EARLY_DATA_ACCEPTED);

            EXPECT_SUCCESS(s2n_encrypted_extensions_send(server_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                    s2n_stuffer_data_available(&server_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_encrypted_extensions_recv(client_conn));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_ACCEPTED);
            EXPECT_EQUAL(server_conn->early_data_state, S2N_EARLY_DATA_ACCEPTED);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /** When early data rejected.
         *
         *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
         *# A server which receives an "early_data" extension MUST behave in one
         *# of three ways:
         *#
         *# -  Ignore the extension and return a regular 1-RTT response.
         **/
        {
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_OK(s2n_append_test_chosen_psk_with_early_data(client_conn, nonzero_max_early_data, expected_cipher_suite));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, security_policy));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_OK(s2n_append_test_chosen_psk_with_early_data(server_conn, 0, expected_cipher_suite));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, security_policy));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            EXPECT_OK(s2n_exchange_hellos(client_conn, server_conn));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_REQUESTED);
            EXPECT_EQUAL(server_conn->early_data_state, S2N_EARLY_DATA_REJECTED);

            EXPECT_SUCCESS(s2n_encrypted_extensions_send(server_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                    s2n_stuffer_data_available(&server_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_encrypted_extensions_recv(client_conn));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_REJECTED);
            EXPECT_EQUAL(server_conn->early_data_state, S2N_EARLY_DATA_REJECTED);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /*
        *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
        *= type=test
        *# A server which receives an "early_data" extension MUST behave in one
        *# of three ways:
        *
        *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
        *= type=test
        *# -  Request that the client send another ClientHello by responding
        *#    with a HelloRetryRequest.
        **/
        {
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_OK(s2n_append_test_chosen_psk_with_early_data(client_conn, nonzero_max_early_data, expected_cipher_suite));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, security_policy));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_OK(s2n_append_test_chosen_psk_with_early_data(server_conn, nonzero_max_early_data, expected_cipher_suite));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, security_policy));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                    s2n_stuffer_data_available(&client_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_REQUESTED);

            /* Force a retry. The S2N server does not reject early data via HRR, so we have
             * to manually trigger the retry. */
            server_conn->early_data_state = S2N_EARLY_DATA_REJECTED;
            EXPECT_SUCCESS(s2n_set_hello_retry_required(server_conn));
            server_conn->handshake.message_number = 2;
            client_conn->handshake.message_number = 2;

            /* Update the selected_group to ensure the HRR is valid */
            client_conn->kex_params.client_ecc_evp_params.negotiated_curve = &s2n_ecc_curve_secp521r1;

            EXPECT_SUCCESS(s2n_server_hello_retry_send(server_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                    s2n_stuffer_data_available(&server_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_REJECTED);
            EXPECT_EQUAL(server_conn->early_data_state, S2N_EARLY_DATA_REJECTED);

            EXPECT_SUCCESS(s2n_encrypted_extensions_send(server_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                    s2n_stuffer_data_available(&server_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_encrypted_extensions_recv(client_conn));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_REJECTED);
            EXPECT_EQUAL(server_conn->early_data_state, S2N_EARLY_DATA_REJECTED);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };
    };

    END_TEST();
    return 0;
}
