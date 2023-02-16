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
#include "tls/extensions/s2n_early_data_indication.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"

static S2N_RESULT s2n_set_early_data_app_protocol(struct s2n_connection *conn, struct s2n_blob *app_protocol)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(app_protocol);

    struct s2n_psk *psk = NULL;
    RESULT_GUARD(s2n_array_get(&conn->psk_params.psk_list, 0, (void **) &psk));
    RESULT_GUARD_POSIX(s2n_psk_set_application_protocol(psk, app_protocol->data, app_protocol->size));
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    /* Test s2n_client_early_data_indication_should_send */
    {
        /* Safety check */
        EXPECT_FALSE(s2n_client_early_data_indication_extension.should_send(NULL));

        const uint32_t nonzero_max_early_data = 10;

        /* All checks pass: send extension */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk_with_early_data(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(conn));

            EXPECT_TRUE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Don't send if early data not supported */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk_with_early_data(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));

            EXPECT_FALSE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(conn));
            EXPECT_TRUE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /** Don't send if no PSK extension is sent.
         *
         *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
         *= type=test
         *# When a PSK is used and early data is allowed for that PSK, the client
         *# can send Application Data in its first flight of messages.  If the
         *# client opts to do so, it MUST supply both the "pre_shared_key" and
         *# "early_data" extensions.
         */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(conn));

            EXPECT_FALSE(s2n_client_psk_extension.should_send(conn));
            EXPECT_FALSE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /**
         * Don't send when performing a retry.
         *
         *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
         *= type=test
         *# A client MUST NOT include the
         *# "early_data" extension in its followup ClientHello.
         *
         *= https://tools.ietf.org/rfc/rfc8446#4.1.2
         *= type=test
         *# -  Removing the "early_data" extension (Section 4.2.10) if one was
         *#    present.  Early data is not permitted after a HelloRetryRequest.
         **/
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk_with_early_data(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(conn));

            EXPECT_TRUE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_set_hello_retry_required(conn));
            EXPECT_FALSE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Don't send if no early data allowed by first PSK */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(conn));

            EXPECT_OK(s2n_append_test_psk_with_early_data(conn, 0, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_OK(s2n_append_test_psk_with_early_data(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_FALSE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_OK(s2n_psk_parameters_wipe(&conn->psk_params));
            EXPECT_OK(s2n_append_test_psk_with_early_data(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_OK(s2n_append_test_psk_with_early_data(conn, 0, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_TRUE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Don't send if protocol version too low */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk_with_early_data(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(conn));

            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_FALSE(s2n_client_early_data_indication_extension.should_send(conn));

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_TRUE(s2n_client_early_data_indication_extension.should_send(conn));

            conn->actual_protocol_version = S2N_TLS13 + 1;
            EXPECT_TRUE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Don't send if cipher suite not allowed by cipher preferences */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(conn));

            EXPECT_OK(s2n_append_test_psk_with_early_data(conn, nonzero_max_early_data, &s2n_rsa_with_3des_ede_cbc_sha));
            EXPECT_FALSE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_OK(s2n_psk_parameters_wipe(&conn->psk_params));
            EXPECT_OK(s2n_append_test_psk_with_early_data(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_TRUE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Don't send if application layer protocol not allowed by preferences */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk_with_early_data(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(conn));

            uint8_t app_protocol_data[] = "protocol preference";
            uint8_t other_app_protocol_data[] = "different protocol";
            struct s2n_blob app_protocol = { 0 }, empty_app_protocol = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&app_protocol, app_protocol_data, sizeof(app_protocol_data)));

            /* No early data alp, empty alpn preferences: send */
            EXPECT_OK(s2n_set_early_data_app_protocol(conn, &empty_app_protocol));
            EXPECT_TRUE(s2n_client_early_data_indication_extension.should_send(conn));

            /* Early data alp, empty alpn preferences: don't send */
            EXPECT_OK(s2n_set_early_data_app_protocol(conn, &app_protocol));
            EXPECT_FALSE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_connection_append_protocol_preference(conn, other_app_protocol_data,
                    sizeof(other_app_protocol_data)));
            EXPECT_SUCCESS(s2n_connection_append_protocol_preference(conn, other_app_protocol_data,
                    sizeof(other_app_protocol_data)));

            /* No early data alp, non-empty alpn preferences: send */
            EXPECT_OK(s2n_set_early_data_app_protocol(conn, &empty_app_protocol));
            EXPECT_TRUE(s2n_client_early_data_indication_extension.should_send(conn));

            /* alpn preferences don't contain alp: don't send */
            EXPECT_OK(s2n_set_early_data_app_protocol(conn, &app_protocol));
            EXPECT_FALSE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_connection_append_protocol_preference(conn, app_protocol.data, app_protocol.size));

            /* alpn preferences contain alp: send */
            EXPECT_OK(s2n_set_early_data_app_protocol(conn, &app_protocol));
            EXPECT_TRUE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* Test s2n_client_early_data_indiction_send */
    {
        /* Set MIDDLEBOX_COMPAT | EARLY_CLIENT_CCS handshake type flags */
        {
            struct s2n_config *config = s2n_config_new();
            EXPECT_NOT_NULL(config);

            struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_OK(s2n_append_test_psk_with_early_data(conn, 0, &s2n_tls13_aes_128_gcm_sha256));

            EXPECT_EQUAL(conn->handshake.handshake_type, 0);

            /* Don't set if < TLS1.3 */
            conn->actual_protocol_version = S2N_TLS12;
            config->quic_enabled = false;
            EXPECT_SUCCESS(s2n_client_early_data_indication_extension.send(conn, NULL));
            EXPECT_EQUAL(conn->handshake.handshake_type, 0);

            /* Don't set if middlebox compat disabled */
            conn->actual_protocol_version = S2N_TLS13;
            config->quic_enabled = true;
            EXPECT_SUCCESS(s2n_client_early_data_indication_extension.send(conn, NULL));
            EXPECT_EQUAL(conn->handshake.handshake_type, 0);

            /* Otherwise, set */
            conn->actual_protocol_version = S2N_TLS13;
            config->quic_enabled = false;
            EXPECT_SUCCESS(s2n_client_early_data_indication_extension.send(conn, NULL));
            EXPECT_EQUAL(conn->handshake.handshake_type, (MIDDLEBOX_COMPAT | EARLY_CLIENT_CCS));

            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* Test s2n_client_early_data_indiction_recv */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(conn);
        conn->actual_protocol_version = S2N_TLS13;

        /* Successful if not retry */
        conn->early_data_state = S2N_UNKNOWN_EARLY_DATA_STATE;
        conn->handshake.message_number = 0;
        EXPECT_SUCCESS(s2n_client_early_data_indication_extension.recv(conn, NULL));
        EXPECT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_REQUESTED);

        /**
         *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
         *= type=test
         *# A client MUST NOT include the
         *# "early_data" extension in its followup ClientHello.
         */
        conn->early_data_state = S2N_UNKNOWN_EARLY_DATA_STATE;
        conn->handshake.message_number = 1;
        EXPECT_FAILURE_WITH_ERRNO(s2n_client_early_data_indication_extension.recv(conn, NULL),
                S2N_ERR_UNSUPPORTED_EXTENSION);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test state transitions */
    {
        /* When early data not enabled on client */
        {
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk_with_early_data(client_conn, 1, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_UNKNOWN_EARLY_DATA_STATE);

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk_with_early_data(server_conn, 1, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_EQUAL(server_conn->early_data_state, S2N_UNKNOWN_EARLY_DATA_STATE);
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                    s2n_stuffer_data_available(&client_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_establish_session(server_conn));

            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_NOT_REQUESTED);
            EXPECT_EQUAL(server_conn->early_data_state, S2N_EARLY_DATA_NOT_REQUESTED);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* When early data not enabled on server */
        {
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk_with_early_data(client_conn, 1, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_UNKNOWN_EARLY_DATA_STATE);
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk_with_early_data(server_conn, 1, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_EQUAL(server_conn->early_data_state, S2N_UNKNOWN_EARLY_DATA_STATE);

            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                    s2n_stuffer_data_available(&client_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_establish_session(server_conn));

            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_REQUESTED);
            EXPECT_EQUAL(server_conn->early_data_state, S2N_EARLY_DATA_REJECTED);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* When early data requested */
        {
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk_with_early_data(client_conn, 1, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_UNKNOWN_EARLY_DATA_STATE);
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk_with_early_data(server_conn, 1, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_EQUAL(server_conn->early_data_state, S2N_UNKNOWN_EARLY_DATA_STATE);
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                    s2n_stuffer_data_available(&client_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_establish_session(server_conn));

            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_REQUESTED);
            EXPECT_EQUAL(server_conn->early_data_state, S2N_EARLY_DATA_ACCEPTED);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* When early data not requested */
        {
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk_with_early_data(client_conn, 0, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_UNKNOWN_EARLY_DATA_STATE);
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk_with_early_data(server_conn, 0, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_EQUAL(server_conn->early_data_state, S2N_UNKNOWN_EARLY_DATA_STATE);
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                    s2n_stuffer_data_available(&client_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_establish_session(server_conn));

            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_NOT_REQUESTED);
            EXPECT_EQUAL(server_conn->early_data_state, S2N_EARLY_DATA_NOT_REQUESTED);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };
    };

    /* Test state transitions with a HelloRetryRequest.
     *
     *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
     *= type=test
     *# A server which receives an "early_data" extension MUST behave in one
     *# of three ways:
     *
     *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
     *= type=test
     *# -  Request that the client send another ClientHello by responding
     *#    with a HelloRetryRequest.
     */
    {
        /* Hello Retry Request because of rejected early data.
         *
         * The S2N server does not reject early data via a HelloRetryRequest, but other implementations might.
         * The S2N client should handle retries triggered by early data gracefully.
         */
        {
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk_with_early_data(client_conn, 1, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_UNKNOWN_EARLY_DATA_STATE);
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk_with_early_data(server_conn, 0, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_EQUAL(server_conn->early_data_state, S2N_UNKNOWN_EARLY_DATA_STATE);
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                    s2n_stuffer_data_available(&client_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_establish_session(server_conn));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_REQUESTED);

            /* Force a retry */
            EXPECT_SUCCESS(s2n_set_hello_retry_required(server_conn));
            /* There is retry handling logic that checks that the current message
             * is a hello retry message, which requires that we be at a specific message number. */
            server_conn->handshake.message_number = 2;
            client_conn->handshake.message_number = 2;

            /* Update the selected_group to ensure the HRR is valid */
            client_conn->kex_params.client_ecc_evp_params.negotiated_curve = &s2n_ecc_curve_secp521r1;

            EXPECT_SUCCESS(s2n_server_hello_retry_send(server_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                    s2n_stuffer_data_available(&server_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_REJECTED);

            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_REJECTED);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* Hello Retry Request because of missing key share: still rejects early data */
        {
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            client_conn->security_policy_override = &security_policy_test_tls13_retry;
            EXPECT_OK(s2n_append_test_psk_with_early_data(client_conn, 1, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_UNKNOWN_EARLY_DATA_STATE);
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            server_conn->security_policy_override = &security_policy_test_all_tls13;
            EXPECT_OK(s2n_append_test_psk_with_early_data(server_conn, 1, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_EQUAL(server_conn->early_data_state, S2N_UNKNOWN_EARLY_DATA_STATE);
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(server_conn));

            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                    s2n_stuffer_data_available(&client_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_establish_session(server_conn));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_REQUESTED);
            EXPECT_EQUAL(server_conn->early_data_state, S2N_EARLY_DATA_REJECTED);

            EXPECT_TRUE(s2n_is_hello_retry_handshake(server_conn));
            /* There is retry handling logic that checks that the current message
             * is a hello retry message, which requires that we be at a specific message number. */
            server_conn->handshake.message_number = 2;
            client_conn->handshake.message_number = 2;

            EXPECT_SUCCESS(s2n_server_hello_retry_send(server_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                    s2n_stuffer_data_available(&server_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));
            EXPECT_TRUE(s2n_is_hello_retry_handshake(client_conn));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_REJECTED);
            EXPECT_EQUAL(server_conn->early_data_state, S2N_EARLY_DATA_REJECTED);

            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_REJECTED);
            EXPECT_EQUAL(server_conn->early_data_state, S2N_EARLY_DATA_REJECTED);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };
    };

    END_TEST();
}
