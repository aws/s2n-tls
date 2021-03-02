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
#include "tls/extensions/s2n_client_psk.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_tls.h"

#define TEST_VALUE "test"

static S2N_RESULT s2n_append_test_psk(struct s2n_connection *conn, uint32_t max_early_data,
        const struct s2n_cipher_suite *cipher_suite)
{
    ENSURE_REF(conn);
    ENSURE_REF(cipher_suite);

    /* We're assuming the index will only take one digit */
    uint8_t buffer[sizeof(TEST_VALUE) + 1] = { 0 };
    int r = snprintf((char*) buffer, sizeof(buffer), "%s%u", TEST_VALUE, conn->psk_params.psk_list.len);
    ENSURE_GT(r, 0);
    ENSURE_LT(r, sizeof(buffer));

    DEFER_CLEANUP(struct s2n_psk *psk = s2n_external_psk_new(), s2n_psk_free);
    GUARD_AS_RESULT(s2n_psk_set_identity(psk, buffer, sizeof(buffer)));
    GUARD_AS_RESULT(s2n_psk_set_secret(psk, buffer, sizeof(buffer)));
    psk->hmac_alg = cipher_suite->prf_alg;
    if (max_early_data > 0) {
        GUARD_AS_RESULT(s2n_psk_configure_early_data(psk, max_early_data,
                cipher_suite->iana_value[0], cipher_suite->iana_value[1]));
    }
    GUARD_AS_RESULT(s2n_connection_append_psk(conn, psk));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_set_early_data_app_protocol(struct s2n_connection *conn, struct s2n_blob *app_protocol)
{
    ENSURE_REF(conn);
    ENSURE_REF(app_protocol);

    struct s2n_psk *psk = NULL;
    GUARD_RESULT(s2n_array_get(&conn->psk_params.psk_list, 0, (void**) &psk));
    GUARD_AS_RESULT(s2n_psk_set_application_protocol(psk, app_protocol->data, app_protocol->size));
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

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
            EXPECT_OK(s2n_append_test_psk(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));

            EXPECT_TRUE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

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

            EXPECT_FALSE(s2n_client_psk_extension.should_send(conn));
            EXPECT_FALSE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /** Don't send when performing a retry.
         *
         *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
         *= type=test
         *# A client MUST NOT include the
         *# "early_data" extension in its followup ClientHello.
         */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));

            EXPECT_TRUE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_set_hello_retry_required(conn));
            EXPECT_FALSE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Don't send if no early data allowed by first PSK */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));

            EXPECT_OK(s2n_append_test_psk(conn, 0, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_OK(s2n_append_test_psk(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_FALSE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_OK(s2n_psk_parameters_wipe(&conn->psk_params));
            EXPECT_OK(s2n_append_test_psk(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_OK(s2n_append_test_psk(conn, 0, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_TRUE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Don't send if protocol version too low */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));

            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_FALSE(s2n_client_early_data_indication_extension.should_send(conn));

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_TRUE(s2n_client_early_data_indication_extension.should_send(conn));

            conn->actual_protocol_version = S2N_TLS13 + 1;
            EXPECT_TRUE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Don't send if cipher suite not allowed by cipher preferences */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));

            EXPECT_OK(s2n_append_test_psk(conn, nonzero_max_early_data, &s2n_rsa_with_rc4_128_md5));
            EXPECT_FALSE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_OK(s2n_psk_parameters_wipe(&conn->psk_params));
            EXPECT_OK(s2n_append_test_psk(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_TRUE(s2n_client_early_data_indication_extension.should_send(conn));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* Don't send if application layer protocol not allowed by preferences */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk(conn, nonzero_max_early_data, &s2n_tls13_aes_256_gcm_sha384));

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
        }
    }

    /* Test s2n_client_early_data_indiction_recv */
    {
        struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(conn);
        conn->actual_protocol_version = S2N_TLS13;

        /* Successful if not retry */
        conn->early_data_state = S2N_UNKNOWN_EARLY_DATA_STATE;
        EXPECT_SUCCESS(s2n_client_early_data_indication_extension.recv(conn, NULL));
        EXPECT_EQUAL(conn->early_data_state, S2N_EARLY_DATA_REQUESTED);

        /**
         *= https://tools.ietf.org/rfc/rfc8446#section-4.2.10
         *= type=test
         *# A client MUST NOT include the
         *# "early_data" extension in its followup ClientHello.
         */
        conn->early_data_state = S2N_UNKNOWN_EARLY_DATA_STATE;
        EXPECT_SUCCESS(s2n_set_hello_retry_required(conn));
        EXPECT_FAILURE_WITH_ERRNO(s2n_client_early_data_indication_extension.recv(conn, NULL),
                S2N_ERR_UNSUPPORTED_EXTENSION);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test state transitions */
    {
        /* When early data requested */
        {
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk(client_conn, 1, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_UNKNOWN_EARLY_DATA_STATE);

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk(server_conn, 1, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_EQUAL(server_conn->early_data_state, S2N_UNKNOWN_EARLY_DATA_STATE);

            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                    s2n_stuffer_data_available(&client_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_REQUESTED);
            EXPECT_EQUAL(server_conn->early_data_state, S2N_EARLY_DATA_REQUESTED);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* When early data not requested */
        {
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk(client_conn, 0, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_EQUAL(client_conn->early_data_state, S2N_UNKNOWN_EARLY_DATA_STATE);

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));
            EXPECT_OK(s2n_append_test_psk(server_conn, 0, &s2n_tls13_aes_256_gcm_sha384));
            EXPECT_EQUAL(server_conn->early_data_state, S2N_UNKNOWN_EARLY_DATA_STATE);

            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                    s2n_stuffer_data_available(&client_conn->handshake.io)));
            EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

            EXPECT_EQUAL(client_conn->early_data_state, S2N_EARLY_DATA_NOT_REQUESTED);
            EXPECT_EQUAL(server_conn->early_data_state, S2N_EARLY_DATA_NOT_REQUESTED);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }
    }

    END_TEST();
}
