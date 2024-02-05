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

#include "tls/s2n_tls13_key_schedule.h"

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cipher_suites.h"

/* For access to secret handlers.
 * We override them for mocking purposees. */
#include "tls/s2n_tls13_secrets.c"

#define NO_TRIGGER_MSG       APPLICATION_DATA
#define TRAFFIC_SECRET_COUNT 6

static uint8_t empty_secret[S2N_TLS13_SECRET_MAX_LEN] = { 0 };

struct s2n_tls13_key_schedule_test_case {
    s2n_mode conn_mode;
    uint32_t handshake_type;
    struct s2n_cipher_suite *cipher_suite;
    bool is_early_data_requested;
};

struct s2n_test_secrets {
    uint8_t bytes[TRAFFIC_SECRET_COUNT][S2N_TLS13_SECRET_MAX_LEN];
    struct s2n_blob blobs[TRAFFIC_SECRET_COUNT];
};

static int s2n_test_secret_cb(void *context, struct s2n_connection *conn,
        s2n_secret_type_t secret_type, uint8_t *secret_bytes, uint8_t secret_size)
{
    struct s2n_test_secrets *secrets = (struct s2n_test_secrets *) context;
    POSIX_ENSURE_REF(secrets);

    POSIX_ENSURE_GTE(secret_type, 0);
    POSIX_ENSURE_LT(secret_type, TRAFFIC_SECRET_COUNT);
    POSIX_ENSURE_EQ(secrets->blobs[secret_type].size, 0);
    POSIX_GUARD(s2n_blob_init(&secrets->blobs[secret_type],
            secrets->bytes[secret_type], secret_size));
    POSIX_CHECKED_MEMCPY(secrets->bytes[secret_type], secret_bytes, secret_size);
    return S2N_SUCCESS;
}

static S2N_RESULT s2n_connection_verify_secrets(struct s2n_connection *conn, struct s2n_test_secrets *secrets,
        bool expect_early_data_traffic_secret)
{
    /* Test: All handshake and master traffic secrets calculated */
    RESULT_ENSURE_EQ(conn->server, conn->secure);
    RESULT_ENSURE_EQ(conn->client, conn->secure);
    RESULT_ENSURE_GT(secrets->blobs[S2N_CLIENT_HANDSHAKE_TRAFFIC_SECRET].size, 0);
    RESULT_ENSURE_GT(secrets->blobs[S2N_SERVER_HANDSHAKE_TRAFFIC_SECRET].size, 0);
    RESULT_ENSURE_GT(secrets->blobs[S2N_CLIENT_APPLICATION_TRAFFIC_SECRET].size, 0);
    RESULT_ENSURE_GT(secrets->blobs[S2N_SERVER_APPLICATION_TRAFFIC_SECRET].size, 0);

    /* Test: Early traffic secrets calculated if early data requested */
    if (expect_early_data_traffic_secret) {
        RESULT_ENSURE_GT(secrets->blobs[S2N_CLIENT_EARLY_TRAFFIC_SECRET].size, 0);
    } else {
        RESULT_ENSURE_EQ(secrets->blobs[S2N_CLIENT_EARLY_TRAFFIC_SECRET].size, 0);
    }

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_mock_extract_method(struct s2n_connection *conn)
{
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_mock_derive_method(struct s2n_connection *conn, struct s2n_blob *secret)
{
    uint8_t size = 0;
    s2n_hmac_algorithm hmac_alg = conn->secure->cipher_suite->prf_alg;
    RESULT_GUARD_POSIX(s2n_hmac_digest_size(hmac_alg, &size));
    RESULT_GUARD_POSIX(s2n_blob_init(secret, empty_secret, size));
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const struct s2n_cipher_preferences *ciphers = &cipher_preferences_test_all_tls13;
    const s2n_mode modes[] = { S2N_CLIENT, S2N_SERVER };
    const bool early_data_req_states[] = { true, false };

    /* Calculate a set of test cases */
    struct s2n_tls13_key_schedule_test_case test_cases[2000] = { 0 };
    size_t test_cases_count = 0;
    struct s2n_connection handshake_test_conn = {
        .actual_protocol_version = S2N_TLS13,
        .handshake = { .message_number = 1, .state_machine = S2N_STATE_MACHINE_TLS13 },
    };
    for (uint32_t handshake_type = 0; handshake_type < S2N_HANDSHAKES_COUNT; handshake_type++) {
        handshake_test_conn.handshake.handshake_type = handshake_type;
        for (size_t req_i = 0; req_i < s2n_array_len(early_data_req_states); req_i++) {
            for (size_t cipher_i = 0; cipher_i < ciphers->count; cipher_i++) {
                for (size_t mode_i = 0; mode_i < s2n_array_len(modes); mode_i++) {
                    if (s2n_conn_get_current_message_type(&handshake_test_conn) == CLIENT_HELLO) {
                        /* Skip empty, all-CLIENT_HELLO handshakes */
                        continue;
                    }
                    if (WITH_EARLY_DATA(&handshake_test_conn) && !early_data_req_states[req_i]) {
                        /* Skip handshakes with inconsistent early data states */
                        continue;
                    }
                    if (!IS_NEGOTIATED(&handshake_test_conn)) {
                        /* Skip initial / incomplete handshakes */
                        continue;
                    }
                    if (!ciphers->suites[cipher_i]->available) {
                        /* Skip unavailable ciphers */
                        continue;
                    }
                    test_cases[test_cases_count] = (struct s2n_tls13_key_schedule_test_case){
                        .conn_mode = modes[mode_i],
                        .handshake_type = handshake_type,
                        .cipher_suite = ciphers->suites[cipher_i],
                        .is_early_data_requested = early_data_req_states[req_i],
                    };
                    test_cases_count++;
                }
            }
        }
    }
    EXPECT_TRUE(test_cases_count > 0);

    /* Test s2n_tls13_key_schedule_update */
    {
        /* Safety */
        {
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_key_schedule_update(NULL), S2N_ERR_NULL);

            /* Minimal client connection that triggers an update */
            struct s2n_connection empty_client_conn = {
                .mode = S2N_CLIENT,
                .client_protocol_version = S2N_TLS13,
                .early_data_state = S2N_EARLY_DATA_REQUESTED
            };
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_key_schedule_update(&empty_client_conn), S2N_ERR_NULL);
            empty_client_conn.client_protocol_version = S2N_TLS12;
            EXPECT_OK(s2n_tls13_key_schedule_update(&empty_client_conn));

            /* Minimal server connection that triggers an update */
            struct s2n_connection empty_server_conn = {
                .mode = S2N_SERVER,
                .actual_protocol_version = S2N_TLS13,
                .handshake = { .message_number = 1 }
            };
            EXPECT_ERROR_WITH_ERRNO(s2n_tls13_key_schedule_update(&empty_server_conn), S2N_ERR_NULL);
            empty_server_conn.actual_protocol_version = S2N_TLS12;
            EXPECT_OK(s2n_tls13_key_schedule_update(&empty_server_conn));
        };

        /* Test key schedule ordering */
        {
            /* Mock derive and extract methods */
            uint8_t saved_derive_methods[sizeof(derive_methods)] = { 0 };
            EXPECT_MEMCPY_SUCCESS(saved_derive_methods, derive_methods, sizeof(derive_methods));
            for (size_t i = 0; i < s2n_array_len(derive_methods); i++) {
                derive_methods[i][S2N_CLIENT] = &s2n_mock_derive_method;
                derive_methods[i][S2N_SERVER] = &s2n_mock_derive_method;
            }
            uint8_t saved_extract_methods[sizeof(extract_methods)] = { 0 };
            EXPECT_MEMCPY_SUCCESS(saved_extract_methods, extract_methods, sizeof(extract_methods));
            for (size_t i = 0; i < s2n_array_len(extract_methods); i++) {
                extract_methods[i] = &s2n_mock_extract_method;
            }

            for (size_t i = 0; i < test_cases_count; i++) {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(test_cases[i].conn_mode),
                        s2n_connection_ptr_free);
                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_OK(s2n_conn_choose_state_machine(conn, S2N_TLS13));

                conn->handshake.handshake_type = test_cases[i].handshake_type;
                conn->secure->cipher_suite = test_cases[i].cipher_suite;
                if (test_cases[i].is_early_data_requested) {
                    conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
                }

                struct s2n_test_secrets secrets = { 0 };
                EXPECT_SUCCESS(s2n_connection_set_secret_callback(conn,
                        s2n_test_secret_cb, (void *) &secrets));

                /* Perform the handshake */
                while (s2n_conn_get_current_message_type(conn) != APPLICATION_DATA) {
                    /*
                     * To avoid calculating the early traffic secret again when
                     * we receive the second ClientHello, we need to include
                     * the logic where a retry request rejects early data.
                     */
                    if (s2n_conn_get_current_message_type(conn) == HELLO_RETRY_MSG) {
                        conn->early_data_state = S2N_EARLY_DATA_REJECTED;
                        EXPECT_OK(s2n_tls13_key_schedule_reset(conn));
                    }

                    /*
                     * We know what secrets every message should be encrypted with.
                     * Verify those secrets are available in time for each message.
                     */
                    switch (s2n_conn_get_current_message_type(conn)) {
                        case CLIENT_HELLO:
                            /* Expect not encrypted */
                            EXPECT_EQUAL(conn->client, conn->initial);
                            break;
                        case HELLO_RETRY_MSG:
                        case SERVER_HELLO:
                            /* Expect not encrypted  */
                            EXPECT_EQUAL(conn->server, conn->initial);
                            break;
                        case END_OF_EARLY_DATA:
                            /* Expect encrypted */
                            EXPECT_EQUAL(conn->client, conn->secure);
                            /* Expect correct secret available */
                            EXPECT_TRUE(secrets.blobs[S2N_CLIENT_EARLY_TRAFFIC_SECRET].size > 0);
                            break;
                        case ENCRYPTED_EXTENSIONS:
                        case SERVER_CERT:
                        case SERVER_CERT_VERIFY:
                        case SERVER_FINISHED:
                        case SERVER_CERT_REQ:
                            /* Expect encrypted */
                            EXPECT_EQUAL(conn->server, conn->secure);
                            /* Expect correct secret available */
                            EXPECT_TRUE(secrets.blobs[S2N_SERVER_HANDSHAKE_TRAFFIC_SECRET].size > 0);
                            break;
                        case CLIENT_CERT:
                        case CLIENT_CERT_VERIFY:
                        case CLIENT_FINISHED:
                            /* Expect encrypted */
                            EXPECT_EQUAL(conn->client, conn->secure);
                            /* Expect correct secret available */
                            EXPECT_TRUE(secrets.blobs[S2N_CLIENT_HANDSHAKE_TRAFFIC_SECRET].size > 0);
                            break;
                        case APPLICATION_DATA:
                            /* Expect encrypted */
                            EXPECT_EQUAL(conn->client, conn->secure);
                            EXPECT_EQUAL(conn->server, conn->secure);
                            /* Expect correct secrets available */
                            EXPECT_TRUE(secrets.blobs[S2N_CLIENT_APPLICATION_TRAFFIC_SECRET].size > 0);
                            EXPECT_TRUE(secrets.blobs[S2N_SERVER_APPLICATION_TRAFFIC_SECRET].size > 0);
                            break;
                        case SERVER_CHANGE_CIPHER_SPEC:
                        case CLIENT_CHANGE_CIPHER_SPEC:
                            /*
                             * Not relevant to TLS1.3 key schedule.
                             * We manually disable encryption when sending.
                             */
                            break;
                        case CLIENT_KEY:
                        case SERVER_KEY:
                        case SERVER_NEW_SESSION_TICKET:
                        case SERVER_CERT_STATUS:
                        case SERVER_HELLO_DONE:
                        case CLIENT_NPN:
                            FAIL_MSG("Unexpected TLS1.2 message");
                            break;
                    }

                    EXPECT_OK(s2n_tls13_secrets_update(conn));
                    EXPECT_OK(s2n_tls13_key_schedule_update(conn));
                    conn->handshake.message_number++;
                }

                EXPECT_OK(s2n_connection_verify_secrets(conn, &secrets, test_cases[i].is_early_data_requested));
            }

            /* Restore derive and extract methods */
            EXPECT_MEMCPY_SUCCESS(derive_methods, saved_derive_methods, sizeof(saved_derive_methods));
            EXPECT_MEMCPY_SUCCESS(extract_methods, saved_extract_methods, sizeof(saved_extract_methods));
        };
    };

    END_TEST();
}
