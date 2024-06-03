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

#include "tls/s2n_connection_serialize.h"

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_config.h"

#define S2N_SERIALIZED_CONN_TLS13_SHA256_SIZE 126

#define TEST_SEQUENCE_NUM 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define TEST_TLS13_SECRET 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

static S2N_RESULT s2n_test_key_update(struct s2n_connection *client_conn, struct s2n_connection *server_conn)
{
    /* One side initiates key update */
    RESULT_GUARD_POSIX(s2n_connection_request_key_update(client_conn, S2N_KEY_UPDATE_NOT_REQUESTED));

    /* Sending and receiving multiple times is successful after key update */
    for (size_t i = 0; i < 10; i++) {
        EXPECT_OK(s2n_send_and_recv_test(client_conn, server_conn));
    }
    EXPECT_EQUAL(client_conn->send_key_updated, 1);
    EXPECT_EQUAL(server_conn->recv_key_updated, 1);

    /* Other side initiates key update */
    EXPECT_SUCCESS(s2n_connection_request_key_update(server_conn, S2N_KEY_UPDATE_NOT_REQUESTED));

    /* Sending and receiving multiple times is successful after key update */
    for (size_t i = 0; i < 10; i++) {
        EXPECT_OK(s2n_send_and_recv_test(server_conn, client_conn));
    }
    EXPECT_EQUAL(client_conn->recv_key_updated, 1);
    EXPECT_EQUAL(server_conn->send_key_updated, 1);

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_ticket_pickup(struct s2n_connection *conn, struct s2n_blob *session_ticket)
{
    int session_length = s2n_connection_get_session_length(conn);
    EXPECT_NOT_EQUAL(session_length, 0);
    EXPECT_SUCCESS(s2n_realloc(session_ticket, session_length));
    EXPECT_SUCCESS(s2n_connection_get_session(conn, session_ticket->data, session_length));
    session_ticket->size = session_length;

    return S2N_RESULT_OK;
}

static int s2n_test_reneg_cb(struct s2n_connection *conn, void *context,
        s2n_renegotiate_response *response)
{
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_config *tls12_config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(tls12_config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(tls12_config));
    EXPECT_SUCCESS(s2n_config_set_serialization_version(tls12_config, S2N_SERIALIZED_CONN_V1));

    DEFER_CLEANUP(struct s2n_config *tls13_config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(tls13_config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(tls13_config));
    EXPECT_SUCCESS(s2n_config_set_serialization_version(tls13_config, S2N_SERIALIZED_CONN_V1));
    /* Security policy that can negotiate TLS13 and has aes_128_gcm_sha256 as its preferred cipher suite */
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(tls13_config, "20210825"));

    /* s2n_connection_serialization_length */
    {
        /* Safety */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            uint32_t length = 0;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_serialization_length(conn, NULL), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_serialization_length(NULL, &length), S2N_ERR_NULL);
        };

        /* Length is correct for all possible cipher suites in TLS1.3 */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, tls13_config));
            conn->actual_protocol_version = S2N_TLS13;

            for (size_t i = 0; i < cipher_preferences_test_all.count; i++) {
                struct s2n_cipher_suite *cipher_suite = cipher_preferences_test_all.suites[i];
                conn->secure->cipher_suite = cipher_suite;
                uint8_t expected_secret_size = 0;
                EXPECT_SUCCESS(s2n_hmac_digest_size(cipher_suite->prf_alg, &expected_secret_size));

                uint32_t length = 0;
                EXPECT_SUCCESS(s2n_connection_serialization_length(conn, &length));
                EXPECT_EQUAL(length, S2N_SERIALIZED_CONN_FIXED_SIZE + (expected_secret_size * 3));
            }
        };

        /* Length is correct for TLS1.2 */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, tls12_config));
            conn->actual_protocol_version = S2N_TLS12;

            uint32_t length = 0;
            EXPECT_SUCCESS(s2n_connection_serialization_length(conn, &length));
            EXPECT_EQUAL(length, S2N_SERIALIZED_CONN_TLS12_SIZE);
        };
    };

    /* s2n_connection_serialize */
    {
        /* Safety */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            uint8_t data = 0;
            uint32_t length = 0;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_serialize(NULL, &data, length), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_serialize(conn, NULL, length), S2N_ERR_NULL);
        };

        /* Invalid usage checks */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            uint8_t buffer[10] = { 0 };
            uint32_t length = sizeof(buffer);

            /* Format version must be set before calling this function */
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_serialize(conn, buffer, length),
                    S2N_ERR_INVALID_STATE);

            /* Negotiation must be complete before calling this function */
            EXPECT_SUCCESS(s2n_config_set_serialization_version(config, S2N_SERIALIZED_CONN_V1));
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_serialize(conn, buffer, length),
                    S2N_ERR_HANDSHAKE_NOT_COMPLETE);

            /* Buffer must be large enough to hold entire serialized length */
            EXPECT_OK(s2n_skip_handshake(conn));
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_serialize(conn, buffer, length),
                    S2N_ERR_INSUFFICIENT_MEM_SIZE);
        };

        /* Serializes TLS 1.2 */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);

            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls12_config));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls12_config));

            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
            EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_EQUAL(s2n_connection_get_actual_protocol_version(server_conn), S2N_TLS12);
            uint8_t iana_value[S2N_TLS_CIPHER_SUITE_LEN] = { 0 };
            EXPECT_SUCCESS(s2n_connection_get_cipher_iana_value(server_conn, &iana_value[0], &iana_value[1]));

            uint32_t length = 0;
            EXPECT_SUCCESS(s2n_connection_serialization_length(server_conn, &length));

            uint8_t buffer[S2N_SERIALIZED_CONN_TLS12_SIZE] = { 0 };
            EXPECT_SUCCESS(s2n_connection_serialize(server_conn, buffer, sizeof(buffer)));

            struct s2n_blob blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&blob, buffer, sizeof(buffer)));
            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init_written(&stuffer, &blob));
            EXPECT_EQUAL(length, s2n_stuffer_data_available(&stuffer));

            uint64_t serialized_version = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint64(&stuffer, &serialized_version));
            EXPECT_EQUAL(serialized_version, S2N_SERIALIZED_CONN_V1);

            uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&stuffer, protocol_version,
                    S2N_TLS_PROTOCOL_VERSION_LEN));
            EXPECT_EQUAL((protocol_version[0] * 10) + protocol_version[1], S2N_TLS12);

            uint8_t cipher_suite[S2N_TLS_CIPHER_SUITE_LEN] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&stuffer, cipher_suite, S2N_TLS_CIPHER_SUITE_LEN));
            EXPECT_BYTEARRAY_EQUAL(cipher_suite, iana_value, S2N_TLS_CIPHER_SUITE_LEN);

            uint8_t client_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&stuffer, client_sequence_number,
                    S2N_TLS_SEQUENCE_NUM_LEN));
            uint8_t expected_sequence_number[] = { 0, 0, 0, 0, 0, 0, 0, 1 };
            EXPECT_BYTEARRAY_EQUAL(client_sequence_number, expected_sequence_number,
                    S2N_TLS_SEQUENCE_NUM_LEN);

            uint8_t server_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&stuffer, server_sequence_number,
                    S2N_TLS_SEQUENCE_NUM_LEN));
            EXPECT_BYTEARRAY_EQUAL(server_sequence_number, expected_sequence_number,
                    S2N_TLS_SEQUENCE_NUM_LEN);

            uint16_t frag_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &frag_len));
            EXPECT_EQUAL(frag_len, S2N_DEFAULT_FRAGMENT_LENGTH);

            uint8_t master_secret[S2N_TLS_SECRET_LEN] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&stuffer, master_secret, S2N_TLS_SECRET_LEN));
            EXPECT_BYTEARRAY_EQUAL(master_secret, server_conn->secrets.version.tls12.master_secret,
                    S2N_TLS_SECRET_LEN);

            uint8_t client_random[S2N_TLS_RANDOM_DATA_LEN] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&stuffer, client_random, S2N_TLS_RANDOM_DATA_LEN));
            EXPECT_BYTEARRAY_EQUAL(client_random, server_conn->handshake_params.client_random,
                    S2N_TLS_RANDOM_DATA_LEN);

            uint8_t server_random[S2N_TLS_RANDOM_DATA_LEN] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&stuffer, server_random, S2N_TLS_RANDOM_DATA_LEN));
            EXPECT_BYTEARRAY_EQUAL(server_random, server_conn->handshake_params.server_random,
                    S2N_TLS_RANDOM_DATA_LEN);

            EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);
        };

        /* Serializes TLS 1.3 */
        if (s2n_is_tls13_fully_supported()) {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);

            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_config));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls13_config));

            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
            EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_EQUAL(s2n_connection_get_actual_protocol_version(server_conn), S2N_TLS13);
            uint8_t iana_value[S2N_TLS_CIPHER_SUITE_LEN] = { 0 };
            EXPECT_SUCCESS(s2n_connection_get_cipher_iana_value(server_conn, &iana_value[0], &iana_value[1]));

            uint32_t length = 0;
            EXPECT_SUCCESS(s2n_connection_serialization_length(server_conn, &length));

            uint8_t buffer[S2N_SERIALIZED_CONN_TLS13_SHA256_SIZE] = { 0 };
            EXPECT_SUCCESS(s2n_connection_serialize(server_conn, buffer, sizeof(buffer)));

            struct s2n_blob blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&blob, buffer, sizeof(buffer)));
            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init_written(&stuffer, &blob));
            EXPECT_EQUAL(length, s2n_stuffer_data_available(&stuffer));

            uint64_t serialized_version = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint64(&stuffer, &serialized_version));
            EXPECT_EQUAL(serialized_version, S2N_SERIALIZED_CONN_V1);

            uint8_t protocol_version[S2N_TLS_PROTOCOL_VERSION_LEN] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&stuffer, protocol_version,
                    S2N_TLS_PROTOCOL_VERSION_LEN));
            EXPECT_EQUAL((protocol_version[0] * 10) + protocol_version[1], S2N_TLS13);

            uint8_t cipher_suite[S2N_TLS_CIPHER_SUITE_LEN] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&stuffer, cipher_suite, S2N_TLS_CIPHER_SUITE_LEN));
            EXPECT_BYTEARRAY_EQUAL(cipher_suite, iana_value, S2N_TLS_CIPHER_SUITE_LEN);

            uint8_t client_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&stuffer, client_sequence_number,
                    S2N_TLS_SEQUENCE_NUM_LEN));
            uint8_t expected_sequence_number[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
            EXPECT_BYTEARRAY_EQUAL(client_sequence_number, expected_sequence_number,
                    S2N_TLS_SEQUENCE_NUM_LEN);

            uint8_t server_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&stuffer, server_sequence_number,
                    S2N_TLS_SEQUENCE_NUM_LEN));
            EXPECT_BYTEARRAY_EQUAL(server_sequence_number, expected_sequence_number,
                    S2N_TLS_SEQUENCE_NUM_LEN);

            uint16_t frag_len = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&stuffer, &frag_len));
            EXPECT_EQUAL(frag_len, S2N_DEFAULT_FRAGMENT_LENGTH);

            uint8_t client_secret[SHA256_DIGEST_LENGTH] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&stuffer, client_secret, SHA256_DIGEST_LENGTH));
            EXPECT_BYTEARRAY_EQUAL(client_secret, server_conn->secrets.version.tls13.client_app_secret,
                    SHA256_DIGEST_LENGTH);

            uint8_t server_secret[SHA256_DIGEST_LENGTH] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&stuffer, server_secret, SHA256_DIGEST_LENGTH));
            EXPECT_BYTEARRAY_EQUAL(server_secret, server_conn->secrets.version.tls13.server_app_secret,
                    SHA256_DIGEST_LENGTH);

            uint8_t resumption_secret[SHA256_DIGEST_LENGTH] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&stuffer, resumption_secret, SHA256_DIGEST_LENGTH));
            EXPECT_BYTEARRAY_EQUAL(resumption_secret, server_conn->secrets.version.tls13.resumption_master_secret,
                    SHA256_DIGEST_LENGTH);

            EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);
        };

        /* IO buffers must be empty before calling this function */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);

            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls12_config));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls12_config));

            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
            EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            uint8_t data[] = "Hello";
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_SUCCESS(s2n_send(client_conn, data, sizeof(data), &blocked));

            /* Partial read so that some data remains in the buffer */
            uint8_t recv_buf[10] = { 0 };
            EXPECT_SUCCESS(s2n_recv(server_conn, &recv_buf, 1, &blocked));

            uint8_t buffer[S2N_SERIALIZED_CONN_TLS12_SIZE] = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_serialize(server_conn, buffer,
                                              sizeof(buffer)),
                    S2N_ERR_INVALID_STATE);

            /* Finish reading to successfully get the serialized connection */
            EXPECT_SUCCESS(s2n_recv(server_conn, &recv_buf, sizeof(recv_buf), &blocked));
            EXPECT_SUCCESS(s2n_connection_serialize(server_conn, buffer, sizeof(buffer)));
        };

        /* Cannot send or recv after serialization */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);

            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_config));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls13_config));

            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
            EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            uint8_t buffer[S2N_SERIALIZED_CONN_TLS12_SIZE] = { 0 };
            EXPECT_SUCCESS(s2n_connection_serialize(server_conn, buffer, sizeof(buffer)));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            const uint8_t send_data[] = "hello world";
            EXPECT_FAILURE_WITH_ERRNO(s2n_send(server_conn, send_data, sizeof(send_data), &blocked), S2N_ERR_CLOSED);

            uint8_t recv_data = 0;
            EXPECT_FAILURE_WITH_ERRNO(s2n_recv(server_conn, &recv_data, sizeof(recv_data), &blocked), S2N_ERR_CLOSED);

            /* Calling shutdown after serialization will cause a plaintext alert to be sent
             * since serialization wipes the encryption context. */
            EXPECT_SUCCESS(s2n_shutdown_send(server_conn, &blocked));

            const uint8_t expected_alert[] = {
                TLS_ALERT,
                S2N_TLS12 / 10,
                S2N_TLS12 % 10,
                0, 2,
                S2N_TLS_ALERT_LEVEL_WARNING, S2N_TLS_ALERT_CLOSE_NOTIFY
            };
            uint8_t actual_alert[sizeof(expected_alert)] = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&io_pair.client_in, actual_alert, sizeof(actual_alert)));
            EXPECT_BYTEARRAY_EQUAL(actual_alert, expected_alert, sizeof(expected_alert));
        }

        /* Cannot serialize after connection has closed */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);

            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_config));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls13_config));

            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
            EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_SUCCESS(s2n_shutdown_send(server_conn, &blocked));

            /* Serializing after the connection closes will cause an error */
            uint8_t buffer[S2N_SERIALIZED_CONN_TLS12_SIZE] = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_serialize(server_conn, buffer, sizeof(buffer)), S2N_ERR_CLOSED);
        }
    };

    /* s2n_connection_deserialize */
    {
        /* Safety */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            uint8_t buffer = 0;
            uint32_t length = 0;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_deserialize(NULL, &buffer, length), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_deserialize(conn, NULL, length), S2N_ERR_NULL);
        };

        /* Errors if format version is unknown */
        {
            uint8_t test_context[] = {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, /* Unknown serialized_connection version */
                0x03, 0x04,                                     /* TLS 1.3 */
                TLS_AES_128_GCM_SHA256,
                TEST_SEQUENCE_NUM, /* Client sequence num */
                TEST_SEQUENCE_NUM, /* Server sequence num */
                0x01, 0x01,        /* Test Fragment length */
                TEST_TLS13_SECRET, /* Client app secret */
                TEST_TLS13_SECRET, /* Server app secret */
                TEST_TLS13_SECRET  /* Resumption master secret */
            };

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_deserialize(client_conn, test_context,
                                              sizeof(test_context)),
                    S2N_ERR_INVALID_SERIALIZED_CONNECTION);
        };

        /* Succeeds if format version is known */
        {
            uint8_t test_context[] = {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, S2N_SERIALIZED_CONN_V1,
                0x03, 0x04, /* TLS 1.3 */
                TLS_AES_128_GCM_SHA256,
                TEST_SEQUENCE_NUM, /* Client sequence num */
                TEST_SEQUENCE_NUM, /* Server sequence num */
                0x01, 0x01,        /* Test Fragment length */
                TEST_TLS13_SECRET, /* Client app secret */
                TEST_TLS13_SECRET, /* Server app secret */
                TEST_TLS13_SECRET  /* Resumption master secret */
            };

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_deserialize(client_conn, test_context,
                    sizeof(test_context)));
        };
    };

    struct s2n_config *config_array[] = { tls12_config, tls13_config };

    /* Self-talk: Client can be serialized and deserialized and continue sending and receiving data
     * in TLS1.2 and TLS1.3 */
    for (size_t i = 0; i < s2n_array_len(config_array); i++) {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config_array[i]));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config_array[i]));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Preliminary send and receive */
        EXPECT_OK(s2n_send_and_recv_test(server_conn, client_conn));
        EXPECT_OK(s2n_send_and_recv_test(client_conn, server_conn));

        uint8_t buffer[S2N_SERIALIZED_CONN_TLS12_SIZE] = { 0 };
        EXPECT_SUCCESS(s2n_connection_serialize(client_conn, buffer, sizeof(buffer)));

        /* Initialize new client connection and deserialize the connection */
        DEFER_CLEANUP(struct s2n_connection *new_client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(new_client_conn);
        EXPECT_SUCCESS(s2n_connection_deserialize(new_client_conn, buffer, sizeof(buffer)));

        /* Wipe and re-initialize IO pipes */
        EXPECT_SUCCESS(s2n_stuffer_wipe(&io_pair.client_in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&io_pair.server_in));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(new_client_conn, server_conn, &io_pair));

        /* Client can send and recv as usual */
        for (size_t idx = 0; idx < 1000; idx++) {
            EXPECT_OK(s2n_send_and_recv_test(server_conn, new_client_conn));
            EXPECT_OK(s2n_send_and_recv_test(new_client_conn, server_conn));
        }
    };

    /* Self-talk: Server can be serialized and deserialized and continue sending and receiving data
     * in TLS1.2 and TLS1.3 */
    for (size_t i = 0; i < s2n_array_len(config_array); i++) {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config_array[i]));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config_array[i]));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Preliminary send and receive */
        EXPECT_OK(s2n_send_and_recv_test(server_conn, client_conn));
        EXPECT_OK(s2n_send_and_recv_test(client_conn, server_conn));

        uint8_t buffer[S2N_SERIALIZED_CONN_TLS12_SIZE] = { 0 };
        EXPECT_SUCCESS(s2n_connection_serialize(server_conn, buffer, sizeof(buffer)));

        /* Initialize new server connection and deserialize the connection */
        DEFER_CLEANUP(struct s2n_connection *new_server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(new_server_conn);
        EXPECT_SUCCESS(s2n_connection_deserialize(new_server_conn, buffer, sizeof(buffer)));

        /* Wipe and re-initialize IO pipes */
        EXPECT_SUCCESS(s2n_stuffer_wipe(&io_pair.client_in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&io_pair.server_in));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, new_server_conn, &io_pair));

        /* Server can send and recv as usual */
        for (size_t idx = 0; idx < 1000; idx++) {
            EXPECT_OK(s2n_send_and_recv_test(new_server_conn, client_conn));
            EXPECT_OK(s2n_send_and_recv_test(client_conn, new_server_conn));
        }
    };

    /* Self-talk: Test interaction between TLS1.2 session resumption and serialization */
    {
        DEFER_CLEANUP(struct s2n_config *resumption_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(resumption_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(resumption_config));
        EXPECT_SUCCESS(s2n_config_set_serialization_version(resumption_config, S2N_SERIALIZED_CONN_V1));
        EXPECT_OK(s2n_resumption_test_ticket_key_setup(resumption_config));

        uint8_t serialized_conn[S2N_SERIALIZED_CONN_TLS12_SIZE] = { 0 };

        /* Initial handshake */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);

            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, resumption_config));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, resumption_config));

            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
            EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_EQUAL(s2n_connection_get_actual_protocol_version(server_conn), S2N_TLS12);

            /* Session ticket should have been received in the handshake */
            EXPECT_TRUE(s2n_connection_get_session_length(client_conn) > 0);

            EXPECT_SUCCESS(s2n_connection_serialize(client_conn, serialized_conn, sizeof(serialized_conn)));
        };

        /* Deserialized connection has no ticket to retrieve */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_deserialize(client_conn, serialized_conn, sizeof(serialized_conn)));

            /* Once deserialized the session ticket is no longer available. */
            EXPECT_TRUE(s2n_connection_get_session_length(client_conn) == 0);
        };
    };

    /* Self-talk: Test interaction between TLS1.3 session resumption and serialization. */
    if (s2n_is_tls13_fully_supported()) {
        DEFER_CLEANUP(struct s2n_config *resumption_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(resumption_config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(resumption_config));
        EXPECT_SUCCESS(s2n_config_set_serialization_version(resumption_config, S2N_SERIALIZED_CONN_V1));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(resumption_config, "default_tls13"));
        EXPECT_OK(s2n_resumption_test_ticket_key_setup(resumption_config));

        /* Client is serialized. Can read a session ticket before/after deserialization and resume with it. */
        {
            uint8_t serialized_conn[S2N_SERIALIZED_CONN_TLS12_SIZE] = { 0 };
            DEFER_CLEANUP(struct s2n_blob session_ticket_0 = { 0 }, s2n_free);
            DEFER_CLEANUP(struct s2n_blob session_ticket_1 = { 0 }, s2n_free);

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, resumption_config));

            /* Initial handshake */
            {
                DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(client_conn);
                EXPECT_SUCCESS(s2n_connection_set_config(client_conn, resumption_config));

                DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
                EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
                EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
                EXPECT_EQUAL(s2n_connection_get_actual_protocol_version(server_conn), S2N_TLS13);

                /* Client does a read here. Picks up initial ticket */
                EXPECT_OK(s2n_send_and_recv_test(server_conn, client_conn));
                EXPECT_OK(s2n_ticket_pickup(client_conn, &session_ticket_0));

                EXPECT_SUCCESS(s2n_connection_serialize(client_conn, serialized_conn, sizeof(serialized_conn)));
            };

            /* Pick up ticket after deserialization */
            {
                DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(client_conn);
                EXPECT_SUCCESS(s2n_connection_deserialize(client_conn, serialized_conn, sizeof(serialized_conn)));
                EXPECT_SUCCESS(s2n_connection_set_config(client_conn, resumption_config));

                DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
                EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
                EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

                EXPECT_SUCCESS(s2n_connection_add_new_tickets_to_send(server_conn, 1));
                EXPECT_OK(s2n_send_and_recv_test(server_conn, client_conn));

                EXPECT_OK(s2n_ticket_pickup(client_conn, &session_ticket_1));
            };

            /* Resumption handshake with initial ticket */
            {
                DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(client_conn);
                EXPECT_SUCCESS(s2n_connection_set_config(client_conn, resumption_config));
                EXPECT_SUCCESS(s2n_connection_set_session(client_conn, session_ticket_0.data, session_ticket_0.size));
                EXPECT_SUCCESS(s2n_connection_wipe(server_conn));

                DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
                EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
                EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
                EXPECT_FALSE(IS_FULL_HANDSHAKE(client_conn));
                EXPECT_FALSE(IS_FULL_HANDSHAKE(server_conn));
            };

            /* Successful resumption handshake with second ticket */
            {
                DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(client_conn);
                EXPECT_SUCCESS(s2n_connection_set_config(client_conn, resumption_config));
                EXPECT_SUCCESS(s2n_connection_set_session(client_conn, session_ticket_1.data, session_ticket_1.size));
                EXPECT_SUCCESS(s2n_connection_wipe(server_conn));

                DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
                EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
                EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
                EXPECT_FALSE(IS_FULL_HANDSHAKE(client_conn));
                EXPECT_FALSE(IS_FULL_HANDSHAKE(server_conn));
            };
        };

        /* Server is serialized. Can write a session ticket before/after deserialization and resumption can
         * occur with it. */
        {
            uint8_t serialized_conn[S2N_SERIALIZED_CONN_TLS12_SIZE] = { 0 };
            DEFER_CLEANUP(struct s2n_blob session_ticket_0 = { 0 }, s2n_free);
            DEFER_CLEANUP(struct s2n_blob session_ticket_1 = { 0 }, s2n_free);

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, resumption_config));

            /* Initial handshake */
            {
                DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(server_conn);
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, resumption_config));

                DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
                EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
                EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
                EXPECT_EQUAL(s2n_connection_get_actual_protocol_version(server_conn), S2N_TLS13);

                /* Client picks up the first ticket */
                EXPECT_OK(s2n_send_and_recv_test(server_conn, client_conn));
                EXPECT_OK(s2n_ticket_pickup(client_conn, &session_ticket_0));

                EXPECT_SUCCESS(s2n_connection_serialize(server_conn, serialized_conn, sizeof(serialized_conn)));
            };

            /* Send ticket after deserialization */
            {
                DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(server_conn);
                EXPECT_SUCCESS(s2n_connection_deserialize(server_conn, serialized_conn, sizeof(serialized_conn)));
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, resumption_config));

                DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
                EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
                EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

                EXPECT_OK(s2n_send_and_recv_test(server_conn, client_conn));
                EXPECT_OK(s2n_ticket_pickup(client_conn, &session_ticket_1));
            };

            /* Resumption handshake with initial ticket */
            {
                DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(server_conn);
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, resumption_config));
                EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
                EXPECT_SUCCESS(s2n_connection_set_session(client_conn, session_ticket_0.data, session_ticket_0.size));

                DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
                EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
                EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
                EXPECT_FALSE(IS_FULL_HANDSHAKE(client_conn));
                EXPECT_FALSE(IS_FULL_HANDSHAKE(server_conn));
            };

            /* Resumption handshake with second ticket */
            {
                DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(server_conn);
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, resumption_config));
                EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
                EXPECT_SUCCESS(s2n_connection_set_session(client_conn, session_ticket_1.data, session_ticket_1.size));

                DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
                EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
                EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
                EXPECT_FALSE(IS_FULL_HANDSHAKE(client_conn));
                EXPECT_FALSE(IS_FULL_HANDSHAKE(server_conn));
            };
        };
    };

    /* Self talk: Test interaction between key update and serialization */
    if (s2n_is_tls13_fully_supported()) {
        /* Deserialized client can do a keyupdate */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls13_config));

            uint8_t serialized_conn[S2N_SERIALIZED_CONN_TLS12_SIZE] = { 0 };

            /* Initial handshake */
            {
                DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(client_conn);
                EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_config));

                DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
                EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
                EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
                EXPECT_EQUAL(s2n_connection_get_actual_protocol_version(server_conn), S2N_TLS13);

                /* Preliminary send and receive */
                EXPECT_OK(s2n_send_and_recv_test(server_conn, client_conn));
                EXPECT_OK(s2n_send_and_recv_test(client_conn, server_conn));

                EXPECT_SUCCESS(s2n_connection_serialize(client_conn, serialized_conn, sizeof(serialized_conn)));
            };

            /* Deserialize and keyupdate */
            {
                DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(client_conn);
                EXPECT_SUCCESS(s2n_connection_deserialize(client_conn, serialized_conn, sizeof(serialized_conn)));

                DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
                EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
                EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

                EXPECT_OK(s2n_test_key_update(client_conn, server_conn));
            };
        };

        /* Deserialized server can do a keyupdate */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_config));

            uint8_t serialized_conn[S2N_SERIALIZED_CONN_TLS12_SIZE] = { 0 };

            /* Initial handshake */
            {
                DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(server_conn);

                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls13_config));

                DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
                EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
                EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
                EXPECT_EQUAL(s2n_connection_get_actual_protocol_version(server_conn), S2N_TLS13);

                /* Preliminary send and receive */
                EXPECT_OK(s2n_send_and_recv_test(server_conn, client_conn));
                EXPECT_OK(s2n_send_and_recv_test(client_conn, server_conn));

                EXPECT_SUCCESS(s2n_connection_serialize(server_conn, serialized_conn, sizeof(serialized_conn)));
            };

            /* Deserialize and keyupdate */
            {
                DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(server_conn);
                EXPECT_SUCCESS(s2n_connection_deserialize(server_conn, serialized_conn, sizeof(serialized_conn)));

                DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
                EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
                EXPECT_OK(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, &io_pair));

                EXPECT_OK(s2n_test_key_update(client_conn, server_conn));
            };
        };
    };

    /* Test: Renegotiation and serialization cannot both be set.
     *
     * Renegotiation is not available after serialization/deserialization.
     * The information needed to perform renegotiation (i.e. client/server finished verify data
     * and secure renegotiation flag) isn't stored during the serialization process and therefore
     * isn't available post-deserialization.
     * 
     * We could add that data to the serialized struct in the future, but for now, the user will get
     * an error if they attempt to configure renegotiation after serialization, and vice versa.
     */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);

        /* Setting a renegotiation callback means you cannot set a serialization version. */
        EXPECT_SUCCESS(s2n_config_set_renegotiate_request_cb(config, s2n_test_reneg_cb, NULL));
        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_serialization_version(config, S2N_SERIALIZED_CONN_V1),
                S2N_ERR_INVALID_STATE);

        /* Reset renegotiate cb */
        EXPECT_SUCCESS(s2n_config_set_renegotiate_request_cb(config, NULL, NULL));

        /* Setting a serialized version means that you cannot set a renegotiation callback. */
        EXPECT_SUCCESS(s2n_config_set_serialization_version(config, S2N_SERIALIZED_CONN_V1));
        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_renegotiate_request_cb(config, s2n_test_reneg_cb,
                                          NULL),
                S2N_ERR_INVALID_STATE);
    };

    END_TEST();
    return 0;
}
