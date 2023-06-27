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

#include "tls/s2n_key_update.h"

#include "crypto/s2n_sequence.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_post_handshake.h"
#include "tls/s2n_quic_support.h"
#include "tls/s2n_tls13_handshake.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"

#define LOWEST_BYTE (S2N_TLS_SEQUENCE_NUM_LEN - 1)

int s2n_key_update_write(struct s2n_blob *out);
int s2n_check_record_limit(struct s2n_connection *conn, struct s2n_blob *sequence_number);

static S2N_RESULT s2n_write_uint64(uint64_t input, uint8_t *output)
{
    struct s2n_blob blob = { 0 };
    struct s2n_stuffer stuffer = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&blob, output, S2N_TLS_SEQUENCE_NUM_LEN));
    EXPECT_SUCCESS(s2n_stuffer_init(&stuffer, &blob));
    EXPECT_SUCCESS(s2n_stuffer_write_uint64(&stuffer, input));
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    S2N_BLOB_FROM_HEX(application_secret,
            "4bc28934ddd802b00f479e14a72d7725dab45d32b3b145f29"
            "e4c5b56677560eb5236b168c71c5c75aa52f3e20ee89bfb");

    struct s2n_cipher_suite *cipher_suite_with_limit = &s2n_tls13_aes_256_gcm_sha384;
    const uint64_t record_limit = cipher_suite_with_limit->record_alg->encryption_limit;
    struct s2n_cipher_suite *cipher_suite_without_limit = &s2n_tls13_chacha20_poly1305_sha256;

    /* We can use a TLS1.2 cipher suite if chacha20 isn't available,
     * since no TLS1.2 cipher suites have record limits.
     */
    if (!cipher_suite_without_limit->available) {
        cipher_suite_without_limit = &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384;
    }

    EXPECT_TRUE(cipher_suite_with_limit->available);
    EXPECT_TRUE(cipher_suite_without_limit->available);

    uint8_t zeroed_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN] = { 0 };

    /* s2n_key_update_write */
    {
        /* Tests s2n_key_update_write writes as expected */
        {
            uint8_t key_update_data[S2N_KEY_UPDATE_MESSAGE_SIZE];
            struct s2n_blob key_update_blob = { 0 };
            struct s2n_stuffer key_update_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&key_update_blob, key_update_data, sizeof(key_update_data)));
            EXPECT_SUCCESS(s2n_stuffer_init(&key_update_stuffer, &key_update_blob));

            /* Write key update message */
            EXPECT_SUCCESS(s2n_key_update_write(&key_update_blob));

            /* Move stuffer write cursor to correct position */
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&key_update_stuffer, S2N_KEY_UPDATE_MESSAGE_SIZE));

            uint8_t post_handshake_id;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&key_update_stuffer, &post_handshake_id));
            EXPECT_EQUAL(post_handshake_id, TLS_KEY_UPDATE);

            uint32_t request_length;
            EXPECT_SUCCESS(s2n_stuffer_read_uint24(&key_update_stuffer, &request_length));
            EXPECT_EQUAL(request_length, S2N_KEY_UPDATE_LENGTH);

            uint8_t key_update_request;
            EXPECT_SUCCESS(s2n_stuffer_read_uint8(&key_update_stuffer, &key_update_request));
            EXPECT_EQUAL(key_update_request, S2N_KEY_UPDATE_NOT_REQUESTED);
        };
    };

    /* s2n_key_update_recv */
    {
        /* Key update message not allowed when running with QUIC
         *
         *= https://tools.ietf.org/rfc/rfc9001.txt#6
         *= type=test
         *# Endpoints MUST treat the receipt of a TLS KeyUpdate message as a connection error
         *# of type 0x010a, equivalent to a fatal TLS alert of unexpected_message
         **/
        {
            const size_t test_data_len = 10;
            DEFER_CLEANUP(struct s2n_stuffer input, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_alloc(&input, test_data_len));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&input, test_data_len));

            struct s2n_config *quic_config;
            EXPECT_NOT_NULL(quic_config = s2n_config_new());
            EXPECT_SUCCESS(s2n_config_enable_quic(quic_config));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, quic_config));

            EXPECT_FAILURE_WITH_ALERT(s2n_key_update_recv(conn, &input),
                    S2N_ERR_BAD_MESSAGE, S2N_TLS_ALERT_UNEXPECTED_MESSAGE);

            /* Verify method was a no-op and the message was not read */
            EXPECT_EQUAL(s2n_stuffer_data_available(&input), test_data_len);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_config_free(quic_config));
        };

        /* Key update message not allowed in TLS1.2 */
        {
            const size_t test_data_len = 10;
            DEFER_CLEANUP(struct s2n_stuffer input, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_alloc(&input, test_data_len));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&input, test_data_len));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS12;

            EXPECT_FAILURE_WITH_ERRNO(s2n_key_update_recv(conn, &input), S2N_ERR_BAD_MESSAGE);

            /* Verify method was a no-op and the message was not read */
            EXPECT_EQUAL(s2n_stuffer_data_available(&input), test_data_len);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Key update message received contains invalid key update request */
        {
            DEFER_CLEANUP(struct s2n_stuffer input, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));

            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            /* Write invalid value for key update request type */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&input, -1));

            EXPECT_FAILURE_WITH_ERRNO(s2n_key_update_recv(conn, &input), S2N_ERR_BAD_MESSAGE);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Server receives valid key update request */
        {
            DEFER_CLEANUP(struct s2n_stuffer input, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));

            struct s2n_connection *server_conn;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            server_conn->actual_protocol_version = S2N_TLS13;
            server_conn->secure->cipher_suite = cipher_suite_with_limit;
            POSIX_CHECKED_MEMCPY(server_conn->secrets.version.tls13.client_app_secret, application_secret.data, application_secret.size);

            server_conn->secure->client_sequence_number[0] = 1;
            /* Write the key update request to the correct stuffer */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&input, S2N_KEY_UPDATE_NOT_REQUESTED));

            EXPECT_SUCCESS(s2n_key_update_recv(server_conn, &input));
            EXPECT_EQUAL(server_conn->secure->client_sequence_number[0], 0);
            EXPECT_FALSE(s2n_atomic_flag_test(&server_conn->key_update_pending));

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        };

        /* Client receives valid key update request */
        {
            DEFER_CLEANUP(struct s2n_stuffer input, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));

            struct s2n_connection *client_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            client_conn->actual_protocol_version = S2N_TLS13;
            client_conn->secure->cipher_suite = cipher_suite_with_limit;
            POSIX_CHECKED_MEMCPY(client_conn->secrets.version.tls13.server_app_secret, application_secret.data, application_secret.size);

            client_conn->secure->server_sequence_number[0] = 1;
            /* Write the key update request to the correct stuffer */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&input, S2N_KEY_UPDATE_NOT_REQUESTED));

            EXPECT_SUCCESS(s2n_key_update_recv(client_conn, &input));
            EXPECT_EQUAL(client_conn->secure->server_sequence_number[0], 0);
            EXPECT_FALSE(s2n_atomic_flag_test(&client_conn->key_update_pending));

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        };

        /* Receiving a KeyUpdate request sets key_update_pending */
        {
            DEFER_CLEANUP(struct s2n_stuffer input, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = cipher_suite_with_limit;

            /* KeyUpdate not pending */
            s2n_atomic_flag_clear(&conn->key_update_pending);

            /* KeyUpdate received */
            conn->secure->client_sequence_number[0] = 1;
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&input, S2N_KEY_UPDATE_REQUESTED));
            EXPECT_SUCCESS(s2n_key_update_recv(conn, &input));
            EXPECT_EQUAL(conn->secure->client_sequence_number[0], 0);

            /* KeyUpdate pending */
            EXPECT_TRUE(s2n_atomic_flag_test(&conn->key_update_pending));
        };

        /* Receiving a KeyUpdate cannot reset key_update_pending */
        {
            DEFER_CLEANUP(struct s2n_stuffer input, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = cipher_suite_with_limit;

            /* KeyUpdate already pending */
            s2n_atomic_flag_set(&conn->key_update_pending);

            /* KeyUpdate received */
            conn->secure->client_sequence_number[0] = 1;
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&input, S2N_KEY_UPDATE_NOT_REQUESTED));
            EXPECT_SUCCESS(s2n_key_update_recv(conn, &input));
            EXPECT_EQUAL(conn->secure->client_sequence_number[0], 0);

            /* KeyUpdate still pending */
            EXPECT_TRUE(s2n_atomic_flag_test(&conn->key_update_pending));
        };
    };

    /* s2n_key_update_send */
    {
        /* Key update has been requested */
        {
            struct s2n_connection *client_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            client_conn->actual_protocol_version = S2N_TLS13;
            client_conn->secure->cipher_suite = cipher_suite_with_limit;
            POSIX_CHECKED_MEMCPY(client_conn->secrets.version.tls13.client_app_secret, application_secret.data, application_secret.size);

            /* Setup io */
            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, client_conn));

            s2n_atomic_flag_set(&client_conn->key_update_pending);

            s2n_blocked_status blocked = 0;
            EXPECT_SUCCESS(s2n_key_update_send(client_conn, &blocked));

            EXPECT_EQUAL(s2n_atomic_flag_test(&client_conn->key_update_pending), false);
            EXPECT_BYTEARRAY_EQUAL(client_conn->secure->client_sequence_number, zeroed_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN);
            EXPECT_TRUE(s2n_stuffer_data_available(&stuffer) > 0);

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        };

        /* Key update is triggered by encryption limits */
        {
            struct s2n_connection *client_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            client_conn->actual_protocol_version = S2N_TLS13;
            client_conn->secure->cipher_suite = cipher_suite_with_limit;
            POSIX_CHECKED_MEMCPY(client_conn->secrets.version.tls13.client_app_secret, application_secret.data, application_secret.size);

            /* Setup io */
            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, client_conn));

            s2n_atomic_flag_clear(&client_conn->key_update_pending);
            EXPECT_OK(s2n_write_uint64(record_limit, client_conn->secure->client_sequence_number));

            s2n_blocked_status blocked = 0;
            EXPECT_SUCCESS(s2n_key_update_send(client_conn, &blocked));

            EXPECT_EQUAL(s2n_atomic_flag_test(&client_conn->key_update_pending), false);
            EXPECT_BYTEARRAY_EQUAL(client_conn->secure->client_sequence_number, zeroed_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN);
            EXPECT_TRUE(s2n_stuffer_data_available(&stuffer) > 0);

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        };

        /* Key update never sent for <TLS1.3, even if requested / required */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            conn->actual_protocol_version = S2N_TLS12;
            conn->secure->cipher_suite = cipher_suite_with_limit;
            POSIX_CHECKED_MEMCPY(conn->secrets.version.tls13.client_app_secret,
                    application_secret.data, application_secret.size);

            /* Setup io */
            DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            /* Key update both pending and required by record limit */
            s2n_atomic_flag_set(&conn->key_update_pending);
            EXPECT_OK(s2n_write_uint64(record_limit, conn->secure->client_sequence_number));

            s2n_blocked_status blocked = 0;
            EXPECT_FAILURE_WITH_ERRNO(s2n_key_update_send(conn, &blocked), S2N_ERR_SAFETY);

            /* Sequence number not reset and no KeyUpdate sent */
            EXPECT_BYTEARRAY_NOT_EQUAL(conn->secure->client_sequence_number,
                    zeroed_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN);
            EXPECT_EQUAL(s2n_stuffer_data_available(&stuffer), 0);
        };

        /* Key update is not triggered */
        {
            struct s2n_connection *client_conn;
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            client_conn->actual_protocol_version = S2N_TLS13;
            client_conn->secure->cipher_suite = cipher_suite_with_limit;
            POSIX_CHECKED_MEMCPY(client_conn->secrets.version.tls13.client_app_secret, application_secret.data, application_secret.size);
            uint8_t expected_sequence_number[S2N_TLS_SEQUENCE_NUM_LEN] = { 0 };

            /* Setup io */
            struct s2n_stuffer stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, client_conn));

            client_conn->secure->client_sequence_number[LOWEST_BYTE] = 1;
            expected_sequence_number[LOWEST_BYTE] = 1;
            s2n_atomic_flag_clear(&client_conn->key_update_pending);

            s2n_blocked_status blocked = 0;
            EXPECT_SUCCESS(s2n_key_update_send(client_conn, &blocked));

            EXPECT_EQUAL(s2n_atomic_flag_test(&client_conn->key_update_pending), false);
            EXPECT_BYTEARRAY_EQUAL(client_conn->secure->client_sequence_number, expected_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN);
            EXPECT_TRUE(s2n_stuffer_data_available(&stuffer) == 0);

            EXPECT_SUCCESS(s2n_stuffer_free(&stuffer));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        };

        /* Key update eventually occurs when record limit reached */
        {
            const uint64_t expected = record_limit;
            const uint64_t start = expected - 100;

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            client_conn->actual_protocol_version = S2N_TLS13;
            client_conn->secure->cipher_suite = cipher_suite_with_limit;
            POSIX_CHECKED_MEMCPY(client_conn->secrets.version.tls13.client_app_secret, application_secret.data, application_secret.size);

            /* Setup io */
            DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, client_conn));

            struct s2n_blob sequence_number = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&sequence_number,
                    client_conn->secure->client_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));
            EXPECT_OK(s2n_write_uint64(start, client_conn->secure->client_sequence_number));

            uint64_t key_update_seq_num = 0;
            for (uint64_t i = start; i <= UINT64_MAX; i++) {
                s2n_blocked_status blocked = 0;
                EXPECT_SUCCESS(s2n_key_update_send(client_conn, &blocked));

                if (s2n_stuffer_data_available(&stuffer) > 0) {
                    key_update_seq_num = i;
                    break;
                }

                EXPECT_SUCCESS(s2n_increment_sequence_number(&sequence_number));
            }

            EXPECT_EQUAL(key_update_seq_num, expected);
        };

        /* Key update eventually occurs before we run out of sequence numbers */
        {
            const uint64_t expected = UINT64_MAX;
            const uint64_t start = expected - 100;

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            client_conn->actual_protocol_version = S2N_TLS13;
            client_conn->secure->cipher_suite = cipher_suite_without_limit;
            POSIX_CHECKED_MEMCPY(client_conn->secrets.version.tls13.client_app_secret, application_secret.data, application_secret.size);

            /* Setup io */
            DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, client_conn));

            struct s2n_blob sequence_number = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&sequence_number,
                    client_conn->secure->client_sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));
            EXPECT_OK(s2n_write_uint64(start, client_conn->secure->client_sequence_number));

            uint64_t key_update_seq_num = 0;
            for (uint64_t i = start; i <= UINT64_MAX; i++) {
                s2n_blocked_status blocked = 0;
                EXPECT_SUCCESS(s2n_key_update_send(client_conn, &blocked));

                if (s2n_stuffer_data_available(&stuffer) > 0) {
                    key_update_seq_num = i;
                    break;
                }

                EXPECT_SUCCESS(s2n_increment_sequence_number(&sequence_number));
            }

            EXPECT_EQUAL(key_update_seq_num, expected);
        };
    };

    /* s2n_check_record_limit */
    {
        /* Record encryption limit exists (AES-GCM) */
        {
            struct s2n_blob sequence_number = { 0 };
            uint8_t sequence_number_bytes[S2N_TLS_SEQUENCE_NUM_LEN] = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&sequence_number, sequence_number_bytes, sizeof(sequence_number_bytes)));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            conn->secure->cipher_suite = cipher_suite_with_limit;

            /* Not at limit yet: no records sent */
            s2n_atomic_flag_clear(&conn->key_update_pending);
            EXPECT_OK(s2n_write_uint64(0, sequence_number_bytes));
            EXPECT_SUCCESS(s2n_check_record_limit(conn, &sequence_number));
            EXPECT_FALSE(s2n_atomic_flag_test(&conn->key_update_pending));

            /* Not at limit yet: 2 records less than limit */
            s2n_atomic_flag_clear(&conn->key_update_pending);
            EXPECT_OK(s2n_write_uint64(record_limit - 2, sequence_number_bytes));
            EXPECT_SUCCESS(s2n_check_record_limit(conn, &sequence_number));
            EXPECT_FALSE(s2n_atomic_flag_test(&conn->key_update_pending));

            /* 1 record less than limit */
            s2n_atomic_flag_clear(&conn->key_update_pending);
            EXPECT_OK(s2n_write_uint64(record_limit - 1, sequence_number_bytes));
            EXPECT_SUCCESS(s2n_check_record_limit(conn, &sequence_number));
            EXPECT_FALSE(s2n_atomic_flag_test(&conn->key_update_pending));

            /* Limit */
            s2n_atomic_flag_clear(&conn->key_update_pending);
            EXPECT_OK(s2n_write_uint64(record_limit, sequence_number_bytes));
            EXPECT_SUCCESS(s2n_check_record_limit(conn, &sequence_number));
            EXPECT_TRUE(s2n_atomic_flag_test(&conn->key_update_pending));

            /* Don't reset the key_update_pending flag if already set */
            EXPECT_OK(s2n_write_uint64(0, sequence_number_bytes));
            EXPECT_SUCCESS(s2n_check_record_limit(conn, &sequence_number));
            EXPECT_TRUE(s2n_atomic_flag_test(&conn->key_update_pending));

            /* Over limit */
            s2n_atomic_flag_clear(&conn->key_update_pending);
            EXPECT_OK(s2n_write_uint64(record_limit + 1, sequence_number_bytes));
            EXPECT_SUCCESS(s2n_check_record_limit(conn, &sequence_number));
            EXPECT_TRUE(s2n_atomic_flag_test(&conn->key_update_pending));
        };

        /* No record encryption limit (CHACHA20) */
        {
            struct s2n_blob sequence_number = { 0 };
            uint8_t sequence_number_bytes[S2N_TLS_SEQUENCE_NUM_LEN] = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&sequence_number, sequence_number_bytes, sizeof(sequence_number_bytes)));

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            conn->secure->cipher_suite = cipher_suite_without_limit;

            /* Not at limit yet: no records sent */
            s2n_atomic_flag_clear(&conn->key_update_pending);
            EXPECT_OK(s2n_write_uint64(0, sequence_number_bytes));
            EXPECT_SUCCESS(s2n_check_record_limit(conn, &sequence_number));
            EXPECT_FALSE(s2n_atomic_flag_test(&conn->key_update_pending));

            /* Not at limit yet: 2 records less than limit */
            s2n_atomic_flag_clear(&conn->key_update_pending);
            EXPECT_OK(s2n_write_uint64(UINT64_MAX - 2, sequence_number_bytes));
            EXPECT_SUCCESS(s2n_check_record_limit(conn, &sequence_number));
            EXPECT_FALSE(s2n_atomic_flag_test(&conn->key_update_pending));

            /* 1 record less than limit */
            s2n_atomic_flag_clear(&conn->key_update_pending);
            EXPECT_OK(s2n_write_uint64(UINT64_MAX - 1, sequence_number_bytes));
            EXPECT_SUCCESS(s2n_check_record_limit(conn, &sequence_number));
            EXPECT_FALSE(s2n_atomic_flag_test(&conn->key_update_pending));

            /* Limit */
            s2n_atomic_flag_clear(&conn->key_update_pending);
            EXPECT_OK(s2n_write_uint64(UINT64_MAX, sequence_number_bytes));
            EXPECT_SUCCESS(s2n_check_record_limit(conn, &sequence_number));
            EXPECT_TRUE(s2n_atomic_flag_test(&conn->key_update_pending));

            /* Don't reset the key_update_pending flag if already set */
            EXPECT_OK(s2n_write_uint64(0, sequence_number_bytes));
            EXPECT_SUCCESS(s2n_check_record_limit(conn, &sequence_number));
            EXPECT_TRUE(s2n_atomic_flag_test(&conn->key_update_pending));

            /* Over limit not possible: limit is maximum value */
        };
    };

    /* Test: KeyUpdate fails if fragmentation required */
    {
        const size_t key_update_record_size = S2N_TLS_MAX_RECORD_LEN_FOR(S2N_KEY_UPDATE_MESSAGE_SIZE);

        /* Test: send buffer cannot be set smaller than a KeyUpdate record */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_send_buffer_size(config, key_update_record_size - 1),
                    S2N_ERR_INVALID_ARGUMENT);
        };

        /* Test: send fails if send buffer is too small for a KeyUpdate record */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_OK(s2n_connection_set_secrets(conn));
            conn->actual_protocol_version = S2N_TLS13;

            DEFER_CLEANUP(struct s2n_stuffer stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&stuffer, &stuffer, conn));

            /* Sanity check: send buffer just large enough for KeyUpdate record */
            config->send_buffer_size_override = key_update_record_size;
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            s2n_atomic_flag_set(&conn->key_update_pending);
            EXPECT_SUCCESS(s2n_key_update_send(conn, &blocked));

            EXPECT_SUCCESS(s2n_connection_release_buffers(conn));

            /* Test: send buffer too small for KeyUpdate record */
            config->send_buffer_size_override = key_update_record_size - 1;
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            s2n_atomic_flag_set(&conn->key_update_pending);
            EXPECT_FAILURE_WITH_ERRNO(s2n_key_update_send(conn, &blocked), S2N_ERR_FRAGMENT_LENGTH_TOO_LARGE);
        };
    };

    /* Test: all cipher suites must have record limits set.
     *
     * If this ever changes, then s2n_check_record_limit needs to consider
     * the case where there is no record limit.
     */
    for (size_t i = 0; i < cipher_preferences_test_all.count; i++) {
        struct s2n_cipher_suite *cipher_suite = cipher_preferences_test_all.suites[i];
        EXPECT_NOT_NULL(cipher_suite);
        if (cipher_suite->available) {
            EXPECT_NOT_NULL(cipher_suite->record_alg);
            EXPECT_TRUE(cipher_suite->record_alg->encryption_limit > 0);
        }
    }

    END_TEST();
}
