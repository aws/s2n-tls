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

#define BUFFER_SIZE 100

#define EXPECT_NOT_BLOCKED(conn, blocked, expected_msg) \
    EXPECT_EQUAL((blocked), S2N_NOT_BLOCKED); \
    EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), (expected_msg))
#define EXPECT_BLOCKED_ON_EARLY_DATA(result) EXPECT_FAILURE_WITH_ERRNO((result), S2N_ERR_EARLY_DATA_BLOCKED)
#define EXPECT_BLOCKED_ON_IO(result) EXPECT_FAILURE_WITH_ERRNO((result), S2N_ERR_IO_BLOCKED)
#define EXPECT_BLOCKED_ON(conn, blocked, expected_blocked, expected_msg) \
    EXPECT_EQUAL((blocked), (expected_blocked)); \
    EXPECT_EQUAL(s2n_conn_get_current_message_type(conn), (expected_msg))

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

uint8_t s2n_allowed_reads = 0;
static int s2n_blocking_buffer_read(void *io_context, uint8_t *buf, uint32_t len)
{
    struct s2n_stuffer *in = (struct s2n_stuffer *) io_context;

    bool would_block = s2n_stuffer_data_available(in) < len;
    if (would_block || !s2n_allowed_reads) {
        errno = EAGAIN;
        return -1;
    }
    s2n_allowed_reads--;
    POSIX_GUARD(s2n_stuffer_read_bytes(in, buf, len));
    return len;
}

uint8_t s2n_allowed_writes = 0;
static int s2n_blocking_buffer_write(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_stuffer *out = (struct s2n_stuffer *) io_context;

    bool would_block = !out->growable && s2n_stuffer_space_remaining(out) < len;
    if (would_block || !s2n_allowed_writes) {
        errno = EAGAIN;
        return -1;
    }
    s2n_allowed_writes--;
    POSIX_GUARD(s2n_stuffer_write_bytes(out, buf, len));
    return len;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const uint8_t test_data[] = "hello world";

    /* Malformed record: empty handshake record */
    uint8_t malformed_record[] = {
           TLS_HANDSHAKE, 0x03, 0x03, 0x00, 0x04,
           TLS_FINISHED, 0x00, 0x00, 0x00
    };

    DEFER_CLEANUP(struct s2n_psk *test_psk = s2n_external_psk_new(), s2n_psk_free);
    EXPECT_SUCCESS(s2n_psk_set_identity(test_psk, test_data, sizeof(test_data)));
    EXPECT_SUCCESS(s2n_psk_set_secret(test_psk, test_data, sizeof(test_data)));
    EXPECT_SUCCESS(s2n_psk_configure_early_data(test_psk, UINT32_MAX, 0x13, 0x01));

    DEFER_CLEANUP(struct s2n_psk *test_psk_without_early_data = s2n_external_psk_new(), s2n_psk_free);
    EXPECT_SUCCESS(s2n_psk_set_identity(test_psk_without_early_data, test_data, sizeof(test_data)));
    EXPECT_SUCCESS(s2n_psk_set_secret(test_psk_without_early_data, test_data, sizeof(test_data)));

    DEFER_CLEANUP(struct s2n_psk *test_psk_with_wrong_early_data = s2n_external_psk_new(), s2n_psk_free);
    EXPECT_SUCCESS(s2n_psk_set_identity(test_psk_with_wrong_early_data, test_data, sizeof(test_data)));
    EXPECT_SUCCESS(s2n_psk_set_secret(test_psk_with_wrong_early_data, test_data, sizeof(test_data)));
    EXPECT_SUCCESS(s2n_psk_configure_early_data(test_psk_with_wrong_early_data, UINT32_MAX, 0x13, 0x03));
    EXPECT_SUCCESS(s2n_psk_set_application_protocol(test_psk_with_wrong_early_data, test_data, sizeof(test_data)));

    /* Test s2n_send_early_data */
    {
        /* Safety checks */
        {
            struct s2n_connection conn = { 0 };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            ssize_t data_size = 0;
            uint8_t data = 0;
            EXPECT_FAILURE_WITH_ERRNO(s2n_send_early_data(NULL, &data, 1, &data_size, &blocked), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_send_early_data(&conn, &data, 1, NULL,  &blocked), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_send_early_data(&conn, &data, 1, &data_size, NULL), S2N_ERR_NULL);

            conn.mode = S2N_SERVER;
            EXPECT_FAILURE_WITH_ERRNO(s2n_send_early_data(&conn, &data, 1, &data_size, &blocked), S2N_ERR_SERVER_MODE);
        }

        /* Propagate errors from s2n_negotiate */
        {
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));
            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));

            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, S2N_DEFAULT_RECORD_LENGTH));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, S2N_DEFAULT_RECORD_LENGTH));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, client_conn));

            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&input, malformed_record, sizeof(malformed_record)));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            ssize_t data_size = 0;

            EXPECT_FAILURE_WITH_ERRNO(s2n_send_early_data(client_conn, test_data, sizeof(test_data),
                    &data_size, &blocked), S2N_ERR_BAD_MESSAGE);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_HELLO);
            EXPECT_EQUAL(data_size, 0);

            EXPECT_SUCCESS(s2n_stuffer_free(&input));
            EXPECT_SUCCESS(s2n_stuffer_free(&output));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        }

        /* Propagate errors from s2n_send */
        {
            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));
            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));

            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, S2N_DEFAULT_RECORD_LENGTH));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, client_conn));

            /* Indicate that we're already sending. That will cause an error. */
            client_conn->send_in_use = true;

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            ssize_t data_size = 0;

            EXPECT_FAILURE_WITH_ERRNO(s2n_send_early_data(client_conn, test_data, sizeof(test_data),
                    &data_size, &blocked), S2N_ERR_REENTRANCY);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), SERVER_HELLO);
            EXPECT_EQUAL(data_size, 0);

            EXPECT_SUCCESS(s2n_stuffer_free(&output));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        }
    }

    /* s2n_recv_early_data */
    {
        /* Safety checks */
        {
            struct s2n_connection conn = { 0 };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            ssize_t data_size = 0;
            uint8_t data = 0;
            EXPECT_FAILURE_WITH_ERRNO(s2n_recv_early_data(NULL, &data, 1, &data_size, &blocked), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_recv_early_data(&conn, &data, 1, NULL, &blocked), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_recv_early_data(&conn, &data, 1, &data_size, NULL), S2N_ERR_NULL);

            conn.mode = S2N_CLIENT;
            EXPECT_FAILURE_WITH_ERRNO(s2n_recv_early_data(&conn, &data, 1, &data_size, &blocked), S2N_ERR_CLIENT_MODE);
        }

        /* Propagate errors from s2n_negotiate */
        {
            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk));

            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, S2N_DEFAULT_RECORD_LENGTH));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, server_conn));

            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&input, malformed_record, sizeof(malformed_record)));

            uint8_t payload[BUFFER_SIZE] = { 0 };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            ssize_t data_size = 0;

            EXPECT_FAILURE_WITH_ERRNO(s2n_recv_early_data(server_conn, payload, sizeof(payload),
                    &data_size, &blocked), S2N_ERR_BAD_MESSAGE);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), CLIENT_HELLO);
            EXPECT_EQUAL(data_size, 0);

            EXPECT_SUCCESS(s2n_stuffer_free(&input));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Propagate errors from s2n_recv */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));
            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk));

            /* Indicate that we're already receiving. That will cause an error. */
            server_conn->recv_in_use = true;

            uint8_t payload[BUFFER_SIZE] = { 0 };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            ssize_t data_size = 0;

            EXPECT_BLOCKED_ON_IO(s2n_send_early_data(client_conn, test_data, sizeof(test_data), &data_size, &blocked));
            EXPECT_BLOCKED_ON(client_conn, blocked, S2N_BLOCKED_ON_READ, SERVER_HELLO);

            EXPECT_FAILURE_WITH_ERRNO(s2n_recv_early_data(server_conn, payload, sizeof(payload),
                    &data_size, &blocked), S2N_ERR_REENTRANCY);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), END_OF_EARLY_DATA);
            EXPECT_EQUAL(data_size, 0);

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }
    }

    /* Test sending and receiving early data */
    {
        /* Send zero-length early data */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk));

            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            ssize_t data_size = 0;
            s2n_early_data_status_t status = 0;

            EXPECT_BLOCKED_ON_IO(s2n_send_early_data(client_conn, NULL, 0, &data_size, &blocked));
            EXPECT_BLOCKED_ON(client_conn, blocked, S2N_BLOCKED_ON_READ, SERVER_HELLO);
            EXPECT_EQUAL(data_size, 0);

            EXPECT_SUCCESS(s2n_connection_get_early_data_status(client_conn, &status));
            EXPECT_EQUAL(status, S2N_EARLY_DATA_STATUS_OK);

            EXPECT_BLOCKED_ON_IO(s2n_recv_early_data(server_conn, NULL, 0, &data_size, &blocked));
            EXPECT_BLOCKED_ON(server_conn, blocked, S2N_BLOCKED_ON_READ, END_OF_EARLY_DATA);
            EXPECT_EQUAL(data_size, 0);

            EXPECT_SUCCESS(s2n_connection_get_early_data_status(server_conn, &status));
            EXPECT_EQUAL(status, S2N_EARLY_DATA_STATUS_OK);

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Send early data once */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk));

            uint8_t actual_payload[BUFFER_SIZE] = { 0 };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            ssize_t data_size = 0;
            s2n_early_data_status_t status = 0;

            EXPECT_BLOCKED_ON_IO(s2n_send_early_data(client_conn, test_data, sizeof(test_data), &data_size, &blocked));
            EXPECT_BLOCKED_ON(client_conn, blocked, S2N_BLOCKED_ON_READ, SERVER_HELLO);
            EXPECT_EQUAL(data_size, sizeof(test_data));

            EXPECT_SUCCESS(s2n_connection_get_early_data_status(client_conn, &status));
            EXPECT_EQUAL(status, S2N_EARLY_DATA_STATUS_OK);

            EXPECT_BLOCKED_ON_IO(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload), &data_size, &blocked));
            EXPECT_BLOCKED_ON(server_conn, blocked, S2N_BLOCKED_ON_READ, END_OF_EARLY_DATA);
            EXPECT_EQUAL(data_size, sizeof(test_data));
            EXPECT_BYTEARRAY_EQUAL(actual_payload, test_data, sizeof(test_data));

            EXPECT_SUCCESS(s2n_connection_get_early_data_status(server_conn, &status));
            EXPECT_EQUAL(status, S2N_EARLY_DATA_STATUS_OK);

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Receive early data too large for buffer */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk));

            uint8_t actual_payload[BUFFER_SIZE] = { 0 };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            ssize_t data_size = 0;

            EXPECT_BLOCKED_ON_IO(s2n_send_early_data(client_conn, test_data, sizeof(test_data), &data_size, &blocked));
            EXPECT_BLOCKED_ON(client_conn, blocked, S2N_BLOCKED_ON_READ, SERVER_HELLO);
            EXPECT_EQUAL(data_size, sizeof(test_data));

            EXPECT_BLOCKED_ON_EARLY_DATA(s2n_recv_early_data(server_conn, NULL, 0, &data_size, &blocked));
            EXPECT_BLOCKED_ON(server_conn, blocked, S2N_BLOCKED_ON_EARLY_DATA, END_OF_EARLY_DATA);
            EXPECT_EQUAL(data_size, 0);

            EXPECT_BLOCKED_ON_EARLY_DATA(s2n_recv_early_data(server_conn, actual_payload, 1, &data_size, &blocked));
            EXPECT_BLOCKED_ON(server_conn, blocked, S2N_BLOCKED_ON_EARLY_DATA, END_OF_EARLY_DATA);
            EXPECT_EQUAL(data_size, 1);
            EXPECT_BYTEARRAY_EQUAL(actual_payload, test_data, 1);

            /* Remaining early data should block handshake.
             * We can't successfully call s2n_negotiate again until we've drained all the early data
             * via s2n_recv_early_data. For safety, we are not allowed to arbitrarily discard any early data.
             */
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                                S2N_ERR_BAD_MESSAGE);

            /* Read the remaining early data properly */
            server_conn->closed = false;
            client_conn->closed = false;
            EXPECT_SUCCESS(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload),
                    &data_size, &blocked));

            EXPECT_NOT_BLOCKED(server_conn, blocked, APPLICATION_DATA);
            EXPECT_EQUAL(data_size, sizeof(test_data) - 1);
            EXPECT_BYTEARRAY_EQUAL(actual_payload, test_data + 1, sizeof(test_data) - 1);

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Send multiple early data messages */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk));

            uint8_t actual_payload[BUFFER_SIZE] = { 0 };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            ssize_t data_size = 0;

            EXPECT_BLOCKED_ON_IO(s2n_send_early_data(client_conn, test_data, sizeof(test_data), &data_size, &blocked));
            EXPECT_BLOCKED_ON(client_conn, blocked, S2N_BLOCKED_ON_READ, SERVER_HELLO);
            EXPECT_EQUAL(data_size, sizeof(test_data));

            EXPECT_BLOCKED_ON_IO(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload), &data_size, &blocked));
            EXPECT_BLOCKED_ON(server_conn, blocked, S2N_BLOCKED_ON_READ, END_OF_EARLY_DATA);
            EXPECT_EQUAL(data_size, sizeof(test_data));
            EXPECT_BYTEARRAY_EQUAL(actual_payload, test_data, sizeof(test_data));

            for (size_t i = 0; i < 10; i++) {
                EXPECT_SUCCESS(s2n_send_early_data(client_conn, test_data, sizeof(test_data),
                        &data_size, &blocked));
                EXPECT_NOT_BLOCKED(client_conn, blocked, END_OF_EARLY_DATA);
                EXPECT_EQUAL(data_size, sizeof(test_data));

                EXPECT_BLOCKED_ON_IO(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload), &data_size, &blocked));
                EXPECT_BLOCKED_ON(client_conn, blocked, S2N_BLOCKED_ON_READ, END_OF_EARLY_DATA);
                EXPECT_EQUAL(data_size, sizeof(test_data));
                EXPECT_BYTEARRAY_EQUAL(actual_payload, test_data, sizeof(test_data));
            }

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Receive and combine multiple early data records */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk));

            uint8_t actual_payload[BUFFER_SIZE] = { 0 };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            ssize_t data_size = 0;

            const size_t send_count = 5;
            for (size_t i = 0; i < send_count; i++) {
                EXPECT_BLOCKED_ON_IO(s2n_send_early_data(client_conn, test_data, sizeof(test_data), &data_size, &blocked));
                EXPECT_BLOCKED_ON(client_conn, blocked, S2N_BLOCKED_ON_READ, SERVER_HELLO);
                EXPECT_EQUAL(data_size, sizeof(test_data));
            }

            EXPECT_BLOCKED_ON_IO(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload), &data_size, &blocked));
            EXPECT_BLOCKED_ON(server_conn, blocked, S2N_BLOCKED_ON_READ, END_OF_EARLY_DATA);
            EXPECT_EQUAL(data_size, sizeof(test_data) * send_count);

            struct s2n_blob payload_blob = { 0 };
            struct s2n_stuffer payload_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&payload_blob, actual_payload, sizeof(actual_payload)));
            EXPECT_SUCCESS(s2n_stuffer_init(&payload_stuffer, &payload_blob));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&payload_stuffer, data_size));

            uint8_t payload_chunk[sizeof(test_data)] = { 0 };
            for (size_t i = 0; i < send_count; i++) {
                EXPECT_SUCCESS(s2n_stuffer_read_bytes(&payload_stuffer, payload_chunk, sizeof(test_data)));
                EXPECT_BYTEARRAY_EQUAL(payload_chunk, test_data, sizeof(test_data));
            }
            EXPECT_EQUAL(s2n_stuffer_data_available(&payload_stuffer), 0);

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Early data not requested */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk_with_wrong_early_data));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk));

            uint8_t actual_payload[BUFFER_SIZE] = { 0 };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            ssize_t data_size = 0;
            s2n_early_data_status_t status = 0;

            EXPECT_SUCCESS(s2n_send_early_data(client_conn, test_data, sizeof(test_data),
                    &data_size, &blocked));
            EXPECT_NOT_BLOCKED(client_conn, blocked, SERVER_HELLO);
            EXPECT_EQUAL(data_size, 0);

            EXPECT_SUCCESS(s2n_connection_get_early_data_status(client_conn, &status));
            EXPECT_EQUAL(status, S2N_EARLY_DATA_STATUS_NOT_REQUESTED);

            EXPECT_SUCCESS(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload),
                    &data_size, &blocked));
            EXPECT_NOT_BLOCKED(server_conn, blocked, CLIENT_FINISHED);
            EXPECT_EQUAL(data_size, 0);

            EXPECT_SUCCESS(s2n_connection_get_early_data_status(server_conn, &status));
            EXPECT_EQUAL(status, S2N_EARLY_DATA_STATUS_NOT_REQUESTED);

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Early data rejected */
        {
            struct s2n_connection *client_conn = NULL, *server_conn = NULL;
            EXPECT_OK(s2n_test_client_and_server_new(&client_conn, &server_conn));

            EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk_with_wrong_early_data));

            uint8_t actual_payload[BUFFER_SIZE] = { 0 };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            ssize_t data_size = 0;
            s2n_early_data_status_t status = 0;

            EXPECT_BLOCKED_ON_IO(s2n_send_early_data(client_conn, test_data, sizeof(test_data), &data_size, &blocked));
            EXPECT_BLOCKED_ON(client_conn, blocked, S2N_BLOCKED_ON_READ, SERVER_HELLO);
            EXPECT_EQUAL(data_size, sizeof(test_data));

            EXPECT_SUCCESS(s2n_connection_get_early_data_status(client_conn, &status));
            EXPECT_EQUAL(status, S2N_EARLY_DATA_STATUS_OK);

            EXPECT_SUCCESS(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload),
                    &data_size, &blocked));
            EXPECT_NOT_BLOCKED(server_conn, blocked, CLIENT_FINISHED);
            EXPECT_EQUAL(data_size, 0);

            EXPECT_SUCCESS(s2n_connection_get_early_data_status(server_conn, &status));
            EXPECT_EQUAL(status, S2N_EARLY_DATA_STATUS_REJECTED);

            EXPECT_SUCCESS(s2n_send_early_data(client_conn, test_data, sizeof(test_data),
                    &data_size, &blocked));
            EXPECT_NOT_BLOCKED(client_conn, blocked, APPLICATION_DATA);
            EXPECT_EQUAL(data_size, 0);

            EXPECT_SUCCESS(s2n_connection_get_early_data_status(client_conn, &status));
            EXPECT_EQUAL(status, S2N_EARLY_DATA_STATUS_REJECTED);

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }
    }

    /* Test blocking behavior when sending and receiving early data.
     *
     * We override the send and recv callbacks to allow us to block on every
     * call to s2n_negotiate, s2n_send, and s2n_recv. This lets us exercise all
     * possible blocking paths.
     */
    {
        /* To read a record, we need to both read its header and read its data */
        const uint8_t full_record_reads = 2;

        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client_conn, "default_tls13"));
        EXPECT_SUCCESS(s2n_connection_append_psk(client_conn, test_psk));

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));
        EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, test_psk));

        DEFER_CLEANUP(struct s2n_stuffer client_in = { 0 }, s2n_stuffer_free);
        DEFER_CLEANUP(struct s2n_stuffer server_in = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_alloc(&client_in, S2N_DEFAULT_RECORD_LENGTH));
        EXPECT_SUCCESS(s2n_stuffer_alloc(&server_in, S2N_DEFAULT_RECORD_LENGTH));

        POSIX_GUARD(s2n_connection_set_recv_cb(client_conn, &s2n_blocking_buffer_read));
        POSIX_GUARD(s2n_connection_set_recv_ctx(client_conn, &client_in));
        POSIX_GUARD(s2n_connection_set_recv_cb(server_conn, &s2n_blocking_buffer_read));
        POSIX_GUARD(s2n_connection_set_recv_ctx(server_conn, &server_in));

        POSIX_GUARD(s2n_connection_set_send_cb(client_conn, &s2n_blocking_buffer_write));
        POSIX_GUARD(s2n_connection_set_send_ctx(client_conn, &server_in));
        POSIX_GUARD(s2n_connection_set_send_cb(server_conn, &s2n_blocking_buffer_write));
        POSIX_GUARD(s2n_connection_set_send_ctx(server_conn, &client_in));

        uint8_t actual_payload[BUFFER_SIZE] = { 0 };
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        ssize_t data_size = 0;

        /* Block writing the ClientHello */
        s2n_allowed_writes = 0;
        EXPECT_BLOCKED_ON_IO(s2n_send_early_data(client_conn, test_data, sizeof(test_data), &data_size, &blocked));
        EXPECT_BLOCKED_ON(client_conn, blocked, S2N_BLOCKED_ON_WRITE, CLIENT_HELLO);
        EXPECT_EQUAL(data_size, 0);

        /* Write the ClientHello, but block on writing the Client CCS message */
        s2n_allowed_writes = 1;
        EXPECT_BLOCKED_ON_IO(s2n_send_early_data(client_conn, test_data, sizeof(test_data), &data_size, &blocked));
        EXPECT_BLOCKED_ON(client_conn, blocked, S2N_BLOCKED_ON_WRITE, CLIENT_CHANGE_CIPHER_SPEC);
        EXPECT_EQUAL(data_size, 0);

        /* Write the Client CCS message, but block on writing the early data */
        s2n_allowed_writes = 1;
        EXPECT_BLOCKED_ON_IO(s2n_send_early_data(client_conn, test_data, sizeof(test_data), &data_size, &blocked));
        EXPECT_BLOCKED_ON(client_conn, blocked, S2N_BLOCKED_ON_WRITE, SERVER_HELLO);
        EXPECT_EQUAL(data_size, 0);

        /* Write the early data, but block on reading the ServerHello */
        s2n_allowed_writes = 1;
        s2n_allowed_reads = 0;
        EXPECT_BLOCKED_ON_IO(s2n_send_early_data(client_conn, test_data, sizeof(test_data), &data_size, &blocked));
        EXPECT_BLOCKED_ON(client_conn, blocked, S2N_BLOCKED_ON_READ, SERVER_HELLO);
        EXPECT_EQUAL(data_size, sizeof(test_data));

        /* Block reading the ClientHello */
        s2n_allowed_reads = 0;
        EXPECT_BLOCKED_ON_IO(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload), &data_size, &blocked));
        EXPECT_BLOCKED_ON(server_conn, blocked, S2N_BLOCKED_ON_READ, CLIENT_HELLO);
        EXPECT_EQUAL(data_size, 0);

        /* Read the ClientHello, but block on writing the ServerHello */
        s2n_allowed_reads = full_record_reads;
        s2n_allowed_writes = 0;
        EXPECT_BLOCKED_ON_IO(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload), &data_size, &blocked));
        EXPECT_BLOCKED_ON(server_conn, blocked, S2N_BLOCKED_ON_WRITE, SERVER_HELLO);
        EXPECT_EQUAL(data_size, 0);

        /* Write the server messages */
        while (s2n_conn_get_current_message_type(server_conn) != SERVER_FINISHED) {
            s2n_allowed_writes = 1;
            EXPECT_FAILURE_WITH_ERRNO(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload),
                    &data_size, &blocked), S2N_ERR_IO_BLOCKED);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
            EXPECT_EQUAL(data_size, 0);
        };

        /* Write the last server message, but block on reading the early data */
        s2n_allowed_writes = 1;
        s2n_allowed_reads = 0;
        EXPECT_BLOCKED_ON_IO(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload), &data_size, &blocked));
        EXPECT_BLOCKED_ON(server_conn, blocked, S2N_BLOCKED_ON_READ, END_OF_EARLY_DATA);
        EXPECT_EQUAL(data_size, 0);

        /* Read the Client CCS message */
        s2n_allowed_reads = full_record_reads;
        EXPECT_BLOCKED_ON_IO(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload), &data_size, &blocked));
        EXPECT_BLOCKED_ON(server_conn, blocked, S2N_BLOCKED_ON_READ, END_OF_EARLY_DATA);
        EXPECT_EQUAL(data_size, 0);

        /* Read the early data */
        s2n_allowed_reads = full_record_reads;
        EXPECT_BLOCKED_ON_IO(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload), &data_size, &blocked));
        EXPECT_BLOCKED_ON(server_conn, blocked, S2N_BLOCKED_ON_READ, END_OF_EARLY_DATA);
        EXPECT_EQUAL(data_size, sizeof(test_data));

        /* Read the ServerHello, but block on writing more early data */
        s2n_allowed_reads = full_record_reads;
        s2n_allowed_writes = 0;
        EXPECT_BLOCKED_ON_IO(s2n_send_early_data(client_conn, test_data, sizeof(test_data), &data_size, &blocked));
        EXPECT_BLOCKED_ON(client_conn, blocked, S2N_BLOCKED_ON_WRITE, ENCRYPTED_EXTENSIONS);
        EXPECT_EQUAL(data_size, 0);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Known-value early data tests.
     * The RFC8848s ClientHello uses x25519, which is only available if evp APIs are supported.
     * Otherwise, skip these tests. */
    if (s2n_is_evp_apis_supported()) {
        DEFER_CLEANUP(struct s2n_psk resumption_psk = { 0 }, s2n_psk_wipe);
        EXPECT_OK(s2n_psk_init(&resumption_psk, S2N_PSK_TYPE_RESUMPTION));
        struct s2n_psk *known_psk = &resumption_psk;

        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-3
         *= type=test
         *# {server}  generate resumption secret "tls13 resumption":
         *#
         *#    PRK (32 octets):  7d f2 35 f2 03 1d 2a 05 12 87 d0 2b 02 41 b0 bf
         *#       da f8 6c c8 56 23 1f 2d 5a ba 46 c4 34 ec 19 6c
         *#
         *#    hash (2 octets):  00 00
         *#
         *#    info (22 octets):  00 20 10 74 6c 73 31 33 20 72 65 73 75 6d 70 74
         *#       69 6f 6e 02 00 00
         *#
         *#    expanded (32 octets):  4e cd 0e b6 ec 3b 4d 87 f5 d6 02 8f 92 2c
         *#       a4 c5 85 1a 27 7f d4 13 11 c9 e6 2d 2c 94 92 e1 c4 f3
         */
        S2N_BLOB_FROM_HEX(psk_secret,"4e cd 0e b6 ec 3b 4d 87 f5 d6 02 8f 92 2c \
                  a4 c5 85 1a 27 7f d4 13 11 c9 e6 2d 2c 94 92 e1 c4 f3");

        EXPECT_SUCCESS(s2n_psk_set_secret(known_psk, psk_secret.data, psk_secret.size));

        /**
         *= https://tools.ietf.org/rfc/rfc8448#section-3
         *= type=test
         *# {server}  construct a NewSessionTicket handshake message:
         *#
         *#    NewSessionTicket (205 octets):  04 00 00 c9 00 00 00 1e fa d6 aa
         *#       c5 02 00 00 00 b2 2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00 00 00
         *#       00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70 ad 3c
         *#       49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9 82 11
         *#       72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6 1d 28
         *#       27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0 37 25
         *#       a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5 90 6c
         *#       5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5 ae a6
         *#       17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d e6 50
         *#       5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57 00 08 00 2a 00
         *#       04 00 00 04 00
         */
        /* Skip past the message type, message size, ticket lifetime,
         * ticket age add, nonce, and ticket size:
         *                                     04 00 00 c9 00 00 00 1e fa d6 aa
         *        c5 02 00 00 00 b2
         */
        S2N_BLOB_FROM_HEX(psk_identity,
                                   "2c 03 5d 82 93 59 ee 5f f7 af 4e c9 00 00 00 \
                  00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf 1b 00 70 ad 3c \
                  49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60 97 a3 a9 82 11 \
                  72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6 1d 28 \
                  27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0 37 25 \
                  a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5 90 6c \
                  5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5 ae a6 \
                  17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d e6 50 \
                  5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57");
        EXPECT_SUCCESS(s2n_psk_set_identity(known_psk, psk_identity.data, psk_identity.size));
        /* Skip past the total extensions size, early data extension type,
         * and early data extension size:                         00 08 00 2a 00
         *        04
         */
        const uint32_t max_early_data = 0x00000400;
        EXPECT_SUCCESS(s2n_psk_configure_early_data(known_psk, max_early_data, 0x13, 0x01));

        /** ClientHello record
         *
         *= https://tools.ietf.org/rfc/rfc8448#section-4
         *= type=test
         *#
         *#    complete record (517 octets):  16 03 01 02 00 01 00 01 fc 03 03 1b
         *#       c3 ce b6 bb e3 9c ff 93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49
         *#       d7 b4 bc 41 9d 78 76 48 7d 95 00 00 06 13 01 13 03 13 02 01 00
         *#       01 cd 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01
         *#       00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02
         *#       01 03 01 04 00 33 00 26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d
         *#       96 c9 9d a2 66 98 34 6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1
         *#       8d 66 8f 0b 00 2a 00 00 00 2b 00 03 02 03 04 00 0d 00 20 00 1e
         *#       04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02
         *#       01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01
         *#       00 15 00 57 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
         *#       00 00 00 00 00 00 00 00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59
         *#       ee 5f f7 af 4e c9 00 00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb
         *#       33 fa 90 bf 1b 00 70 ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc
         *#       55 cd 22 60 97 a3 a9 82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3
         *#       6d 64 e8 61 be 7f d6 1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66
         *#       4d 4e 6d a4 d2 9e e0 37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29
         *#       51 3e 3d a2 67 7f a5 90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72
         *#       14 70 f9 fb f2 97 b5 ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6
         *#       21 a7 91 41 ef 5f 7d e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93
         *#       4a e4 d3 57 fa d6 aa cb 00 21 20 3a dd 4f b2 d8 fd f8 22 a0 ca
         *#       3c f7 67 8e f5 e8 8d ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f
         *#       9d
         */
        S2N_BLOB_FROM_HEX(ch_record,         "16 03 01 02 00 01 00 01 fc 03 03 1b \
                  c3 ce b6 bb e3 9c ff 93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49 \
                  d7 b4 bc 41 9d 78 76 48 7d 95 00 00 06 13 01 13 03 13 02 01 00 \
                  01 cd 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 \
                  00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 \
                  01 03 01 04 00 33 00 26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d \
                  96 c9 9d a2 66 98 34 6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1 \
                  8d 66 8f 0b 00 2a 00 00 00 2b 00 03 02 03 04 00 0d 00 20 00 1e \
                  04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 \
                  01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01 \
                  00 15 00 57 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                  00 00 00 00 00 00 00 00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59 \
                  ee 5f f7 af 4e c9 00 00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb \
                  33 fa 90 bf 1b 00 70 ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc \
                  55 cd 22 60 97 a3 a9 82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 \
                  6d 64 e8 61 be 7f d6 1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66 \
                  4d 4e 6d a4 d2 9e e0 37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29 \
                  51 3e 3d a2 67 7f a5 90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 \
                  14 70 f9 fb f2 97 b5 ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6 \
                  21 a7 91 41 ef 5f 7d e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93 \
                  4a e4 d3 57 fa d6 aa cb 00 21 20 3a dd 4f b2 d8 fd f8 22 a0 ca \
                  3c f7 67 8e f5 e8 8d ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f \
                  9d");

        /* ApplicationData record containing early data
         *
         *= https://tools.ietf.org/rfc/rfc8448#section-4
         *= type=test
         *# {client}  send application_data record:
         *#
         *#    payload (6 octets):  41 42 43 44 45 46
         *#
         *#    complete record (28 octets):  17 03 03 00 17 ab 1d f4 20 e7 5c 45
         *#       7a 7c c5 d2 84 4f 76 d5 ae e4 b4 ed bf 04 9b e0
         */
        S2N_BLOB_FROM_HEX(payload, "41 42 43 44 45 46");
        S2N_BLOB_FROM_HEX(early_record,     "17 03 03 00 17 ab 1d f4 20 e7 5c 45 \
                  7a 7c c5 d2 84 4f 76 d5 ae e4 b4 ed bf 04 9b e0")

        /* EndOfEarlyData record
         *
         *= https://tools.ietf.org/rfc/rfc8448#section-4
         *= type=test
         *#
         *#    complete record (26 octets):  17 03 03 00 15 ac a6 fc 94 48 41 29
         *#       8d f9 95 93 72 5f 9b f9 75 44 29 b1 2f 09
         */
        S2N_BLOB_FROM_HEX(end_record,       "17 03 03 00 15 ac a6 fc 94 48 41 29 \
                  8d f9 95 93 72 5f 9b f9 75 44 29 b1 2f 09");

        /* Test s2n_recv_early_data without any blocking */
        {
            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, known_psk));
            EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(server_conn, max_early_data));
            /* We need to explicitly set the psk_params type to skip our stateless session resumption recv 
             * code because the handshake traces we're using are meant for stateful session resumption.
             * TODO: https://github.com/aws/s2n-tls/issues/2742 */
            server_conn->psk_params.type = S2N_PSK_TYPE_EXTERNAL;

            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, S2N_DEFAULT_RECORD_LENGTH));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, S2N_DEFAULT_RECORD_LENGTH));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, server_conn));

            EXPECT_SUCCESS(s2n_stuffer_write(&input, &ch_record));
            EXPECT_SUCCESS(s2n_stuffer_write(&input, &early_record));
            EXPECT_SUCCESS(s2n_stuffer_write(&input, &end_record));

            uint8_t actual_payload[BUFFER_SIZE] = { 0 };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            ssize_t data_read = 0;

            EXPECT_SUCCESS(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload),
                    &data_read, &blocked));
            EXPECT_NOT_BLOCKED(server_conn, blocked, CLIENT_FINISHED);
            EXPECT_EQUAL(data_read, payload.size);
            EXPECT_BYTEARRAY_EQUAL(actual_payload, payload.data, payload.size);
            EXPECT_EQUAL(server_conn->early_data_state, S2N_END_OF_EARLY_DATA);

            EXPECT_SUCCESS(s2n_stuffer_free(&input));
            EXPECT_SUCCESS(s2n_stuffer_free(&output));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Test s2n_recv_early_data with blocking */
        {
            /* When we block, we should continue to block regardless of how many times the API is called.
             * Let's choose an arbitrary "retry" test value > 1.
             */
            const size_t repeat_count = 5;

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, known_psk));
            EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(server_conn, max_early_data));
            /* We need to explicitly set the psk_params type to skip our stateless session resumption recv 
             * code because the handshake traces we're using are meant for stateful session resumption.
             * TODO: https://github.com/aws/s2n-tls/issues/2742 */
            server_conn->psk_params.type = S2N_PSK_TYPE_EXTERNAL;

            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, S2N_DEFAULT_RECORD_LENGTH));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, server_conn));

            uint8_t actual_payload[BUFFER_SIZE] = { 0 };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            ssize_t data_read = 0;

            for (size_t i = 0; i < repeat_count; i++) {
                EXPECT_BLOCKED_ON_IO(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload), &data_read, &blocked));
                EXPECT_BLOCKED_ON(server_conn, blocked, S2N_BLOCKED_ON_READ, CLIENT_HELLO);
                EXPECT_EQUAL(data_read, 0);
            }

            EXPECT_SUCCESS(s2n_stuffer_write(&input, &ch_record));

            for (size_t i = 0; i < repeat_count; i++) {
                EXPECT_BLOCKED_ON_IO(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload), &data_read, &blocked));
                EXPECT_BLOCKED_ON(server_conn, blocked, S2N_BLOCKED_ON_WRITE, SERVER_HELLO);
                EXPECT_EQUAL(data_read, 0);
            }

            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, S2N_DEFAULT_RECORD_LENGTH));

            for (size_t i = 0; i < repeat_count; i++) {
                EXPECT_BLOCKED_ON_IO(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload), &data_read, &blocked));
                EXPECT_BLOCKED_ON(server_conn, blocked, S2N_BLOCKED_ON_READ, END_OF_EARLY_DATA);
                EXPECT_EQUAL(data_read, 0);
            }
            EXPECT_EQUAL(server_conn->early_data_state, S2N_EARLY_DATA_ACCEPTED);

            EXPECT_SUCCESS(s2n_stuffer_write(&input, &early_record));

            EXPECT_BLOCKED_ON_IO(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload), &data_read, &blocked));
            EXPECT_BLOCKED_ON(server_conn, blocked, S2N_BLOCKED_ON_READ, END_OF_EARLY_DATA);
            EXPECT_EQUAL(data_read, payload.size);
            EXPECT_BYTEARRAY_EQUAL(actual_payload, payload.data, payload.size);

            for (size_t i = 0; i < repeat_count; i++) {
                EXPECT_BLOCKED_ON_IO(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload), &data_read, &blocked));
                EXPECT_BLOCKED_ON(server_conn, blocked, S2N_BLOCKED_ON_READ, END_OF_EARLY_DATA);
                EXPECT_EQUAL(data_read, 0);
            }
            EXPECT_EQUAL(server_conn->early_data_state, S2N_EARLY_DATA_ACCEPTED);

            EXPECT_SUCCESS(s2n_stuffer_write(&input, &end_record));

            for (size_t i = 0; i < repeat_count; i++) {
                EXPECT_SUCCESS(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload),
                        &data_read, &blocked));
                EXPECT_NOT_BLOCKED(server_conn, blocked, CLIENT_FINISHED);
                EXPECT_EQUAL(data_read, 0);
                EXPECT_EQUAL(server_conn->early_data_state, S2N_END_OF_EARLY_DATA);
            }

            EXPECT_BLOCKED_ON_IO(s2n_negotiate(server_conn, &blocked));
            EXPECT_BLOCKED_ON(server_conn, blocked, S2N_BLOCKED_ON_READ, CLIENT_FINISHED);
            EXPECT_EQUAL(server_conn->early_data_state, S2N_END_OF_EARLY_DATA);

            EXPECT_SUCCESS(s2n_stuffer_free(&input));
            EXPECT_SUCCESS(s2n_stuffer_free(&output));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Test s2n_recv_early_data when early data not allowed for PSK */
        {
            struct s2n_psk psk_copy = *known_psk;
            EXPECT_SUCCESS(s2n_psk_configure_early_data(&psk_copy, 0, 0x13, 0x01));
            struct s2n_psk *known_psk_without_early_data = &psk_copy;

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, known_psk_without_early_data));
            EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(server_conn, max_early_data));
            /* We need to explicitly set the psk_params type to skip our stateless session resumption recv 
             * code because the handshake traces we're using are meant for stateful session resumption.
             * TODO: https://github.com/aws/s2n-tls/issues/2742 */
            server_conn->psk_params.type = S2N_PSK_TYPE_EXTERNAL;

            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, S2N_DEFAULT_RECORD_LENGTH));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, S2N_DEFAULT_RECORD_LENGTH));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, server_conn));

            EXPECT_SUCCESS(s2n_stuffer_write(&input, &ch_record));
            EXPECT_SUCCESS(s2n_stuffer_write(&input, &early_record));
            EXPECT_SUCCESS(s2n_stuffer_write(&input, &end_record));

            uint8_t actual_payload[BUFFER_SIZE] = { 0 };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            ssize_t data_read = 0;

            EXPECT_SUCCESS(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload),
                    &data_read, &blocked));
            EXPECT_NOT_BLOCKED(server_conn, blocked, CLIENT_HELLO);
            EXPECT_EQUAL(data_read, 0);

            EXPECT_BLOCKED_ON_IO(s2n_negotiate(server_conn, &blocked));
            EXPECT_BLOCKED_ON(server_conn, blocked, S2N_BLOCKED_ON_READ, CLIENT_FINISHED);
            EXPECT_EQUAL(server_conn->early_data_state, S2N_EARLY_DATA_REJECTED);

            EXPECT_SUCCESS(s2n_stuffer_free(&input));
            EXPECT_SUCCESS(s2n_stuffer_free(&output));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }

        /* Test s2n_recv_early_data when early data rejected */
        {
            struct s2n_psk psk_copy = *known_psk;
            EXPECT_SUCCESS(s2n_psk_configure_early_data(&psk_copy, max_early_data, 0x13, 0x03));
            struct s2n_psk *known_psk_with_wrong_cipher_suite = &psk_copy;

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server_conn, "default_tls13"));
            EXPECT_SUCCESS(s2n_connection_append_psk(server_conn, known_psk_with_wrong_cipher_suite));
            EXPECT_SUCCESS(s2n_connection_set_server_max_early_data_size(server_conn, max_early_data));
            /* We need to explicitly set the psk_params type to skip our stateless session resumption recv 
             * code because the handshake traces we're using are meant for stateful session resumption.
             * TODO: https://github.com/aws/s2n-tls/issues/2742 */
            server_conn->psk_params.type = S2N_PSK_TYPE_EXTERNAL;

            DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, S2N_DEFAULT_RECORD_LENGTH));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, S2N_DEFAULT_RECORD_LENGTH));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, server_conn));

            EXPECT_SUCCESS(s2n_stuffer_write(&input, &ch_record));
            EXPECT_SUCCESS(s2n_stuffer_write(&input, &early_record));
            EXPECT_SUCCESS(s2n_stuffer_write(&input, &end_record));

            uint8_t actual_payload[BUFFER_SIZE] = { 0 };
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            ssize_t data_read = 0;

            EXPECT_SUCCESS(s2n_recv_early_data(server_conn, actual_payload, sizeof(actual_payload),
                    &data_read, &blocked));
            EXPECT_NOT_BLOCKED(server_conn, blocked, CLIENT_FINISHED);
            EXPECT_EQUAL(data_read, 0);
            EXPECT_EQUAL(server_conn->early_data_state, S2N_EARLY_DATA_REJECTED);

            EXPECT_SUCCESS(s2n_stuffer_free(&input));
            EXPECT_SUCCESS(s2n_stuffer_free(&output));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
        }
    }

    END_TEST();
}
