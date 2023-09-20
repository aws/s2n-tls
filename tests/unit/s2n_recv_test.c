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

#include "api/s2n.h"
#include "api/unstable/renegotiate.h"
#include "s2n_test.h"
#include "testlib/s2n_ktls_test_utils.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_random.h"

bool s2n_custom_recv_fn_called = false;

int s2n_expect_concurrent_error_recv_fn(void *io_context, uint8_t *buf, uint32_t len)
{
    struct s2n_connection *conn = (struct s2n_connection *) io_context;
    s2n_custom_recv_fn_called = true;

    s2n_blocked_status blocked = 0;
    ssize_t result = s2n_recv(conn, buf, len, &blocked);
    EXPECT_FAILURE_WITH_ERRNO(result, S2N_ERR_REENTRANCY);
    return result;
}

static ssize_t s2n_test_ktls_recvmsg_cb(void *io_context, struct msghdr *msg)
{
    POSIX_ENSURE_REF(io_context);
    return *(ssize_t *) io_context;
}

static int s2n_test_reneg_req_cb(struct s2n_connection *conn, void *context,
        s2n_renegotiate_response *response)
{
    POSIX_ENSURE_REF(context);
    size_t *count = (size_t *) context;
    (*count)++;
    *response = S2N_RENEGOTIATE_IGNORE;
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_cert_chain_and_key * chain_and_key,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
            s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));

    /* s2n_peek */
    {
        /* We do full handshakes and send with a real connection here instead of
         * just calling s2n_connection_set_secrets because s2n_peek depends on details
         * of how data is encrypted, and we don't want to make any incorrect assumptions.
         */

        /* Safety check */
        EXPECT_EQUAL(s2n_peek(NULL), 0);

        const uint8_t test_data[100] = "hello world";
        const size_t test_data_size = sizeof(test_data);

        /* s2n_peek reports available plaintext bytes */
        {
            s2n_blocked_status blocked = 0;

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            /* Write some data */
            EXPECT_EQUAL(s2n_send(client_conn, test_data, sizeof(test_data), &blocked), sizeof(test_data));

            /* Initially, no data reported as available */
            EXPECT_EQUAL(s2n_peek(server_conn), 0);

            /* Read some, but not all, of the data written */
            uint8_t output[sizeof(test_data)] = { 0 };
            const size_t expected_peek_size = 10;
            const size_t recv_size = test_data_size - expected_peek_size;
            EXPECT_EQUAL(s2n_recv(server_conn, output, recv_size, &blocked), recv_size);

            /* After a partial read, some data reported as available */
            EXPECT_EQUAL(s2n_peek(server_conn), expected_peek_size);

            /* Read the rest of the data */
            EXPECT_EQUAL(s2n_recv(server_conn, output, expected_peek_size, &blocked), expected_peek_size);

            /* After the complete read, no data reported as available */
            EXPECT_EQUAL(s2n_peek(server_conn), 0);
        };

        /* s2n_peek doesn't report bytes belonging to partially read, still encrypted records */
        {
            s2n_blocked_status blocked = 0;

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            /* Use stuffers for IO so that we can trigger a block on a read */
            DEFER_CLEANUP(struct s2n_stuffer server_in = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer server_out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_in, 0));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_out, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_out, &server_in, client_conn));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_in, &server_out, server_conn));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            /* Write some data */
            EXPECT_EQUAL(s2n_send(client_conn, test_data, sizeof(test_data), &blocked), sizeof(test_data));

            /* Drop some of the data */
            EXPECT_SUCCESS(s2n_stuffer_wipe_n(&server_in, 10));

            /* Try to read the data, but block */
            uint8_t output[sizeof(test_data)] = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(s2n_recv(server_conn, output, sizeof(test_data), &blocked),
                    S2N_ERR_IO_BLOCKED);

            /* conn->in contains data, but s2n_peek reports no data available */
            EXPECT_TRUE(s2n_stuffer_data_available(&server_conn->in));
            EXPECT_EQUAL(s2n_peek(server_conn), 0);
        };

        /* s2n_peek doesn't report bytes belonging to post-handshake messages */
        if (s2n_is_tls13_fully_supported()) {
            s2n_blocked_status blocked = 0;

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            /* Use stuffers for IO so that we can trigger a block on a read */
            DEFER_CLEANUP(struct s2n_stuffer server_in = { 0 }, s2n_stuffer_free);
            DEFER_CLEANUP(struct s2n_stuffer server_out = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_in, 0));
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&server_out, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_out, &server_in, client_conn));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&server_in, &server_out, server_conn));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            /* Send a KeyUpdate message */
            s2n_atomic_flag_set(&client_conn->key_update_pending);
            EXPECT_SUCCESS(s2n_key_update_send(client_conn, &blocked));
            EXPECT_FALSE(s2n_atomic_flag_test(&client_conn->key_update_pending));

            /* Drop some of the data */
            EXPECT_SUCCESS(s2n_stuffer_wipe_n(&server_in, 10));

            /* Try to read the KeyUpdate message, but block */
            uint8_t output[1] = { 0 };
            EXPECT_FAILURE_WITH_ERRNO(s2n_recv(server_conn, output, sizeof(output), &blocked),
                    S2N_ERR_IO_BLOCKED);

            /* conn->in contains data, but s2n_peek reports no data available */
            EXPECT_TRUE(s2n_stuffer_data_available(&server_conn->in));
            EXPECT_EQUAL(s2n_peek(server_conn), 0);
        };
    };

    /* s2n_recv cannot be called concurrently */
    {
        /* Setup connection */
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

        /* Setup bad recv callback */
        EXPECT_SUCCESS(s2n_connection_set_recv_cb(conn, s2n_expect_concurrent_error_recv_fn));
        EXPECT_SUCCESS(s2n_connection_set_recv_ctx(conn, (void *) conn));
        EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));

        uint8_t test_data[100] = { 0 };
        s2n_blocked_status blocked = 0;
        s2n_custom_recv_fn_called = false;
        EXPECT_FAILURE_WITH_ERRNO(s2n_recv(conn, test_data, sizeof(test_data), &blocked),
                S2N_ERR_IO);
        EXPECT_TRUE(s2n_custom_recv_fn_called);

        /* Cleanup */
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* s2n_config_set_recv_multi_record */
    {
        const uint8_t test_data_size = 100;
        DEFER_CLEANUP(struct s2n_blob test_data = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&test_data, test_data_size));

        const size_t recv_size = test_data_size * 2;
        DEFER_CLEANUP(struct s2n_blob output = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&output, recv_size));

        {
            s2n_blocked_status blocked = 0;

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            /* Write some data, in three records */
            for (size_t i = 0; i < 3; i++) {
                EXPECT_EQUAL(s2n_send(client_conn, test_data.data, test_data.size, &blocked), test_data.size);
            }

            /* Disable multi-record recv, set legacy behavior */
            EXPECT_SUCCESS(s2n_config_set_recv_multi_record(config, false));

            EXPECT_EQUAL(s2n_recv(server_conn, output.data, recv_size, &blocked), test_data_size);

            /* Now enable multi record recv */
            EXPECT_SUCCESS(s2n_config_set_recv_multi_record(config, true));

            /* So we should be able to read the remaining two records in a single call */
            EXPECT_EQUAL(s2n_recv(server_conn, output.data, recv_size, &blocked), recv_size);
        }
    }

    /* recv blocked status
     *
     * This test preserves the `blocked` parameter contract with various states of the connection
     */
    {
        const uint8_t test_data_size = 100;
        const size_t record_count = 3;
        DEFER_CLEANUP(struct s2n_blob test_data = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&test_data, test_data_size));

        const size_t total_data_size = test_data_size * record_count;
        DEFER_CLEANUP(struct s2n_blob output = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&output, total_data_size));

        s2n_blocked_status blocked = 0;

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        for (size_t multi_record = 0; multi_record <= 1; multi_record++) {
            EXPECT_SUCCESS(s2n_config_set_recv_multi_record(config, multi_record));
            size_t max_recv_size = test_data_size;

            /* In multi-record, we can read all of the records in one go */
            if (multi_record) {
                max_recv_size *= record_count;
            }

            for (size_t read_size = 1; read_size <= total_data_size; read_size++) {
                /* Write some data across multiple records */
                for (size_t send_count = 0; send_count < record_count; send_count++) {
                    EXPECT_EQUAL(s2n_send(client_conn, test_data.data, test_data.size, &blocked), test_data.size);
                }

                /* Call `s2n_recv` multiple times with an empty buffer to make sure that's handled correctly */
                for (size_t empty_count = 0; empty_count < 10; empty_count++) {
                    EXPECT_EQUAL(s2n_recv(server_conn, output.data, 0, &blocked), 0);
                    EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
                }

                size_t recv_bytes = 0;
                while (recv_bytes < total_data_size) {
                    size_t expected_recv_size = MIN(MIN(read_size, total_data_size - recv_bytes), max_recv_size);

                    /* Perform the actual recv call */
                    ssize_t actual_recv_size = s2n_recv(server_conn, output.data, read_size, &blocked);

                    if (multi_record) {
                        /* In multi-record mode we should always read the size we expect */
                        EXPECT_EQUAL(actual_recv_size, expected_recv_size);
                    } else {
                        /* In single-record mode, we could potentially get a smaller read than a full record due to
                         * random record boundaries so we can only assert it's within the range we expect. */
                        EXPECT_NOT_EQUAL(actual_recv_size, 0);
                        EXPECT_TRUE(actual_recv_size <= expected_recv_size);
                    }

                    /* Keep track of the total amount of bytes read */
                    recv_bytes += actual_recv_size;

                    /* Due to the history of this API, some applications depend on the blocked status to know if
                     * the connection's `in` stuffer was completely cleared. This behavior needs to be preserved.
                     *
                     * Moving forward, applications should instead use `s2n_peek`, which accomplishes the same thing
                     * without conflating being blocked on reading from the OS socket vs blocked on the application's
                     * buffer size.
                     */
                    if (s2n_peek(server_conn) == 0) {
                        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
                    } else {
                        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
                    }
                }

                /* The final read should return blocked since we don't have any more data from the socket */
                EXPECT_FAILURE_WITH_ERRNO(s2n_recv(server_conn, output.data, read_size, &blocked), S2N_ERR_IO_BLOCKED);
                EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
            }
        }

        EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(client_conn, &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

        /* Call `s2n_recv` multiple times at the end of the stream after receiving a shutdown */
        for (size_t eos_count = 0; eos_count < 10; eos_count++) {
            EXPECT_EQUAL(s2n_recv(server_conn, output.data, output.size, &blocked), 0);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        }

        EXPECT_SUCCESS(s2n_shutdown(server_conn, &blocked));
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
        EXPECT_SUCCESS(s2n_shutdown(client_conn, &blocked));
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
    };

    /* Test with ktls */
    {
        uint8_t test_data[100] = { 0 };
        struct s2n_blob test_data_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&test_data_blob, test_data, sizeof(test_data)));
        EXPECT_OK(s2n_get_public_random_data(&test_data_blob));

        const struct iovec test_iovec = {
            .iov_base = test_data,
            .iov_len = sizeof(test_data),
        };

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;

        /* Test: receive all requested application data */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            s2n_ktls_configure_connection(conn, S2N_KTLS_MODE_RECV);

            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(conn, conn, &pair));
            struct s2n_test_ktls_io_stuffer *ctx = &pair.client_in;

            size_t written = 0;
            EXPECT_OK(s2n_ktls_sendmsg(ctx, TLS_APPLICATION_DATA,
                    &test_iovec, 1, &blocked, &written));
            EXPECT_EQUAL(written, sizeof(test_data));

            uint8_t output[sizeof(test_data)] = { 0 };
            int read = s2n_recv(conn, output, sizeof(output), &blocked);
            EXPECT_EQUAL(read, written);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_BYTEARRAY_EQUAL(output, test_data, read);
        };

        /* Test: receive partial application data */
        {
            const size_t partial_size = sizeof(test_data) / 2;
            struct iovec partial_iovec = test_iovec;
            partial_iovec.iov_len = partial_size;

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            s2n_ktls_configure_connection(conn, S2N_KTLS_MODE_RECV);

            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(conn, conn, &pair));
            struct s2n_test_ktls_io_stuffer *ctx = &pair.client_in;

            size_t written = 0;
            EXPECT_OK(s2n_ktls_sendmsg(ctx, TLS_APPLICATION_DATA,
                    &partial_iovec, 1, &blocked, &written));
            EXPECT_EQUAL(written, partial_size);

            uint8_t output[sizeof(test_data)] = { 0 };
            int read = s2n_recv(conn, output, sizeof(output), &blocked);
            EXPECT_EQUAL(read, written);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_BYTEARRAY_EQUAL(output, test_data, read);
        };

        /* Test: drain buffered application data */
        {
            const size_t partial_size = sizeof(test_data) / 2;

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            s2n_ktls_configure_connection(conn, S2N_KTLS_MODE_RECV);

            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(conn, conn, &pair));
            struct s2n_test_ktls_io_stuffer *ctx = &pair.client_in;

            size_t written = 0;
            EXPECT_OK(s2n_ktls_sendmsg(ctx, TLS_APPLICATION_DATA,
                    &test_iovec, 1, &blocked, &written));
            EXPECT_EQUAL(written, sizeof(test_data));

            /* The first read doesn't read all the available data */
            uint8_t output[sizeof(test_data)] = { 0 };
            int read = s2n_recv(conn, output, partial_size, &blocked);
            EXPECT_EQUAL(read, partial_size);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
            EXPECT_BYTEARRAY_EQUAL(output, test_data, partial_size);
            EXPECT_EQUAL(ctx->recvmsg_invoked_count, 1);

            /* The second read drains the remaining data */
            const size_t remaining = sizeof(test_data) - partial_size;
            read = s2n_recv(conn, output + read, remaining, &blocked);
            EXPECT_EQUAL(read, remaining);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_BYTEARRAY_EQUAL(output, test_data, sizeof(test_data));
            EXPECT_EQUAL(ctx->recvmsg_invoked_count, 1);
        };

        /* Test: receive blocks */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            s2n_ktls_configure_connection(conn, S2N_KTLS_MODE_RECV);

            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(conn, conn, &pair));

            uint8_t output[sizeof(test_data)] = { 0 };
            int read = s2n_recv(conn, output, sizeof(output), &blocked);
            EXPECT_FAILURE_WITH_ERRNO(read, S2N_ERR_IO_BLOCKED);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
        };

        /* Test: receive indicates end-of-data */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            s2n_ktls_configure_connection(conn, S2N_KTLS_MODE_RECV);

            ssize_t ret_val = 0;
            EXPECT_OK(s2n_ktls_set_recvmsg_cb(conn, s2n_test_ktls_recvmsg_cb, &ret_val));

            uint8_t output[10] = { 0 };
            int read = s2n_recv(conn, output, sizeof(output), &blocked);
            EXPECT_FAILURE_WITH_ERRNO(read, S2N_ERR_CLOSED);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

            /* Error fatal but not blinded */
            EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_CLOSED));
            EXPECT_EQUAL(s2n_connection_get_delay(conn), 0);
        };

        /* Test: receive alert */
        {
            /* Use a specific alert -- if we just use random data, we might
             * stumble into a close_notify or user_canceled.
             */
            uint8_t alert_data[] = {
                S2N_TLS_ALERT_LEVEL_FATAL,
                S2N_TLS_ALERT_DECRYPT_ERROR,
            };
            const struct iovec alert_iovec = {
                .iov_base = alert_data,
                .iov_len = sizeof(alert_data),
            };

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            s2n_ktls_configure_connection(conn, S2N_KTLS_MODE_RECV);

            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(conn, conn, &pair));
            struct s2n_test_ktls_io_stuffer *ctx = &pair.client_in;

            size_t written = 0;
            EXPECT_OK(s2n_ktls_sendmsg(ctx, TLS_ALERT, &alert_iovec, 1, &blocked, &written));
            EXPECT_EQUAL(written, sizeof(alert_data));

            uint8_t output[10] = { 0 };
            int read = s2n_recv(conn, output, sizeof(output), &blocked);
            EXPECT_FAILURE_WITH_ERRNO(read, S2N_ERR_ALERT);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

            /* Error fatal but not blinded */
            EXPECT_TRUE(s2n_connection_check_io_status(conn, S2N_IO_CLOSED));
            EXPECT_EQUAL(s2n_connection_get_delay(conn), 0);
        };

        /* Test: receive handshake message */
        {
            DEFER_CLEANUP(struct s2n_config *reneg_config = s2n_config_new(),
                    s2n_config_ptr_free);
            EXPECT_NOT_NULL(reneg_config);

            size_t reneg_request_count = 0;
            EXPECT_SUCCESS(s2n_config_set_renegotiate_request_cb(reneg_config,
                    s2n_test_reneg_req_cb, &reneg_request_count));

            uint8_t hello_request[TLS_HANDSHAKE_HEADER_LENGTH] = { TLS_HELLO_REQUEST };
            const struct iovec hello_request_iovec = {
                .iov_base = hello_request,
                .iov_len = sizeof(hello_request),
            };

            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, reneg_config));
            s2n_ktls_configure_connection(conn, S2N_KTLS_MODE_RECV);
            conn->secure_renegotiation = true;

            DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair pair = { 0 },
                    s2n_ktls_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_ktls_io_stuffer(conn, conn, &pair));
            struct s2n_test_ktls_io_stuffer *ctx = &pair.client_in;

            size_t written = 0;

            /* Send the handshake message */
            EXPECT_OK(s2n_ktls_sendmsg(ctx, TLS_HANDSHAKE,
                    &hello_request_iovec, 1, &blocked, &written));
            EXPECT_EQUAL(written, sizeof(hello_request));

            /* Also send some application data */
            EXPECT_OK(s2n_ktls_sendmsg(ctx, TLS_APPLICATION_DATA,
                    &test_iovec, 1, &blocked, &written));
            EXPECT_EQUAL(written, sizeof(test_data));

            /* Verify that we received the application data */
            uint8_t output[sizeof(test_data)] = { 0 };
            int read = s2n_recv(conn, output, sizeof(output), &blocked);
            EXPECT_EQUAL(read, sizeof(test_data));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_BYTEARRAY_EQUAL(output, test_data, read);

            /* Verify that we received and processed the handshake message */
            EXPECT_EQUAL(reneg_request_count, 1);
        };

        /* Test: Multirecord mode */
        {
            DEFER_CLEANUP(struct s2n_config *multi_config = s2n_config_new(),
                    s2n_config_ptr_free);
            EXPECT_NOT_NULL(multi_config);
            EXPECT_SUCCESS(s2n_config_set_recv_multi_record(multi_config, true));

            /* Test: receive all requested application data */
            {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(conn);
                EXPECT_SUCCESS(s2n_connection_set_config(conn, multi_config));
                s2n_ktls_configure_connection(conn, S2N_KTLS_MODE_RECV);

                DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair pair = { 0 },
                        s2n_ktls_io_stuffer_pair_free);
                EXPECT_OK(s2n_test_init_ktls_io_stuffer(conn, conn, &pair));
                struct s2n_test_ktls_io_stuffer *ctx = &pair.client_in;

                /* Write a lot of very small records */
                struct iovec offset_iovec = { 0 };
                for (size_t offset = 0; offset < sizeof(test_data); offset++) {
                    offset_iovec.iov_base = test_data + offset;
                    offset_iovec.iov_len = 1;

                    size_t written = 0;
                    EXPECT_OK(s2n_ktls_sendmsg(ctx, TLS_APPLICATION_DATA,
                            &offset_iovec, 1, &blocked, &written));
                    EXPECT_EQUAL(written, 1);
                }

                /* Receive all the data from the many small records */
                uint8_t output[sizeof(test_data)] = { 0 };
                int read = s2n_recv(conn, output, sizeof(output), &blocked);
                EXPECT_EQUAL(read, sizeof(test_data));
                EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
                EXPECT_BYTEARRAY_EQUAL(output, test_data, sizeof(test_data));
            };

            /* Test: receive partial application data */
            {
                DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                EXPECT_NOT_NULL(conn);
                EXPECT_SUCCESS(s2n_connection_set_config(conn, multi_config));
                s2n_ktls_configure_connection(conn, S2N_KTLS_MODE_RECV);

                DEFER_CLEANUP(struct s2n_test_ktls_io_stuffer_pair pair = { 0 },
                        s2n_ktls_io_stuffer_pair_free);
                EXPECT_OK(s2n_test_init_ktls_io_stuffer(conn, conn, &pair));
                struct s2n_test_ktls_io_stuffer *ctx = &pair.client_in;

                /* Write a lot of very small records, but don't write the full
                 * expected test data size. */
                const size_t partial_size = sizeof(test_data) / 2;
                struct iovec offset_iovec = { 0 };
                for (size_t offset = 0; offset < partial_size; offset++) {
                    offset_iovec.iov_base = test_data + offset;
                    offset_iovec.iov_len = 1;

                    size_t written = 0;
                    EXPECT_OK(s2n_ktls_sendmsg(ctx, TLS_APPLICATION_DATA,
                            &offset_iovec, 1, &blocked, &written));
                    EXPECT_EQUAL(written, 1);
                }

                /* Receive the partial data */
                uint8_t output[sizeof(test_data)] = { 0 };
                int read = s2n_recv(conn, output, sizeof(output), &blocked);
                EXPECT_EQUAL(read, partial_size);
                EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
                EXPECT_BYTEARRAY_EQUAL(output, test_data, partial_size);
            };
        };
    };

    END_TEST();
}
