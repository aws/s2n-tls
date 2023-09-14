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

#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_ktls.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_random.h"

/* There are issues with MacOS and FreeBSD so we define the constant ourselves.
 * https://stackoverflow.com/a/34042435 */
#define S2N_TEST_INADDR_LOOPBACK 0x7f000001 /* 127.0.0.1 */

/* Unlike our other self-talk tests, this test cannot use AF_UNIX / AF_LOCAL.
 * For a real self-talk test we need real kernel support for kTLS, and only
 * AF_INET sockets support kTLS.
 */
static S2N_RESULT s2n_new_inet_socket_pair(struct s2n_test_io_pair *io_pair)
{
    RESULT_ENSURE_REF(io_pair);

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    RESULT_ENSURE_GT(listener, 0);

    struct sockaddr_in saddr = { 0 };
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(S2N_TEST_INADDR_LOOPBACK);
    saddr.sin_port = 0;

    socklen_t addrlen = sizeof(saddr);
    RESULT_ENSURE_EQ(bind(listener, (struct sockaddr *) &saddr, addrlen), 0);
    RESULT_ENSURE_EQ(getsockname(listener, (struct sockaddr *) &saddr, &addrlen), 0);
    RESULT_ENSURE_EQ(listen(listener, 1), 0);

    io_pair->client = socket(AF_INET, SOCK_STREAM, 0);
    RESULT_ENSURE_GT(io_pair->client, 0);

    fflush(stdout);
    pid_t pid = fork();
    RESULT_ENSURE_GTE(pid, 0);
    if (pid == 0) {
        RESULT_ENSURE_EQ(connect(io_pair->client, (struct sockaddr *) &saddr, addrlen), 0);
        ZERO_TO_DISABLE_DEFER_CLEANUP(io_pair);
        exit(0);
    }
    io_pair->server = accept(listener, NULL, NULL);
    RESULT_ENSURE_GT(io_pair->server, 0);
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* ktls is complicated to enable. We should ensure that it's actually enabled
     * where we think we're testing it.
     */
    bool ktls_expected = (getenv("S2N_KTLS_TESTING_EXPECTED") != NULL);

    if (!s2n_ktls_is_supported_on_platform() && !ktls_expected) {
        END_TEST();
    }

    const s2n_mode modes[] = { S2N_CLIENT, S2N_SERVER };

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    uint8_t test_data[100] = { 0 };
    struct s2n_blob test_data_blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&test_data_blob, test_data, sizeof(test_data)));
    EXPECT_OK(s2n_get_public_random_data(&test_data_blob));

    DEFER_CLEANUP(struct s2n_test_iovecs test_iovecs = { 0 }, s2n_test_iovecs_free);
    size_t test_iovecs_lens[20] = { 5, 6, 1, 10, 0 };
    EXPECT_OK(s2n_test_new_iovecs(&test_iovecs, &test_data_blob, test_iovecs_lens,
            s2n_array_len(test_iovecs_lens)));

    const size_t test_offsets[] = {
        0,
        test_iovecs_lens[0],
        test_iovecs_lens[0] + 1,
        test_iovecs_lens[0] + test_iovecs_lens[1],
        sizeof(test_data) - 1,
        sizeof(test_data),
    };

    uint8_t file_test_data[100] = { 0 };
    int file = open(argv[0], O_RDONLY);
    EXPECT_TRUE(file > 0);
    int file_read = pread(file, file_test_data, sizeof(file_test_data), 0);
    EXPECT_EQUAL(file_read, sizeof(file_test_data));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));

    /* Even if we detected ktls support at compile time, enabling ktls
     * can fail at runtime if the system is not properly configured.
     */
    bool ktls_send_supported = true;
    bool ktls_recv_supported = true;

    /* Test enabling ktls for sending */
    {
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        if (s2n_result_is_error(s2n_new_inet_socket_pair(&io_pair))) {
            /* We should be able to setup AF_INET sockets everywhere, but if
             * we can't, don't block the build unless the build explicitly expects
             * to be able to test ktls.
             */
            EXPECT_FALSE(ktls_expected);
            END_TEST();
        }
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

        /* The test negotiate method assumes non-blocking sockets */
        EXPECT_SUCCESS(s2n_fd_set_non_blocking(io_pair.server));
        EXPECT_SUCCESS(s2n_fd_set_non_blocking(io_pair.client));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        if (s2n_connection_ktls_enable_send(client) == S2N_SUCCESS) {
            EXPECT_SUCCESS(s2n_connection_ktls_enable_send(server));
        } else {
            EXPECT_FALSE(ktls_expected);
            ktls_send_supported = false;
        }

        if (s2n_connection_ktls_enable_recv(client) == S2N_SUCCESS) {
            EXPECT_SUCCESS(s2n_connection_ktls_enable_recv(server));
        } else {
            EXPECT_FALSE(ktls_expected);
            ktls_recv_supported = false;
        }
    };

    /* Test sending with ktls */
    for (size_t mode_i = 0; mode_i < s2n_array_len(modes); mode_i++) {
        if (!ktls_send_supported) {
            break;
        }

        const s2n_mode mode = modes[mode_i];

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_OK(s2n_new_inet_socket_pair(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

        /* The test negotiate method assumes non-blocking sockets */
        EXPECT_SUCCESS(s2n_fd_set_non_blocking(io_pair.server));
        EXPECT_SUCCESS(s2n_fd_set_non_blocking(io_pair.client));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        struct s2n_connection *conns[] = {
            [S2N_CLIENT] = client,
            [S2N_SERVER] = server,
        };
        struct s2n_connection *writer = conns[mode];
        struct s2n_connection *reader = conns[S2N_PEER_MODE(mode)];
        EXPECT_SUCCESS(s2n_connection_ktls_enable_send(writer));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;

        /* Our IO methods are more predictable if they use blocking sockets. */
        EXPECT_SUCCESS(s2n_fd_set_blocking(io_pair.server));
        EXPECT_SUCCESS(s2n_fd_set_blocking(io_pair.client));

        /* Test: s2n_send */
        for (size_t i = 0; i < 5; i++) {
            int written = s2n_send(writer, test_data, sizeof(test_data), &blocked);
            EXPECT_EQUAL(written, sizeof(test_data));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            uint8_t buffer[sizeof(test_data)] = { 0 };
            int read = s2n_recv(reader, buffer, sizeof(buffer), &blocked);
            EXPECT_EQUAL(read, sizeof(test_data));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            EXPECT_BYTEARRAY_EQUAL(test_data, buffer, read);
        }

        /* Test: s2n_sendv */
        for (size_t i = 0; i < 5; i++) {
            int written = s2n_sendv(writer,
                    test_iovecs.iovecs, test_iovecs.iovecs_count, &blocked);
            EXPECT_EQUAL(written, sizeof(test_data));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            uint8_t buffer[sizeof(test_data)] = { 0 };
            int read = s2n_recv(reader, buffer, sizeof(buffer), &blocked);
            EXPECT_EQUAL(read, sizeof(test_data));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            EXPECT_BYTEARRAY_EQUAL(test_data, buffer, read);
        }

        /* Test: s2n_sendv_with_offset */
        for (size_t offset_i = 0; offset_i < s2n_array_len(test_offsets); offset_i++) {
            const size_t offset = test_offsets[offset_i];
            const size_t expected_written = sizeof(test_data) - offset;

            int written = s2n_sendv_with_offset(writer,
                    test_iovecs.iovecs, test_iovecs.iovecs_count, offset, &blocked);
            EXPECT_EQUAL(written, expected_written);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            uint8_t buffer[sizeof(test_data)] = { 0 };
            int read = s2n_recv(reader, buffer, expected_written, &blocked);
            EXPECT_EQUAL(read, expected_written);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            EXPECT_BYTEARRAY_EQUAL(test_data + offset, buffer, read);
        };

        /* Test: s2n_sendfile */
        for (size_t offset_i = 0; offset_i < s2n_array_len(test_offsets); offset_i++) {
            const size_t offset = test_offsets[offset_i];
            const size_t expected_written = sizeof(test_data) - offset;

            size_t written = 0;
            EXPECT_SUCCESS(s2n_sendfile(writer, file, offset, expected_written,
                    &written, &blocked));
            EXPECT_EQUAL(written, expected_written);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            uint8_t buffer[sizeof(file_test_data)] = { 0 };
            int read = s2n_recv(reader, buffer, expected_written, &blocked);
            EXPECT_EQUAL(read, expected_written);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            EXPECT_BYTEARRAY_EQUAL(file_test_data + offset, buffer, read);
        }

        /* Test: s2n_shutdown */
        {
            EXPECT_SUCCESS(s2n_shutdown_send(writer, &blocked));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            EXPECT_SUCCESS(s2n_shutdown(reader, &blocked));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_TRUE(s2n_connection_check_io_status(reader, S2N_IO_CLOSED));
        };
    };

    /* Test receiving with ktls */
    for (size_t mode_i = 0; mode_i < s2n_array_len(modes); mode_i++) {
        if (!ktls_recv_supported) {
            break;
        }

        const s2n_mode mode = modes[mode_i];

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_OK(s2n_new_inet_socket_pair(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

        /* The test negotiate method assumes non-blocking sockets */
        EXPECT_SUCCESS(s2n_fd_set_non_blocking(io_pair.server));
        EXPECT_SUCCESS(s2n_fd_set_non_blocking(io_pair.client));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        struct s2n_connection *conns[] = {
            [S2N_CLIENT] = client,
            [S2N_SERVER] = server,
        };
        struct s2n_connection *reader = conns[mode];
        struct s2n_connection *writer = conns[S2N_PEER_MODE(mode)];
        EXPECT_SUCCESS(s2n_connection_ktls_enable_recv(reader));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;

        /* Our IO methods are more predictable if they use blocking sockets. */
        EXPECT_SUCCESS(s2n_fd_set_blocking(io_pair.server));
        EXPECT_SUCCESS(s2n_fd_set_blocking(io_pair.client));

        /* Test: s2n_recv not implemented yet */
        {
            uint8_t buffer[10] = { 0 };
            int received = s2n_recv(reader, buffer, sizeof(buffer), &blocked);
            EXPECT_FAILURE_WITH_ERRNO(received, S2N_ERR_UNIMPLEMENTED);
        }

        /* Test: s2n_shutdown */
        {
            /* Send some application data for the reader to skip */
            for (size_t i = 0; i < 3; i++) {
                EXPECT_SUCCESS(s2n_send(writer, test_data, 10, &blocked));
            }

            /* Send the close_notify */
            EXPECT_SUCCESS(s2n_shutdown_send(writer, &blocked));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            /* Verify that the reader skips the application data and successfully
             * receives the close_notify.
             *
             * The close_notify was sent after the application data, so if the
             * close_notify was received, then the application data was also received.
             */
            EXPECT_SUCCESS(s2n_shutdown(reader, &blocked));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            EXPECT_TRUE(s2n_connection_check_io_status(reader, S2N_IO_CLOSED));
        };
    };

    END_TEST();
}
