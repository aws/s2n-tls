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
#include <sys/socket.h>

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_ktls.h"
#include "utils/s2n_random.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

#ifdef S2N_LINUX_SENDFILE
    const bool sendfile_supported = true;
#else
    const bool sendfile_supported = false;
#endif

    /* Test feature probe */
    {
#if defined(__linux__)
        EXPECT_TRUE(sendfile_supported);
#endif
#if defined(__FreeBSD__)
        EXPECT_FALSE(sendfile_supported);
#endif
    };

    /* Safety */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        size_t bytes_written = 0;

        EXPECT_FAILURE_WITH_ERRNO(
                s2n_sendfile(NULL, 0, 0, 0, &bytes_written, &blocked),
                S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_sendfile(conn, 0, 0, 0, NULL, &blocked),
                S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_sendfile(conn, 0, 0, 0, &bytes_written, NULL),
                S2N_ERR_NULL);
    };

    /* Test s2n_sendfile unsupported */
    if (!sendfile_supported) {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        conn->ktls_send_enabled = true;

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(conn, &io_pair));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        size_t bytes_written = 0;
        int result = s2n_sendfile(conn, 1, 0, 1, &bytes_written, &blocked);
        EXPECT_FAILURE_WITH_ERRNO(result, S2N_ERR_UNIMPLEMENTED);

        /* We do not run any further tests */
        END_TEST();
    };

    /* The one file we know definitely exists is our own executable */
    int ro_file = open(argv[0], O_RDONLY);
    EXPECT_TRUE(ro_file > 0);

    /* use pread to read the beginning of the file without updating its offset.
     * Careful: if any call to sendfile sets offset=NULL, the file's offset will
     * be updated and different data will be read.
     */
    uint8_t test_data[100] = { 0 };
    EXPECT_EQUAL(pread(ro_file, test_data, sizeof(test_data), 0), sizeof(test_data));

    /* Test: successful send */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        conn->ktls_send_enabled = true;

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        int write_fd = io_pair.server;
        int read_fd = io_pair.client;
        EXPECT_SUCCESS(s2n_connection_set_write_fd(conn, write_fd));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        size_t bytes_written = 0;
        EXPECT_SUCCESS(s2n_sendfile(conn, ro_file, 0, sizeof(test_data),
                &bytes_written, &blocked));
        EXPECT_EQUAL(bytes_written, sizeof(test_data));
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

        uint8_t written[sizeof(test_data)] = { 0 };
        EXPECT_EQUAL(read(read_fd, written, sizeof(written)), sizeof(test_data));
        EXPECT_BYTEARRAY_EQUAL(written, test_data, sizeof(test_data));
        EXPECT_TRUE(read(read_fd, written, sizeof(written)) < 0);
    };

    /* Test: IO error */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        conn->ktls_send_enabled = true;

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        int write_fd = io_pair.server;
        int read_fd = io_pair.client;
        EXPECT_SUCCESS(s2n_connection_set_write_fd(conn, write_fd));

        /* Close one side of the stream to make the fds invalid */
        close(read_fd);

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        size_t bytes_written = 0;
        int ret = s2n_sendfile(conn, ro_file, 0, sizeof(test_data),
                &bytes_written, &blocked);
        EXPECT_FAILURE_WITH_ERRNO(ret, S2N_ERR_IO);
        EXPECT_EQUAL(bytes_written, 0);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
    };

    /* Test: send blocks */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        conn->ktls_send_enabled = true;

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        int write_fd = io_pair.server;
        EXPECT_SUCCESS(s2n_connection_set_write_fd(conn, write_fd));

        /* We can force the socket to block by filling up its send buffer. */
        int buffer_size = 0;
        socklen_t optlen = sizeof(buffer_size);
        EXPECT_EQUAL(getsockopt(write_fd, SOL_SOCKET, SO_SNDBUF, &buffer_size, &optlen), 0);
        EXPECT_TRUE(buffer_size > 0);

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        size_t bytes_written = 0;
        size_t total_bytes_written = 0;
        while (true) {
            int result = s2n_sendfile(conn, ro_file, 0, sizeof(test_data),
                    &bytes_written, &blocked);
            if (result < 0) {
                EXPECT_FAILURE_WITH_ERRNO(result, S2N_ERR_IO_BLOCKED);
                EXPECT_EQUAL(bytes_written, 0);
                EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_WRITE);
                break;
            }

            EXPECT_TRUE(bytes_written <= sizeof(test_data));
            EXPECT_TRUE(bytes_written > 0);
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
            total_bytes_written += bytes_written;

            /* The socket will block before buffer_size bytes are written.
             * If we successfully send buffer_size bytes, something is wrong.
             */
            EXPECT_TRUE(total_bytes_written < buffer_size);
        }
    };

    /* Test: partial write */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        conn->ktls_send_enabled = true;

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        int write_fd = io_pair.server;
        EXPECT_SUCCESS(s2n_connection_set_write_fd(conn, write_fd));

        int buffer_size = 0;
        socklen_t optlen = sizeof(buffer_size);
        EXPECT_EQUAL(getsockopt(write_fd, SOL_SOCKET, SO_SNDBUF, &buffer_size, &optlen), 0);
        EXPECT_TRUE(buffer_size > 0);

        /* Try to write more data than the buffer can hold in a single sendfile call */
        size_t bytes_to_write = buffer_size * 2;
        size_t bytes_written = 0;
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_SUCCESS(s2n_sendfile(conn, ro_file, 0, bytes_to_write,
                &bytes_written, &blocked));
        EXPECT_TRUE(bytes_written > 0);
        EXPECT_TRUE(bytes_written < bytes_to_write);
        EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);
    };

    EXPECT_EQUAL(close(ro_file), 0);
    END_TEST();
}
