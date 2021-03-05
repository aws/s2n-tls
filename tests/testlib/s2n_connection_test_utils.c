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

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "tls/s2n_connection.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_socket.h"
#include "testlib/s2n_testlib.h"


int s2n_fd_set_blocking(int fd) {
    return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
}

int s2n_fd_set_non_blocking(int fd) {
    return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

static int buffer_read(void *io_context, uint8_t *buf, uint32_t len)
{
    struct s2n_stuffer *in_buf;
    int n_read, n_avail;


    if (buf == NULL) {
        return 0;
    }

    in_buf = (struct s2n_stuffer *) io_context;
    if (in_buf == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* read the number of bytes requested or less if it isn't available */
    n_avail = s2n_stuffer_data_available(in_buf);
    n_read = (len < n_avail) ? len : n_avail;

    if (n_read == 0) {
        errno = EAGAIN;
        return -1;
    }

    s2n_stuffer_read_bytes(in_buf, buf, n_read);
    return n_read;
}

static int buffer_write(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_stuffer *out;

    if (buf == NULL) {
        return 0;
    }

    out = (struct s2n_stuffer *) io_context;
    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (s2n_stuffer_write_bytes(out, buf, len) < 0) {
        errno = EAGAIN;
        return -1;
    }

    return len;
}

/* The connection will read/write to/from a stuffer, instead of sockets */
int s2n_connection_set_io_stuffers(struct s2n_stuffer *input, struct s2n_stuffer *output, struct s2n_connection *conn)
{
    /* Set Up Callbacks*/
    POSIX_GUARD(s2n_connection_set_recv_cb(conn, &buffer_read));
    POSIX_GUARD(s2n_connection_set_send_cb(conn, &buffer_write));

    /* Set up Callback Contexts to use stuffers */
    POSIX_GUARD(s2n_connection_set_recv_ctx(conn, input));
    POSIX_GUARD(s2n_connection_set_send_ctx(conn, output));

    return 0;
}

int s2n_io_pair_init(struct s2n_test_io_pair *io_pair)
{
    signal(SIGPIPE, SIG_IGN);

    int socket_pair[2];

    POSIX_GUARD(socketpair(AF_UNIX, SOCK_STREAM, 0, socket_pair));

    io_pair->client = socket_pair[0];
    io_pair->server = socket_pair[1];

    return 0;
}

int s2n_io_pair_init_non_blocking(struct s2n_test_io_pair *io_pair)
{
    POSIX_GUARD(s2n_io_pair_init(io_pair));

    POSIX_GUARD(s2n_fd_set_non_blocking(io_pair->client));
    POSIX_GUARD(s2n_fd_set_non_blocking(io_pair->server));

    return 0;
}

int s2n_connection_set_io_pair(struct s2n_connection *conn, struct s2n_test_io_pair *io_pair)
{
    if (conn->mode == S2N_CLIENT) {
        POSIX_GUARD(s2n_connection_set_fd(conn, io_pair->client));
    } else if (conn->mode == S2N_SERVER) {
        POSIX_GUARD(s2n_connection_set_fd(conn, io_pair->server));
    }

    return 0;
}

int s2n_connections_set_io_pair(struct s2n_connection *client, struct s2n_connection *server,
                                struct s2n_test_io_pair *io_pair)
{
    POSIX_GUARD(s2n_connection_set_io_pair(client, io_pair));
    POSIX_GUARD(s2n_connection_set_io_pair(server, io_pair));
    return 0;
}

int s2n_io_pair_close(struct s2n_test_io_pair *io_pair)
{
    POSIX_GUARD(s2n_io_pair_close_one_end(io_pair, S2N_CLIENT));
    POSIX_GUARD(s2n_io_pair_close_one_end(io_pair, S2N_SERVER));
    return 0;
}

int s2n_io_pair_close_one_end(struct s2n_test_io_pair *io_pair, int mode_to_close)
{
    if (mode_to_close == S2N_CLIENT) {
        POSIX_GUARD(close(io_pair->client));
    } else if(mode_to_close == S2N_SERVER) {
        POSIX_GUARD(close(io_pair->server));
    }
    return 0;
}

int s2n_io_pair_shutdown_one_end(struct s2n_test_io_pair *io_pair, int mode_to_close, int how)
{
    if (mode_to_close == S2N_CLIENT) {
        POSIX_GUARD(shutdown(io_pair->client, how));
    } else if(mode_to_close == S2N_SERVER) {
        POSIX_GUARD(shutdown(io_pair->server, how));
    }
    return 0;
}

void s2n_print_connection(struct s2n_connection *conn, const char *marker)
{
    int i;

    printf("marker: %s\n", marker);
    printf("HEADER IN Stuffer (write: %d, read: %d, size: %d)\n", conn->header_in.write_cursor, conn->header_in.read_cursor, conn->header_in.blob.size);
    for (i = 0; i < conn->header_in.blob.size; i++) {
        printf("%02x", conn->header_in.blob.data[i]);
        if ((i + 1) % 8 == 0) {
            printf(" ");
        }
        if ((i + 1) % 40 == 0) {
            printf("\n");
        }
    }
    printf("\n");
 
    printf("IN Stuffer (write: %d, read: %d, size: %d)\n", conn->in.write_cursor, conn->in.read_cursor, conn->in.blob.size);
    for (i = 0; i < conn->in.write_cursor; i++) {
        printf("%02x", conn->in.blob.data[i]);
        if ((i + 1) % 8 == 0) {
            printf(" ");
        }
        if ((i + 1) % 40 == 0) {
            printf("\n");
        }
    }
    printf("\n");

    printf("OUT Stuffer (write: %d, read: %d, size: %d)\n", conn->out.write_cursor, conn->out.read_cursor, conn->out.blob.size);
    for (i = 0; i < conn->out.write_cursor; i++) {
        printf("%02x", conn->out.blob.data[i]);
        if ((i + 1) % 8 == 0) {
            printf(" ");
        }
        if ((i + 1) % 40 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

int s2n_set_connection_hello_retry_flags(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);

    conn->handshake.message_number = 1;
    conn->handshake.handshake_type = NEGOTIATED | HELLO_RETRY_REQUEST | FULL_HANDSHAKE;

    return S2N_SUCCESS;
}

int s2n_connection_set_all_protocol_versions(struct s2n_connection *conn, uint8_t version)
{
    POSIX_ENSURE_REF(conn);

    conn->server_protocol_version = version;
    conn->client_protocol_version = version;
    conn->actual_protocol_version = version;

    return S2N_SUCCESS;
}
