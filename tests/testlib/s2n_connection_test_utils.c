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
#include <stdio.h>
#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/socket.h>
    #include <unistd.h>
#endif
#include <sys/types.h>

#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "utils/s2n_safety.h"
#ifndef _WIN32
    #include "utils/s2n_socket.h"
#endif

int s2n_fd_set_blocking(int fd)
{
#ifdef _WIN32
    u_long mode = 0;
    return ioctlsocket(fd, FIONBIO, &mode);
#else
    return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
#endif
}

int s2n_fd_set_non_blocking(int fd)
{
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode);
#else
    return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
#endif
}

static int buffer_read(void *io_context, uint8_t *buf, uint32_t len)
{
    struct s2n_stuffer *in_buf = NULL;
    int n_read = 0, n_avail = 0;
    errno = EIO;

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

    POSIX_GUARD(s2n_stuffer_read_bytes(in_buf, buf, n_read));
    return n_read;
}

static int buffer_write(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_stuffer *out = NULL;

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
    POSIX_GUARD(s2n_connection_set_recv_io_stuffer(input, conn));
    POSIX_GUARD(s2n_connection_set_send_io_stuffer(output, conn));

    return S2N_SUCCESS;
}

int s2n_connection_set_recv_io_stuffer(struct s2n_stuffer *input, struct s2n_connection *conn)
{
    POSIX_GUARD(s2n_connection_set_recv_cb(conn, &buffer_read));
    POSIX_GUARD(s2n_connection_set_recv_ctx(conn, input));

    return S2N_SUCCESS;
}

int s2n_connection_set_send_io_stuffer(struct s2n_stuffer *output, struct s2n_connection *conn)
{
    POSIX_GUARD(s2n_connection_set_send_cb(conn, &buffer_write));
    POSIX_GUARD(s2n_connection_set_send_ctx(conn, output));

    return S2N_SUCCESS;
}

S2N_RESULT s2n_io_stuffer_pair_init(struct s2n_test_io_stuffer_pair *io_pair)
{
    RESULT_ENSURE_REF(io_pair);
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(&io_pair->client_in, 0));
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(&io_pair->server_in, 0));
    return S2N_RESULT_OK;
}

S2N_CLEANUP_RESULT s2n_io_stuffer_pair_free(struct s2n_test_io_stuffer_pair *io_pair)
{
    RESULT_ENSURE_REF(io_pair);
    RESULT_GUARD_POSIX(s2n_stuffer_free(&io_pair->client_in));
    RESULT_GUARD_POSIX(s2n_stuffer_free(&io_pair->server_in));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_connections_set_io_stuffer_pair(struct s2n_connection *client, struct s2n_connection *server,
        struct s2n_test_io_stuffer_pair *io_pair)
{
    RESULT_ENSURE_REF(io_pair);
    RESULT_GUARD_POSIX(s2n_connection_set_io_stuffers(&io_pair->client_in, &io_pair->server_in, client));
    RESULT_GUARD_POSIX(s2n_connection_set_io_stuffers(&io_pair->server_in, &io_pair->client_in, server));
    return S2N_RESULT_OK;
}

int s2n_io_pair_init(struct s2n_test_io_pair *io_pair)
{
#ifdef _WIN32
    /* Winsock requires initialization before any socket call. */
    WSADATA wsa_data = { 0 };
    int wsa_rc = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    POSIX_ENSURE(wsa_rc == 0, S2N_ERR_IO);

    /* Windows doesn't have socketpair. Emulate with TCP loopback. */
    int listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    POSIX_ENSURE(listener >= 0, S2N_ERR_IO);

    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    POSIX_ENSURE(bind(listener, (struct sockaddr *) &addr, sizeof(addr)) == 0, S2N_ERR_IO);
    POSIX_ENSURE(listen(listener, 1) == 0, S2N_ERR_IO);

    int addrlen = sizeof(addr);
    POSIX_ENSURE(getsockname(listener, (struct sockaddr *) &addr, &addrlen) == 0, S2N_ERR_IO);

    io_pair->client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    POSIX_ENSURE(io_pair->client >= 0, S2N_ERR_IO);
    POSIX_ENSURE(connect(io_pair->client, (struct sockaddr *) &addr, sizeof(addr)) == 0, S2N_ERR_IO);

    io_pair->server = accept(listener, NULL, NULL);
    POSIX_ENSURE(io_pair->server >= 0, S2N_ERR_IO);

    closesocket(listener);
#else
    signal(SIGPIPE, SIG_IGN);

    int socket_pair[2];

    POSIX_GUARD(socketpair(AF_UNIX, SOCK_STREAM, 0, socket_pair));

    io_pair->client = socket_pair[0];
    io_pair->server = socket_pair[1];
#endif

    return 0;
}

int s2n_io_pair_init_non_blocking(struct s2n_test_io_pair *io_pair)
{
    POSIX_GUARD(s2n_io_pair_init(io_pair));

    POSIX_GUARD(s2n_fd_set_non_blocking(io_pair->client));
    POSIX_GUARD(s2n_fd_set_non_blocking(io_pair->server));

    return 0;
}

#ifdef _WIN32
/* On Windows, the s2n library does not provide built-in socket I/O.
 * Tests use these custom I/O callbacks that wrap Winsock recv/send.
 * The socket fd is passed directly as the io_context pointer via uintptr_t cast.
 */
static int s2n_test_recv_cb(void *io_context, uint8_t *buf, uint32_t len)
{
    int fd = (int) (uintptr_t) io_context;

    int result = recv(fd, (char *) buf, len, 0);
    if (result < 0) {
        int wsa_err = WSAGetLastError();
        if (wsa_err == WSAEWOULDBLOCK) {
            errno = EAGAIN;
        } else {
            errno = EIO;
        }
    }
    return result;
}

static int s2n_test_send_cb(void *io_context, const uint8_t *buf, uint32_t len)
{
    int fd = (int) (uintptr_t) io_context;

    int result = send(fd, (const char *) buf, len, 0);
    if (result < 0) {
        int wsa_err = WSAGetLastError();
        if (wsa_err == WSAEWOULDBLOCK) {
            errno = EAGAIN;
        } else {
            errno = EIO;
        }
    }
    return result;
}
#endif

int s2n_connection_set_io_pair(struct s2n_connection *conn, struct s2n_test_io_pair *io_pair)
{
    int fd = 0;
    if (conn->mode == S2N_CLIENT) {
        fd = io_pair->client;
    } else if (conn->mode == S2N_SERVER) {
        fd = io_pair->server;
    } else {
        POSIX_BAIL(S2N_ERR_INVALID_STATE);
    }

#ifdef _WIN32
    POSIX_GUARD(s2n_connection_set_recv_cb(conn, s2n_test_recv_cb));
    POSIX_GUARD(s2n_connection_set_send_cb(conn, s2n_test_send_cb));
    POSIX_GUARD(s2n_connection_set_recv_ctx(conn, (void *) (uintptr_t) fd));
    POSIX_GUARD(s2n_connection_set_send_ctx(conn, (void *) (uintptr_t) fd));
#else
    POSIX_GUARD(s2n_connection_set_fd(conn, fd));
#endif

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
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}

int s2n_io_pair_close_one_end(struct s2n_test_io_pair *io_pair, int mode_to_close)
{
    if (mode_to_close == S2N_CLIENT && io_pair->client != S2N_CLOSED_FD) {
#ifdef _WIN32
        POSIX_GUARD(closesocket(io_pair->client));
#else
        POSIX_GUARD(close(io_pair->client));
#endif
        io_pair->client = S2N_CLOSED_FD;
    } else if (mode_to_close == S2N_SERVER && io_pair->server != S2N_CLOSED_FD) {
#ifdef _WIN32
        POSIX_GUARD(closesocket(io_pair->server));
#else
        POSIX_GUARD(close(io_pair->server));
#endif
        io_pair->server = S2N_CLOSED_FD;
    }
    return 0;
}

int s2n_io_pair_shutdown_one_end(struct s2n_test_io_pair *io_pair, int mode_to_close, int how)
{
    if (mode_to_close == S2N_CLIENT) {
        POSIX_GUARD(shutdown(io_pair->client, how));
    } else if (mode_to_close == S2N_SERVER) {
        POSIX_GUARD(shutdown(io_pair->server, how));
    }
    return 0;
}

void s2n_print_connection(struct s2n_connection *conn, const char *marker)
{
    size_t i = 0;

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

static int mock_time(void *data, uint64_t *nanoseconds)
{
    POSIX_ENSURE_REF(data);
    POSIX_ENSURE_REF(nanoseconds);
    *nanoseconds = *((uint64_t *) data);
    return S2N_SUCCESS;
}

S2N_RESULT s2n_config_mock_wall_clock(struct s2n_config *config, uint64_t *test_time_in_ns)
{
    RESULT_ENSURE_REF(config);
    RESULT_GUARD_POSIX(s2n_config_set_wall_clock(config, mock_time, test_time_in_ns));
    return S2N_RESULT_OK;
}

/* Sets the encryption and decryption keys to enable sending and receiving encrypted data.
 * Basically, it bypasses the usual key exchange -> shared secret -> derive keys process
 * and just uses static mock keys.
 */
S2N_RESULT s2n_connection_set_secrets(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);
    conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
    const struct s2n_cipher *cipher = conn->secure->cipher_suite->record_alg->cipher;

    uint8_t client_key_bytes[S2N_TLS13_SECRET_MAX_LEN] = "client key";
    struct s2n_blob client_key = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&client_key, client_key_bytes, cipher->key_material_size));
    RESULT_GUARD(cipher->init(&conn->secure->client_key));
    RESULT_GUARD(cipher->set_encryption_key(&conn->secure->client_key, &client_key));

    uint8_t server_key_bytes[S2N_TLS13_SECRET_MAX_LEN] = "server key";
    struct s2n_blob server_key = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&server_key, server_key_bytes, cipher->key_material_size));
    RESULT_GUARD(cipher->init(&conn->secure->server_key));
    RESULT_GUARD(cipher->set_encryption_key(&conn->secure->server_key, &server_key));

    conn->client = conn->secure;
    conn->server = conn->secure;

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_set_all_mutually_supported_groups(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);

    const struct s2n_ecc_preferences *ecc_pref = NULL;
    RESULT_GUARD_POSIX(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
    RESULT_ENSURE_REF(ecc_pref);

    for (size_t i = 0; i < ecc_pref->count; i++) {
        conn->kex_params.mutually_supported_curves[i] = ecc_pref->ecc_curves[i];
    }

    const struct s2n_kem_preferences *kem_pref = NULL;
    RESULT_GUARD_POSIX(s2n_connection_get_kem_preferences(conn, &kem_pref));
    RESULT_ENSURE_REF(kem_pref);

    for (size_t i = 0; i < kem_pref->tls13_kem_group_count; i++) {
        conn->kex_params.mutually_supported_kem_groups[i] = kem_pref->tls13_kem_groups[i];
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_skip_handshake(struct s2n_connection *conn)
{
    conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE;
    while (!s2n_handshake_is_complete(conn)) {
        conn->handshake.message_number++;
    }
    return S2N_RESULT_OK;
}
