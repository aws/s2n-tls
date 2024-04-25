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
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_socket.h"

int s2n_fd_set_blocking(int fd)
{
    return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
}

int s2n_fd_set_non_blocking(int fd)
{
    return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
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
    } else if (mode_to_close == S2N_SERVER) {
        POSIX_GUARD(close(io_pair->server));
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
    RESULT_GUARD_POSIX(cipher->init(&conn->secure->client_key));
    RESULT_GUARD_POSIX(cipher->set_encryption_key(&conn->secure->client_key, &client_key));

    uint8_t server_key_bytes[S2N_TLS13_SECRET_MAX_LEN] = "server key";
    struct s2n_blob server_key = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&server_key, server_key_bytes, cipher->key_material_size));
    RESULT_GUARD_POSIX(cipher->init(&conn->secure->server_key));
    RESULT_GUARD_POSIX(cipher->set_encryption_key(&conn->secure->server_key, &server_key));

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
