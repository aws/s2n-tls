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

/*
 * On some platforms(NixOS) SOL_TCP definition is missing.
 * https://github.com/torvalds/linux/blob/d2d11f342b179f1894a901f143ec7c008caba43e/include/linux/socket.h#L344
 */
#ifndef _GNU_SOURCE
    #define _GNU_SOURCE
#endif

#include "tls/s2n_ktls.h"

#include <linux/tls.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include "error/s2n_errno.h"
#include "tls/s2n_connection.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_safety_macros.h"
#include "utils/s2n_socket.h"

#define S2N_TLS_ULP_NAME      "tls"
#define S2N_TLS_ULP_NAME_SIZE sizeof(S2N_TLS_ULP_NAME)

S2N_RESULT s2n_ktls_validate(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(conn->config);
    RESULT_ENSURE_REF(conn->secure);
    RESULT_ENSURE_REF(conn->secure->cipher_suite);
    RESULT_ENSURE_REF(conn->secure->cipher_suite->record_alg);
    RESULT_ENSURE_REF(conn->secure->cipher_suite->record_alg->cipher);

    /* TODO support TLS 1.3
     *
     * TLS 1.3 support requires sending the KeyUpdate message when the cryptographic
     * KeyLimits are met. However, this is currently only possible by applying a
     * kernel patch to support this functionality.
     */
    RESULT_ENSURE_EQ(conn->actual_protocol_version, S2N_TLS12);

    /* Check if the cipher supports kTLS */
    RESULT_ENSURE_EQ(conn->secure->cipher_suite->record_alg->cipher->ktls_supported, true);
    /* TODO key length is a weak check. Is there a better mechanism? */
    uint8_t key_size = conn->secure->cipher_suite->record_alg->cipher->key_material_size;
    /* only AES_GCM_128 is supported at the moment */
    RESULT_ENSURE_EQ(key_size, S2N_TLS_AES_128_GCM_KEY_LEN);

    /* confirm that the application requested ktls */
    RESULT_ENSURE_EQ(conn->config->ktls_recv_requested || conn->config->ktls_send_requested, S2N_ERR_OK);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ktls_validate_socket_mode(struct s2n_connection *conn, s2n_ktls_mode ktls_mode)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE(ktls_mode == S2N_KTLS_MODE_RECV || ktls_mode == S2N_KTLS_MODE_SEND, S2N_ERR_T_INTERNAL);

    /* kTLS I/O functionality is managed by s2n-tls. kTLS cannot be enabled if the
     * application sets custom I/O (managed_send_io == false means application has
     * set custom I/O).
     *
     * - Confirm application is has not using custom I/O
     * - Confirm kTLS isn't enabled already
     */
    switch (ktls_mode) {
        case S2N_KTLS_MODE_SEND:
            RESULT_ENSURE(!conn->managed_send_io, S2N_ERR_KTLS);
            RESULT_ENSURE(!conn->ktls_send_enabled, S2N_ERR_KTLS);
            break;
        case S2N_KTLS_MODE_RECV:
            RESULT_ENSURE(!conn->managed_recv_io, S2N_ERR_KTLS);
            RESULT_ENSURE(!conn->ktls_recv_enabled, S2N_ERR_KTLS);
            break;
        case S2N_KTLS_MODE_DISABLED:
        case S2N_KTLS_MODE_DUPLEX:
            RESULT_BAIL(S2N_ERR_T_INTERNAL);
            break;
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ktls_retrieve_file_descriptor(struct s2n_connection *conn, s2n_ktls_mode ktls_mode, int *fd)
{
    RESULT_GUARD(s2n_ktls_validate_socket_mode(conn, ktls_mode));

    if (ktls_mode == S2N_KTLS_MODE_RECV) {
        /* retrieve the receive fd */
        const struct s2n_socket_read_io_context *peer_socket_ctx = conn->recv_io_context;
        *fd = peer_socket_ctx->fd;
    } else if (ktls_mode == S2N_KTLS_MODE_SEND) {
        /* retrieve the send fd */
        const struct s2n_socket_write_io_context *peer_socket_ctx = conn->send_io_context;
        *fd = peer_socket_ctx->fd;
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ktls_configure_socket(struct s2n_connection *conn, s2n_ktls_mode ktls_mode)
{
    RESULT_GUARD(s2n_ktls_validate_socket_mode(conn, ktls_mode));

    /* register the tls ULP */
    int fd;
    RESULT_GUARD(s2n_ktls_retrieve_file_descriptor(conn, ktls_mode, &fd));
    RESULT_GUARD_POSIX(setsockopt(fd, SOL_TCP, TCP_ULP, S2N_TLS_ULP_NAME, S2N_TLS_ULP_NAME_SIZE));

    /* TODO configure keys */

    return S2N_RESULT_OK;
}

/*
 * kTLS has been enabled on the socket. Errors are likely to be fatal and
 * unrecoverable.
 */
S2N_RESULT s2n_ktls_configure_connection(struct s2n_connection *conn, s2n_ktls_mode ktls_mode)
{
    RESULT_ENSURE_REF(conn);

    /* TODO mark kTLS enabled on the connection */

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ktls_enable(struct s2n_connection *conn)
{
    if (s2n_result_is_error(s2n_ktls_validate(conn))) {
        return S2N_RESULT_OK;
    }

    if (conn->config->ktls_recv_requested) {
        if (s2n_result_is_ok(s2n_ktls_configure_socket(conn, S2N_KTLS_MODE_RECV))) {
            RESULT_ENSURE_OK(s2n_ktls_configure_connection(conn, S2N_KTLS_MODE_RECV), S2N_ERR_KTLS);
        }
    }

    if (conn->config->ktls_send_requested) {
        if (s2n_result_is_ok(s2n_ktls_configure_socket(conn, S2N_KTLS_MODE_SEND))) {
            RESULT_ENSURE_OK(s2n_ktls_configure_connection(conn, S2N_KTLS_MODE_SEND), S2N_ERR_KTLS);
        }
    }

    return S2N_RESULT_OK;
}
