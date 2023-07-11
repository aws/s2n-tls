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

#include "tls/s2n_ktls.h"

#include <sys/socket.h>

#include "utils/s2n_socket.h"

bool s2n_ktls_is_supported_on_platform()
{
    return S2N_KTLS_SUPPORTED;
}

static S2N_RESULT s2n_ktls_validate(struct s2n_connection *conn, s2n_ktls_mode ktls_mode)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(conn->secure);
    RESULT_ENSURE_REF(conn->secure->cipher_suite);
    RESULT_ENSURE_REF(conn->secure->cipher_suite->record_alg);
    const struct s2n_cipher *cipher = conn->secure->cipher_suite->record_alg->cipher;
    RESULT_ENSURE_REF(cipher);

    RESULT_ENSURE(s2n_ktls_is_supported_on_platform(), S2N_ERR_KTLS_UNSUPPORTED_PLATFORM);

    /* kTLS enable should only be called once the handshake has completed. */
    RESULT_ENSURE(is_handshake_complete(conn), S2N_ERR_HANDSHAKE_NOT_COMPLETE);

    /* TODO support TLS 1.3
     *
     * TLS 1.3 support requires sending the KeyUpdate message when the cryptographic
     * key usage limits are met. However, this is currently only possible by applying a
     * kernel patch to support this functionality.
     */
    RESULT_ENSURE(conn->actual_protocol_version == S2N_TLS12, S2N_ERR_KTLS_UNSUPPORTED_CONN);

    /* Check if the cipher supports kTLS */
    RESULT_ENSURE(cipher->ktls_supported, S2N_ERR_KTLS_UNSUPPORTED_CONN);

    /* kTLS I/O functionality is managed by s2n-tls. kTLS cannot be enabled if the
     * application sets custom I/O (managed_send_io == false means application has
     * set custom I/O).
     */
    switch (ktls_mode) {
        case S2N_KTLS_MODE_SEND:
            RESULT_ENSURE(conn->managed_send_io, S2N_ERR_KTLS_MANAGED_IO);
            /* The output stuffer should be empty before enabling kTLS. */
            RESULT_ENSURE(s2n_stuffer_data_available(&conn->out) == 0, S2N_ERR_RECORD_STUFFER_NEEDS_DRAINING);
            break;
        case S2N_KTLS_MODE_RECV:
            RESULT_ENSURE(conn->managed_recv_io, S2N_ERR_KTLS_MANAGED_IO);
            /* The input stuffer should be empty before enabling kTLS. */
            RESULT_ENSURE(s2n_stuffer_data_available(&conn->in) == 0, S2N_ERR_RECORD_STUFFER_NEEDS_DRAINING);
            break;
        default:
            RESULT_BAIL(S2N_ERR_SAFETY);
            break;
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ktls_retrieve_file_descriptor(struct s2n_connection *conn, s2n_ktls_mode ktls_mode, int *fd)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(fd);

    if (ktls_mode == S2N_KTLS_MODE_RECV) {
        RESULT_GUARD_POSIX(s2n_connection_get_read_fd(conn, fd));
    } else if (ktls_mode == S2N_KTLS_MODE_SEND) {
        RESULT_GUARD_POSIX(s2n_connection_get_write_fd(conn, fd));
    }

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_ktls_configure_socket(struct s2n_connection *conn, s2n_ktls_mode ktls_mode)
{
    RESULT_ENSURE_REF(conn);

    int fd = 0;
    RESULT_GUARD(s2n_ktls_retrieve_file_descriptor(conn, ktls_mode, &fd));

    /* Calls to setsockopt require a real socket, which is not used in unit tests. */
    if (s2n_in_unit_test()) {
        return S2N_RESULT_OK;
    }

    /* Enable 'tls' ULP for the socket. https://lwn.net/Articles/730207
     *
     * Its not possible to detect kTLS support at compile time. We need rely on
     * the call to setsockopt(..TCP_ULP...) to determine if kTLS is supported.
     * This is a safe and non destructive operation on Linux.
     */
    int ret = setsockopt(fd, S2N_SOL_TCP, S2N_TCP_ULP, S2N_TLS_ULP_NAME, S2N_TLS_ULP_NAME_SIZE);

    if (ret != 0) {
        /* https://man7.org/linux/man-pages/man3/errno.3.html
         * EEXIST indicates that TCP_ULP has already been enabled on the socket.
         * This is a noop and therefore safe to ignore.
         */
        RESULT_ENSURE(errno == EEXIST, S2N_ERR_KTLS_ULP);
    }

    return S2N_RESULT_OK;
}

/*
 * Since kTLS is an optimization, it is possible to continue operation
 * by using userspace TLS if kTLS is not supported.
 *
 * kTLS configuration errors are recoverable since calls to setsockopt are
 * non-destructive and its possible to fallback to userspace.
 */
int s2n_connection_ktls_enable_send(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);
    POSIX_GUARD_RESULT(s2n_ktls_validate(conn, S2N_KTLS_MODE_SEND));

    /* If already enabled then return success */
    if (conn->ktls_send_enabled) {
        return S2N_SUCCESS;
    }

    POSIX_GUARD_RESULT(s2n_ktls_configure_socket(conn, S2N_KTLS_MODE_SEND));
    conn->ktls_send_enabled = true;

    return S2N_SUCCESS;
}

int s2n_connection_ktls_enable_recv(struct s2n_connection *conn)
{
    POSIX_ENSURE_REF(conn);
    POSIX_GUARD_RESULT(s2n_ktls_validate(conn, S2N_KTLS_MODE_RECV));

    /* If already enabled then return success */
    if (conn->ktls_recv_enabled) {
        return S2N_SUCCESS;
    }

    POSIX_GUARD_RESULT(s2n_ktls_configure_socket(conn, S2N_KTLS_MODE_RECV));
    conn->ktls_recv_enabled = true;

    return S2N_SUCCESS;
}
