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

#ifdef S2N_PLATFORM_SUPPORTS_KTLS
    /*
     * https://github.com/aws/s2n-tls/issues/3813
     *
     * _GNU_SOURCE is needed for resolving the constant SOL_TCP
     * when building `tls/s2n_ktls.c`.
     */
    #ifndef _GNU_SOURCE
        #define _GNU_SOURCE
        #include <netinet/tcp.h>
        #undef _GNU_SOURCE
    #else
        #include <netinet/tcp.h>
    #endif

    #include <linux/tls.h>
#endif

#define S2N_TLS_ULP_NAME      "tls"
#define S2N_TLS_ULP_NAME_SIZE sizeof(S2N_TLS_ULP_NAME)

#include <sys/socket.h>

#include "tls/s2n_ktls.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_socket.h"

/* These variables are used to disable ktls mechanisms during testing. */
static bool disable_ktls_socket_config_for_testing = false;

bool platform_supports_ktls()
{
#ifdef S2N_PLATFORM_SUPPORTS_KTLS
    return true;
#else
    return false;
#endif
}

static S2N_RESULT s2n_ktls_validate(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(conn->secure);
    RESULT_ENSURE_REF(conn->secure->cipher_suite);
    RESULT_ENSURE_REF(conn->secure->cipher_suite->record_alg);
    RESULT_ENSURE_REF(conn->secure->cipher_suite->record_alg->cipher);
    const struct s2n_cipher *cipher = conn->secure->cipher_suite->record_alg->cipher;
    RESULT_ENSURE_REF(cipher);

    /* TODO support TLS 1.3
     *
     * TLS 1.3 support requires sending the KeyUpdate message when the cryptographic
     * KeyLimits are met. However, this is currently only possible by applying a
     * kernel patch to support this functionality.
     */
    RESULT_ENSURE(conn->actual_protocol_version == S2N_TLS12, S2N_ERR_KTLS_UNSUPPORTED_CONN);

    /* Check if the cipher supports kTLS */
    RESULT_ENSURE(cipher->ktls_supported, S2N_ERR_KTLS_UNSUPPORTED_CONN);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ktls_retrieve_file_descriptor(struct s2n_connection *conn, s2n_ktls_mode ktls_mode, int *fd)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(fd);

    if (ktls_mode == S2N_KTLS_MODE_RECV) {
        RESULT_ENSURE_REF(conn->recv_io_context);
        RESULT_ENSURE(conn->managed_recv_io, S2N_ERR_KTLS_RECV_MANAGED_IO);
        /* retrieve the receive fd */
        const struct s2n_socket_read_io_context *peer_socket_ctx = conn->recv_io_context;
        *fd = peer_socket_ctx->fd;
    } else if (ktls_mode == S2N_KTLS_MODE_SEND) {
        RESULT_ENSURE_REF(conn->send_io_context);
        RESULT_ENSURE(conn->managed_send_io, S2N_ERR_KTLS_SEND_MANAGED_IO);

        /* retrieve the send fd */
        const struct s2n_socket_write_io_context *peer_socket_ctx = conn->send_io_context;
        *fd = peer_socket_ctx->fd;
    }

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_ktls_configure_socket(struct s2n_connection *conn, s2n_ktls_mode ktls_mode)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE(ktls_mode == S2N_KTLS_MODE_RECV || ktls_mode == S2N_KTLS_MODE_SEND, S2N_ERR_SAFETY);

    /* If already enabled then return success */
    if (ktls_mode == S2N_KTLS_MODE_SEND && conn->ktls_send_enabled) {
        return S2N_RESULT_OK;
    }
    if (ktls_mode == S2N_KTLS_MODE_RECV && conn->ktls_recv_enabled) {
        return S2N_RESULT_OK;
    }

    int fd = 0;
    RESULT_GUARD(s2n_ktls_retrieve_file_descriptor(conn, ktls_mode, &fd));

    /* Calls to setsockopt require a real socket, which is not used in unit tests. */
    RESULT_ENSURE(!disable_ktls_socket_config_for_testing, S2N_ERR_KTLS_DISABLED_FOR_TEST);

#ifdef S2N_PLATFORM_SUPPORTS_KTLS
    /* Enable 'tls' ULP for the socket. https://lwn.net/Articles/730207 */
    int ret = setsockopt(fd, SOL_TCP, TCP_ULP, S2N_TLS_ULP_NAME, S2N_TLS_ULP_NAME_SIZE);
    RESULT_ENSURE(ret == 0, S2N_ERR_KTLS_ULP);
#endif

    /* TODO configure keys */

    return S2N_RESULT_OK;
}

/*
 * Since kTLS is an optimization, it is possible to continue operation
 * by using userspace TLS if kTLS is not supported. Upon successfully
 * enabling kTLS, we set connection->ktls_send_enabled (and recv) to true.
 *
 * For this reason we categorize kTLS errors into recoverable and
 * un-recoverable and handle them appropriately:
 *
 * - Errors related to the socket configuration are considered recoverable
 *   since kTLS related `setsockopt` operations are non-destructive.
 *
 * - Errors related to connection configuration are considered
 *   un-recoverable since we attempt to modify s2n_connection state.
 */
int s2n_connection_ktls_enable(struct s2n_connection *conn, s2n_ktls_mode ktls_mode)
{
    if (!platform_supports_ktls()) {
        POSIX_BAIL(S2N_ERR_KTLS_UNSUPPORTED_PLATFORM);
    }

    POSIX_ENSURE_REF(conn);
    POSIX_GUARD_RESULT(s2n_ktls_validate(conn));

    if (ktls_mode == S2N_KTLS_MODE_RECV || ktls_mode == S2N_KTLS_MODE_DUPLEX) {
        POSIX_GUARD_RESULT(s2n_ktls_configure_socket(conn, S2N_KTLS_MODE_RECV));
    }

    if (ktls_mode == S2N_KTLS_MODE_SEND || ktls_mode == S2N_KTLS_MODE_DUPLEX) {
        POSIX_GUARD_RESULT(s2n_ktls_configure_socket(conn, S2N_KTLS_MODE_SEND));
    }

    return S2N_SUCCESS;
}

/* Use for testing only.
 *
 * This function disables the setsockopt call to enable ULP. Calls to setsockopt
 * require a real socket, which is not used in unit tests.
 */
S2N_RESULT s2n_disable_ktls_socket_config_for_testing(void)
{
    RESULT_ENSURE(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);

    disable_ktls_socket_config_for_testing = true;

    return S2N_RESULT_OK;
}
