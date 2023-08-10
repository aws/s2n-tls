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

#if defined(S2N_KTLS_SUPPORTED)

    #include "utils/s2n_socket.h"

/* Used to override sendmsg and recvmsg for testing. */
static ssize_t s2n_ktls_default_sendmsg(void *io_context, const struct msghdr *msg);
static ssize_t s2n_ktls_default_recvmsg(void *io_context, struct msghdr *msg);
s2n_ktls_sendmsg_fn s2n_sendmsg_fn = s2n_ktls_default_sendmsg;
s2n_ktls_recvmsg_fn s2n_recvmsg_fn = s2n_ktls_default_recvmsg;

S2N_RESULT s2n_ktls_set_sendmsg_cb(struct s2n_connection *conn, s2n_ktls_sendmsg_fn send_cb, void *send_ctx)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(send_ctx);
    RESULT_ENSURE(s2n_in_test(), S2N_ERR_NOT_IN_TEST);
    conn->send_io_context = send_ctx;
    s2n_sendmsg_fn = send_cb;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ktls_set_recvmsg_cb(struct s2n_connection *conn, s2n_ktls_recvmsg_fn recv_cb, void *recv_ctx)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(recv_ctx);
    RESULT_ENSURE(s2n_in_test(), S2N_ERR_NOT_IN_TEST);
    conn->recv_io_context = recv_ctx;
    s2n_recvmsg_fn = recv_cb;
    return S2N_RESULT_OK;
}

static ssize_t s2n_ktls_default_recvmsg(void *io_context, struct msghdr *msg)
{
    POSIX_ENSURE_REF(io_context);
    POSIX_ENSURE_REF(msg);

    const struct s2n_socket_read_io_context *peer_socket_ctx = io_context;
    POSIX_ENSURE_REF(peer_socket_ctx);
    int fd = peer_socket_ctx->fd;

    return recvmsg(fd, msg, 0);
}

static ssize_t s2n_ktls_default_sendmsg(void *io_context, const struct msghdr *msg)
{
    POSIX_ENSURE_REF(io_context);
    POSIX_ENSURE_REF(msg);

    const struct s2n_socket_write_io_context *peer_socket_ctx = io_context;
    POSIX_ENSURE_REF(peer_socket_ctx);
    int fd = peer_socket_ctx->fd;

    return sendmsg(fd, msg, 0);
}

S2N_RESULT s2n_ktls_set_control_data(struct msghdr *msg, uint8_t record_type)
{
    RESULT_ENSURE_REF(msg);
    RESULT_ENSURE_REF(msg->msg_control);
    RESULT_ENSURE_GTE(msg->msg_controllen, CMSG_SPACE(sizeof(record_type)));

    struct cmsghdr *hdr = CMSG_FIRSTHDR(msg);
    RESULT_ENSURE(hdr != NULL, S2N_ERR_IO);
    hdr->cmsg_level = S2N_SOL_TLS;
    hdr->cmsg_type = TLS_SET_RECORD_TYPE;
    hdr->cmsg_len = CMSG_LEN(sizeof(record_type));
    *CMSG_DATA(hdr) = record_type;
    msg->msg_controllen = hdr->cmsg_len;

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_ktls_sendmsg_impl(struct s2n_connection *conn, const struct msghdr *msg,
        uint8_t record_type, s2n_blocked_status *blocked, ssize_t *bytes_written)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(msg);
    RESULT_ENSURE_REF(blocked);
    RESULT_ENSURE_REF(bytes_written);
    RESULT_ENSURE_REF(conn->send_io_context);

    *blocked = S2N_BLOCKED_ON_WRITE;
    *bytes_written = s2n_sendmsg_fn(conn->send_io_context, msg);
    bool did_fail = *bytes_written < 0;

    /* handle blocked error */
    if (did_fail && (errno == EWOULDBLOCK || errno == EAGAIN)) {
        RESULT_BAIL(S2N_ERR_IO_BLOCKED);
    }

    *blocked = S2N_NOT_BLOCKED;
    RESULT_ENSURE(!did_fail, S2N_ERR_IO);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ktls_sendmsg(struct s2n_connection *conn, uint8_t record_type, struct iovec *msg_iov,
        size_t count, s2n_blocked_status *blocked, ssize_t *bytes_written)
{
    RESULT_ENSURE_REF(msg_iov);
    RESULT_ENSURE_REF(msg_iov->iov_base);
    RESULT_ENSURE(msg_iov->iov_len > 0, S2N_ERR_INVALID_ARGUMENT);
    RESULT_ENSURE(count > 0, S2N_ERR_INVALID_ARGUMENT);
    RESULT_ENSURE_REF(blocked);
    RESULT_ENSURE_REF(bytes_written);

    /* Note: The following assumption is based on implementation details of
     * CMSG_SPACE. However, since CMSG_* macros are platform specific the
     * following assumption must be re-validated when adding support for
     * new platforms.
     *
     * The documentation for [cmsg](https://man7.org/linux/man-pages/man3/cmsg.3.html)
     * uses a union to achieve alignment and mentions:
     *   > Ancillary data buffer, wrapped in a union in order to ensure it is
     *     suitably aligned
     *
     * The memory for msghdr.msg_control must be properly aligned to `cmsghdr` since
     * that is the actual underlying type. However, since sizeof(record_type) is
     * less than `cmsghdr` and CMSG_SPACE rounds up to sizeof(struct cmsghdr) bytes,
     * proper alignment can be achieved without a union.
     */
    char cmsg_buf[CMSG_SPACE(sizeof(record_type))];
    /* Init msghdr */
    struct msghdr msg = {
        .msg_iov = msg_iov,
        .msg_iovlen = count,
        .msg_control = cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf)
    };
    RESULT_GUARD(s2n_ktls_set_control_data(&msg, record_type));
    RESULT_GUARD(s2n_ktls_sendmsg_impl(conn, &msg, record_type, blocked, bytes_written));

    return S2N_RESULT_OK;
}
#else
S2N_RESULT s2n_ktls_sendmsg(struct s2n_connection *conn, uint8_t record_type, struct iovec *msg_iov,
        size_t count, s2n_blocked_status *blocked, ssize_t *bytes_written)
{
    RESULT_BAIL(S2N_ERR_KTLS_UNSUPPORTED_PLATFORM);
}
S2N_RESULT s2n_ktls_set_sendmsg_cb(struct s2n_connection *conn, s2n_ktls_sendmsg_fn send_cb, void *send_ctx)
{
    RESULT_BAIL(S2N_ERR_KTLS_UNSUPPORTED_PLATFORM);
}
S2N_RESULT s2n_ktls_set_recvmsg_cb(struct s2n_connection *conn, s2n_ktls_recvmsg_fn recv_cb, void *recv_ctx)
{
    RESULT_BAIL(S2N_ERR_KTLS_UNSUPPORTED_PLATFORM);
}
#endif
