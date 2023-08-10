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
#include "utils/s2n_socket.h"

#ifdef S2N_KTLS_SUPPORTED

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
/* TODO: can we detect if this assumption is false? Check size of msg_controllen against cmsghdr */
#define S2N_CONTROL_DATA_BUF_SIZE (CMSG_SPACE(sizeof(uint8_t)))

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


S2N_RESULT s2n_ktls_set_control_data(struct msghdr *msg, uint8_t record_type,
    uint8_t *cmsg_buf, size_t cmsg_buf_size, int cmsg_type)
{

    RESULT_ENSURE_REF(msg);

    RESULT_ENSURE_REF(cmsg_buf);
    RESULT_ENSURE(cmsg_buf_size >= CMSG_SPACE(sizeof(record_type)));

    /*
     * https://man7.org/linux/man-pages/man3/cmsg.3.html
     * To create ancillary data, first initialize the msg_controllen
     * member of the msghdr with the length of the control message
     * buffer. 
     */
    msg->msg_control = cmsg_buf;
    msg->msg_controllen = sizeof(cmsg_buf);

    /* 
    TODO: clean up comment
    https://man7.org/linux/man-pages/man3/cmsg.3.html
    Use CMSG_FIRSTHDR() on the msghdr to get the first
       control message and CMSG_NXTHDR() to get all subsequent ones.
       */
    struct cmsghdr *hdr = CMSG_FIRSTHDR(msg);
    RESULT_ENSURE_REF(hdr);

    /* KTLS documentation? */
    hdr->cmsg_level = S2N_SOL_TLS;
    hdr->cmsg_type = cmsg_type;

    /* 
    TODO: clean up comment
    https://man7.org/linux/man-pages/man3/cmsg.3.html
    In
       each control message, initialize cmsg_len (with CMSG_LEN()), the
       other cmsghdr header fields, and the data portion using
       CMSG_DATA().
       */
    hdr->cmsg_len = CMSG_LEN(sizeof(record_type));

    *CMSG_DATA(hdr) = record_type;

        /* 
    TODO: clean up comment
    https://man7.org/linux/man-pages/man3/cmsg.3.html
    Finally, the msg_controllen field of the msghdr
       should be set to the sum of the CMSG_SPACE() of the length of all
       control messages in the buffer
       */
    msg->msg_controllen = CMSG_SPACE(sizeof(record_type));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ktls_sendmsg(struct s2n_connection *conn, uint8_t record_type, const struct iovec *msg_iov,
        size_t count, s2n_blocked_status *blocked, size_t *bytes_written)
{
    RESULT_ENSURE_REF(msg_iov);
    RESULT_ENSURE_REF(blocked);

    *blocked = S2N_BLOCKED_ON_WRITE;

    RESULT_ENSURE(msg_iov->iov_base, S2N_ERR_INVALID_ARGUMENT);
    RESULT_ENSURE(msg_iov->iov_len > 0, S2N_ERR_INVALID_ARGUMENT);
    RESULT_ENSURE(count > 0, S2N_ERR_INVALID_ARGUMENT);

    struct msghdr msg = {
        /* TODO: properly discard const, add comment */
        .msg_iov = (struct iovec*) msg_iov,
        .msg_iovlen = count,
    };

    char control_data[S2N_CONTROL_DATA_BUF_SIZE] = { 0 };
    RESULT_GUARD(s2n_ktls_set_control_data(&msg, record_type, control_data, sizeof(control_data),
        TLS_SET_RECORD_TYPE));

    ssize_t result = s2n_sendmsg_fn(conn->send_io_context, msg);
    if (result < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            RESULT_BAIL(S2N_ERR_IO_BLOCKED);
        }
        RESULT_BAIL(S2N_ERR_IO);
    }

    *blocked = S2N_NOT_BLOCKED;
    *bytes_written = result;
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
