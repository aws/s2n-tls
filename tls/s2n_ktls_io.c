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

#include "utils/s2n_safety_macros.h"
#if defined(__FreeBSD__) || defined(__APPLE__)
    /* https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/sys_socket.h.html
     * The POSIX standard does not define the CMSG_LEN and CMSG_SPACE macros. FreeBSD
     * and APPLE check and disable these macros if the _POSIX_C_SOURCE flag is set.
     *
     * Since s2n-tls already unsets the _POSIX_C_SOURCE in other files and is not
     * POSIX compliant, we continue the pattern here.
     */
    #undef _POSIX_C_SOURCE
#endif
#include <sys/socket.h>

#include "error/s2n_errno.h"
#include "tls/s2n_ktls.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_socket.h"

/* record_type is of type uint8_t */
#define S2N_KTLS_RECORD_TYPE_SIZE    (sizeof(uint8_t))
#define S2N_KTLS_CONTROL_BUFFER_SIZE (CMSG_SPACE(S2N_KTLS_RECORD_TYPE_SIZE))

/* Used to override sendmsg and recvmsg for testing. */
static ssize_t s2n_ktls_default_sendmsg(void *io_context, const struct msghdr *msg);
static ssize_t s2n_ktls_default_recvmsg(void *io_context, struct msghdr *msg);
s2n_ktls_sendmsg_fn s2n_sendmsg_fn = s2n_ktls_default_sendmsg;
s2n_ktls_recvmsg_fn s2n_recvmsg_fn = s2n_ktls_default_recvmsg;

S2N_RESULT s2n_ktls_set_sendmsg_cb(struct s2n_connection *conn, s2n_ktls_sendmsg_fn send_cb,
        void *send_ctx)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(send_ctx);
    RESULT_ENSURE(s2n_in_test(), S2N_ERR_NOT_IN_TEST);
    conn->send_io_context = send_ctx;
    s2n_sendmsg_fn = send_cb;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ktls_set_recvmsg_cb(struct s2n_connection *conn, s2n_ktls_recvmsg_fn recv_cb,
        void *recv_ctx)
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

S2N_RESULT s2n_ktls_set_control_data(struct msghdr *msg, char *buf, size_t buf_size,
        int cmsg_type, uint8_t record_type)
{
    RESULT_ENSURE_REF(msg);
    RESULT_ENSURE_REF(buf);

    /*
     * https://man7.org/linux/man-pages/man3/cmsg.3.html
     * To create ancillary data, first initialize the msg_controllen
     * member of the msghdr with the length of the control message
     * buffer.
     */
    msg->msg_control = buf;
    msg->msg_controllen = buf_size;

    /*
     * https://man7.org/linux/man-pages/man3/cmsg.3.html
     * Use CMSG_FIRSTHDR() on the msghdr to get the first
     * control message and CMSG_NXTHDR() to get all subsequent ones.
     */
    struct cmsghdr *hdr = CMSG_FIRSTHDR(msg);
    RESULT_ENSURE_REF(hdr);

    /*
     * https://man7.org/linux/man-pages/man3/cmsg.3.html
     * In each control message, initialize cmsg_len (with CMSG_LEN()), the
     * other cmsghdr header fields, and the data portion using
     * CMSG_DATA().
     */
    hdr->cmsg_len = CMSG_LEN(S2N_KTLS_RECORD_TYPE_SIZE);
    hdr->cmsg_level = S2N_SOL_TLS;
    hdr->cmsg_type = cmsg_type;
    *CMSG_DATA(hdr) = record_type;

    /*
     * https://man7.org/linux/man-pages/man3/cmsg.3.html
     * Finally, the msg_controllen field of the msghdr
     * should be set to the sum of the CMSG_SPACE() of the length of all
     * control messages in the buffer
     */
    RESULT_ENSURE_GTE(msg->msg_controllen, CMSG_SPACE(S2N_KTLS_RECORD_TYPE_SIZE));
    msg->msg_controllen = CMSG_SPACE(S2N_KTLS_RECORD_TYPE_SIZE);

    return S2N_RESULT_OK;
}

/* Expect to receive a single cmsghdr containing the TLS record_type.
 *
 * s2n-tls allocates enough space to receive a single cmsghdr. Since this is
 * used to get the record_type when receiving over kTLS (enabled via
 * `s2n_connection_ktls_enable_recv`), the application should not configure
 * the socket to receive additional control messages. In the event s2n-tls
 * can not retrieve the record_type, it is safer to drop the record.
 */
S2N_RESULT s2n_ktls_get_control_data(struct msghdr *msg, int cmsg_type, uint8_t *record_type)
{
    RESULT_ENSURE_REF(msg);
    RESULT_ENSURE_REF(record_type);

    /* https://man7.org/linux/man-pages/man3/recvmsg.3p.html
     * MSG_CTRUNC  Control data was truncated.
     */
    if (msg->msg_flags & MSG_CTRUNC) {
        RESULT_BAIL(S2N_ERR_KTLS_BAD_CMSG);
    }

    /*
     * https://man7.org/linux/man-pages/man3/cmsg.3.html
     * To create ancillary data, first initialize the msg_controllen
     * member of the msghdr with the length of the control message
     * buffer.
     */
    RESULT_ENSURE(msg->msg_control, S2N_ERR_SAFETY);
    RESULT_ENSURE(msg->msg_controllen >= CMSG_SPACE(S2N_KTLS_RECORD_TYPE_SIZE), S2N_ERR_SAFETY);

    /* https://man7.org/linux/man-pages/man3/cmsg.3.html
     * Use CMSG_FIRSTHDR() on the msghdr to get the first
     * control message and CMSG_NXTHDR() to get all subsequent ones.
     */
    struct cmsghdr *hdr = CMSG_FIRSTHDR(msg);
    RESULT_ENSURE(hdr, S2N_ERR_KTLS_BAD_CMSG);

    /*
     * https://man7.org/linux/man-pages/man3/cmsg.3.html
     * In each control message, initialize cmsg_len (with CMSG_LEN()), the
     * other cmsghdr header fields, and the data portion using
     * CMSG_DATA().
     */
    RESULT_ENSURE(hdr->cmsg_level == S2N_SOL_TLS, S2N_ERR_KTLS_BAD_CMSG);
    RESULT_ENSURE(hdr->cmsg_type == cmsg_type, S2N_ERR_KTLS_BAD_CMSG);
    RESULT_ENSURE(hdr->cmsg_len == CMSG_LEN(S2N_KTLS_RECORD_TYPE_SIZE), S2N_ERR_KTLS_BAD_CMSG);
    *record_type = *CMSG_DATA(hdr);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ktls_sendmsg(struct s2n_connection *conn, uint8_t record_type, struct iovec *msg_iov,
        size_t msg_iovlen, s2n_blocked_status *blocked, size_t *bytes_written)
{
    RESULT_ENSURE_REF(bytes_written);
    RESULT_ENSURE_REF(msg_iov);
    RESULT_ENSURE_REF(blocked);
    RESULT_ENSURE_REF(conn);

    *blocked = S2N_BLOCKED_ON_WRITE;
    *bytes_written = 0;

    struct msghdr msg = {
        .msg_iov = msg_iov,
        .msg_iovlen = msg_iovlen,
    };

    char control_data[S2N_KTLS_CONTROL_BUFFER_SIZE] = { 0 };
    RESULT_GUARD(s2n_ktls_set_control_data(&msg, control_data, sizeof(control_data),
            S2N_TLS_SET_RECORD_TYPE, record_type));

    ssize_t result = s2n_sendmsg_fn(conn->send_io_context, &msg);
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

S2N_RESULT s2n_ktls_recvmsg(struct s2n_connection *conn, uint8_t *record_type, uint8_t *buf,
        size_t buf_len, s2n_blocked_status *blocked, size_t *bytes_read)
{
    RESULT_ENSURE_REF(record_type);
    RESULT_ENSURE_REF(bytes_read);
    RESULT_ENSURE_REF(blocked);
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(buf);
    /* Ensure that buf_len is > 0 since trying to receive 0 bytes does not
     * make sense and a return value of `0` from recvmsg is treated as EOF.
     */
    RESULT_ENSURE_GT(buf_len, 0);

    *blocked = S2N_BLOCKED_ON_READ;
    *record_type = 0;
    *bytes_read = 0;
    struct iovec msg_iov = {
        .iov_base = buf,
        .iov_len = buf_len
    };
    struct msghdr msg = {
        .msg_iov = &msg_iov,
        .msg_iovlen = 1,
    };

    /*
     * https://man7.org/linux/man-pages/man3/cmsg.3.html
     * To create ancillary data, first initialize the msg_controllen
     * member of the msghdr with the length of the control message
     * buffer.
     */
    char control_data[S2N_KTLS_CONTROL_BUFFER_SIZE] = { 0 };
    msg.msg_controllen = sizeof(control_data);
    msg.msg_control = control_data;

    ssize_t result = s2n_recvmsg_fn(conn->recv_io_context, &msg);
    if (result < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            RESULT_BAIL(S2N_ERR_IO_BLOCKED);
        }
        RESULT_BAIL(S2N_ERR_IO);
    } else if (result == 0) {
        /* The return value will be 0 when the socket reads EOF. */
        RESULT_BAIL(S2N_ERR_CLOSED);
    }

    RESULT_GUARD(s2n_ktls_get_control_data(&msg, S2N_TLS_GET_RECORD_TYPE, record_type));

    *blocked = S2N_NOT_BLOCKED;
    *bytes_read = result;
    return S2N_RESULT_OK;
}

/* Update iovec to account for partially sends.
 *
 * sendmsg returns the number of bytes sent; which can be less than the total
 * requested amount. This function updates iovec to skip data which has already
 * been sent. */
static S2N_RESULT s2n_ktls_send_update_iovec(struct iovec *msg_iov, size_t msg_iovlen, size_t bytes_sent)
{
    RESULT_ENSURE_REF(msg_iov);

    for (size_t i = 0; i < msg_iovlen; i++) {
        size_t current_iov_len = msg_iov[i].iov_len;

        if (current_iov_len > bytes_sent) {
            msg_iov[i].iov_base = (uint8_t *) msg_iov[i].iov_base + bytes_sent;
            msg_iov[i].iov_len = current_iov_len - bytes_sent;
            return S2N_RESULT_OK;
        }

        msg_iov[i].iov_len = 0;
        bytes_sent -= current_iov_len;
    }

    return S2N_RESULT_OK;
}

/* TODO
 D - handle updating msg_iov
 D - update connection state
 *   (recv)
 D   - s2n_connection_get_wire_bytes_in: wire_bytes_in
 *   (send)
 D   - s2n_connection_get_wire_bytes_out: wire_bytes_out
 D   - write_fd_broken (errno == EPIPE). Just return S2N_ERR_IO
 *   (error)
 D   - read_closed
 D   - write_closed
 *   (alert)
 *   - s2n_connection_get_alert alert_in;
 *   - alert_sent
 *   - error_alert_received
 *   - close_notify_received
 *   - reader_warning_out
 *   (handshake)
 *   - tickets_to_send/tickets_sent
 *
 * - check s2n_sendv_with_offset_impl for missing logic
 D - test template
 * - ?error handling (close connection)
 */
/* TODO
 D - Check case: First send succeeds, second send IO errors
 D - Return error from s2n_connection_get_wire_bytes_in/out
 */
S2N_RESULT s2n_ktls_send_impl(struct s2n_connection *conn, const struct iovec *msg_iov,
        size_t msg_iovlen, size_t offset, s2n_blocked_status *blocked, size_t *bytes_written)
{
    RESULT_ENSURE_REF(bytes_written);
    RESULT_ENSURE_REF(msg_iov);

    size_t total_size = 0;
    for (size_t i = 0; i < msg_iovlen; i++) {
        total_size += msg_iov[i].iov_len;
    }
    total_size -= offset;

    DEFER_CLEANUP(struct s2n_blob iovec_mem = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&iovec_mem, sizeof(struct iovec) * msg_iovlen));
    struct iovec *msg_iov_skip_sent = (struct iovec *) (void *) iovec_mem.data;
    RESULT_CHECKED_MEMCPY(msg_iov_skip_sent, msg_iov, sizeof(struct iovec) * msg_iovlen);

    /* Update msg_iov_skip_sent based on offset amount passed by application */
    RESULT_GUARD(s2n_ktls_send_update_iovec(msg_iov_skip_sent, msg_iovlen, offset));

    /* Attempt to send until either we send all the data or we become blocked. */
    size_t total_data_sent = 0;
    while (total_size - total_data_sent) {
        size_t sendmsg_bytes_written = 0;
        s2n_result sendmsg_result = s2n_ktls_sendmsg(conn, TLS_APPLICATION_DATA, msg_iov_skip_sent,
                msg_iovlen, blocked, &sendmsg_bytes_written);
        if (s2n_result_is_error(sendmsg_result)) {
            bool some_data_sent = total_data_sent || sendmsg_bytes_written;
            if (s2n_errno == S2N_ERR_IO_BLOCKED && some_data_sent) {
                /* Acknowledge the data sent.
                 *
                 * Successfully sent > 0 user bytes, but not the full requested payload because
                 * we became blocked on I/O. */
                total_data_sent += sendmsg_bytes_written;
                *bytes_written = total_data_sent;
                return S2N_RESULT_OK;
            } else {
                /* All non-blocked errors are considered fatal. */
                return sendmsg_result;
            }
        }

        /* Update msg_iov_skip_sent based on bytes sent this past round */
        total_data_sent += sendmsg_bytes_written;
        RESULT_ENSURE_LTE(total_data_sent, total_size);
        RESULT_GUARD(s2n_ktls_send_update_iovec(msg_iov_skip_sent, msg_iovlen, sendmsg_bytes_written));
    }

    *bytes_written = total_data_sent;
    return S2N_RESULT_OK;
}

ssize_t s2n_ktls_send(struct s2n_connection *conn, const struct iovec *msg_iov,
        size_t msg_iovlen, size_t offset, s2n_blocked_status *blocked)
{
    size_t bytes_written = 0;
    POSIX_GUARD_RESULT(s2n_ktls_send_impl(conn, msg_iov, msg_iovlen, offset, blocked, &bytes_written));
    return bytes_written;
}
