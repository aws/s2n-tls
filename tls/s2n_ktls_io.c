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

#include <sys/socket.h>

#include "tls/s2n_ktls.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"
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
    hdr->cmsg_len = CMSG_LEN(sizeof(record_type));
    hdr->cmsg_level = S2N_SOL_TLS;
    hdr->cmsg_type = cmsg_type;
    *CMSG_DATA(hdr) = record_type;

    /* 
     * https://man7.org/linux/man-pages/man3/cmsg.3.html
     * Finally, the msg_controllen field of the msghdr
     * should be set to the sum of the CMSG_SPACE() of the length of all
     * control messages in the buffer
     */
    RESULT_ENSURE_GTE(msg->msg_controllen, CMSG_SPACE(sizeof(record_type)));
    msg->msg_controllen = CMSG_SPACE(sizeof(record_type));

    return S2N_RESULT_OK;
}

/* TODO: do we want a more specific error that S2N_ERR_IO? */
S2N_RESULT s2n_ktls_get_control_data(struct msghdr *msg, int cmsg_type, uint8_t *record_type)
{
    RESULT_ENSURE_REF(msg);
    RESULT_ENSURE_REF(record_type);

    /*
     * https://man7.org/linux/man-pages/man3/cmsg.3.html
     * To create ancillary data, first initialize the msg_controllen
     * member of the msghdr with the length of the control message
     * buffer. 
     */
    RESULT_ENSURE_REF(msg->msg_control);
    RESULT_ENSURE_GTE(msg->msg_controllen, CMSG_SPACE(sizeof(record_type)));

    /* 
     * https://man7.org/linux/man-pages/man3/cmsg.3.html
     * Use CMSG_FIRSTHDR() on the msghdr to get the first
     * control message and CMSG_NXTHDR() to get all subsequent ones.
     */
    /* TODO: comment about the protocol + socket config determining the headers */
    struct cmsghdr *hdr = CMSG_FIRSTHDR(msg);
    RESULT_ENSURE(hdr, S2N_ERR_IO);

    /* 
     * https://man7.org/linux/man-pages/man3/cmsg.3.html
     * In each control message, initialize cmsg_len (with CMSG_LEN()), the
     * other cmsghdr header fields, and the data portion using
     * CMSG_DATA().
     */
    RESULT_ENSURE(hdr->cmsg_level == S2N_SOL_TLS, S2N_ERR_IO);
    RESULT_ENSURE(hdr->cmsg_type == cmsg_type, S2N_ERR_IO);
    RESULT_ENSURE(hdr->cmsg_len == CMSG_LEN(sizeof(*record_type)), S2N_ERR_IO);
    *record_type = *CMSG_DATA(hdr);

    return S2N_RESULT_OK;
}
