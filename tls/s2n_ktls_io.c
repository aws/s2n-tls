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
#include "utils/s2n_socket.h"

#if S2N_KTLS_SUPPORTED /* CMSG_* macros are platform specific */

/*
 * sendmsg and recvmsg are syscalls which can be used to send 'real' data along
 * with ancillary data. Ancillary data is used to communicate to the socket the
 * type of the TLS record being sent/received.
 *
 * Ancillary data macros (CMSG_*) are platform specific and gated.
 */

S2N_RESULT s2n_ktls_send_msg_impl(int sock, struct msghdr *msg,
        struct iovec *msg_iov, size_t count, s2n_blocked_status *blocked, ssize_t *send_len)
{
    RESULT_ENSURE_REF(msg);
    RESULT_ENSURE_REF(msg_iov);
    RESULT_ENSURE_REF(blocked);
    RESULT_ENSURE_REF(send_len);
    RESULT_ENSURE_GT(count, 0);

    /* set send buffer */
    msg->msg_iov = msg_iov;
    msg->msg_iovlen = count;

    *blocked = S2N_BLOCKED_ON_WRITE;
    *send_len = sendmsg(sock, msg, 0);
    if (*send_len < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            RESULT_BAIL(S2N_ERR_IO_BLOCKED);
        }
        RESULT_BAIL(S2N_ERR_IO);
    }
    *blocked = S2N_NOT_BLOCKED;

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ktls_set_ancillary_data(struct msghdr *msg, uint8_t record_type)
{
    RESULT_ENSURE_REF(msg);

    RESULT_ENSURE_REF(msg->msg_control);
    RESULT_ENSURE_GTE(msg->msg_controllen, CMSG_SPACE(sizeof(uint8_t)));

    /* set ancillary data */
    struct cmsghdr *hdr = CMSG_FIRSTHDR(msg);
    RESULT_ENSURE(hdr != NULL, S2N_ERR_IO);
    hdr->cmsg_level = S2N_SOL_TLS;
    hdr->cmsg_type = S2N_TLS_SET_RECORD_TYPE;
    hdr->cmsg_len = CMSG_LEN(sizeof(uint8_t));
    RESULT_CHECKED_MEMCPY(CMSG_DATA(hdr), &record_type, sizeof(uint8_t));

    return S2N_RESULT_OK;
}

/* Best practices taken from
 * https://man7.org/tlpi/code/online/dist/sockets/scm_cred_send.c.html */
S2N_RESULT s2n_ktls_send_msg(
        int sock, uint8_t record_type, struct iovec *msg_iov,
        size_t count, s2n_blocked_status *blocked, ssize_t *send_len)
{
    RESULT_ENSURE_REF(msg_iov);
    RESULT_ENSURE_REF(msg_iov->iov_base);
    RESULT_ENSURE_GT(msg_iov->iov_len, 0);
    RESULT_ENSURE_GT(count, 0);
    RESULT_ENSURE_REF(blocked);
    RESULT_ENSURE_REF(send_len);

    /* Init msghdr */
    struct msghdr msg = { 0 };

    /* Allocate a char array of suitable size to hold the ancillary data.
     * However, since this buffer is in reality a 'struct cmsghdr', use a
     * union to ensure that it is aligned as required for that structure.
     */
    union {
        char buf[CMSG_SPACE(sizeof(uint8_t))];
        struct cmsghdr _align;
    } control_msg = { 0 };
    msg.msg_control = control_msg.buf;
    msg.msg_controllen = sizeof(control_msg.buf);

    RESULT_GUARD(s2n_ktls_set_ancillary_data(&msg, record_type));
    RESULT_GUARD(s2n_ktls_send_msg_impl(sock, &msg, msg_iov, count, blocked, send_len));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ktls_recv_msg_impl(struct s2n_connection *conn, int sock, struct msghdr *msg,
        struct iovec *msg_iov, s2n_blocked_status *blocked, ssize_t *bytes_read)
{
    RESULT_ENSURE_REF(msg);
    RESULT_ENSURE_REF(msg_iov);
    RESULT_ENSURE_REF(blocked);
    RESULT_ENSURE_REF(bytes_read);

    /* set receive buffer */
    msg->msg_iov = msg_iov;
    msg->msg_iovlen = 1;

    *blocked = S2N_BLOCKED_ON_READ;
    *bytes_read = recvmsg(sock, msg, 0);

    /* The return value will be 0 when the peer has performed an orderly shutdown. */
    if (*bytes_read == 0) {
        *bytes_read = 0;
        s2n_atomic_flag_set(&conn->read_closed);
        RESULT_BAIL(S2N_ERR_CLOSED);
    } else if (*bytes_read < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            RESULT_BAIL(S2N_ERR_IO_BLOCKED);
        }
        RESULT_BAIL(S2N_ERR_IO);
    }
    *blocked = S2N_NOT_BLOCKED;

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ktls_parse_ancillary_data(struct msghdr *msg, uint8_t *record_type)
{
    RESULT_ENSURE_REF(msg);
    RESULT_ENSURE_REF(record_type);

    RESULT_ENSURE_REF(msg->msg_control);
    RESULT_ENSURE_GTE(msg->msg_controllen, CMSG_SPACE(sizeof(uint8_t)));

    /* attempt to read the ancillary data */
    struct cmsghdr *hdr = CMSG_FIRSTHDR(msg);
    RESULT_ENSURE(hdr != NULL, S2N_ERR_IO);

    /* iterate over all headers until it matches RECORD_TYPE.
     * CMSG_NXTHDR will return NULL if there are no more cmsg */
    while (hdr != NULL) {
        if (hdr->cmsg_level == S2N_SOL_TLS && hdr->cmsg_type == S2N_TLS_GET_RECORD_TYPE) {
            *record_type = *(unsigned char *) CMSG_DATA(hdr);
            return S2N_RESULT_OK;
        }

        /* attempt to get the next header */
        hdr = CMSG_NXTHDR(msg, hdr);
    }

    /* return an IO error if no record was received */
    RESULT_BAIL(S2N_ERR_IO);
}

/* Best practices taken from
 * https://man7.org/tlpi/code/online/dist/sockets/scm_cred_recv.c.html */
S2N_RESULT s2n_ktls_recv_msg(struct s2n_connection *conn, int sock, uint8_t *buf, size_t length,
        uint8_t *record_type, s2n_blocked_status *blocked, ssize_t *bytes_read)
{
    RESULT_ENSURE_REF(buf);
    RESULT_ENSURE_REF(record_type);
    RESULT_ENSURE_REF(blocked);
    RESULT_ENSURE_REF(bytes_read);
    RESULT_ENSURE_GT(length, 0);

    /* Init msghdr */
    struct msghdr msg = { 0 };

    /* Allocate a char array of suitable size to hold the ancillary data.
     * However, since this buffer is in reality a 'struct cmsghdr', use a
     * union to ensure that it is aligned as required for that structure.
     */
    union {
        /* alloc enough space incase the application recieves more than one cmsg */
        char buf[CMSG_SPACE(sizeof(uint8_t)) * 4];
        struct cmsghdr _align;
    } control_msg = { 0 };
    msg.msg_control = control_msg.buf;
    msg.msg_controllen = sizeof(control_msg.buf);

    struct iovec msg_iov = { 0 };
    msg_iov.iov_base = buf;
    msg_iov.iov_len = length;

    /* receive msg */
    RESULT_GUARD(s2n_ktls_recv_msg_impl(conn, sock, &msg, &msg_iov, blocked, bytes_read));
    RESULT_GUARD(s2n_ktls_parse_ancillary_data(&msg, record_type));

    return S2N_RESULT_OK;
}
#else

S2N_RESULT s2n_ktls_send_msg_impl(int sock, struct msghdr *msg,
        struct iovec *msg_iov, size_t count, s2n_blocked_status *blocked, ssize_t *send_len)
{
    RESULT_BAIL(S2N_ERR_KTLS_UNSUPPORTED_PLATFORM);
}
S2N_RESULT s2n_ktls_recv_msg_impl(struct s2n_connection *conn, int sock, struct msghdr *msg,
        struct iovec *msg_iov, s2n_blocked_status *blocked, ssize_t *bytes_read)
{
    RESULT_BAIL(S2N_ERR_KTLS_UNSUPPORTED_PLATFORM);
}
S2N_RESULT s2n_ktls_parse_ancillary_data(struct msghdr *msg, uint8_t *record_type)
{
    RESULT_BAIL(S2N_ERR_KTLS_UNSUPPORTED_PLATFORM);
}
S2N_RESULT s2n_ktls_set_ancillary_data(struct msghdr *msg, uint8_t record_type)
{
    RESULT_BAIL(S2N_ERR_KTLS_UNSUPPORTED_PLATFORM);
}

#endif
