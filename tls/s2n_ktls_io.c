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

/* Used to override sendmsg and recvmsg for testing. */
static ssize_t s2n_ktls_default_sendmsg(struct s2n_connection *conn, struct msghdr *msg, uint8_t record_type);
static ssize_t s2n_ktls_default_recvmsg(struct s2n_connection *conn, struct msghdr *msg, uint8_t *record_type);
s2n_ktls_sendmsg_fn s2n_sendmsg_fn = s2n_ktls_default_sendmsg;
s2n_ktls_recvmsg_fn s2n_recvmsg_fn = s2n_ktls_default_recvmsg;

/* TODO make use of record_type when we implement this function */
static ssize_t s2n_ktls_default_recvmsg(struct s2n_connection *conn, struct msghdr *msg, uint8_t *record_type)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(msg);
    POSIX_ENSURE_REF(record_type);
    /* kTLS doesn't modify the recv_io_context so its possible to retrieve the socket fd */
    int fd = 0;
    POSIX_GUARD_RESULT(s2n_ktls_get_file_descriptor(conn, S2N_KTLS_MODE_RECV, &fd));

    return recvmsg(fd, msg, 0);
}

/* TODO make use of record_type when we implement this function */
static ssize_t s2n_ktls_default_sendmsg(struct s2n_connection *conn, struct msghdr *msg, uint8_t record_type)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(msg);
    /* kTLS doesn't modify the send_io_context so its possible to retrieve the socket fd */
    int fd = 0;
    POSIX_GUARD_RESULT(s2n_ktls_get_file_descriptor(conn, S2N_KTLS_MODE_SEND, &fd));

    return sendmsg(fd, msg, 0);
}

S2N_RESULT s2n_ktls_set_send_recv_msg_fn(s2n_ktls_sendmsg_fn send_cb, s2n_ktls_recvmsg_fn recv_cb)
{
    RESULT_ENSURE(s2n_in_test(), S2N_ERR_NOT_IN_TEST);
    s2n_sendmsg_fn = send_cb;
    s2n_recvmsg_fn = recv_cb;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ktls_set_send_recv_msg_ctx(struct s2n_connection *conn, void *send_ctx, void *recv_ctx)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(send_ctx);
    RESULT_ENSURE_REF(recv_ctx);
    RESULT_ENSURE(s2n_in_test(), S2N_ERR_NOT_IN_TEST);

    conn->send_io_context = send_ctx;
    conn->recv_io_context = recv_ctx;
    return S2N_RESULT_OK;
}
