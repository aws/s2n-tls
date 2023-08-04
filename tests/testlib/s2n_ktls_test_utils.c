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

#include "testlib/s2n_ktls_test_utils.h"

/* Since it is possible to read partial data, we need a way to update the length
 * of the previous record for the mock stuffer IO implementation. */
static S2N_RESULT s2n_test_ktls_update_prev_header_len(struct s2n_test_ktls_io_stuffer *io_ctx, uint16_t remaining_len)
{
    RESULT_ENSURE_REF(io_ctx);
    RESULT_ENSURE(remaining_len > 0, S2N_ERR_IO);

    /* rewind so we can read the last header with the updated len */
    RESULT_GUARD_POSIX(s2n_stuffer_rewind_read(&io_ctx->ancillary_buffer, S2N_TEST_KTLS_MOCK_HEADER_SIZE));

    /* get position for the last header's length */
    uint32_t rewrite_len_ptr = io_ctx->ancillary_buffer.read_cursor + S2N_TEST_KTLS_MOCK_HEADER_TAG_SIZE;
    /* create a new stuffer pointing to len data and rewrite it */
    struct s2n_stuffer rewrite_len_stuffer = io_ctx->ancillary_buffer;
    RESULT_GUARD_POSIX(s2n_stuffer_rewrite(&rewrite_len_stuffer));
    RESULT_GUARD_POSIX(s2n_stuffer_skip_write(&rewrite_len_stuffer, rewrite_len_ptr));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(&rewrite_len_stuffer, remaining_len));

    return S2N_RESULT_OK;
}

ssize_t s2n_test_ktls_sendmsg_stuffer_io(void *io_context, const struct msghdr *msg)
{
    POSIX_ENSURE_REF(io_context);
    POSIX_ENSURE_REF(msg);
    POSIX_ENSURE_REF(msg->msg_iov);

    uint8_t *record_type = (uint8_t *) msg->msg_control;
    POSIX_ENSURE_REF(record_type);
    struct s2n_test_ktls_io_stuffer *io_ctx = (struct s2n_test_ktls_io_stuffer *) io_context;
    POSIX_ENSURE_REF(io_ctx);
    io_ctx->send_recv_msg_invoked_count++;

    size_t total_len = 0;
    for (size_t count = 0; count < msg->msg_iovlen; count++) {
        uint8_t *buf = msg->msg_iov[count].iov_base;
        POSIX_ENSURE_REF(buf);
        size_t len = msg->msg_iov[count].iov_len;

        if (s2n_stuffer_write_bytes(&io_ctx->data_buffer, buf, len) < 0) {
            /* This mock implementation doesn't handle partial writes for msg_iovlen > 1.
             *
             * This simplifies the implementation and importantly doesn't limit our test
             * coverage because partial write are handled the same regardless of
             * msg_iovlen. */
            POSIX_ENSURE(count == 0, S2N_ERR_SAFETY);

            errno = EAGAIN;
            return -1;
        }

        total_len += len;
    }
    if (total_len) {
        /* write record_type and len after some data was written successfully */
        POSIX_GUARD(s2n_stuffer_write_uint8(&io_ctx->ancillary_buffer, *record_type));
        POSIX_GUARD(s2n_stuffer_write_uint16(&io_ctx->ancillary_buffer, total_len));
    }

    return total_len;
}

/* In userspace TLS, s2n first reads the header to determine the length of next record
 * and then reads the entire record into conn->in. In kTLS it is not possible to know
 * the length of the next record. Instead the socket returns the minimum of
 * bytes-requested and data-available; reading multiple consecutive records if they
 * are of the same type. */
ssize_t s2n_test_ktls_recvmsg_stuffer_io(void *io_context, struct msghdr *msg)
{
    POSIX_ENSURE_REF(io_context);
    POSIX_ENSURE_REF(msg);
    POSIX_ENSURE_REF(msg->msg_iov);

    uint8_t *record_type = (uint8_t *) msg->msg_control;
    POSIX_ENSURE_REF(record_type);
    struct s2n_test_ktls_io_stuffer *io_ctx = (struct s2n_test_ktls_io_stuffer *) io_context;
    POSIX_ENSURE_REF(io_ctx);
    io_ctx->send_recv_msg_invoked_count++;
    /* s2n only receives using msg_iovlen of 1 */
    POSIX_ENSURE_EQ(msg->msg_iovlen, 1);
    uint8_t *buf = msg->msg_iov->iov_base;
    POSIX_ENSURE_REF(buf);

    /* There is no data available so return blocked */
    if (!s2n_stuffer_data_available(&io_ctx->ancillary_buffer)) {
        errno = EAGAIN;
        return -1;
    }

    ssize_t total_read = 0;
    size_t amount_requested = msg->msg_iov->iov_len;
    while (true) {
        /* read record_type and number of bytes available in the next record */
        POSIX_GUARD(s2n_stuffer_read_uint8(&io_ctx->ancillary_buffer, record_type));
        uint16_t n_avail = 0;
        POSIX_GUARD(s2n_stuffer_read_uint16(&io_ctx->ancillary_buffer, &n_avail));
        POSIX_ENSURE_LTE(n_avail, s2n_stuffer_data_available(&io_ctx->data_buffer));

        /* read minimum of requested_len and bytes_available */
        size_t n_read = MIN(amount_requested, n_avail);
        POSIX_ENSURE_GT(n_read, 0);
        POSIX_GUARD(s2n_stuffer_read_bytes(&io_ctx->data_buffer, buf + total_read, n_read));

        amount_requested -= n_read;
        POSIX_ENSURE_GTE(amount_requested, 0);
        total_read += n_read;

        /* handle partially read records */
        ssize_t remaining_len = n_avail - n_read;
        if (remaining_len) {
            POSIX_GUARD_RESULT(s2n_test_ktls_update_prev_header_len(io_ctx, remaining_len));
        }

        /* if we have read the amount_requested then we are done */
        if (amount_requested == 0) {
            break;
        }
        /* attempt to read multiple records (must be of the same type) */
        if (amount_requested) {
            uint8_t next_record_type = 0;
            int ret = s2n_stuffer_peek_char(&io_ctx->ancillary_buffer, (char *) &next_record_type);
            bool no_more_records = ret < 0;
            bool next_record_different_type = next_record_type != *record_type;
            if (no_more_records || next_record_different_type) {
                break;
            }
        }
    }

    return total_read;
}

S2N_RESULT s2n_test_init_ktls_stuffer_io(struct s2n_connection *server, struct s2n_connection *client,
        struct s2n_test_ktls_io_pair *io_pair)
{
    RESULT_ENSURE_REF(server);
    RESULT_ENSURE_REF(client);
    RESULT_ENSURE_REF(io_pair);
    /* setup stuffer IO */
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(&io_pair->server_in.data_buffer, 0));
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(&io_pair->server_in.ancillary_buffer, 0));
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(&io_pair->client_in.data_buffer, 0));
    RESULT_GUARD_POSIX(s2n_stuffer_growable_alloc(&io_pair->client_in.ancillary_buffer, 0));

    RESULT_GUARD(s2n_ktls_set_sendmsg_cb(server, s2n_test_ktls_sendmsg_stuffer_io, &io_pair->client_in));
    RESULT_GUARD(s2n_ktls_set_recvmsg_cb(server, s2n_test_ktls_recvmsg_stuffer_io, &io_pair->server_in));
    RESULT_GUARD(s2n_ktls_set_sendmsg_cb(client, s2n_test_ktls_sendmsg_stuffer_io, &io_pair->server_in));
    RESULT_GUARD(s2n_ktls_set_recvmsg_cb(client, s2n_test_ktls_recvmsg_stuffer_io, &io_pair->client_in));

    return S2N_RESULT_OK;
}

S2N_CLEANUP_RESULT s2n_ktls_io_pair_free(struct s2n_test_ktls_io_pair *ctx)
{
    RESULT_ENSURE_REF(ctx);
    RESULT_GUARD_POSIX(s2n_stuffer_free(&ctx->client_in.data_buffer));
    RESULT_GUARD_POSIX(s2n_stuffer_free(&ctx->client_in.ancillary_buffer));
    RESULT_GUARD_POSIX(s2n_stuffer_free(&ctx->server_in.data_buffer));
    RESULT_GUARD_POSIX(s2n_stuffer_free(&ctx->server_in.ancillary_buffer));

    return S2N_RESULT_OK;
}
