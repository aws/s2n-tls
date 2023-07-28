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

/* These MOCK_IO* macros set errno before returning an error. These macros are
 * mainly used for IO related operations (stuffer writes, NULL arguments,
 * invalid length). Other sanity checks are guarded by the POSIX* macros.
 *
 * EINVAL will always be treated as a fatal errno code so its sufficient to
 * use that as the generic errno code in the guard macros. */
#define MOCK_IO_ENSURE(x)   \
    do {                    \
        if (!(x)) {         \
            errno = EINVAL; \
            return -1;      \
        }                   \
    } while (0)

#define MOCK_IO_GUARD(x) \
    MOCK_IO_ENSURE((x) > S2N_FAILURE)

#define MOCK_IO_ENSURE_REF(x) \
    MOCK_IO_ENSURE(S2N_OBJECT_PTR_IS_READABLE(x))

static S2N_RESULT s2n_ktls_validate_ktls_io(struct s2n_test_ktls_io_stuffer *io_ctx)
{
    RESULT_ENSURE_REF(io_ctx);

    /* Assert ancillary_buffer is growable, which simplifies IO logic. Blocking IO can
     * be mocked by restricting the data_buffer. */
    RESULT_ENSURE(io_ctx->ancillary_buffer.growable, S2N_ERR_SAFETY);

    uint32_t ancillary_len = s2n_stuffer_data_available(&io_ctx->ancillary_buffer);
    uint32_t data_len = s2n_stuffer_data_available(&io_ctx->data_buffer);

    /* ensure ancillary data is not malformed */
    RESULT_ENSURE(ancillary_len % S2N_TEST_KTLS_MOCK_HEADER_SIZE == 0, S2N_ERR_SAFETY);
    if (ancillary_len == 0) {
        RESULT_ENSURE(data_len == 0, S2N_ERR_SAFETY);
    }

    return S2N_RESULT_OK;
}

/* Since its possible to read partial data, we need a way to update the length
 * of the previous record for the mock stuffer IO implementation. */
S2N_RESULT s2n_test_ktls_update_prev_header_len(struct s2n_test_ktls_io_stuffer *io_ctx, uint16_t remaining_len)
{
    RESULT_ENSURE_REF(io_ctx);
    RESULT_ENSURE(remaining_len > 0, S2N_ERR_SAFETY);

    /* rewind the read ptr */
    RESULT_GUARD_POSIX(s2n_stuffer_rewind_read(&io_ctx->ancillary_buffer, S2N_TEST_KTLS_MOCK_HEADER_LENGTH_SIZE));

    /* rewrite the length */
    uint8_t *ptr = s2n_stuffer_raw_read(&io_ctx->ancillary_buffer, S2N_TEST_KTLS_MOCK_HEADER_LENGTH_SIZE);
    struct s2n_blob ancillary_blob = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&ancillary_blob, ptr, S2N_TEST_KTLS_MOCK_HEADER_LENGTH_SIZE));
    struct s2n_stuffer ancillary_stuffer = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init(&ancillary_stuffer, &ancillary_blob));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(&ancillary_stuffer, remaining_len));

    /* rewind to re-read the record with the remaining length */
    RESULT_GUARD_POSIX(s2n_stuffer_rewind_read(&io_ctx->ancillary_buffer, S2N_TEST_KTLS_MOCK_HEADER_SIZE));

    return S2N_RESULT_OK;
}

ssize_t s2n_test_ktls_sendmsg_stuffer_io(struct s2n_connection *conn, struct msghdr *msg, uint8_t record_type)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->send_io_context);
    POSIX_ENSURE_REF(msg);
    POSIX_ENSURE_REF(msg->msg_iov);

    struct s2n_test_ktls_io_stuffer *io_ctx = (struct s2n_test_ktls_io_stuffer *) conn->send_io_context;
    POSIX_ENSURE_REF(io_ctx);
    io_ctx->invoked_count++;
    POSIX_GUARD_RESULT(s2n_ktls_validate_ktls_io(io_ctx));

    size_t total_len = 0;
    for (size_t count = 0; count < msg->msg_iovlen; count++) {
        uint8_t *buf = msg->msg_iov[count].iov_base;
        MOCK_IO_ENSURE_REF(buf);
        size_t len = msg->msg_iov[count].iov_len;

        /* If we fail to write to stuffer then return blocked */
        if (s2n_stuffer_write_bytes(&io_ctx->data_buffer, buf, len) < 0) {
            POSIX_GUARD_RESULT(s2n_ktls_validate_ktls_io(io_ctx));
            errno = EAGAIN;
            return -1;
        }

        total_len += len;
    }
    /* write record_type and len after data was written successfully. ancillary_buffer is
     * growable so this operation should always succeed. */
    MOCK_IO_GUARD(s2n_stuffer_write_uint8(&io_ctx->ancillary_buffer, record_type));
    MOCK_IO_GUARD(s2n_stuffer_write_uint16(&io_ctx->ancillary_buffer, total_len));

    POSIX_GUARD_RESULT(s2n_ktls_validate_ktls_io(io_ctx));
    return total_len;
}

/* In userspace TLS, s2n first reads the header to determine the length of next record
 * and then reads the entire record into conn->in. In kTLS its not possible to know
 * the length of the next record. Instead the socket returns the minimum of
 * bytes-requested and data-available; reading multiple consecutive records if they
 * are of the same type. */
ssize_t s2n_test_ktls_recvmsg_stuffer_io(struct s2n_connection *conn, struct msghdr *msg, uint8_t *record_type)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->recv_io_context);
    POSIX_ENSURE_REF(msg);
    POSIX_ENSURE_REF(msg->msg_iov);

    struct s2n_test_ktls_io_stuffer *io_ctx = (struct s2n_test_ktls_io_stuffer *) conn->recv_io_context;
    POSIX_ENSURE_REF(io_ctx);
    POSIX_GUARD_RESULT(s2n_ktls_validate_ktls_io(io_ctx));
    io_ctx->invoked_count++;

    /* s2n only receives using msg_iovlen of 1 */
    MOCK_IO_ENSURE(msg->msg_iovlen == 1);

    uint8_t *buf = msg->msg_iov->iov_base;
    MOCK_IO_ENSURE_REF(buf);

    /* There is no data available so return blocked */
    if (!s2n_stuffer_data_available(&io_ctx->ancillary_buffer)) {
        POSIX_GUARD_RESULT(s2n_ktls_validate_ktls_io(io_ctx));
        errno = EAGAIN;
        return -1;
    }

    ssize_t total_read = 0;
    /* updated as partial or multiple records are read */
    size_t updated_requested_len = msg->msg_iov->iov_len;
    /* track two record_types since its possible to read multiple records of the same type */
    *record_type = 0;
    uint8_t next_record_type = 0;
    while (*record_type == next_record_type) {
        /* read record_type and number of bytes available in the next record */
        MOCK_IO_GUARD(s2n_stuffer_read_uint8(&io_ctx->ancillary_buffer, record_type));
        uint16_t n_avail = 0;
        MOCK_IO_GUARD(s2n_stuffer_read_uint16(&io_ctx->ancillary_buffer, &n_avail));
        POSIX_ENSURE_LTE(n_avail, s2n_stuffer_data_available(&io_ctx->data_buffer));

        size_t n_read = MIN(updated_requested_len, n_avail);
        MOCK_IO_ENSURE(n_read > 0);

        /* we have already verified that there is more data, so this should succeed */
        MOCK_IO_GUARD(s2n_stuffer_read_bytes(&io_ctx->data_buffer, buf + total_read, n_read));
        updated_requested_len -= n_read;
        POSIX_ENSURE_GTE(updated_requested_len, 0);
        total_read += n_read;

        /* Handle if we partially read a record */
        ssize_t remaining_len = n_avail - n_read;
        if (remaining_len) {
            POSIX_GUARD_RESULT(s2n_test_ktls_update_prev_header_len(io_ctx, remaining_len));
        }

        /* if already read the requested amount then break */
        if (updated_requested_len == 0) {
            break;
        }
        /* Attempt to read multiple records (must be of the same type) */
        if (updated_requested_len) {
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

S2N_RESULT s2n_test_validate_data(struct s2n_test_ktls_io_stuffer *ktls_io, uint8_t *expected_data, uint16_t len)
{
    RESULT_ENSURE_REF(ktls_io);
    RESULT_ENSURE_REF(expected_data);

    /* verify data */
    struct s2n_stuffer *stuffer = &ktls_io->data_buffer;
    RESULT_ENSURE_EQ(s2n_stuffer_data_available(stuffer), len);
    uint8_t *data_ptr = s2n_stuffer_raw_read(stuffer, len);
    RESULT_ENSURE_REF(data_ptr);
    RESULT_ENSURE_EQ(memcmp(data_ptr, expected_data, len), 0);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_test_validate_ancillary(struct s2n_test_ktls_io_stuffer *ktls_io, uint8_t expected_record_type, uint16_t len)
{
    RESULT_ENSURE_REF(ktls_io);
    /* create expected ancillary header */
    RESULT_STACK_BLOB(expected_ancillary, S2N_TEST_KTLS_MOCK_HEADER_SIZE, S2N_TEST_KTLS_MOCK_HEADER_SIZE);
    struct s2n_stuffer expected_ancillary_stuffer = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init(&expected_ancillary_stuffer, &expected_ancillary));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint8(&expected_ancillary_stuffer, expected_record_type));
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(&expected_ancillary_stuffer, len));

    /* verify ancillary data */
    uint8_t *ancillary_ptr = s2n_stuffer_raw_read(&ktls_io->ancillary_buffer, S2N_TEST_KTLS_MOCK_HEADER_SIZE);
    RESULT_ENSURE_REF(ancillary_ptr);
    RESULT_ENSURE_EQ(memcmp(ancillary_ptr, expected_ancillary_buf, S2N_TEST_KTLS_MOCK_HEADER_SIZE), 0);

    return S2N_RESULT_OK;
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

    RESULT_GUARD(s2n_ktls_set_send_recv_msg_fn(s2n_test_ktls_sendmsg_stuffer_io, s2n_test_ktls_recvmsg_stuffer_io));
    RESULT_GUARD(s2n_ktls_set_send_recv_msg_ctx(server, &io_pair->client_in, &io_pair->server_in));
    RESULT_GUARD(s2n_ktls_set_send_recv_msg_ctx(client, &io_pair->server_in, &io_pair->client_in));

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
