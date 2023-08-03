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

#include "tls/s2n_connection.h"
#include "tls/s2n_ktls.h"

#define S2N_TEST_KTLS_MOCK_HEADER_SIZE     3
#define S2N_TEST_KTLS_MOCK_HEADER_TAG_SIZE 1

/* The record_type is communicated via ancillary data when using kTLS. For this
 * reason s2n must use `send/recvmsg` syscalls rather than `send/read`. To mimic
 * the send/recvmsg calls more accurately, we mock the socket via two separate
 * buffers: data_buffer and ancillary_buffer.
 *
 * The mock implementation, uses 3 bytes with a tag + len format to represent
 * each record. The first byte(tag) is the record_type and the next two represent
 * the length of the record. Length is represented as a u16 to capture the max
 * possible TLS record length.
 *
 * memory layout per record:
 * ```
 *    [     u8    |    u16    ]
 *     record_type   length
 * ```
 *
 * memory layout of ancillary_buffer with 3 records and how it maps
 * to the data_buffer:
 * ```
 *            ancillary_buffer
 *    [ [record] [record] [record] ]
 *    [ [u8|u16] [u8|u16] [u8|u16] ]
 *    [  [23|5]   [23|7]    [21|2] ]
 *           |        |         |
 *     v-------v v-----------v v-v
 *    [1 2 3 4 5 1 2 3 4 5 6 7 1 2]
 *              data_buffer
 * ```
 */
struct s2n_test_ktls_io_stuffer {
    struct s2n_stuffer ancillary_buffer;
    struct s2n_stuffer data_buffer;
    size_t send_recv_msg_invoked_count;
};
struct s2n_test_ktls_io_pair {
    struct s2n_test_ktls_io_stuffer client_in;
    struct s2n_test_ktls_io_stuffer server_in;
};
ssize_t s2n_test_ktls_sendmsg_stuffer_io(void *io_context, const struct msghdr *msg, uint8_t record_type);
ssize_t s2n_test_ktls_recvmsg_stuffer_io(void *io_context, struct msghdr *msg, uint8_t *record_type);

S2N_RESULT s2n_test_init_ktls_stuffer_io(struct s2n_connection *server, struct s2n_connection *client,
        struct s2n_test_ktls_io_pair *io_pair);
S2N_RESULT s2n_test_ktls_update_prev_header_len(struct s2n_test_ktls_io_stuffer *io_ctx, uint16_t new_len);
S2N_CLEANUP_RESULT s2n_ktls_io_pair_free(struct s2n_test_ktls_io_pair *ctx);
