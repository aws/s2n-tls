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
 * The mock implementation uses 3 bytes with a tag + len format to represent
 * each record. The first byte represents the record_type and the next two represent
 * the length of the record. Length is represented as a u16 to capture the max
 * possible TLS record length.
 *
 * Example: ancillary_buffer memory layout per record:
 * ```
 *    [     u8    |    u16    ]
 *     record_type   length
 * ```
 *
 * Example: memory layout of ancillary_buffer and data_buffer with 3 records:
 * ```
 *            ancillary_buffer
 *
 *    [ [record] [record] [record] ]
 *    [ [u8|u16] [u8|u16] [u8|u16] ]
 *    [  [23|5]   [23|7]    [21|2] ]
 *           |        |         |
 *     v-------v v-----------v v-v
 *    [1 2 3 4 5 1 2 3 4 5 6 7 1 2]
 *
 *              data_buffer
 * ```
 */
struct s2n_test_ktls_io_stuffer {
    struct s2n_stuffer ancillary_buffer;
    struct s2n_stuffer data_buffer;
    size_t sendmsg_invoked_count;
    size_t recvmsg_invoked_count;
};
struct s2n_test_ktls_io_stuffer_pair {
    struct s2n_test_ktls_io_stuffer client_in;
    struct s2n_test_ktls_io_stuffer server_in;
};
ssize_t s2n_test_ktls_sendmsg_io_stuffer(void *io_context, const struct msghdr *msg);
ssize_t s2n_test_ktls_recvmsg_io_stuffer(void *io_context, struct msghdr *msg);

S2N_RESULT s2n_test_init_ktls_io_stuffer_send(struct s2n_connection *conn,
        struct s2n_test_ktls_io_stuffer *io);
S2N_RESULT s2n_test_init_ktls_io_stuffer(struct s2n_connection *server,
        struct s2n_connection *client, struct s2n_test_ktls_io_stuffer_pair *io_pair);
S2N_CLEANUP_RESULT s2n_ktls_io_stuffer_free(struct s2n_test_ktls_io_stuffer *io);
S2N_CLEANUP_RESULT s2n_ktls_io_stuffer_pair_free(struct s2n_test_ktls_io_stuffer_pair *pair);
S2N_RESULT s2n_test_validate_data(struct s2n_test_ktls_io_stuffer *ktls_io,
        const uint8_t *expected_data, uint16_t expected_len);
S2N_RESULT s2n_test_validate_ancillary(struct s2n_test_ktls_io_stuffer *ktls_io,
        uint8_t expected_record_type, uint16_t expected_len);
S2N_RESULT s2n_test_records_in_ancillary(struct s2n_test_ktls_io_stuffer *ktls_io,
        uint16_t expected_records);
