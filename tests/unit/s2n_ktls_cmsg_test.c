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

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_ktls.h"
#include "utils/s2n_random.h"

S2N_RESULT s2n_ktls_send_msg_impl(int sock, struct msghdr *msg,
        struct iovec *msg_iov, size_t count, s2n_blocked_status *blocked, ssize_t *send_len);
S2N_RESULT s2n_ktls_recv_msg_impl(struct s2n_connection *conn, int sock, struct msghdr *msg,
        struct iovec *msg_iov, s2n_blocked_status *blocked, ssize_t *bytes_read);
S2N_RESULT s2n_ktls_set_ancillary_data(struct msghdr *msg, uint8_t record_type);
S2N_RESULT s2n_ktls_parse_ancillary_data(struct msghdr *msg, uint8_t *record_type);

#define TEST_MAX_DATA_LEN 20000
uint8_t TEST_SEND_RECORD_TYPE = 10;

int main(int argc, char **argv)
{
    BEGIN_TEST();

#if !S2N_KTLS_SUPPORTED /* CMSG_* macros are platform specific */
    char buf[sizeof(uint8_t)] = { 0 };

    /* Init msghdr */
    struct msghdr msg = { 0 };
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(uint8_t);

    EXPECT_ERROR_WITH_ERRNO(s2n_ktls_set_ancillary_data(&msg, TEST_SEND_RECORD_TYPE), S2N_ERR_KTLS_UNSUPPORTED_PLATFORM);
    uint8_t record_type = 0;
    EXPECT_ERROR_WITH_ERRNO(s2n_ktls_parse_ancillary_data(&msg, &record_type), S2N_ERR_KTLS_UNSUPPORTED_PLATFORM);

#else /* kTLS supported */

    uint8_t test_data[TEST_MAX_DATA_LEN] = { 0 };
    struct s2n_blob test_data_blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&test_data_blob, test_data, sizeof(test_data)));
    EXPECT_OK(s2n_get_public_random_data(&test_data_blob));

    /* Test send/recv msg */
    {
        /* ctrl_msg send and recv data */
        for (size_t to_send = 1; to_send < TEST_MAX_DATA_LEN; to_send += 500) {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;

            /* init send msg */
            struct msghdr send_msg = { 0 };
            struct iovec send_msg_iov = { 0 };
            send_msg_iov.iov_base = (void *) (uintptr_t) test_data;
            send_msg_iov.iov_len = to_send;
            /* init rev msg */
            uint8_t recv_buffer[TEST_MAX_DATA_LEN] = { 0 };
            struct msghdr recv_msg = { 0 };
            struct iovec recv_msg_iov = { 0 };
            recv_msg_iov.iov_base = recv_buffer;
            recv_msg_iov.iov_len = to_send;

            /* send msg */
            ssize_t sent_len = 0;
            EXPECT_OK(s2n_ktls_send_msg_impl(io_pair.client, &send_msg, &send_msg_iov, 1, &blocked, &sent_len));
            EXPECT_EQUAL(sent_len, to_send);

            /* recv msg */
            ssize_t recv_len = 0;
            EXPECT_OK(s2n_ktls_recv_msg_impl(conn, io_pair.server, &recv_msg, &recv_msg_iov, &blocked, &recv_len));
            EXPECT_EQUAL(recv_len, to_send);
            EXPECT_EQUAL(memcmp(test_data, recv_buffer, recv_len), 0);
        }

        /* partial reads */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;

            /* only read half the total data sent to simulate multiple reads */
            size_t to_send = 10;
            size_t to_recv = 4;

            /* init send msg */
            struct msghdr send_msg = { 0 };
            struct iovec send_msg_iov = { 0 };
            send_msg_iov.iov_base = (void *) (uintptr_t) test_data;
            send_msg_iov.iov_len = to_send;
            /* init rev msg */
            uint8_t recv_buffer[TEST_MAX_DATA_LEN] = { 0 };
            struct msghdr recv_msg = { 0 };
            struct iovec recv_msg_iov = { 0 };
            recv_msg_iov.iov_base = recv_buffer;

            /* send msg */
            ssize_t sent_len = 0;
            EXPECT_OK(s2n_ktls_send_msg_impl(io_pair.client, &send_msg, &send_msg_iov, 1, &blocked, &sent_len));
            EXPECT_EQUAL(sent_len, to_send);

            /* read partial amount */
            recv_msg_iov.iov_len = to_recv;
            ssize_t recv_len = 0;
            EXPECT_OK(s2n_ktls_recv_msg_impl(conn, io_pair.server, &recv_msg, &recv_msg_iov, &blocked, &recv_len));
            EXPECT_EQUAL(recv_len, to_recv);
            EXPECT_EQUAL(memcmp(test_data, recv_buffer, to_recv), 0);

            /* read remaining amount */
            recv_len = 0;
            recv_msg_iov.iov_len = to_send - to_recv;
            recv_msg_iov.iov_base = recv_buffer + to_recv;
            EXPECT_OK(s2n_ktls_recv_msg_impl(conn, io_pair.server, &recv_msg, &recv_msg_iov, &blocked, &recv_len));
            EXPECT_EQUAL(recv_len, to_send - to_recv);

            /* confirm that all data was read and matches sent data of length `to_send` */
            EXPECT_EQUAL(memcmp(test_data, recv_buffer, to_send), 0);
        }

        /* blocked reads */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;

            size_t to_send = 10;

            /* init send msg */
            struct msghdr send_msg = { 0 };
            struct iovec send_msg_iov = { 0 };
            send_msg_iov.iov_base = (void *) (uintptr_t) test_data;
            send_msg_iov.iov_len = to_send;
            /* init rev msg */
            uint8_t recv_buffer[TEST_MAX_DATA_LEN] = { 0 };
            struct msghdr recv_msg = { 0 };
            struct iovec recv_msg_iov = { 0 };
            recv_msg_iov.iov_base = recv_buffer;
            recv_msg_iov.iov_len = to_send;

            /* send msg */
            ssize_t sent_len = 0;
            EXPECT_OK(s2n_ktls_send_msg_impl(io_pair.client, &send_msg, &send_msg_iov, 1, &blocked, &sent_len));
            EXPECT_EQUAL(sent_len, to_send);

            /* recv msg */
            ssize_t recv_len = 0;
            EXPECT_OK(s2n_ktls_recv_msg_impl(conn, io_pair.server, &recv_msg, &recv_msg_iov, &blocked, &recv_len));
            EXPECT_EQUAL(recv_len, to_send);
            EXPECT_EQUAL(memcmp(test_data, recv_buffer, to_send), 0);

            /* calling recv after all data has been read blocks */
            recv_len = 0;
            recv_msg_iov.iov_len = 1;
            EXPECT_ERROR_WITH_ERRNO(s2n_ktls_recv_msg_impl(conn, io_pair.server, &recv_msg, &recv_msg_iov, &blocked, &recv_len), S2N_ERR_IO_BLOCKED);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
        }

        /* check for peer closed */
        {
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;

            size_t to_send = 10;

            /* init send msg */
            struct msghdr send_msg = { 0 };
            struct iovec send_msg_iov = { 0 };
            send_msg_iov.iov_base = (void *) (uintptr_t) test_data;
            send_msg_iov.iov_len = to_send;
            /* init rev msg */
            uint8_t recv_buffer[TEST_MAX_DATA_LEN] = { 0 };
            struct msghdr recv_msg = { 0 };
            struct iovec recv_msg_iov = { 0 };
            recv_msg_iov.iov_base = recv_buffer;
            recv_msg_iov.iov_len = to_send;

            /* send msg */
            ssize_t sent_len = 0;
            EXPECT_OK(s2n_ktls_send_msg_impl(io_pair.client, &send_msg, &send_msg_iov, 1, &blocked, &sent_len));
            EXPECT_EQUAL(sent_len, to_send);

            /* recv msg */
            ssize_t recv_len = 0;
            EXPECT_OK(s2n_ktls_recv_msg_impl(conn, io_pair.server, &recv_msg, &recv_msg_iov, &blocked, &recv_len));
            EXPECT_EQUAL(recv_len, to_send);
            EXPECT_EQUAL(memcmp(test_data, recv_buffer, to_send), 0);

            /* simulate the peer closing the socket */
            close(io_pair.client);

            /* calling recv after all data has been read blocks */
            EXPECT_FALSE(s2n_atomic_flag_test(&conn->read_closed));
            recv_len = 0;
            recv_msg_iov.iov_len = 1;
            EXPECT_ERROR_WITH_ERRNO(s2n_ktls_recv_msg_impl(conn, io_pair.server, &recv_msg, &recv_msg_iov, &blocked, &recv_len), S2N_ERR_CLOSED);
            EXPECT_TRUE(s2n_atomic_flag_test(&conn->read_closed));
        }
    }

    /* Test parse/add ancillary data */
    {
        /* set ancillary data */
        {
            union {
                char buf[CMSG_SPACE(sizeof(uint8_t)) * 2];
                struct cmsghdr _align;
            } control_msg = { 0 };

            /* Init msghdr */
            struct msghdr send_msg = { 0 };
            send_msg.msg_control = control_msg.buf;
            send_msg.msg_controllen = sizeof(control_msg.buf);
            EXPECT_TRUE(send_msg.msg_controllen == CMSG_SPACE(sizeof(uint8_t)) * 2);

            /* add ancillary data */
            EXPECT_OK(s2n_ktls_set_ancillary_data(&send_msg, TEST_SEND_RECORD_TYPE));

            /* validate 1st header */
            struct cmsghdr *hdr = CMSG_FIRSTHDR(&send_msg);
            EXPECT_NOT_NULL(hdr);
            EXPECT_EQUAL(hdr->cmsg_level, S2N_SOL_TLS);
            EXPECT_EQUAL(hdr->cmsg_type, S2N_TLS_SET_RECORD_TYPE);
            uint8_t *record_type = (unsigned char *) CMSG_DATA(hdr);
            EXPECT_EQUAL(*record_type, TEST_SEND_RECORD_TYPE);

            /* validate that there is a 2 header and is zeroed */
            hdr = CMSG_NXTHDR(&send_msg, hdr);
            EXPECT_NOT_NULL(hdr);
            EXPECT_EQUAL(hdr->cmsg_level, 0);
            EXPECT_EQUAL(hdr->cmsg_type, 0);
            record_type = (unsigned char *) CMSG_DATA(hdr);
            EXPECT_EQUAL(*record_type, 0);

            /* validate that a 3rd header doesnt exist */
            hdr = CMSG_NXTHDR(&send_msg, hdr);
            EXPECT_NULL(hdr);
        }

        /* creating and parsing ancillary data */
        {
            union {
                char buf[CMSG_SPACE(sizeof(uint8_t)) * 2];
                struct cmsghdr _align;
            } control_msg = { 0 };
            /* Init msghdr */
            struct msghdr msg = { 0 };
            msg.msg_control = control_msg.buf;
            msg.msg_controllen = sizeof(control_msg.buf);

            /* add ancillary data */
            EXPECT_OK(s2n_ktls_set_ancillary_data(&msg, TEST_SEND_RECORD_TYPE));
            /* modify control_msg for the recv side. cmsg_type is GET_RECORD_TYPE on the receiving socket */
            struct cmsghdr *hdr = CMSG_FIRSTHDR(&msg);
            hdr->cmsg_type = S2N_TLS_GET_RECORD_TYPE;

            /* parse ancillary data */
            uint8_t recv_record_type = 0;
            EXPECT_OK(s2n_ktls_parse_ancillary_data(&msg, &recv_record_type));
            EXPECT_EQUAL(recv_record_type, TEST_SEND_RECORD_TYPE);
        }

        /* iterating multiple ancillary data */
        {
            uint8_t MALFORMED_RECORD_TYPE = 32;
            uint8_t CORRECT_RECORD_TYPE = 42;

            union {
                /* Space large enough to hold 2 record_type */
                char buf[CMSG_SPACE(sizeof(uint8_t)) * 2];
                struct cmsghdr _align;
            } control_msg = { 0 };

            /* Init msghdr */
            struct msghdr msg = { 0 };
            memset(&control_msg.buf, 0, sizeof(control_msg.buf));
            msg.msg_control = control_msg.buf;
            msg.msg_controllen = sizeof(control_msg.buf);

            /* add ancillary data */
            EXPECT_OK(s2n_ktls_set_ancillary_data(&msg, MALFORMED_RECORD_TYPE));
            /* modify control_msg for the recv side */
            struct cmsghdr *hdr = CMSG_FIRSTHDR(&msg);
            /* tamper with the first header (MALFORMED_RECORD_TYPE) */
            hdr->cmsg_type = 0;

            /* add second correctly formatted cmsg (CORRECT_RECORD_TYPE)  */
            hdr = CMSG_NXTHDR(&msg, hdr);
            EXPECT_NOT_NULL(hdr);
            hdr->cmsg_level = S2N_SOL_TLS;
            hdr->cmsg_type = S2N_TLS_GET_RECORD_TYPE;
            hdr->cmsg_len = CMSG_LEN(sizeof(uint8_t));
            POSIX_CHECKED_MEMCPY(CMSG_DATA(hdr), &CORRECT_RECORD_TYPE, sizeof(uint8_t));

            /* receive CORRECT_RECORD_TYPE, set on the second header */
            uint8_t recv_record_type = 0;
            EXPECT_OK(s2n_ktls_parse_ancillary_data(&msg, &recv_record_type));
            EXPECT_NOT_EQUAL(recv_record_type, MALFORMED_RECORD_TYPE);
            EXPECT_EQUAL(recv_record_type, CORRECT_RECORD_TYPE);
        }

        /* missing ancillary data */
        {
            union {
                char buf[CMSG_SPACE(sizeof(uint8_t)) * 4];
                struct cmsghdr _align;
            } control_msg = { 0 };

            /* Init msghdr */
            struct msghdr msg = { 0 };
            msg.msg_control = control_msg.buf;
            msg.msg_controllen = sizeof(control_msg.buf);

            /* attempt to parse missing ancillary data */
            uint8_t recv_record_type = 0;
            EXPECT_ERROR_WITH_ERRNO(s2n_ktls_parse_ancillary_data(&msg, &recv_record_type), S2N_ERR_IO);
        }

        /* malformed ancillary data */
        {
            union {
                char buf[CMSG_SPACE(sizeof(uint8_t)) * 4];
                struct cmsghdr _align;
            } control_msg = { 0 };

            /* Init msghdr */
            struct msghdr msg = { 0 };
            msg.msg_control = control_msg.buf;
            msg.msg_controllen = sizeof(control_msg.buf);

            /* add ancillary data */
            EXPECT_OK(s2n_ktls_set_ancillary_data(&msg, TEST_SEND_RECORD_TYPE));
            /* modify control_msg for the recv side */
            struct cmsghdr *hdr = CMSG_FIRSTHDR(&msg);
            /* tamper with the first header (MALFORMED_RECORD_TYPE) */
            hdr->cmsg_type = 0;

            uint8_t recv_record_type = 0;
            EXPECT_ERROR_WITH_ERRNO(s2n_ktls_parse_ancillary_data(&msg, &recv_record_type), S2N_ERR_IO);
        }
    }
#endif

    END_TEST();
}
