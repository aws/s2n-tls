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

#include "crypto/s2n_cipher.h"
#include "error/s2n_errno.h"
#include "s2n.h"
#include "s2n_test.h"
#include "stdio.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_handshake_type.h"
#include "utils/s2n_safety.h"

#define S2N_TEST_INADDR_LOOPBACK 0x7f000001 /* 127.0.0.1 */

S2N_RESULT s2n_ktls_validate(struct s2n_connection *conn);
S2N_RESULT s2n_ktls_validate_socket_mode(struct s2n_connection *conn, s2n_ktls_mode ktls_mode);
S2N_RESULT s2n_ktls_retrieve_file_descriptor(struct s2n_connection *conn, s2n_ktls_mode ktls_mode, int *fd);
S2N_RESULT s2n_ktls_configure_socket(struct s2n_connection *conn, s2n_ktls_mode ktls_mode);
S2N_RESULT s2n_ignore_ktls_ulp_for_testing(void);

S2N_RESULT s2n_test_configure_ktls_connection(struct s2n_connection *conn, int *fd)
{
    *fd = 1;
    EXPECT_SUCCESS(s2n_connection_set_write_fd(conn, *fd));
    EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, *fd));

    conn->managed_send_io = true;
    conn->ktls_send_enabled = false;
    conn->managed_recv_io = true;
    conn->ktls_recv_enabled = false;

    conn->initial->cipher_suite->record_alg = &s2n_record_alg_aes128_gcm;
    conn->actual_protocol_version = S2N_TLS12;

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_OK(s2n_ignore_ktls_ulp_for_testing());

    /* kTLS feature probe */
    {
#ifdef __FreeBSD__
    #ifndef S2N_PLATFORM_SUPPORTS_KTLS
        /* https://github.com/torvalds/linux/commit/3c4d7559159bfe1e3b94df3a657b2cda3a34e218
        * kTLS support was first added in linux 4.13.0. */
        FAIL_MSG("kTLS feature probe is not working");
    #endif
#endif
    }

    /* ktls_supported ciphers */
    {
        struct s2n_cipher cipher = s2n_aes128_gcm;
        EXPECT_TRUE(cipher.ktls_supported);

        cipher = s2n_aes256_gcm;
        EXPECT_FALSE(cipher.ktls_supported);

        cipher = s2n_tls13_aes128_gcm;
        EXPECT_FALSE(cipher.ktls_supported);

        cipher = s2n_tls13_aes256_gcm;
        EXPECT_FALSE(cipher.ktls_supported);

        cipher = s2n_chacha20_poly1305;
        EXPECT_FALSE(cipher.ktls_supported);
    }

    /* s2n_ktls_validate TLS 1.2 */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        int fd = 0;
        EXPECT_OK(s2n_test_configure_ktls_connection(server_conn, &fd));

        EXPECT_OK(s2n_ktls_validate(server_conn));
    }

    /* s2n_ktls_validate TLS 1.3 */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        int fd = 0;
        EXPECT_OK(s2n_test_configure_ktls_connection(server_conn, &fd));

        server_conn->actual_protocol_version = S2N_TLS13;

        EXPECT_ERROR_WITH_ERRNO(s2n_ktls_validate(server_conn), S2N_ERR_KTLS_UNSUPPORTED_CONN);
    }

    /* s2n_ktls_validate_socket_mode send */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        int fd = 0;
        EXPECT_OK(s2n_test_configure_ktls_connection(server_conn, &fd));

        /* base case */
        EXPECT_OK(s2n_ktls_validate_socket_mode(server_conn, S2N_KTLS_MODE_RECV));
        EXPECT_OK(s2n_ktls_validate_socket_mode(server_conn, S2N_KTLS_MODE_SEND));

        /* send managed io */
        server_conn->managed_send_io = false;
        EXPECT_ERROR_WITH_ERRNO(s2n_ktls_validate_socket_mode(server_conn, S2N_KTLS_MODE_SEND), S2N_ERR_KTLS_SEND_MANAGED_IO);
        EXPECT_OK(s2n_ktls_validate_socket_mode(server_conn, S2N_KTLS_MODE_RECV));
        server_conn->managed_send_io = true;

        /* ktls enabled send */
        server_conn->ktls_send_enabled = true;
        EXPECT_ERROR_WITH_ERRNO(s2n_ktls_validate_socket_mode(server_conn, S2N_KTLS_MODE_SEND), S2N_ERR_KTLS_SEND_ENABLED);
        EXPECT_OK(s2n_ktls_validate_socket_mode(server_conn, S2N_KTLS_MODE_RECV));
    }

    /* s2n_ktls_validate_socket_mode recv */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        int fd = 0;
        EXPECT_OK(s2n_test_configure_ktls_connection(server_conn, &fd));

        /* base case */
        EXPECT_OK(s2n_ktls_validate_socket_mode(server_conn, S2N_KTLS_MODE_RECV));
        EXPECT_OK(s2n_ktls_validate_socket_mode(server_conn, S2N_KTLS_MODE_SEND));

        /* recv managed io */
        server_conn->managed_recv_io = false;
        EXPECT_ERROR_WITH_ERRNO(s2n_ktls_validate_socket_mode(server_conn, S2N_KTLS_MODE_RECV), S2N_ERR_KTLS_RECV_MANAGED_IO);
        EXPECT_OK(s2n_ktls_validate_socket_mode(server_conn, S2N_KTLS_MODE_SEND));
        server_conn->managed_recv_io = true;

        /* ktls enabled recv */
        server_conn->ktls_recv_enabled = true;
        EXPECT_ERROR_WITH_ERRNO(s2n_ktls_validate_socket_mode(server_conn, S2N_KTLS_MODE_RECV), S2N_ERR_KTLS_RECV_ENABLED);
        EXPECT_OK(s2n_ktls_validate_socket_mode(server_conn, S2N_KTLS_MODE_SEND));
    }

    /* s2n_ktls_retrieve_file_descriptor */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        int fd_orig = 1;
        EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, fd_orig));

        int fd_ret = 0;
        EXPECT_OK(s2n_ktls_retrieve_file_descriptor(server_conn, S2N_KTLS_MODE_SEND, &fd_ret));
        EXPECT_EQUAL(fd_orig, fd_ret);
    }

    /* s2n_ktls_configure_socket */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        int fd = 0;
        EXPECT_OK(s2n_test_configure_ktls_connection(server_conn, &fd));

#ifdef S2N_PLATFORM_SUPPORTS_KTLS
        EXPECT_OK(s2n_ktls_configure_socket(server_conn, S2N_KTLS_MODE_SEND));
#else
        EXPECT_ERROR_WITH_ERRNO(s2n_ktls_configure_socket(server_conn, S2N_KTLS_MODE_SEND), S2N_ERR_KTLS_UNSUPPORTED_PLATFORM);
#endif
    }

    /* s2n_ktls_enable */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        int fd = 0;
        EXPECT_OK(s2n_test_configure_ktls_connection(server_conn, &fd));

#ifdef S2N_PLATFORM_SUPPORTS_KTLS
        EXPECT_SUCCESS(s2n_ktls_enable(server_conn, S2N_KTLS_MODE_SEND));
#else
        EXPECT_ERROR_WITH_ERRNO(s2n_ktls_configure_socket(server_conn, S2N_KTLS_MODE_SEND), S2N_ERR_KTLS_UNSUPPORTED_PLATFORM);
#endif
    }

    END_TEST();
}
