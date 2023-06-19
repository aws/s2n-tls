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

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

S2N_RESULT s2n_ktls_retrieve_file_descriptor(struct s2n_connection *conn, s2n_ktls_mode ktls_mode, int *fd);
S2N_RESULT s2n_disable_ktls_socket_config_for_testing(void);

/* set kTLS supported cipher */
struct s2n_cipher ktls_temp_supported_cipher = {
    .ktls_supported = true,
};
struct s2n_record_algorithm ktls_temp_supported_record_alg = {
    .cipher = &ktls_temp_supported_cipher,
};
struct s2n_cipher_suite ktls_temp_supported_cipher_suite = {
    .record_alg = &ktls_temp_supported_record_alg,
};

S2N_RESULT s2n_test_configure_mock_ktls_connection(struct s2n_connection *conn, int fd, bool complete_handshake)
{
    RESULT_ENSURE_REF(conn);

    /* config I/O */
    RESULT_GUARD_POSIX(s2n_connection_set_write_fd(conn, fd));
    RESULT_GUARD_POSIX(s2n_connection_set_read_fd(conn, fd));
    conn->managed_send_io = true;
    conn->managed_recv_io = true;
    conn->ktls_send_enabled = false;
    conn->ktls_recv_enabled = false;

    /* configure connection so that the handshake is complete */
    conn->secure->cipher_suite = &ktls_temp_supported_cipher_suite;
    conn->actual_protocol_version = S2N_TLS12;
    if (complete_handshake) {
        RESULT_GUARD(s2n_skip_handshake(conn));
    }

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_OK(s2n_disable_ktls_socket_config_for_testing());

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
    };

    if (!s2n_ktls_is_supported_on_platform()) {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        int fd = 1;
        EXPECT_OK(s2n_test_configure_mock_ktls_connection(server_conn, fd, true));

        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn), S2N_ERR_KTLS_UNSUPPORTED_PLATFORM);
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_recv(server_conn), S2N_ERR_KTLS_UNSUPPORTED_PLATFORM);
    } else {
        /* ktls handshake must be complete */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            int fd = 1;
            EXPECT_OK(s2n_test_configure_mock_ktls_connection(server_conn, fd, false));

            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn), S2N_ERR_KTLS_HANDSHAKE_NOT_COMPLETE);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_recv(server_conn), S2N_ERR_KTLS_HANDSHAKE_NOT_COMPLETE);
        };

        /* s2n_connection_ktls_enable */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            int fd = 1;
            EXPECT_OK(s2n_test_configure_mock_ktls_connection(server_conn, fd, true));

            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn), S2N_ERR_KTLS_DISABLED_FOR_TEST);

            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_recv(server_conn), S2N_ERR_KTLS_DISABLED_FOR_TEST);
        };

        /* ktls already enabled */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            int fd = 1;
            EXPECT_OK(s2n_test_configure_mock_ktls_connection(server_conn, fd, true));

            server_conn->ktls_send_enabled = true;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn), S2N_ERR_KTLS_ALREADY_ENABLED);

            server_conn->ktls_recv_enabled = true;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_recv(server_conn), S2N_ERR_KTLS_ALREADY_ENABLED);
        };

        /* unsupported protocols */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            int fd = 1;
            EXPECT_OK(s2n_test_configure_mock_ktls_connection(server_conn, fd, true));

            server_conn->actual_protocol_version = S2N_TLS13;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn), S2N_ERR_KTLS_UNSUPPORTED_CONN);

            server_conn->actual_protocol_version = S2N_TLS11;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn), S2N_ERR_KTLS_UNSUPPORTED_CONN);
        };

        /* unsupported ciphers */
        {
            /* set kTLS un-supported cipher */
            struct s2n_cipher ktls_temp_unsupported_cipher = {
                .ktls_supported = false,
            };
            struct s2n_record_algorithm ktls_temp_unsupported_record_alg = {
                .cipher = &ktls_temp_unsupported_cipher,
            };
            struct s2n_cipher_suite ktls_temp_unsupported_cipher_suite = {
                .record_alg = &ktls_temp_unsupported_record_alg,
            };

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            int fd = 1;
            EXPECT_OK(s2n_test_configure_mock_ktls_connection(server_conn, fd, true));

            /* base case */
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn), S2N_ERR_KTLS_DISABLED_FOR_TEST);

            server_conn->ktls_send_enabled = false; /* reset ktls enable connection */
            server_conn->secure->cipher_suite = &ktls_temp_unsupported_cipher_suite;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn), S2N_ERR_KTLS_UNSUPPORTED_CONN);
        };

        /* drain buffer prior to enabling kTLS */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            int fd = 1;
            EXPECT_OK(s2n_test_configure_mock_ktls_connection(server_conn, fd, true));

            /* base case */
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn), S2N_ERR_KTLS_DISABLED_FOR_TEST);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_recv(server_conn), S2N_ERR_KTLS_DISABLED_FOR_TEST);

            uint8_t write_byte = 8;
            uint8_t read_byte = 0;
            /* write to conn->out buffer and assert error */
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&server_conn->out, &write_byte, 1));
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn), S2N_ERR_RECORD_STUFFER_NEEDS_DRAINING);
            /* drain conn->out buffer and assert base case */
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&server_conn->out, &read_byte, 1));
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn), S2N_ERR_KTLS_DISABLED_FOR_TEST);

            /* write to conn->in buffer and assert error */
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&server_conn->in, &write_byte, 1));
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_recv(server_conn), S2N_ERR_RECORD_STUFFER_NEEDS_DRAINING);
            /* drain conn->in buffer and assert base case */
            EXPECT_SUCCESS(s2n_stuffer_read_bytes(&server_conn->in, &read_byte, 1));
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_recv(server_conn), S2N_ERR_KTLS_DISABLED_FOR_TEST);
        };

        /* managed_send_io */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            int fd = 1;
            EXPECT_OK(s2n_test_configure_mock_ktls_connection(server_conn, fd, true));

            /* base case */
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn), S2N_ERR_KTLS_DISABLED_FOR_TEST);

            server_conn->ktls_send_enabled = false; /* reset ktls enable connection */
            /* expect failure if connection is using custom IO */
            server_conn->managed_send_io = false;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn), S2N_ERR_KTLS_MANAGED_IO);

            server_conn->ktls_send_enabled = false; /* reset ktls enable connection */
            /* expect success if connection is NOT using custom IO */
            server_conn->managed_send_io = true;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_send(server_conn), S2N_ERR_KTLS_DISABLED_FOR_TEST);
        };

        /* managed_recv_io */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            int fd = 1;
            EXPECT_OK(s2n_test_configure_mock_ktls_connection(server_conn, fd, true));

            /* base case */
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_recv(server_conn), S2N_ERR_KTLS_DISABLED_FOR_TEST);

            server_conn->ktls_recv_enabled = false; /* reset ktls enable connection */
            /* recv managed io */
            server_conn->managed_recv_io = false;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_recv(server_conn), S2N_ERR_KTLS_MANAGED_IO);

            server_conn->ktls_recv_enabled = false; /* reset ktls enable connection */
            /* expect success if connection is NOT using custom IO */
            server_conn->managed_recv_io = true;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_ktls_enable_recv(server_conn), S2N_ERR_KTLS_DISABLED_FOR_TEST);
        };

        /* s2n_ktls_retrieve_file_descriptor */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            int write_fd_orig = 1;
            int read_fd_orig = 2;
            int fd_ret = 0;

            EXPECT_SUCCESS(s2n_connection_set_write_fd(server_conn, write_fd_orig));
            EXPECT_OK(s2n_ktls_retrieve_file_descriptor(server_conn, S2N_KTLS_MODE_SEND, &fd_ret));
            EXPECT_EQUAL(write_fd_orig, fd_ret);

            EXPECT_SUCCESS(s2n_connection_set_read_fd(server_conn, read_fd_orig));
            EXPECT_OK(s2n_ktls_retrieve_file_descriptor(server_conn, S2N_KTLS_MODE_RECV, &fd_ret));
            EXPECT_EQUAL(read_fd_orig, fd_ret);
        };
    }

    END_TEST();
}
