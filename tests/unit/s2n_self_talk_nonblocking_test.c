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

#include <fcntl.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"

static const float minimum_send_percent = 5.0;

#define MIN_PERCENT_COMPLETE(remaining, total) ((((total - remaining) / (total * 1.0)) * 100.0) > minimum_send_percent)

int mock_client(struct s2n_test_io_pair *io_pair, uint8_t *expected_data, uint32_t size)
{
    uint8_t *buffer = malloc(size);
    uint8_t *ptr = buffer;
    struct s2n_connection *client_conn;
    struct s2n_config *client_config;
    s2n_blocked_status blocked;
    int result = 0;
    /* If something goes wrong, and the server never finishes sending,
     * we'll want to have the child process die eventually, or certain
     * CI/CD pipelines might never complete */
    int should_block = 1;

    /* Give the server a chance to listen */
    sleep(1);

    client_conn = s2n_connection_new(S2N_CLIENT);
    client_config = s2n_config_new();
    s2n_config_disable_x509_verification(client_config);
    s2n_connection_set_config(client_conn, client_config);
    POSIX_GUARD(s2n_config_set_cipher_preferences(client_config, "test_all"));

    s2n_connection_set_io_pair(client_conn, io_pair);

    result = s2n_negotiate(client_conn, &blocked);
    if (result < 0) {
        return 1;
    }

    /* Receive 10MB of data */
    uint32_t remaining = size;
    while (remaining) {
        int r = s2n_recv(client_conn, ptr, remaining, &blocked);
        if (r < 0) {
            return 1;
        }
        remaining -= r;
        ptr += r;
        if (should_block && MIN_PERCENT_COMPLETE(remaining, size)) {
            raise(SIGSTOP);
            should_block = 0;
        }
    }

    int shutdown_rc = -1;
    do {
        shutdown_rc = s2n_shutdown(client_conn, &blocked);
    } while (shutdown_rc != 0);

    for (size_t i = 0; i < size; i++) {
        if (buffer[i] != expected_data[i]) {
            return 1;
        }
    }

    free(buffer);
    s2n_connection_free(client_conn);
    s2n_config_free(client_config);

    s2n_cleanup();

    return 0;
}

int mock_client_iov(struct s2n_test_io_pair *io_pair, struct iovec *iov, uint32_t iov_size)
{
    struct s2n_connection *client_conn;
    struct s2n_config *client_config;
    s2n_blocked_status blocked;
    int result = 0;
    int total_size = 0, i;
    int should_block = 1;

    for (i = 0; i < iov_size; i++) {
        total_size += iov[i].iov_len;
    }
    uint8_t *buffer = malloc(total_size + iov[0].iov_len);
    int buffer_offs = 0;

    /* Give the server a chance to listen */
    sleep(1);

    client_conn = s2n_connection_new(S2N_CLIENT);
    client_config = s2n_config_new();
    s2n_config_disable_x509_verification(client_config);
    s2n_connection_set_config(client_conn, client_config);
    POSIX_GUARD(s2n_config_set_cipher_preferences(client_config, "test_all"));

    s2n_connection_set_io_pair(client_conn, io_pair);

    result = s2n_negotiate(client_conn, &blocked);
    if (result < 0) {
        return 1;
    }

    uint32_t remaining = total_size;
    while (remaining) {
        int r = s2n_recv(client_conn, &buffer[buffer_offs], remaining, &blocked);
        if (r < 0) {
            return 1;
        }
        remaining -= r;
        buffer_offs += r;
        if (should_block && MIN_PERCENT_COMPLETE(remaining, total_size)) {
            raise(SIGSTOP);
            should_block = 0;
        }
    }

    remaining = iov[0].iov_len;
    while (remaining) {
        int r = s2n_recv(client_conn, &buffer[buffer_offs], remaining, &blocked);
        if (r < 0) {
            return 1;
        }
        remaining -= r;
        buffer_offs += r;
    }

    int shutdown_rc = -1;
    do {
        shutdown_rc = s2n_shutdown(client_conn, &blocked);
    } while (shutdown_rc != 0);

    for (i = 0, buffer_offs = 0; i < iov_size; i++) {
        if (memcmp(iov[i].iov_base, &buffer[buffer_offs], iov[i].iov_len)) {
            return 1;
        }
        buffer_offs += iov[i].iov_len;
    }

    if (memcmp(iov[0].iov_base, &buffer[buffer_offs], iov[0].iov_len)) {
        return 1;
    }

    free(buffer);
    s2n_connection_free(client_conn);
    s2n_config_free(client_config);

    return 0;
}

S2N_RESULT cleanup_io_data(struct iovec **iov, int iov_size, struct s2n_blob *blob)
{
    if (*iov) {
        for (int i = 0; i < iov_size; i++) {
            free((*iov)[i].iov_base);
        }
        free(*iov);
    } else {
        s2n_free(blob);
    }

    return S2N_RESULT_OK;
}

int test_send(int use_tls13, int use_iov, int prefer_throughput)
{
    s2n_blocked_status blocked;
    int status;
    pid_t pid;
    char cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
    char private_key_pem[S2N_MAX_TEST_PEM_SIZE];
    char dhparams_pem[S2N_MAX_TEST_PEM_SIZE];

    /* Get some random data to send/receive */
    uint32_t data_size = 0;
    struct s2n_blob blob = { 0 };

    /* These numbers are chosen so that some of the payload is bigger
     * than max TLS1.3 record size (2**14 + 1), which is needed to validate
     * that we handle record sizing correctly.
     *  (see https://github.com/awslabs/s2n/pull/1780).
     *
     * Note that for each iov in the list, the payload size is doubled
     * to ensure the implementation handles various lengths.
     *
     * With the current values, it will include
     * * 8192 bytes
     * * 16384 bytes
     * * 32768 bytes
     * * 65536 bytes
     * * 131072 bytes
     * * 262144 bytes
     * * 524288 bytes */
    int iov_payload_size = 8192, iov_size = 7;

    struct iovec *iov = NULL;
    if (!use_iov) {
        data_size = 10000000;
        s2n_alloc(&blob, data_size);
        EXPECT_OK(s2n_get_public_random_data(&blob));
    } else {
        iov = malloc(sizeof(*iov) * iov_size);
        data_size = 0;
        for (int i = 0; i < iov_size; i++, iov_payload_size *= 2) {
            struct s2n_blob blob_local = { 0 };
            iov[i].iov_base = blob_local.data = malloc(iov_payload_size);
            iov[i].iov_len = blob_local.size = iov_payload_size;
            EXPECT_OK(s2n_get_public_random_data(&blob));
            data_size += iov_payload_size;
        }
    }

    /* Create a pipe */
    struct s2n_test_io_pair io_pair;
    EXPECT_SUCCESS(s2n_io_pair_init(&io_pair));

    /* Create a child process */
    pid = fork();
    if (pid == 0) {
        /* This is the client process, close the server end of the pipe */
        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_SERVER));

        /* Run the client */
        const int client_rc = !use_iov ? mock_client(&io_pair, blob.data, data_size) : mock_client_iov(&io_pair, iov, iov_size);

        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_CLIENT));
        EXPECT_OK(cleanup_io_data(&iov, iov_size, &blob));
        exit(client_rc);
    }

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = s2n_cert_chain_and_key_new(), s2n_cert_chain_and_key_ptr_free);

    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));

    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_config_add_dhparams(config, dhparams_pem));

    if (use_tls13) {
        POSIX_GUARD(s2n_config_set_cipher_preferences(config, "test_all"));
    } else {
        POSIX_GUARD(s2n_config_set_cipher_preferences(config, "test_all_tls12"));
    }

    /* This is the server process, close the client end of the pipe */
    EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_CLIENT));

    EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

    if (prefer_throughput) {
        EXPECT_SUCCESS(s2n_connection_prefer_throughput(conn));
    } else {
        EXPECT_SUCCESS(s2n_connection_prefer_low_latency(conn));
    }

    /* Set up the connection to read from the fd */
    EXPECT_SUCCESS(s2n_connection_set_io_pair(conn, &io_pair));

    EXPECT_SUCCESS(s2n_connection_use_corked_io(conn));

    /* Negotiate the handshake. */
    EXPECT_SUCCESS(s2n_negotiate(conn, &blocked));

    /* Make sure we negotiated the expected version */
    if (use_tls13) {
        EXPECT_EQUAL(conn->actual_protocol_version, s2n_get_highest_fully_supported_tls_version());
    } else {
        EXPECT_EQUAL(conn->actual_protocol_version, S2N_TLS12);
    }

    /* Make our pipes non-blocking */
    s2n_fd_set_non_blocking(io_pair.server);

    /* Try to all 10MB of data, should be enough to fill PIPEBUF, so
       we'll get blocked at some point */
    uint32_t remaining = data_size;
    uint8_t *ptr = blob.data;
    uint32_t iov_offs = 0;

    while (remaining) {
        int r = !use_iov ? s2n_send(conn, ptr, remaining, &blocked) :
                           s2n_sendv_with_offset(conn, iov, iov_size, iov_offs, &blocked);
        /* We will send up to minimum_send_percent, after which the client will automatically block itself.
         * This allows us to cover the case where s2n_send gets EAGAIN on the very first call
         * which can happen on certain platforms. By making sure we've successfully sent something
         * we can ensure write -> block -> client drain -> write ordering.*/
        if (r < 0 && !MIN_PERCENT_COMPLETE(remaining, data_size)) {
            continue;
        }

        if (r < 0 && blocked == S2N_BLOCKED_ON_WRITE) {
            /* We reached a blocked state and made no forward progress last call */
            break;
        }

        EXPECT_TRUE(r > 0);
        remaining -= r;
        if (!use_iov) {
            ptr += r;
        } else {
            iov_offs += r;
        }
    }

    /* Remaining should be between data_size and 0 */
    EXPECT_TRUE(remaining < data_size);
    EXPECT_TRUE(remaining > 0);

    /* Wait for the child process to read some bytes and block itself*/
    sleep(1);
    /* Wake the child process by sending it SIGCONT */
    EXPECT_SUCCESS(kill(pid, SIGCONT));

    /* Make our sockets blocking again */
    s2n_fd_set_blocking(io_pair.server);

    /* Actually send the remaining data */
    while (remaining) {
        int r = !use_iov ? s2n_send(conn, ptr, remaining, &blocked) :
                           s2n_sendv_with_offset(conn, iov, iov_size, iov_offs, &blocked);
        EXPECT_TRUE(r > 0);
        remaining -= r;
        if (!use_iov) {
            ptr += r;
        } else {
            iov_offs += r;
        }
    }

    if (use_iov) {
        int r = s2n_sendv(conn, iov, 1, &blocked);
        EXPECT_TRUE(r > 0);
    }

    EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));

    EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
    EXPECT_EQUAL(status, 0);

    /* Clean up */
    EXPECT_OK(cleanup_io_data(&iov, iov_size, &blob));
    EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_SERVER));

    return 0;
}

int main(int argc, char **argv)
{
    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);

    BEGIN_TEST();

    for (int use_tls13 = 0; use_tls13 < 2; use_tls13++) {
        for (int use_iovec = 0; use_iovec < 2; use_iovec++) {
            for (int use_throughput = 0; use_throughput < 2; use_throughput++) {
                test_send(use_tls13, use_iovec, use_throughput);
            }
        }
    }
    END_TEST();
    return 0;
}
