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

#include "s2n_test.h"

#include "testlib/s2n_testlib.h"

#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

#include <s2n.h>

#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_tls13.h"

int mock_client(struct s2n_test_io_pair *io_pair, uint8_t *expected_data, uint32_t size)
{
    uint8_t *buffer = malloc(size);
    uint8_t *ptr = buffer;
    struct s2n_connection *client_conn;
    struct s2n_config *client_config;
    s2n_blocked_status blocked;
    int result = 0;

    /* Give the server a chance to listen */
    sleep(1);

    client_conn = s2n_connection_new(S2N_CLIENT);
    client_config = s2n_config_new();
    s2n_config_disable_x509_verification(client_config);
    s2n_connection_set_config(client_conn, client_config);
    GUARD(s2n_config_set_cipher_preferences(client_config, "test_all"));

    s2n_connection_set_io_pair(client_conn, io_pair);

    result = s2n_negotiate(client_conn, &blocked);
    if (result < 0) {
        return 1;
    }

    /* Receive 10MB of data */
    uint32_t remaining = size;
    while(remaining) {
        int r = s2n_recv(client_conn, ptr, remaining, &blocked);
        if (r < 0) {
            return 1;
        }
        remaining -= r;
        ptr += r;
    }

    int shutdown_rc= -1;
    do {
        shutdown_rc = s2n_shutdown(client_conn, &blocked);
    } while(shutdown_rc != 0);

    for (int i = 0; i < size; i++) {
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
    GUARD(s2n_config_set_cipher_preferences(client_config, "test_all"));

    s2n_connection_set_io_pair(client_conn, io_pair);

    result = s2n_negotiate(client_conn, &blocked);
    if (result < 0) {
        return 1;
    }

    uint32_t remaining = total_size;
    while(remaining) {
        int r = s2n_recv(client_conn, &buffer[buffer_offs], remaining, &blocked);
        if (r < 0) {
            return 1;
        }
        remaining -= r;
        buffer_offs += r;
    }

    remaining = iov[0].iov_len;
    while(remaining) {
        int r = s2n_recv(client_conn, &buffer[buffer_offs], remaining, &blocked);
        if (r < 0) {
            return 1;
        }
        remaining -= r;
        buffer_offs += r;
    }

    int shutdown_rc= -1;
    do {
        shutdown_rc = s2n_shutdown(client_conn, &blocked);
    } while(shutdown_rc != 0);

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

char *cert_chain_pem;
char *private_key_pem;
char *dhparams_pem;

int test_send(int use_tls13, int use_iov, int prefer_throughput)
{
    if (use_tls13) {
        EXPECT_SUCCESS(s2n_enable_tls13());
    }

    struct s2n_connection *conn;
    struct s2n_config *config;
    s2n_blocked_status blocked;
    int status;
    pid_t pid;
    struct s2n_cert_chain_and_key *chain_and_key;

    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(chain_and_key = s2n_cert_chain_and_key_new());
    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_key, cert_chain_pem, private_key_pem));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
    EXPECT_SUCCESS(s2n_config_add_dhparams(config, dhparams_pem));
    GUARD(s2n_config_set_cipher_preferences(config, "test_all"));

    /* Get some random data to send/receive */
    uint32_t data_size = 0;
    DEFER_CLEANUP(struct s2n_blob blob = {0}, s2n_free);

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

    struct iovec* iov = NULL;
    if (!use_iov) {
        data_size = 10000000;
        s2n_alloc(&blob, data_size);
        EXPECT_OK(s2n_get_urandom_data(&blob));
    } else {
        iov = malloc(sizeof(*iov) * iov_size);
        data_size = 0;
        for (int i = 0; i < iov_size; i++, iov_payload_size *= 2) {
            struct s2n_blob blob_local;
            iov[i].iov_base = blob_local.data = malloc(iov_payload_size);
            iov[i].iov_len = blob_local.size = iov_payload_size;
            EXPECT_OK(s2n_get_urandom_data(&blob));
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
        const int client_rc = !use_iov ? mock_client(&io_pair, blob.data, data_size)
            : mock_client_iov(&io_pair, iov, iov_size);

        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_CLIENT));
        _exit(client_rc);
    }

    /* This is the server process, close the client end of the pipe */
    EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_CLIENT));

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
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
        EXPECT_EQUAL(conn->actual_protocol_version, S2N_TLS13);
    } else {
        EXPECT_EQUAL(conn->actual_protocol_version, S2N_TLS12);
    }

    /* Pause the child process by sending it SIGSTP */
    EXPECT_SUCCESS(kill(pid, SIGSTOP));

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
    EXPECT_SUCCESS(s2n_connection_free(conn));

    /* Clean up */
    EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
    EXPECT_EQUAL(status, 0);
    EXPECT_SUCCESS(s2n_config_free(config));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_SERVER));

    if (iov) {
        for (int i = 0; i < iov_size; i++) {
            free(iov[i].iov_base);
        }
        free(iov);
    }

    if (use_tls13) {
        EXPECT_SUCCESS(s2n_disable_tls13());
    }

    return 0;
}

int main(int argc, char **argv)
{
    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);

    BEGIN_TEST();
    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

    for (int use_tls13 = 0; use_tls13 < 2; use_tls13 ++) {
        for (int use_iovec = 0; use_iovec < 2; use_iovec ++) {
            for (int use_throughput = 0; use_throughput < 2; use_throughput ++) {
                test_send(use_tls13, use_iovec, use_throughput);
            }
        }
    }
    free(cert_chain_pem);
    free(private_key_pem);
    free(dhparams_pem);
    END_TEST();
    return 0;
}
