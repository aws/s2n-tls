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
#include <time.h>
#include <stdint.h>

#include <s2n.h>

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"

#define SUPPORTED_CERTIFICATE_FORMATS (2)

static const char *certificate_paths[SUPPORTED_CERTIFICATE_FORMATS] = { S2N_RSA_2048_PKCS1_CERT_CHAIN, S2N_RSA_2048_PKCS8_CERT_CHAIN };
static const char *private_key_paths[SUPPORTED_CERTIFICATE_FORMATS] = { S2N_RSA_2048_PKCS1_KEY, S2N_RSA_2048_PKCS8_KEY };

#define HISTOGRAM_SIZE 100
static uint32_t histogram_values[HISTOGRAM_SIZE] = { 0 };
static uint32_t histogram_counts[HISTOGRAM_SIZE] = { 0 };

static int custom_mem_init(void)
{
    return 0;
}

static int custom_mem_cleanup(void)
{

    return 0;
}

static int custom_mem_malloc(void **ptr, uint32_t requested, uint32_t *allocated)
{
    int i;
    for (i = 0; i < HISTOGRAM_SIZE; i++) {
        if (histogram_values[i] == 0) {
            histogram_values[i] = requested;
        }

        if (histogram_values[i] == requested) {
            break;
        }
    }

    if (i < HISTOGRAM_SIZE) {
        histogram_counts[i] += 1;
    }

    *ptr = malloc(requested);
    *allocated = requested;

    /* Fill the memory with non-zeroes to check that s2n handles that fine */
    memset(*ptr, 'a', requested);

    return 0;
}

static int custom_mem_free(void *ptr, uint32_t size)
{
    free(ptr);
    return 0;
}

void mock_client(struct s2n_test_io_pair *io_pair)
{
    char buffer[0xffff];
    struct s2n_connection *conn;
    struct s2n_config *config;
    s2n_blocked_status blocked;

    /* Give the server a chance to listen */
    sleep(1);

    conn = s2n_connection_new(S2N_CLIENT);
    config = s2n_config_new();
    s2n_config_disable_x509_verification(config);
    s2n_connection_set_config(conn, config);
    conn->server_protocol_version = S2N_TLS12;
    conn->client_protocol_version = S2N_TLS12;
    conn->actual_protocol_version = S2N_TLS12;

    s2n_connection_set_io_pair(conn, io_pair);

    s2n_negotiate(conn, &blocked);

    s2n_connection_free_handshake(conn);

    uint16_t timeout = 1;
    s2n_connection_set_dynamic_record_threshold(conn, 0x7fff, timeout);
    int i;
    for (i = 1; i < 0xffff - 100; i += 100) {
        for (int j = 0; j < i; j++) {
            buffer[j] = 33;
        }
        s2n_send(conn, buffer, i, &blocked);
    }

    for (int j = 0; j < i; j++) {
        buffer[j] = 33;
    }

    /* release the buffers here to validate we can continue IO after */
    s2n_connection_release_buffers(conn);

    /* Simulate timeout second conneciton inactivity and tolerate 50 ms error */
    struct timespec sleep_time = {.tv_sec = timeout, .tv_nsec = 50000000};
    int r;
    do {
        r = nanosleep(&sleep_time, &sleep_time);
    } while (r != 0);
    /* Active application bytes consumed is reset to 0 in before writing data. */
    /* Its value should equal to bytes written after writing */
    ssize_t bytes_written = s2n_send(conn, buffer, i, &blocked);
    if (bytes_written != conn->active_application_bytes_consumed) {
        exit(0);
    }

    int shutdown_rc = -1;
    while(shutdown_rc != 0) {
        shutdown_rc = s2n_shutdown(conn, &blocked);
    }

    s2n_connection_free(conn);
    s2n_config_free(config);

    /* Give the server a chance to a void a sigpipe */
    sleep(1);

    s2n_io_pair_close_one_end(io_pair, S2N_CLIENT);

    _exit(0);
}

int main(int argc, char **argv)
{
    struct s2n_connection *conn;
    struct s2n_config *config;
    s2n_blocked_status blocked;
    int status;
    pid_t pid;
    char *cert_chain_pem;
    char *private_key_pem;
    char *dhparams_pem;

    /* We have to set the callback before BEGIN_TEST, because s2n_init() is called
     * there.
     */
    int rc = s2n_mem_set_callbacks(custom_mem_init, custom_mem_cleanup, custom_mem_malloc, custom_mem_free);

    BEGIN_TEST();

    /* Can't add callbacks if s2n is initialized */
    EXPECT_FAILURE(s2n_mem_set_callbacks(custom_mem_init, custom_mem_cleanup, custom_mem_malloc, custom_mem_free));

    EXPECT_SUCCESS(rc);
    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

    for (int is_dh_key_exchange = 0; is_dh_key_exchange <= 1; is_dh_key_exchange++) {
        struct s2n_cert_chain_and_key *chain_and_keys[SUPPORTED_CERTIFICATE_FORMATS];

        /* Create a pipe */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init(&io_pair));

        /* Create a child process */
        pid = fork();
        if (pid == 0) {
            /* This is the client process, close the server end of the pipe */
            EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_SERVER));

            /* Write the fragmented hello message */
            mock_client(&io_pair);
        }

        /* This is the server process, close the client end of the pipe */
        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_CLIENT));

        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        conn->server_protocol_version = S2N_TLS12;
        conn->client_protocol_version = S2N_TLS12;
        conn->actual_protocol_version = S2N_TLS12;

        EXPECT_NOT_NULL(config = s2n_config_new());
        for (int cert = 0; cert < SUPPORTED_CERTIFICATE_FORMATS; cert++) {
            EXPECT_SUCCESS(s2n_read_test_pem(certificate_paths[cert], cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_read_test_pem(private_key_paths[cert], private_key_pem, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_NOT_NULL(chain_and_keys[cert] = s2n_cert_chain_and_key_new());
            EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(chain_and_keys[cert], cert_chain_pem, private_key_pem));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_keys[cert]));
        }

        if (is_dh_key_exchange) {
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_config_add_dhparams(config, dhparams_pem));
        }

        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* Set up the connection to read from the fd */
        EXPECT_SUCCESS(s2n_connection_set_io_pair(conn, &io_pair));

        /* Negotiate the handshake. */
        EXPECT_SUCCESS(s2n_negotiate(conn, &blocked));

        char buffer[0xffff];
        for (int i = 1; i < 0xffff; i += 100) {
            char * ptr = buffer;
            int size = i;

            do {
                int bytes_read = 0;
                EXPECT_SUCCESS(bytes_read = s2n_recv(conn, ptr, size, &blocked));

                size -= bytes_read;
                ptr += bytes_read;
            } while(size);

            for (int j = 0; j < i; j++) {
                EXPECT_EQUAL(buffer[j], 33);
            }

            /* release the buffers here to validate we can continue IO after */
            EXPECT_SUCCESS(s2n_connection_release_buffers(conn));
        }

        int shutdown_rc = -1;
        do {
            shutdown_rc = s2n_shutdown(conn, &blocked);
            EXPECT_TRUE(shutdown_rc == 0 || (errno == EAGAIN && blocked));
        } while(shutdown_rc != 0);

        EXPECT_SUCCESS(s2n_connection_free(conn));
        for (int cert = 0; cert < SUPPORTED_CERTIFICATE_FORMATS; cert++) {
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_keys[cert]));
        }
        EXPECT_SUCCESS(s2n_config_free(config));

        /* Clean up */
        EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
        EXPECT_EQUAL(status, 0);
        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_SERVER));
    }

    free(cert_chain_pem);
    free(private_key_pem);
    free(dhparams_pem);

#if defined(S2N_TEST_DEBUG)
    /* Sort our histogram */
    uint32_t spare_value, spare_count;
    for (int i = 0; i < HISTOGRAM_SIZE; i++) {
        if (histogram_counts[i] == 0) {
            break;
        }

        for (int j = i + 1; j < HISTOGRAM_SIZE; j++) {
            if (histogram_counts[j] == 0) {
                break;
            }

            if (histogram_values[j] < histogram_values[i]) {
                spare_value = histogram_values[i];
                spare_count = histogram_counts[i];

                histogram_values[i] = histogram_values[j];
                histogram_counts[i] = histogram_counts[j];

                histogram_values[j] = spare_value;
                histogram_counts[j] = spare_count;
            }
        }
    }

    /* Print the histogram values */
    TEST_DEBUG_PRINT("\n\n");
    for (int i = 0; i < HISTOGRAM_SIZE; i++) {
        if (histogram_values[i] == 0) {
            break;
        }
        TEST_DEBUG_PRINT("Allocated %d bytes %d times\n", histogram_values[i], histogram_counts[i]);
    }
    TEST_DEBUG_PRINT("\n");
#endif

    END_TEST();

    return 0;
}
