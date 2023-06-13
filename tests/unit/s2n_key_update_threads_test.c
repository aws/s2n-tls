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

#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "crypto/s2n_sequence.h"
#include "s2n_test.h"
#include "testlib/s2n_examples.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_random.h"

#define S2N_TEST_BUFFER_SIZE      1000
#define S2N_TEST_ENCRYPTION_LIMIT 3
#define S2N_TEST_KEY_UPDATE_COUNT 10
#define S2N_TEST_RECORD_COUNT     (S2N_TEST_ENCRYPTION_LIMIT * S2N_TEST_KEY_UPDATE_COUNT)
#define S2N_TEST_BYTES_TO_SEND    (S2N_DEFAULT_FRAGMENT_LENGTH * S2N_TEST_RECORD_COUNT)

static void *s2n_send_random_data(void *arg)
{
    struct s2n_connection *conn = (struct s2n_connection *) arg;

    uint8_t buffer[100] = "hello world";

    size_t bytes_to_send = S2N_TEST_BYTES_TO_SEND;
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    while (bytes_to_send) {
        int r = s2n_send(conn, buffer, MIN(sizeof(buffer), bytes_to_send), &blocked);
        if (r >= 0) {
            bytes_to_send -= r;
        } else if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
            fprintf(stderr, "Send error: %s. %s\n", s2n_strerror(s2n_errno, NULL), s2n_strerror_debug(s2n_errno, NULL));
            return NULL;
        }
    }
    return conn;
}

static void *s2n_recv_random_data(void *arg)
{
    struct s2n_connection *conn = (struct s2n_connection *) arg;

    uint8_t buffer[S2N_TEST_BUFFER_SIZE] = { 0 };

    size_t bytes_to_read = S2N_TEST_BYTES_TO_SEND;
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    while (bytes_to_read) {
        int r = s2n_recv(conn, buffer, MIN(sizeof(buffer), bytes_to_read), &blocked);
        if (r >= 0) {
            bytes_to_read -= r;
        } else if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
            fprintf(stderr, "Recv error: %s. %s\n", s2n_strerror(s2n_errno, NULL), s2n_strerror_debug(s2n_errno, NULL));
            return NULL;
        }
    }
    return conn;
}

static S2N_RESULT s2n_test_shutdown(struct s2n_connection *conn)
{
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    int r = 0;
    while ((r = s2n_shutdown(conn, &blocked)) != S2N_SUCCESS) {
        if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
            RESULT_GUARD_POSIX(r);
        }
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_send_and_recv_random_data(struct s2n_connection *conn)
{
    /*
     * This test is intended to find concurrency issues when sending and receiving
     * KeyUpdates, so we need to run the reader and writer in separate threads.
     */

    pthread_t reader = 0;
    RESULT_ENSURE_EQ(pthread_create(&reader, NULL, s2n_recv_random_data, (void *) conn), 0);

    pthread_t writer = 0;
    RESULT_ENSURE_EQ(pthread_create(&writer, NULL, s2n_send_random_data, (void *) conn), 0);

    void *reader_return = NULL;
    RESULT_ENSURE_EQ(pthread_join(reader, &reader_return), 0);
    RESULT_ENSURE_REF(reader_return);

    void *writer_return = NULL;
    RESULT_ENSURE_EQ(pthread_join(writer, &writer_return), 0);
    RESULT_ENSURE_REF(writer_return);

    RESULT_ENSURE_GT(conn->wire_bytes_out, S2N_TEST_BYTES_TO_SEND);
    RESULT_ENSURE_GT(conn->wire_bytes_in, S2N_TEST_BYTES_TO_SEND);
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_key_update(struct s2n_connection *conn)
{
    RESULT_GUARD_POSIX(s2n_example_negotiate(conn));

    /* Force frequent KeyUpdates by lowering the chosen cipher's encryption limit */
    struct s2n_cipher_suite cipher_suite = *conn->secure->cipher_suite;
    struct s2n_record_algorithm record_alg = *cipher_suite.record_alg;
    record_alg.encryption_limit = S2N_TEST_ENCRYPTION_LIMIT;
    cipher_suite.record_alg = &record_alg;
    conn->secure->cipher_suite = &cipher_suite;

    /* Send and receive ApplicationData + KeyUpdates */
    RESULT_GUARD(s2n_send_and_recv_random_data(conn));

    uint64_t client_seq_num = 0;
    struct s2n_blob client_seq_num_blob = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&client_seq_num_blob, conn->secure->client_sequence_number,
            sizeof(conn->secure->client_sequence_number)));
    RESULT_GUARD_POSIX(s2n_sequence_number_to_uint64(&client_seq_num_blob, &client_seq_num));
    RESULT_ENSURE_GTE(client_seq_num, 0);
    RESULT_ENSURE_LTE(client_seq_num, S2N_TEST_ENCRYPTION_LIMIT);

    uint64_t server_seq_num = 0;
    struct s2n_blob server_seq_num_blob = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&server_seq_num_blob, conn->secure->server_sequence_number,
            sizeof(conn->secure->server_sequence_number)));
    RESULT_GUARD_POSIX(s2n_sequence_number_to_uint64(&server_seq_num_blob, &server_seq_num));
    RESULT_ENSURE_GTE(server_seq_num, 0);
    RESULT_ENSURE_LTE(server_seq_num, S2N_TEST_ENCRYPTION_LIMIT);

    uint64_t out_seq_num = server_seq_num;
    uint64_t in_seq_num = client_seq_num;
    if (conn->mode == S2N_CLIENT) {
        out_seq_num = client_seq_num;
        in_seq_num = server_seq_num;
    }

    /* We don't track the number of KeyUpdates sent or received, but we can at
     * least sanity check that we could not have sent enough records to account
     * for `wire_bytes_out` or `wire_bytes_in` without having reset the sequence number.
     */
    RESULT_ENSURE_EQ(conn->max_outgoing_fragment_length, S2N_DEFAULT_FRAGMENT_LENGTH);
    RESULT_ENSURE_GT(conn->wire_bytes_out, S2N_DEFAULT_RECORD_LENGTH * out_seq_num);
    RESULT_ENSURE_GT(conn->wire_bytes_in, S2N_DEFAULT_RECORD_LENGTH * in_seq_num);

    RESULT_GUARD(s2n_test_shutdown(conn));
    conn->secure->cipher_suite = NULL;
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* KeyUpdate requires TLS1.3 */
    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
            s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

    DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
    EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

    /* We're going to fork, so flush the initial test output first */
    EXPECT_EQUAL(fflush(stdout), 0);

    pid_t client_pid = fork();
    if (client_pid == 0) {
        /* Suppress stdout when running the examples.
         * This only affects the new client process.
         */
        fclose(stdout);

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));

        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client, &io_pair));

        EXPECT_OK(s2n_test_key_update(client));
        exit(EXIT_SUCCESS);
    }

    pid_t server_pid = fork();
    if (server_pid == 0) {
        /* Suppress stdout when running the examples.
         * This only affects the new server process.
         */
        fclose(stdout);

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server, &io_pair));

        EXPECT_OK(s2n_test_key_update(server));
        exit(EXIT_SUCCESS);
    }

    int status = 0;
    EXPECT_EQUAL(waitpid(client_pid, &status, 0), client_pid);
    EXPECT_EQUAL(status, EXIT_SUCCESS);
    EXPECT_EQUAL(waitpid(server_pid, &status, 0), server_pid);
    EXPECT_EQUAL(status, EXIT_SUCCESS);

    END_TEST();
}
