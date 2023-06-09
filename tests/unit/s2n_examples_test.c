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

#include "testlib/s2n_examples.h"

#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_random.h"

#define S2N_TEST_RECORD_COUNT      200
#define S2N_TEST_BYTES_TO_SEND     (S2N_DEFAULT_FRAGMENT_LENGTH * S2N_TEST_RECORD_COUNT)
#define S2N_TEST_LAST_SEQ_NUM_BYTE (S2N_TLS_SEQUENCE_NUM_LEN - 1)

typedef int (*s2n_io_fn)(struct s2n_connection *conn, uint8_t *buffer, size_t buffer_size);
struct s2n_test_thread_input {
    s2n_io_fn fn;
    struct s2n_connection *conn;
    struct s2n_blob *mem;
};

static void *s2n_run_io_fn(void *arg)
{
    struct s2n_test_thread_input *input = (struct s2n_test_thread_input *) arg;
    if (input && input->fn && input->mem) {
        if (input->fn(input->conn, input->mem->data, input->mem->size) == 0) {
            return arg;
        }
    }
    return NULL;
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

static S2N_RESULT s2n_test_shutdown_send(struct s2n_connection *conn)
{
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    int r = 0;
    while ((r = s2n_shutdown_send(conn, &blocked)) != S2N_SUCCESS) {
        if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
            RESULT_GUARD_POSIX(r);
        }
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_example_negotiate(struct s2n_connection *conn,
        struct s2n_blob *input)
{
    RESULT_GUARD_POSIX(s2n_example_negotiate(conn));
    RESULT_GUARD(s2n_test_shutdown(conn));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_example_send_and_recv(struct s2n_connection *conn,
        struct s2n_blob *input)
{
    RESULT_GUARD_POSIX(s2n_example_negotiate(conn));

    DEFER_CLEANUP(struct s2n_blob output = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&output, input->size));

    pthread_t reader = 0;
    struct s2n_test_thread_input reader_input = {
        .fn = s2n_example_recv,
        .conn = conn,
        .mem = &output,
    };
    RESULT_ENSURE_EQ(pthread_create(&reader, NULL, s2n_run_io_fn, (void *) &reader_input), 0);

    pthread_t writer = 0;
    struct s2n_test_thread_input writer_input = {
        .fn = s2n_example_send,
        .conn = conn,
        .mem = input,
    };
    RESULT_ENSURE_EQ(pthread_create(&writer, NULL, s2n_run_io_fn, (void *) &writer_input), 0);

    void *reader_return = NULL;
    RESULT_ENSURE_EQ(pthread_join(reader, &reader_return), 0);
    RESULT_ENSURE_REF(reader_return);

    void *writer_return = NULL;
    RESULT_ENSURE_EQ(pthread_join(writer, &writer_return), 0);
    RESULT_ENSURE_REF(writer_return);

    RESULT_ENSURE_EQ(memcmp(output.data, input->data, input->size), 0);

    RESULT_GUARD(s2n_test_shutdown(conn));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_example_sendv(struct s2n_connection *conn,
        struct s2n_blob *input)
{
    RESULT_GUARD_POSIX(s2n_example_negotiate(conn));

    DEFER_CLEANUP(struct s2n_blob output = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&output, input->size));

    pthread_t reader = 0;
    struct s2n_test_thread_input reader_input = {
        .fn = s2n_example_recv,
        .conn = conn,
        .mem = &output,
    };
    RESULT_ENSURE_EQ(pthread_create(&reader, NULL, s2n_run_io_fn, (void *) &reader_input), 0);

    pthread_t writer = 0;
    struct s2n_test_thread_input writer_input = {
        .fn = s2n_example_sendv,
        .conn = conn,
        .mem = input,
    };
    RESULT_ENSURE_EQ(pthread_create(&writer, NULL, s2n_run_io_fn, (void *) &writer_input), 0);

    void *reader_return = NULL;
    RESULT_ENSURE_EQ(pthread_join(reader, &reader_return), 0);
    RESULT_ENSURE_REF(reader_return);

    void *writer_return = NULL;
    RESULT_ENSURE_EQ(pthread_join(writer, &writer_return), 0);
    RESULT_ENSURE_REF(writer_return);

    RESULT_ENSURE_EQ(memcmp(output.data, input->data, input->size), 0);

    RESULT_GUARD(s2n_test_shutdown(conn));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_example_recv_echo(struct s2n_connection *conn,
        struct s2n_blob *input)
{
    RESULT_GUARD_POSIX(s2n_example_negotiate(conn));

    /* We need to send a close_notify to stop the reader thread, which will cause
     * a full connection shutdown without TLS1.3's half-close behavior.
     * That can lead to unexpected "connection closed" errors depending on the timings.
     */
    if (conn->actual_protocol_version < S2N_TLS13) {
        return S2N_RESULT_OK;
    }

    DEFER_CLEANUP(struct s2n_blob output = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&output, 100));

    pthread_t reader = 0;
    struct s2n_test_thread_input reader_input = {
        .fn = s2n_example_recv_echo,
        .conn = conn,
        .mem = &output,
    };
    RESULT_ENSURE_EQ(pthread_create(&reader, NULL, s2n_run_io_fn, (void *) &reader_input), 0);

    pthread_t writer = 0;
    struct s2n_test_thread_input writer_input = {
        .fn = s2n_example_send,
        .conn = conn,
        .mem = input,
    };
    RESULT_ENSURE_EQ(pthread_create(&writer, NULL, s2n_run_io_fn, (void *) &writer_input), 0);

    void *writer_return = NULL;
    RESULT_ENSURE_EQ(pthread_join(writer, &writer_return), 0);
    RESULT_ENSURE_REF(writer_return);

    RESULT_GUARD(s2n_test_shutdown_send(conn));

    void *reader_return = NULL;
    RESULT_ENSURE_EQ(pthread_join(reader, &reader_return), 0);
    RESULT_ENSURE_REF(reader_return);

    /* We can't verify the exact data read, since we read in chunks and the buffer
     * never contains the full data sent, but we can sanity check the number of
     * records and total bytes read.
     */
    RESULT_ENSURE_GT(conn->wire_bytes_in, input->size);
    RESULT_ENSURE_LTE(S2N_TEST_RECORD_COUNT, UINT8_MAX);
    RESULT_ENSURE_GTE(conn->secure->client_sequence_number[S2N_TEST_LAST_SEQ_NUM_BYTE],
            S2N_TEST_RECORD_COUNT);
    RESULT_ENSURE_GTE(conn->secure->server_sequence_number[S2N_TEST_LAST_SEQ_NUM_BYTE],
            S2N_TEST_RECORD_COUNT);

    RESULT_GUARD(s2n_test_shutdown(conn));
    return S2N_RESULT_OK;
}

typedef S2N_RESULT (*s2n_test_scenario)(struct s2n_connection *conn, struct s2n_blob *input);
static S2N_RESULT s2n_run_self_talk_test(s2n_test_scenario scenario_fn)
{
    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
            s2n_cert_chain_and_key_ptr_free);
    RESULT_GUARD_POSIX(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
            s2n_config_ptr_free);
    RESULT_GUARD_POSIX(s2n_config_set_unsafe_for_testing(config));
    RESULT_GUARD_POSIX(s2n_config_set_cipher_preferences(config, "default_tls13"));
    RESULT_GUARD_POSIX(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

    DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
    RESULT_GUARD_POSIX(s2n_io_pair_init_non_blocking(&io_pair));

    DEFER_CLEANUP(struct s2n_blob input = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&input, S2N_TEST_BYTES_TO_SEND));
    RESULT_GUARD(s2n_get_public_random_data(&input));

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

        EXPECT_OK(scenario_fn(client, &input));

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

        EXPECT_OK(scenario_fn(server, &input));

        exit(EXIT_SUCCESS);
    }

    int status = 0;
    RESULT_ENSURE_EQ(waitpid(client_pid, &status, 0), client_pid);
    RESULT_ENSURE_EQ(status, EXIT_SUCCESS);
    RESULT_ENSURE_EQ(waitpid(server_pid, &status, 0), server_pid);
    RESULT_ENSURE_EQ(status, EXIT_SUCCESS);

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_run_failure_tests()
{
    uint8_t buffer[100] = { 0 };
    size_t buffer_size = sizeof(buffer);

    DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
            s2n_connection_ptr_free);
    EXPECT_SUCCESS(s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING));

    pid_t pid = fork();
    if (pid == 0) {
        /* Suppress stdout AND stderr when running the examples.
         * This only affects the new process.
         */
        fclose(stdout);
        fclose(stderr);

        EXPECT_EQUAL(s2n_example_negotiate(conn), S2N_FAILURE);
        EXPECT_EQUAL(s2n_example_send(conn, buffer, buffer_size), S2N_FAILURE);
        EXPECT_EQUAL(s2n_example_sendv(conn, buffer, buffer_size), S2N_FAILURE);
        EXPECT_EQUAL(s2n_example_recv(conn, buffer, buffer_size), S2N_FAILURE);
        EXPECT_EQUAL(s2n_example_recv_echo(conn, buffer, buffer_size), S2N_FAILURE);

        exit(EXIT_SUCCESS);
    }

    int status = 0;
    RESULT_ENSURE_EQ(waitpid(pid, &status, 0), pid);
    RESULT_ENSURE_EQ(status, EXIT_SUCCESS);

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* We're going to fork, so flush the initial test output first */
    EXPECT_EQUAL(fflush(stdout), 0);

    EXPECT_OK(s2n_run_failure_tests());
    EXPECT_OK(s2n_run_self_talk_test(s2n_test_example_negotiate));
    EXPECT_OK(s2n_run_self_talk_test(s2n_test_example_send_and_recv));
    EXPECT_OK(s2n_run_self_talk_test(s2n_test_example_sendv));
    EXPECT_OK(s2n_run_self_talk_test(s2n_test_example_recv_echo));
    END_TEST();

    END_TEST();
}
