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
#define S2N_TEST_KEY_UPDATE_COUNT 25
#define S2N_TEST_RECORD_COUNT     (S2N_TEST_ENCRYPTION_LIMIT * S2N_TEST_KEY_UPDATE_COUNT)
#define S2N_TEST_BYTES_TO_SEND    (S2N_DEFAULT_FRAGMENT_LENGTH * S2N_TEST_RECORD_COUNT)

#define S2N_CIPHER_SUITE_WITH_LIMIT(name, source, limit)                 \
    struct s2n_cipher_suite name = *(source);                            \
    struct s2n_record_algorithm _##name##_record_alg = *name.record_alg; \
    _##name##_record_alg.encryption_limit = limit;                       \
    name.record_alg = &_##name##_record_alg;

S2N_RESULT s2n_set_key_update_request_for_testing(keyupdate_request request);

static void *s2n_send_random_data(void *arg)
{
    struct s2n_connection *conn = (struct s2n_connection *) arg;

    uint8_t buffer[S2N_TEST_BUFFER_SIZE] = "hello world";

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

static S2N_RESULT s2n_sanity_check_key_updates_sent(struct s2n_connection *conn)
{
    struct s2n_blob seq_num_blob = { 0 };
    if (conn->mode == S2N_CLIENT) {
        RESULT_GUARD_POSIX(s2n_blob_init(&seq_num_blob, conn->secure->client_sequence_number,
                sizeof(conn->secure->client_sequence_number)));
    } else {
        RESULT_GUARD_POSIX(s2n_blob_init(&seq_num_blob, conn->secure->server_sequence_number,
                sizeof(conn->secure->server_sequence_number)));
    }

    uint64_t seq_num = 0;
    RESULT_GUARD_POSIX(s2n_sequence_number_to_uint64(&seq_num_blob, &seq_num));
    RESULT_ENSURE_LTE(seq_num, conn->secure->cipher_suite->record_alg->encryption_limit);

    /* s2n-tls doesn't keep a running count of KeyUpdates, so to sanity check that
     * at least one KeyUpdate occurred we have to rely on some math.
     *
     * wire_bytes_out represents the total bytes sent, and should therefore be
     * less than or equal to (number of records sent) * (maximum size of a record).
     *
     * (maximum size of a record) can be calculated based on max_outgoing_fragment_length.
     * We will call it max_record_size.
     *
     * (number of records sent) is seq_num, if no KeyUpdates were sent. seq_num
     * starts at 0, is incremented by one for every record, and is reset to 0 by
     * a KeyUpdate. So if no KeyUpdate occurs, seq_num represents the total number
     * of records sent.
     *
     * If seq_num represents the total number of records sent, then wire_bytes_out
     * must be less than or equal to (seq_num) * (max_record_size).
     * If wire_bytes_out is instead greater than (seq_num) * (max_record_size),
     * then more records were sent than seq_num accounts for. That means that seq_num
     * must have been reset, which means that at least one KeyUpdate was sent.
     */
    size_t max_record_size = S2N_TLS13_MAX_RECORD_LEN_FOR(conn->max_outgoing_fragment_length);
    RESULT_ENSURE_GT(conn->wire_bytes_out, max_record_size * seq_num);

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_encryption_limits(struct s2n_connection *conn)
{
    RESULT_GUARD_POSIX(s2n_example_negotiate(conn));

    struct s2n_cipher_suite *original_suite = conn->secure->cipher_suite;
    S2N_CIPHER_SUITE_WITH_LIMIT(key_limit_suite, original_suite, S2N_TEST_ENCRYPTION_LIMIT);

    conn->secure->cipher_suite = &key_limit_suite;

    RESULT_GUARD(s2n_send_and_recv_random_data(conn));
    RESULT_GUARD(s2n_sanity_check_key_updates_sent(conn));

    conn->secure->cipher_suite = original_suite;
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_peer_requests(struct s2n_connection *conn)
{
    RESULT_GUARD_POSIX(s2n_example_negotiate(conn));

    struct s2n_cipher_suite *original_suite = conn->secure->cipher_suite;
    S2N_CIPHER_SUITE_WITH_LIMIT(key_limit_suite, original_suite, S2N_TEST_ENCRYPTION_LIMIT);

    conn->secure->cipher_suite = &key_limit_suite;
    if (conn->mode == S2N_CLIENT) {
        RESULT_GUARD(s2n_set_key_update_request_for_testing(S2N_KEY_UPDATE_REQUESTED));
    }

    RESULT_GUARD(s2n_send_and_recv_random_data(conn));
    RESULT_GUARD(s2n_sanity_check_key_updates_sent(conn));

    conn->secure->cipher_suite = original_suite;
    return S2N_RESULT_OK;
}

typedef S2N_RESULT (*s2n_test_scenario)(struct s2n_connection *conn);
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

    pid_t client_pid = fork();
    if (client_pid == 0) {
        /* Suppress stdout.
         * This only affects the new client process.
         */
        fclose(stdout);

        struct s2n_connection *client = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));

        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client, &io_pair));

        EXPECT_OK(scenario_fn(client));

        EXPECT_SUCCESS(s2n_connection_free(client));
        exit(EXIT_SUCCESS);
    }

    pid_t server_pid = fork();
    if (server_pid == 0) {
        /* Suppress stdouts.
         * This only affects the new server process.
         */
        fclose(stdout);

        struct s2n_connection *server = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server, &io_pair));

        EXPECT_OK(scenario_fn(server));

        EXPECT_SUCCESS(s2n_connection_free(server));
        exit(EXIT_SUCCESS);
    }

    int status = 0;
    RESULT_ENSURE_EQ(waitpid(client_pid, &status, 0), client_pid);
    RESULT_ENSURE_EQ(status, EXIT_SUCCESS);
    RESULT_ENSURE_EQ(waitpid(server_pid, &status, 0), server_pid);
    RESULT_ENSURE_EQ(status, EXIT_SUCCESS);

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* KeyUpdate requires TLS1.3 */
    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    /* We're going to fork, so flush the initial test output first */
    EXPECT_EQUAL(fflush(stdout), 0);

    EXPECT_OK(s2n_run_self_talk_test(s2n_test_encryption_limits));
    EXPECT_OK(s2n_run_self_talk_test(s2n_test_peer_requests));

    END_TEST();
}
