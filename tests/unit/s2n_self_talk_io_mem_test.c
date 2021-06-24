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
#include "tls/s2n_tls13.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_cert_chain_and_key *chain_and_key;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    struct s2n_config *config = s2n_config_new();
    EXPECT_NOT_NULL(config);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

    /* Allocate output buffer based on default fragment length */
    {
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Do handshake */
        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, SERVER_CERT));
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

        /* Output memory allocated according to max fragment length. */
        EXPECT_EQUAL(client_conn->max_outgoing_fragment_length, S2N_DEFAULT_FRAGMENT_LENGTH);
        EXPECT_EQUAL(server_conn->max_outgoing_fragment_length, S2N_DEFAULT_FRAGMENT_LENGTH);
        /* The client allocates the protocol-agnostic max record size because when it sends its
         * first message (ClientHello) the protocol hasn't been negotiated yet. */
        EXPECT_EQUAL(client_conn->out.blob.size, S2N_TLS_MAX_RECORD_LEN_FOR(S2N_DEFAULT_FRAGMENT_LENGTH));
        /* The server allocates only enough memory for TLS1.3 records because when it sends its
         * first message (ServerHello) the protocol has already been negotiated. */
        EXPECT_EQUAL(server_conn->out.blob.size, S2N_TLS13_MAX_RECORD_LEN_FOR(S2N_DEFAULT_FRAGMENT_LENGTH));

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Allocate output buffer to max fragment size set manually */
    {
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Set connections to use different fragment sizes */
        EXPECT_SUCCESS(s2n_connection_prefer_low_latency(client_conn));
        EXPECT_SUCCESS(s2n_connection_prefer_throughput(server_conn));

        /* Do handshake */
        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, SERVER_CERT));
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

        /* Output memory allocated according to max fragment length. */
        EXPECT_EQUAL(client_conn->max_outgoing_fragment_length, S2N_SMALL_FRAGMENT_LENGTH);
        EXPECT_EQUAL(server_conn->max_outgoing_fragment_length, S2N_LARGE_FRAGMENT_LENGTH);
        EXPECT_EQUAL(client_conn->out.blob.size, S2N_TLS_MAX_RECORD_LEN_FOR(S2N_SMALL_FRAGMENT_LENGTH));
        EXPECT_EQUAL(server_conn->out.blob.size, S2N_TLS13_MAX_RECORD_LEN_FOR(S2N_LARGE_FRAGMENT_LENGTH));

        /* Switch max fragment lengths after handshake to verify whether buffers are resized */
        EXPECT_SUCCESS(s2n_connection_prefer_throughput(client_conn));
        EXPECT_SUCCESS(s2n_connection_prefer_low_latency(server_conn));
        EXPECT_EQUAL(client_conn->max_outgoing_fragment_length, S2N_LARGE_FRAGMENT_LENGTH);
        EXPECT_EQUAL(server_conn->max_outgoing_fragment_length, S2N_SMALL_FRAGMENT_LENGTH);
        EXPECT_EQUAL(client_conn->out.blob.size, S2N_TLS13_MAX_RECORD_LEN_FOR(S2N_LARGE_FRAGMENT_LENGTH));
        EXPECT_EQUAL(server_conn->out.blob.size, S2N_TLS13_MAX_RECORD_LEN_FOR(S2N_LARGE_FRAGMENT_LENGTH));

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Allocate output buffer to value negotiated with max_fragment_length extension */
    {
        const s2n_max_frag_len mfl_code = S2N_TLS_MAX_FRAG_LEN_2048;
        const uint16_t expected_mfl = 2048;

        struct s2n_config *config_for_mfl = s2n_config_new();
        EXPECT_NOT_NULL(config_for_mfl);
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config_for_mfl, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config_for_mfl));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config_for_mfl, chain_and_key));
        EXPECT_SUCCESS(s2n_config_send_max_fragment_length(config_for_mfl, mfl_code));
        EXPECT_SUCCESS(s2n_config_accept_max_fragment_length(config_for_mfl));

        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config_for_mfl));

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config_for_mfl));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Set connections to use fragment size larger than what will be negotiated
         * via the max_fragment_length extension */
        EXPECT_SUCCESS(s2n_connection_prefer_throughput(client_conn));
        EXPECT_SUCCESS(s2n_connection_prefer_throughput(server_conn));

        /* Do handshake */
        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, SERVER_CERT));
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

        /* Output memory allocated according to max fragment length. */
        EXPECT_EQUAL(client_conn->max_outgoing_fragment_length, expected_mfl);
        EXPECT_EQUAL(server_conn->max_outgoing_fragment_length, expected_mfl);
        /* The client allocates enough memory for the initial large max_fragment_length, because the
         * final smaller max_fragment_length has not be negotiated yet when its first message (the ClientHello) is sent. */
        EXPECT_EQUAL(client_conn->out.blob.size, S2N_TLS_MAX_RECORD_LEN_FOR(S2N_LARGE_FRAGMENT_LENGTH));
        /* The server only allocates enough memory for the negotiated small max_fragment_length, because the
         * max_fragment_length is negotiated before its first message (the ServerHello) is sent. */
        EXPECT_EQUAL(server_conn->out.blob.size, S2N_TLS13_MAX_RECORD_LEN_FOR(expected_mfl));

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_config_free(config_for_mfl));
    }

    /* Output and input buffers both freed on connection wipe */
    {
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        /* All IO buffers empty */
        EXPECT_EQUAL(client_conn->in.blob.size, 0);
        EXPECT_EQUAL(server_conn->in.blob.size, 0);
        EXPECT_EQUAL(client_conn->out.blob.size, 0);
        EXPECT_EQUAL(server_conn->out.blob.size, 0);

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* Do handshake */
        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn, SERVER_CERT));

        /* All IO buffers not empty */
        EXPECT_NOT_EQUAL(client_conn->in.blob.size, 0);
        EXPECT_NOT_EQUAL(server_conn->in.blob.size, 0);
        EXPECT_NOT_EQUAL(client_conn->out.blob.size, 0);
        EXPECT_NOT_EQUAL(server_conn->out.blob.size, 0);

        /* Wipe connections */
        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        EXPECT_EQUAL(client_conn->in.blob.size, 0);
        EXPECT_EQUAL(server_conn->in.blob.size, 0);
        EXPECT_EQUAL(client_conn->out.blob.size, 0);
        EXPECT_EQUAL(server_conn->out.blob.size, 0);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    EXPECT_SUCCESS(s2n_config_free(config));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    END_TEST();
}
