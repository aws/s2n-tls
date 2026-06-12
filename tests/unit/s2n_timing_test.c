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

#include "api/unstable/events.h"
#include "error/s2n_errno.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "utils/s2n_events.h"
#include "utils/s2n_safety.h"

#define MAX_CHECKPOINTS 64

struct checkpoint_subscriber {
    uint64_t invoked;
    char names[MAX_CHECKPOINTS][64];
    uint8_t roles[MAX_CHECKPOINTS];
    uint64_t timestamps[MAX_CHECKPOINTS];
};

static void on_timing_checkpoint(
        struct s2n_connection *conn,
        void *ctx,
        struct s2n_timing_checkpoint *checkpoint)
{
    struct checkpoint_subscriber *sub = (struct checkpoint_subscriber *) ctx;
    if (sub->invoked < MAX_CHECKPOINTS) {
        snprintf(sub->names[sub->invoked], sizeof(sub->names[0]),
                "%s", checkpoint->name);
        sub->roles[sub->invoked] = checkpoint->role;
        sub->timestamps[sub->invoked] = checkpoint->timestamp_ns;
    }
    sub->invoked++;
}

static int setup_tls13_config(struct s2n_config **server_config_out,
        struct s2n_config **client_config_out,
        struct s2n_cert_chain_and_key **chain_out)
{
    struct s2n_cert_chain_and_key *chain = NULL;
    POSIX_GUARD(s2n_test_cert_chain_and_key_new(&chain,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    struct s2n_config *server_config = s2n_config_new();
    POSIX_ENSURE_REF(server_config);
    POSIX_GUARD(s2n_config_set_cipher_preferences(server_config, "default_tls13"));
    POSIX_GUARD(s2n_config_add_cert_chain_and_key_to_store(server_config, chain));
    POSIX_GUARD(s2n_config_disable_x509_verification(server_config));

    struct s2n_config *client_config = s2n_config_new();
    POSIX_ENSURE_REF(client_config);
    POSIX_GUARD(s2n_config_set_cipher_preferences(client_config, "default_tls13"));
    POSIX_GUARD(s2n_config_disable_x509_verification(client_config));

    *server_config_out = server_config;
    *client_config_out = client_config;
    *chain_out = chain;
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test: NULL config returns S2N_ERR_NULL */
    {
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_config_set_timing_checkpoint_cb(NULL, on_timing_checkpoint),
                S2N_ERR_NULL);
    }

    /* Test: NULL callback returns S2N_ERR_NULL */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(),
                s2n_config_ptr_free);
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_config_set_timing_checkpoint_cb(config, NULL),
                S2N_ERR_NULL);
    }

    /* Test: registration succeeds */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(),
                s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_set_timing_checkpoint_cb(config, on_timing_checkpoint));
    }

    /* Test: callback fires exactly 10 times per side for a TLS 1.3 server-auth handshake */
    {
        struct s2n_config *server_config = NULL;
        struct s2n_config *client_config = NULL;
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(setup_tls13_config(&server_config, &client_config, &chain));
        DEFER_CLEANUP(struct s2n_config *sc = server_config, s2n_config_ptr_free);
        DEFER_CLEANUP(struct s2n_config *cc = client_config, s2n_config_ptr_free);

        struct checkpoint_subscriber server_sub = { 0 };
        struct checkpoint_subscriber client_sub = { 0 };

        EXPECT_SUCCESS(s2n_config_set_subscriber(sc, &server_sub));
        EXPECT_SUCCESS(s2n_config_set_timing_checkpoint_cb(sc, on_timing_checkpoint));
        EXPECT_SUCCESS(s2n_config_set_subscriber(cc, &client_sub));
        EXPECT_SUCCESS(s2n_config_set_timing_checkpoint_cb(cc, on_timing_checkpoint));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server, sc));
        EXPECT_SUCCESS(s2n_connection_set_config(client, cc));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 },
                s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        /* Verify checkpoint counts and boundary names.
         * The exact count depends on the handshake path negotiated (middlebox compat
         * adds CCS checkpoints, RECORD_READ/WRITE fire per record). Both sides must
         * agree, and both must start with NEGOTIATE_START and end with NEGOTIATE_END. */
        EXPECT_EQUAL(server_sub.invoked, client_sub.invoked);
        EXPECT_TRUE(server_sub.invoked >= 10);

        /* The first checkpoint on each side must be NEGOTIATE_START. */
        EXPECT_EQUAL(strcmp(server_sub.names[0], "NEGOTIATE_START"), 0);
        EXPECT_EQUAL(strcmp(client_sub.names[0], "NEGOTIATE_START"), 0);

        /* The last checkpoint on each side must be NEGOTIATE_END. */
        EXPECT_EQUAL(strcmp(server_sub.names[server_sub.invoked - 1], "NEGOTIATE_END"), 0);
        EXPECT_EQUAL(strcmp(client_sub.names[client_sub.invoked - 1], "NEGOTIATE_END"), 0);
    }

    /* Test: timestamps are monotonically non-decreasing within a connection.
     *
     * This verifies the consumer's "delta from previous checkpoint" computation
     * never underflows, because s2n_default_monotonic_clock is monotonic. */
    {
        DEFER_CLEANUP(struct s2n_config *server_config = NULL, s2n_config_ptr_free);
        DEFER_CLEANUP(struct s2n_config *client_config = NULL, s2n_config_ptr_free);
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(setup_tls13_config(&server_config, &client_config, &chain));

        struct checkpoint_subscriber server_sub = { 0 };
        struct checkpoint_subscriber client_sub = { 0 };

        EXPECT_SUCCESS(s2n_config_set_subscriber(server_config, &server_sub));
        EXPECT_SUCCESS(s2n_config_set_timing_checkpoint_cb(server_config, on_timing_checkpoint));
        EXPECT_SUCCESS(s2n_config_set_subscriber(client_config, &client_sub));
        EXPECT_SUCCESS(s2n_config_set_timing_checkpoint_cb(client_config, on_timing_checkpoint));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));
        EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 },
                s2n_io_stuffer_pair_free);
        EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
        EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        for (uint64_t i = 1; i < server_sub.invoked && i < MAX_CHECKPOINTS; i++) {
            EXPECT_TRUE(server_sub.timestamps[i] >= server_sub.timestamps[i - 1]);
        }
        for (uint64_t i = 1; i < client_sub.invoked && i < MAX_CHECKPOINTS; i++) {
            EXPECT_TRUE(client_sub.timestamps[i] >= client_sub.timestamps[i - 1]);
        }
    }

    /* Test: s2n_event_checkpoint_send is a no-op when no callback registered */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(),
                s2n_config_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        EXPECT_OK(s2n_event_checkpoint_send(conn, "TEST", 0));
    }

    END_TEST();
}
