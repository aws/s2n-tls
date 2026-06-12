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

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls13.h"

/*
 * Helper: create a matching server+client config pair for a given cipher
 * preference string. The caller owns both configs and must free them.
 *
 * cert_chain / private_key are the PEM paths passed to
 * s2n_test_cert_chain_and_key_new().
 */
static S2N_RESULT s2n_setup_negotiated_pair(
        const char *cipher_pref,
        struct s2n_cert_chain_and_key *chain_and_key,
        struct s2n_connection **out_client,
        struct s2n_connection **out_server,
        struct s2n_config **out_config,
        struct s2n_test_io_pair *out_io_pair)
{
    RESULT_ENSURE_REF(out_client);
    RESULT_ENSURE_REF(out_server);
    RESULT_ENSURE_REF(out_config);
    RESULT_ENSURE_REF(out_io_pair);

    struct s2n_config *config = s2n_config_new();
    RESULT_ENSURE_REF(config);
    RESULT_GUARD_POSIX(s2n_config_set_unsafe_for_testing(config));
    RESULT_GUARD_POSIX(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    RESULT_GUARD_POSIX(s2n_config_set_cipher_preferences(config, cipher_pref));

    struct s2n_connection *client = s2n_connection_new(S2N_CLIENT);
    RESULT_ENSURE_REF(client);
    RESULT_GUARD_POSIX(s2n_connection_set_config(client, config));

    struct s2n_connection *server = s2n_connection_new(S2N_SERVER);
    RESULT_ENSURE_REF(server);
    RESULT_GUARD_POSIX(s2n_connection_set_config(server, config));

    RESULT_GUARD_POSIX(s2n_io_pair_init_non_blocking(out_io_pair));
    RESULT_GUARD_POSIX(s2n_connections_set_io_pair(client, server, out_io_pair));

    *out_client = client;
    *out_server = server;
    *out_config = config;

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Load certs used across multiple sub-tests */
    struct s2n_cert_chain_and_key *rsa_chain_and_key = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    struct s2n_cert_chain_and_key *ecdsa_chain_and_key = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    /* ── Safety ─────────────────────────────────────────────────────────── */
    {
        /* NULL connection must return an error (< 0), not 0 or 1 */
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_handshake_complete(NULL), S2N_ERR_NULL);
    };

    /* ── Fresh connection: not yet complete ─────────────────────────────── */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        /* A brand-new connection has never negotiated anything */
        EXPECT_EQUAL(s2n_connection_handshake_complete(conn), 0);
    };

    /* ── TLS 1.2: complete only after server Finished is consumed ────────
     *
     * This is the regression test for the bug described in the issue:
     * checking handshake_type() for "NEGOTIATED" returned true one loop
     * iteration before the server's Finished message was actually read,
     * leaving a stray handshake record that was then misrouted through
     * s2n_post_handshake_recv() and triggered S2N_ERR_BAD_MESSAGE.
     *
     * s2n_connection_handshake_complete() must NOT return 1 until
     * s2n_handshake_is_complete() is true on both sides.
     */
    {
        struct s2n_connection *client_conn = NULL;
        struct s2n_connection *server_conn = NULL;
        struct s2n_config *config = NULL;
        struct s2n_test_io_pair io_pair = {0};

        EXPECT_OK(s2n_setup_negotiated_pair("20170210", rsa_chain_and_key,
            &client_conn, &server_conn, &config, &io_pair));

        EXPECT_EQUAL(s2n_connection_handshake_complete(client_conn), 0);
        EXPECT_EQUAL(s2n_connection_handshake_complete(server_conn), 0);

        /* Drive the handshake one message at a time.
        * We stop as soon as the server side reports its handshake done
        * but BEFORE the client has had a chance to read the server's Finished.
        * At that exact point the old "NEGOTIATED bit" logic would have returned
        * 1 for the client; the new s2n_handshake_is_complete() path must return 0.
        */
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        bool server_done = false;
        
        while(!server_done){
            int server_rc = s2n_negotiate(server_conn, &blocked);
            if (server_rc == S2N_SUCCESS){
                server_done = true;
            }else{
                EXPECT_EQUAL(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
            }

            /* Key assertion: client must NOT yet be complete even though
            * the server just finished sending its Finished message.
            * The old buggy logic (handshake_type & NEGOTIATED) would
            * return 1 here; the correct implementation must return 0. */
            if (server_done) {
                EXPECT_EQUAL(s2n_connection_handshake_complete(server_conn), 1);
                EXPECT_EQUAL(s2n_connection_handshake_complete(client_conn), 0); /* <-- regression guard */
            }

            /* Pump client one step to consume what the server just wrote */
            int client_rc = s2n_negotiate(client_conn, &blocked);
            if (client_rc != S2N_SUCCESS) {
                EXPECT_EQUAL(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
            }
        }

        /* Now drain the client fully */
        while (s2n_negotiate(client_conn, &blocked) != S2N_SUCCESS) {
            EXPECT_EQUAL(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
        }

        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);

        EXPECT_EQUAL(s2n_connection_handshake_complete(client_conn), 1);
        EXPECT_EQUAL(s2n_connection_handshake_complete(server_conn), 1);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* ── TLS 1.3: complete after initial handshake exchange ─────────────
     *
     * Post-handshake messages (NewSessionTicket, KeyUpdate) must NOT reset
     * the completion flag — once 1, always 1 for the lifetime of the conn.
     */
    if (s2n_is_tls13_fully_supported()) {
        struct s2n_connection *client_conn = NULL;
        struct s2n_connection *server_conn = NULL;
        struct s2n_config *config = NULL;
        struct s2n_test_io_pair io_pair = { 0 };

        /* "default_tls13" negotiates TLS 1.3 when both sides support it */
        EXPECT_OK(s2n_setup_negotiated_pair("default_tls13", ecdsa_chain_and_key,
                &client_conn, &server_conn, &config, &io_pair));

        /* Before negotiation: neither side is complete */
        EXPECT_EQUAL(s2n_connection_handshake_complete(client_conn), 0);
        EXPECT_EQUAL(s2n_connection_handshake_complete(server_conn), 0);

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        bool server_done = false;

        while (!server_done) {
            int server_rc = s2n_negotiate(server_conn, &blocked);
            if (server_rc == S2N_SUCCESS) {
                server_done = true;
            } else {
                EXPECT_EQUAL(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
            }

            if (server_done) {
                EXPECT_EQUAL(s2n_connection_handshake_complete(server_conn), 1);
                EXPECT_EQUAL(s2n_connection_handshake_complete(client_conn), 0);
            }

            int client_rc = s2n_negotiate(client_conn, &blocked);
            if (client_rc != S2N_SUCCESS) {
                EXPECT_EQUAL(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
            }
        }

        /* Drain client fully */
        while (s2n_negotiate(client_conn, &blocked) != S2N_SUCCESS) {
            EXPECT_EQUAL(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
        }

        /* Verify we actually negotiated TLS 1.3 */
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

        /* After handshake: both sides complete */
        EXPECT_EQUAL(s2n_connection_handshake_complete(client_conn), 1);
        EXPECT_EQUAL(s2n_connection_handshake_complete(server_conn), 1);

        /* Post-handshake: pump NST server→client and assert flag stays 1 */
        s2n_negotiate(server_conn, &blocked);
        s2n_negotiate(client_conn, &blocked);

        EXPECT_EQUAL(s2n_connection_handshake_complete(client_conn), 1);
        EXPECT_EQUAL(s2n_connection_handshake_complete(server_conn), 1);
        
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* ── Return value semantics ──────────────────────────────────────────
     *
     * The public contract is:
     *   1  → complete
     *   0  → not yet complete
     *  <0  → error (e.g. NULL)
     *
     * Verify the non-error path returns exactly 0 or 1, never another int.
     */
    {
        struct s2n_connection *client_conn = NULL;
        struct s2n_connection *server_conn = NULL;
        struct s2n_config *config = NULL;
        struct s2n_test_io_pair io_pair = { 0 };

        EXPECT_OK(s2n_setup_negotiated_pair("20170210", rsa_chain_and_key,
                &client_conn, &server_conn, &config, &io_pair));

        int before = s2n_connection_handshake_complete(client_conn);
        EXPECT_TRUE(before == 0 || before == 1); /* must be exactly 0 before */
        EXPECT_EQUAL(before, 0);

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        int after = s2n_connection_handshake_complete(client_conn);
        EXPECT_TRUE(after == 0 || after == 1); /* must be exactly 1 after */
        EXPECT_EQUAL(after, 1);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* Cleanup shared certs */
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(rsa_chain_and_key));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_chain_and_key));

    END_TEST();
}
