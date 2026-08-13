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
        /* NULL connection is infallible: it must return false, not an error */
        EXPECT_EQUAL(s2n_connection_handshake_complete(NULL), false);
    };

    /* ── Fresh connection: not yet complete ─────────────────────────────── */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        /* A brand-new connection has never negotiated anything */
        EXPECT_EQUAL(s2n_connection_handshake_complete(conn), false);
    };

    /* ── TLS 1.2: complete only after server Finished is consumed ────────
     *
     * This is the regression test for the bug described in the issue:
     * checking handshake_type() for "NEGOTIATED" returned true one loop
     * iteration before the server's Finished message was actually read,
     * leaving a stray handshake record that was then misrouted through
     * s2n_post_handshake_recv() and triggered S2N_ERR_BAD_MESSAGE.
     *
     * s2n_connection_handshake_complete() must NOT return true until
     * s2n_handshake_is_complete() is true on both sides.
     */
    {
        struct s2n_connection *client_conn = NULL;
        struct s2n_connection *server_conn = NULL;
        struct s2n_config *config = NULL;
        struct s2n_test_io_pair io_pair = { 0 };

        EXPECT_OK(s2n_setup_negotiated_pair("20170210", rsa_chain_and_key,
                &client_conn, &server_conn, &config, &io_pair));

        EXPECT_EQUAL(s2n_connection_handshake_complete(client_conn), false);
        EXPECT_EQUAL(s2n_connection_handshake_complete(server_conn), false);

        /* Deterministically stop the client right before it consumes the
         * server's Finished message, while letting the server run to
         * completion. This avoids relying on a hand-pumped s2n_negotiate()
         * loop, where the exact interleaving of client/server steps is not
         * guaranteed and could mask this regression instead of catching it.
         *
         * s2n_negotiate_until_message() only performs a single I/O attempt
         * per call and returns S2N_ERR_T_BLOCKED like s2n_negotiate() does,
         * so we still have to pump it in a loop until the connection is
         * actually blocked waiting to read SERVER_FINISHED (rather than
         * blocked on a socket write it hasn't finished yet).
         *
         * Key assertion: client must NOT yet be complete even though
         * the server has already finished sending its Finished message.
         * The old buggy logic (handshake_type & NEGOTIATED) would
         * return true here; the correct implementation must return false.
         */
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;

        while (s2n_result_is_error(s2n_negotiate_until_message(client_conn, &blocked, SERVER_FINISHED))) {
            EXPECT_EQUAL(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
            if (s2n_negotiate(server_conn, &blocked) != S2N_SUCCESS) {
                EXPECT_EQUAL(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
            }
        }

        EXPECT_EQUAL(s2n_connection_handshake_complete(server_conn), true);
        EXPECT_EQUAL(s2n_connection_handshake_complete(client_conn), false); /* <-- regression guard */

        /* Now drain the client fully */
        while (s2n_negotiate(client_conn, &blocked) != S2N_SUCCESS) {
            EXPECT_EQUAL(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
        }

        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);

        EXPECT_EQUAL(s2n_connection_handshake_complete(client_conn), true);
        EXPECT_EQUAL(s2n_connection_handshake_complete(server_conn), true);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* ── TLS 1.3: complete after initial handshake exchange ─────────────
     *
     * Post-handshake messages (NewSessionTicket, KeyUpdate) must NOT reset
     * the completion flag — once true, always true for the lifetime of the conn.
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
        EXPECT_EQUAL(s2n_connection_handshake_complete(client_conn), false);
        EXPECT_EQUAL(s2n_connection_handshake_complete(server_conn), false);

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;

        /* Drive the server to completion. Unlike TLS 1.2, TLS 1.3's message
         * flow doesn't guarantee the client is still incomplete once the
         * server is done, so we don't assert on the client's state here -
         * we only assert what TLS 1.3 actually guarantees: the server
         * is done once s2n_negotiate() returns success for it.
         */
        while (s2n_negotiate(server_conn, &blocked) != S2N_SUCCESS) {
            EXPECT_EQUAL(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
        }
        EXPECT_EQUAL(s2n_connection_handshake_complete(server_conn), true);

        /* Drain client fully */
        while (s2n_negotiate(client_conn, &blocked) != S2N_SUCCESS) {
            EXPECT_EQUAL(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
        }

        /* Verify we actually negotiated TLS 1.3 */
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

        /* After handshake: both sides complete */
        EXPECT_EQUAL(s2n_connection_handshake_complete(client_conn), true);
        EXPECT_EQUAL(s2n_connection_handshake_complete(server_conn), true);

        /* Post-handshake: deterministically pump a NewSessionTicket from
         * server to client, and confirm one was actually received rather
         * than assuming the two bare s2n_negotiate() calls did something.
         */
        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server_conn, client_conn,
                SERVER_NEW_SESSION_TICKET));
        EXPECT_TRUE(s2n_connection_get_session_ticket_lifetime_hint(client_conn) > 0);

        EXPECT_EQUAL(s2n_connection_handshake_complete(client_conn), true);
        EXPECT_EQUAL(s2n_connection_handshake_complete(server_conn), true);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_config_free(config));
    };

    /* ── Return value semantics ──────────────────────────────────────────
     *
     * The public contract is:
     *   true  → complete
     *   false → not yet complete (or conn is NULL)
     *
     * The function is infallible: verify it returns exactly a bool value
     * before and after negotiation.
     */
    {
        struct s2n_connection *client_conn = NULL;
        struct s2n_connection *server_conn = NULL;
        struct s2n_config *config = NULL;
        struct s2n_test_io_pair io_pair = { 0 };

        EXPECT_OK(s2n_setup_negotiated_pair("20170210", rsa_chain_and_key,
                &client_conn, &server_conn, &config, &io_pair));

        bool before = s2n_connection_handshake_complete(client_conn);
        EXPECT_EQUAL(before, false);

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        bool after = s2n_connection_handshake_complete(client_conn);
        EXPECT_EQUAL(after, true);

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
