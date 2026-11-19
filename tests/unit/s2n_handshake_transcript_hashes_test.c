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
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls13.h"

static size_t s2n_count_required_hashes(struct s2n_connection *conn)
{
    size_t count = 0;
    for (s2n_hash_algorithm hash_alg = 0; hash_alg < S2N_HASH_ALGS_COUNT; hash_alg++) {
        if (s2n_handshake_is_hash_required(&conn->handshake, hash_alg)) {
            count++;
        }
    }
    return count;
}

/* required_hash_algs must never contain a hash that the security policy ruled
 * out. Such a hash state would be missing earlier transcript messages while
 * still being advertised as usable. */
static S2N_RESULT s2n_assert_hashes_within_policy(struct s2n_connection *conn)
{
    const struct s2n_security_policy *policy = NULL;
    RESULT_GUARD_POSIX(s2n_connection_get_security_policy(conn, &policy));

    uint8_t possible[S2N_HASH_ALGS_COUNT] = { 0 };
    RESULT_GUARD(s2n_security_policy_get_required_hash_algs(policy, possible));

    for (s2n_hash_algorithm hash_alg = 0; hash_alg < S2N_HASH_ALGS_COUNT; hash_alg++) {
        if (s2n_handshake_is_hash_required(&conn->handshake, hash_alg)) {
            RESULT_ENSURE_EQ(possible[hash_alg], 1);
        }
    }
    return S2N_RESULT_OK;
}

static struct s2n_config *s2n_test_config_new(struct s2n_cert_chain_and_key *chain, const char *policy)
{
    struct s2n_config *config = s2n_config_new();
    PTR_ENSURE_REF(config);
    PTR_GUARD_POSIX(s2n_config_add_cert_chain_and_key_to_store(config, chain));
    PTR_GUARD_POSIX(s2n_config_set_unsafe_for_testing(config));
    PTR_GUARD_POSIX(s2n_config_set_cipher_preferences(config, policy));
    return config;
}

static int s2n_test_swap_config_client_hello_cb(struct s2n_connection *conn, void *ctx)
{
    POSIX_GUARD(s2n_connection_set_config(conn, (struct s2n_config *) ctx));
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    /* The client hedges across every hash until it knows the cipher suite, so
     * narrowing by policy reduces the hashes used for its ClientHello.
     *
     * The server never hedges: it negotiates the cipher suite while handling the
     * ClientHello, before that message is added to the transcript, so it is
     * already down to the single PRF hash before it hashes anything. Narrowing by
     * policy must not undo that. */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_test_config_new(chain, "default_tls13"),
                s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

        /* Before anything is hashed, both peers require every hash */
        EXPECT_EQUAL(s2n_count_required_hashes(client), S2N_HASH_ALGS_COUNT);
        EXPECT_EQUAL(s2n_count_required_hashes(server), S2N_HASH_ALGS_COUNT);

        /* Stop here: the server hashed the ClientHello when it received it, and the
         * client's narrowed set is overwritten by the negotiated hash as soon as it
         * reads a ServerHello. */
        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server, client, SERVER_HELLO));

        /* The client is down to the hashes default_tls13 could need. It permits
         * TLS1.2, so its TLS1.2 signature preferences contribute SHA512 on top of
         * the two possible PRF hashes. The legacy hashes are ruled out. */
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&client->handshake, S2N_HASH_MD5), 0);
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&client->handshake, S2N_HASH_SHA1), 0);
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&client->handshake, S2N_HASH_SHA224), 0);
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&client->handshake, S2N_HASH_SHA256), 1);
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&client->handshake, S2N_HASH_SHA384), 1);
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&client->handshake, S2N_HASH_SHA512), 1);

        /* The server has already reached the single negotiated hash */
        EXPECT_EQUAL(s2n_count_required_hashes(server), 1);
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&server->handshake, S2N_HASH_SHA256), 1);

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
        /* Everything above holds on any libcrypto, because default_tls13 permits
         * TLS1.2 and computes the same hash set either way. These last checks are
         * TLS1.3 specific, so they are skipped on a libcrypto without RSA-PSS
         * support, such as openssl-1.0.2, which cannot negotiate TLS1.3.
         */
        if (s2n_is_tls13_fully_supported()) {
            EXPECT_EQUAL(server->actual_protocol_version, S2N_TLS13);
            EXPECT_EQUAL(s2n_count_required_hashes(client), 1);
            EXPECT_EQUAL(s2n_count_required_hashes(server), 1);
        }
    };

    /* Narrowing must never widen an already narrowed set, for any policy, in
     * either mode, with or without client auth.
     *
     * Client auth is the interesting case: in TLS1.2 the CertificateVerify
     * transcript hash is the negotiated signature scheme's hash, so
     * s2n_conn_update_required_handshake_hashes re-enables every hash until that
     * message is past. Those must still be restricted to the policy, otherwise a
     * hash is marked usable while missing earlier messages.
     *
     * The policies cover the distinct shapes of the computed set: modern TLS1.2
     * and TLS1.3, TLS1.3 only, and a legacy policy that can rule nothing out. */
    {
        struct {
            const char *policy;
            bool requires_tls13;
        } test_cases[] = {
            { .policy = "default_tls13" },
            { .policy = "20240501" },
            { .policy = "20250414", .requires_tls13 = true },
            { .policy = "20170210" },
        };
        const s2n_cert_auth_type auth_types[] = { S2N_CERT_AUTH_NONE, S2N_CERT_AUTH_REQUIRED };

        for (size_t p = 0; p < s2n_array_len(test_cases); p++) {
            /* A TLS1.3-only policy is rejected outright by a libcrypto that cannot
             * do TLS1.3, so there is nothing to negotiate. */
            if (test_cases[p].requires_tls13 && !s2n_is_tls13_fully_supported()) {
                continue;
            }

            for (size_t a = 0; a < s2n_array_len(auth_types); a++) {
                DEFER_CLEANUP(struct s2n_config *config = s2n_test_config_new(chain, test_cases[p].policy),
                        s2n_config_ptr_free);
                EXPECT_NOT_NULL(config);
                EXPECT_SUCCESS(s2n_config_set_client_auth_type(config, auth_types[a]));

                DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                        s2n_connection_ptr_free);
                DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                EXPECT_SUCCESS(s2n_connection_set_config(client, config));
                EXPECT_SUCCESS(s2n_connection_set_config(server, config));

                DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
                EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
                EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

                /* A handshake only completes if every hash that was read had the
                 * full transcript, so success is itself an assertion. */
                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

                EXPECT_OK(s2n_assert_hashes_within_policy(client));
                EXPECT_OK(s2n_assert_hashes_within_policy(server));
                EXPECT_EQUAL(s2n_count_required_hashes(client), 1);
                EXPECT_EQUAL(s2n_count_required_hashes(server), 1);
            }
        }
    };

    /* Replacing the config during the client hello callback changes the effective
     * policy before the ClientHello is hashed, so narrowing must use the policy
     * that is actually in effect. Here the replacement needs the legacy hashes
     * that the original policy ruled out. */
    {
        DEFER_CLEANUP(struct s2n_config *client_config = s2n_test_config_new(chain, "test_all_tls12"),
                s2n_config_ptr_free);
        DEFER_CLEANUP(struct s2n_config *initial_config = s2n_test_config_new(chain, "default_tls13"),
                s2n_config_ptr_free);
        DEFER_CLEANUP(struct s2n_config *swapped_config = s2n_test_config_new(chain, "20170210"),
                s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_NOT_NULL(initial_config);
        EXPECT_NOT_NULL(swapped_config);
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(initial_config,
                s2n_test_swap_config_client_hello_cb, swapped_config));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server, initial_config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
        EXPECT_EQUAL(server->config, swapped_config);
        EXPECT_OK(s2n_assert_hashes_within_policy(server));
    };

    /* A wiped connection requires every hash again, so a reused or renegotiated
     * connection does not inherit the previous handshake's narrowed set.
     * s2n_connection_new ends with a wipe, so this covers new connections too.
     *
     * The reused connection must then narrow again by itself. Narrowing happens
     * on the transcript update rather than when the config is set, so reuse does
     * not depend on the application calling s2n_connection_set_config a second
     * time. s2n_connection_wipe preserves conn->config, and that is the only
     * thing the narrowing needs. */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_test_config_new(chain, "default_tls13"),
                s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_SUCCESS(s2n_connection_set_config(client, config));
        EXPECT_SUCCESS(s2n_connection_set_config(server, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));

        /* Wiping restores the hedge across every hash */
        EXPECT_SUCCESS(s2n_connection_wipe(client));
        EXPECT_SUCCESS(s2n_connection_wipe(server));
        EXPECT_EQUAL(s2n_count_required_hashes(client), S2N_HASH_ALGS_COUNT);
        EXPECT_EQUAL(s2n_count_required_hashes(server), S2N_HASH_ALGS_COUNT);

        /* Reuse both connections without touching their config again */
        DEFER_CLEANUP(struct s2n_test_io_pair reuse_io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&reuse_io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &reuse_io_pair));

        /* Stop here: the server hashed the ClientHello when it received it, and the
         * client's narrowed set is overwritten by the negotiated hash as soon as it
         * reads a ServerHello. */
        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server, client, SERVER_HELLO));

        /* The second handshake narrowed to the policy's hashes just like the
         * first, rather than staying on the full hedge */
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&client->handshake, S2N_HASH_MD5), 0);
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&client->handshake, S2N_HASH_SHA1), 0);
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&client->handshake, S2N_HASH_SHA224), 0);
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&client->handshake, S2N_HASH_SHA256), 1);
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&client->handshake, S2N_HASH_SHA384), 1);
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&client->handshake, S2N_HASH_SHA512), 1);
        EXPECT_EQUAL(s2n_count_required_hashes(server), 1);

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
    };

    END_TEST();
}
