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

#include "pq-crypto/s2n_pq.h"
#include "s2n.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_client_renegotiation_info.h"
#include "tls/extensions/s2n_cookie.h"
#include "tls/extensions/s2n_extension_type_lists.h"
#include "tls/extensions/s2n_server_supported_versions.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_tls13_handshake.h"

/* This include is required to access static function s2n_server_hello_parse */
#include "error/s2n_errno.h"
#include "tls/extensions/s2n_early_data_indication.h"
#include "tls/extensions/s2n_server_key_share.h"
#include "tls/s2n_server_hello.c"
#include "utils/s2n_bitmap.h"
#include "utils/s2n_safety.h"

#define HELLO_RETRY_MSG_NO  1
#define SERVER_HELLO_MSG_NO 5

static int s2n_client_hello_cb_with_get_server_name(struct s2n_connection *conn, void *ctx)
{
    const char *expected_server_name = (const char *) ctx;
    const char *actual_server_name = s2n_get_server_name(conn);
    POSIX_ENSURE_EQ(strcmp(expected_server_name, actual_server_name), 0);
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    EXPECT_SUCCESS(s2n_enable_tls13_in_test());

    /* Test s2n_server_hello_retry_recv */
    {
        /* s2n_server_hello_retry_recv must fail when a keyshare for a matching curve was already present */
        {
            struct s2n_config *config;
            struct s2n_connection *conn;

            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            const struct s2n_ecc_preferences *ecc_pref = NULL;
            POSIX_GUARD(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            conn->actual_protocol_version = S2N_TLS13;
            conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
            conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];

            EXPECT_NULL(conn->kex_params.client_ecc_evp_params.evp_pkey);
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.client_ecc_evp_params));
            EXPECT_NOT_NULL(conn->kex_params.client_ecc_evp_params.evp_pkey);

            EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_retry_recv(conn), S2N_ERR_INVALID_HELLO_RETRY);

            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* s2n_server_hello_retry_recv must fail for a connection with actual protocol version less than TLS13 */
        {
            struct s2n_config *config;
            struct s2n_connection *conn;

            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

            conn->actual_protocol_version = S2N_TLS12;

            EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_retry_recv(conn), S2N_ERR_INVALID_HELLO_RETRY);

            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test ECC success case for s2n_server_hello_retry_recv */
        {
            struct s2n_config *server_config;
            struct s2n_config *client_config;

            struct s2n_connection *server_conn;
            struct s2n_connection *client_conn;

            struct s2n_cert_chain_and_key *tls13_chain_and_key;
            char tls13_cert_chain[S2N_MAX_TEST_PEM_SIZE] = { 0 };
            char tls13_private_key[S2N_MAX_TEST_PEM_SIZE] = { 0 };

            EXPECT_NOT_NULL(server_config = s2n_config_new());
            EXPECT_NOT_NULL(client_config = s2n_config_new());

            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

            EXPECT_NOT_NULL(tls13_chain_and_key = s2n_cert_chain_and_key_new());
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, tls13_cert_chain, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, tls13_private_key, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(tls13_chain_and_key, tls13_cert_chain, tls13_private_key));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, tls13_chain_and_key));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, tls13_chain_and_key));

            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

            /* Force the HRR path */
            client_conn->security_policy_override = &security_policy_test_tls13_retry;

            /* ClientHello 1 */
            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                    s2n_stuffer_data_available(&client_conn->handshake.io)));

            /* Server receives ClientHello 1 */
            EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

            server_conn->kex_params.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];
            EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(server_conn));

            /* Server sends HelloRetryMessage */
            EXPECT_SUCCESS(s2n_server_hello_retry_send(server_conn));

            EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                    s2n_stuffer_data_available(&server_conn->handshake.io)));
            client_conn->handshake.message_number = HELLO_RETRY_MSG_NO;
            /* Read the message off the wire */
            EXPECT_SUCCESS(s2n_server_hello_parse(client_conn));
            client_conn->actual_protocol_version_established = 1;

            EXPECT_SUCCESS(s2n_conn_set_handshake_type(client_conn));
            /* Client receives the HelloRetryRequest mesage */
            EXPECT_SUCCESS(s2n_server_hello_retry_recv(client_conn));

            EXPECT_SUCCESS(s2n_config_free(client_config));
            EXPECT_SUCCESS(s2n_config_free(server_config));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls13_chain_and_key));
        };

        {
            const struct s2n_kem_group *test_kem_groups[] = {
                &s2n_secp256r1_kyber_512_r3,
#if EVP_APIS_SUPPORTED
                &s2n_x25519_kyber_512_r3,
#endif
            };

            const struct s2n_kem_preferences test_kem_prefs = {
                .kem_count = 0,
                .kems = NULL,
                .tls13_kem_group_count = s2n_array_len(test_kem_groups),
                .tls13_kem_groups = test_kem_groups,
            };

            const struct s2n_security_policy test_security_policy = {
                .minimum_protocol_version = S2N_SSLv3,
                .cipher_preferences = &cipher_preferences_test_all_tls13,
                .kem_preferences = &test_kem_prefs,
                .signature_preferences = &s2n_signature_preferences_20200207,
                .ecc_preferences = &s2n_ecc_preferences_20200310,
            };

            if (!s2n_pq_is_enabled()) {
                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                conn->actual_protocol_version = S2N_TLS13;
                conn->security_policy_override = &test_security_policy;

                const struct s2n_kem_preferences *kem_pref = NULL;
                POSIX_GUARD(s2n_connection_get_kem_preferences(conn, &kem_pref));
                EXPECT_NOT_NULL(kem_pref);

                conn->kex_params.server_kem_group_params.kem_group = kem_pref->tls13_kem_groups[0];
                EXPECT_NULL(conn->kex_params.server_ecc_evp_params.negotiated_curve);

                EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_retry_recv(conn), S2N_ERR_PQ_DISABLED);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            } else {
                /* s2n_server_hello_retry_recv must fail when a keyshare for a matching PQ KEM was already present */
                {
                    struct s2n_connection *conn;
                    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                    conn->actual_protocol_version = S2N_TLS13;
                    conn->security_policy_override = &test_security_policy;

                    const struct s2n_kem_preferences *kem_pref = NULL;
                    POSIX_GUARD(s2n_connection_get_kem_preferences(conn, &kem_pref));
                    EXPECT_NOT_NULL(kem_pref);

                    conn->kex_params.server_kem_group_params.kem_group = kem_pref->tls13_kem_groups[0];
                    EXPECT_NULL(conn->kex_params.server_ecc_evp_params.negotiated_curve);

                    struct s2n_kem_group_params *client_params = &conn->kex_params.client_kem_group_params;
                    client_params->kem_group = kem_pref->tls13_kem_groups[0];
                    client_params->kem_params.kem = kem_pref->tls13_kem_groups[0]->kem;
                    client_params->ecc_params.negotiated_curve = kem_pref->tls13_kem_groups[0]->curve;

                    EXPECT_NULL(client_params->ecc_params.evp_pkey);
                    EXPECT_NULL(client_params->kem_params.private_key.data);

                    kem_public_key_size public_key_size = kem_pref->tls13_kem_groups[0]->kem->public_key_length;
                    EXPECT_SUCCESS(s2n_alloc(&client_params->kem_params.public_key, public_key_size));

                    EXPECT_OK(s2n_kem_generate_keypair(&client_params->kem_params));
                    EXPECT_NOT_NULL(client_params->kem_params.private_key.data);
                    EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_params->ecc_params));
                    EXPECT_NOT_NULL(client_params->ecc_params.evp_pkey);

                    EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_retry_recv(conn), S2N_ERR_INVALID_HELLO_RETRY);

                    EXPECT_SUCCESS(s2n_free(&client_params->kem_params.public_key));
                    EXPECT_SUCCESS(s2n_connection_free(conn));
                };
                /* Test failure if exactly one of {named_curve, kem_group} isn't non-null */
                {
                    struct s2n_connection *conn;
                    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                    conn->actual_protocol_version = S2N_TLS13;
                    conn->security_policy_override = &test_security_policy;

                    conn->kex_params.server_kem_group_params.kem_group = &s2n_secp256r1_kyber_512_r3;
                    conn->kex_params.server_ecc_evp_params.negotiated_curve = &s2n_ecc_curve_secp256r1;

                    EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_retry_recv(conn), S2N_ERR_INVALID_HELLO_RETRY);

                    conn->kex_params.server_kem_group_params.kem_group = NULL;
                    conn->kex_params.server_ecc_evp_params.negotiated_curve = NULL;

                    EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_retry_recv(conn), S2N_ERR_INVALID_HELLO_RETRY);

                    EXPECT_SUCCESS(s2n_connection_free(conn));
                };
                /* Test PQ KEM success case for s2n_server_hello_retry_recv. */
                /* Need at least two KEM's to test fallback */
                if (test_security_policy.kem_preferences->tls13_kem_group_count >= 2) {
                    struct s2n_config *config;
                    struct s2n_connection *conn;

                    struct s2n_cert_chain_and_key *tls13_chain_and_key;
                    char tls13_cert_chain[S2N_MAX_TEST_PEM_SIZE] = { 0 };
                    char tls13_private_key[S2N_MAX_TEST_PEM_SIZE] = { 0 };

                    EXPECT_NOT_NULL(config = s2n_config_new());
                    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                    conn->security_policy_override = &test_security_policy;

                    EXPECT_NOT_NULL(tls13_chain_and_key = s2n_cert_chain_and_key_new());
                    EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, tls13_cert_chain, S2N_MAX_TEST_PEM_SIZE));
                    EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, tls13_private_key, S2N_MAX_TEST_PEM_SIZE));
                    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(tls13_chain_and_key, tls13_cert_chain, tls13_private_key));
                    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, tls13_chain_and_key));

                    /* Client sends ClientHello containing key share for p256+Kyber
                     * (but indicates support for x25519+Kyber in supported_groups) */
                    EXPECT_SUCCESS(s2n_client_hello_send(conn));

                    EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->handshake.io));
                    conn->session_id_len = 0; /* Wipe the session id to match the HRR hex */

                    /* Server responds with HRR indicating x25519+Kyber as choice for negotiation;
                     * the last 6 bytes (0033 0002 2F39) are the key share extension with x25519+Kyber */
                    DEFER_CLEANUP(struct s2n_stuffer hrr = { 0 }, s2n_stuffer_free);
                    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&hrr,
                            "0303CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C00130200000C002B00020304003300022F39"));

                    EXPECT_SUCCESS(s2n_stuffer_copy(&hrr, &conn->handshake.io, s2n_stuffer_data_available(&hrr)));
                    conn->handshake.message_number = HELLO_RETRY_MSG_NO;
                    /* Read the message off the wire */
                    EXPECT_SUCCESS(s2n_server_hello_parse(conn));
                    conn->actual_protocol_version_established = 1;

                    EXPECT_SUCCESS(s2n_conn_set_handshake_type(conn));
                    /* Client receives the HelloRetryRequest message */
                    EXPECT_SUCCESS(s2n_server_hello_retry_recv(conn));

                    EXPECT_SUCCESS(s2n_config_free(config));
                    EXPECT_SUCCESS(s2n_connection_free(conn));
                    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls13_chain_and_key));
                }
            }
        };
    };

    /* Verify that the hash transcript recreation function is called correctly,
     * within the s2n_server_hello_retry_send and s2n_server_hello_retry_recv functions.
     * The hash transcript recreation function, if called correctly takes the existing ClientHello1
     * hash, and generates a synthetic message. This test verifies that transcript hash recreated is the same
     * on both the server and client side. */
    {
        struct s2n_config *server_config;
        struct s2n_config *client_config;

        struct s2n_connection *server_conn;
        struct s2n_connection *client_conn;

        struct s2n_cert_chain_and_key *tls13_chain_and_key;
        char tls13_cert_chain[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        char tls13_private_key[S2N_MAX_TEST_PEM_SIZE] = { 0 };

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(client_config = s2n_config_new());

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        EXPECT_NOT_NULL(tls13_chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, tls13_cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, tls13_private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(tls13_chain_and_key, tls13_cert_chain, tls13_private_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, tls13_chain_and_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, tls13_chain_and_key));

        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Force the HRR path */
        client_conn->security_policy_override = &security_policy_test_tls13_retry;

        /* ClientHello 1 */
        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));

        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                s2n_stuffer_data_available(&client_conn->handshake.io)));

        /* Server receives ClientHello 1 */
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));
        EXPECT_TRUE(s2n_is_hello_retry_handshake(server_conn));
        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(server_conn));

        server_conn->kex_params.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];

        /* Server sends HelloRetryRequest message, note that s2n_server_hello_retry_recreate_transcript
         * is called within the s2n_server_hello_retry_send function */
        EXPECT_SUCCESS(s2n_server_hello_retry_send(server_conn));

        s2n_tls13_connection_keys(server_keys, server_conn);
        uint8_t hash_digest_length = server_keys.size;

        /* Obtain the transcript hash recreated within the HelloRetryRequest message */
        DEFER_CLEANUP(struct s2n_hash_state server_hash = { 0 }, s2n_hash_free);
        uint8_t server_digest_out[S2N_MAX_DIGEST_LEN] = { 0 };
        POSIX_GUARD(s2n_hash_new(&server_hash));
        POSIX_GUARD_RESULT(s2n_handshake_copy_hash_state(server_conn, server_keys.hash_algorithm, &server_hash));
        POSIX_GUARD(s2n_hash_digest(&server_hash, server_digest_out, hash_digest_length));

        struct s2n_blob server_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&server_blob, server_digest_out, hash_digest_length));

        EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                s2n_stuffer_data_available(&server_conn->handshake.io)));
        client_conn->handshake.message_number = HELLO_RETRY_MSG_NO;
        /* Client receives the HelloRetryRequest mesage, note that s2n_server_hello_retry_recreate_transcript
         * is called within the s2n_server_hello_recv function */
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));

        s2n_tls13_connection_keys(client_keys, client_conn);
        hash_digest_length = client_keys.size;

        /* Obtain the transcript hash recreated within ClientHello2 message */
        DEFER_CLEANUP(struct s2n_hash_state client_hash = { 0 }, s2n_hash_free);
        uint8_t client_digest_out[S2N_MAX_DIGEST_LEN];
        POSIX_GUARD(s2n_hash_new(&client_hash));
        POSIX_GUARD_RESULT(s2n_handshake_copy_hash_state(client_conn, client_keys.hash_algorithm, &client_hash));
        POSIX_GUARD(s2n_hash_digest(&client_hash, client_digest_out, hash_digest_length));

        struct s2n_blob client_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&client_blob, client_digest_out, hash_digest_length));

        /* Test that the transcript hash recreated MUST be the same on the server and client side */
        S2N_BLOB_EXPECT_EQUAL(client_blob, server_blob);

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls13_chain_and_key));
    };

    /**
     * Self-Talk test: the client initiates a handshake with an unknown keyshare.
     * The server sends a HelloRetryRequest that requires the client to generate a
     * key share on the server negotiated curve.
     *
     *= https://tools.ietf.org/rfc/rfc8446#4.1.4
     *= type=test
     *# Otherwise, the client MUST process all extensions in the
     *# HelloRetryRequest and send a second updated ClientHello.
     **/
    {
        struct s2n_config *server_config;
        struct s2n_config *client_config;

        struct s2n_connection *server_conn;
        struct s2n_connection *client_conn;

        struct s2n_cert_chain_and_key *tls13_chain_and_key;
        char tls13_cert_chain[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        char tls13_private_key[S2N_MAX_TEST_PEM_SIZE] = { 0 };

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(client_config = s2n_config_new());

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        EXPECT_NOT_NULL(tls13_chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, tls13_cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, tls13_private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(tls13_chain_and_key, tls13_cert_chain, tls13_private_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, tls13_chain_and_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, tls13_chain_and_key));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));

        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        server_conn->x509_validator.skip_cert_validation = 1;
        client_conn->x509_validator.skip_cert_validation = 1;

        /* Force the HRR path */
        client_conn->security_policy_override = &security_policy_test_tls13_retry;

        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Negotiate handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls13_chain_and_key));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    };

    /**
     * Self-Talk test: the client initiates a handshake with an X25519 share.
     * The server, however does not support x25519 and prefers P-256.
     * The server then sends a HelloRetryRequest that requires the
     * client to generate a key share on the P-256 curve.
     *
     *= https://tools.ietf.org/rfc/rfc8446#4.1.1
     *= type=test
     *# If the server selects an (EC)DHE group and the client did not offer a
     *# compatible "key_share" extension in the initial ClientHello, the
     *# server MUST respond with a HelloRetryRequest (Section 4.1.4) message.
     **/
    if (s2n_is_evp_apis_supported()) {
        struct s2n_config *server_config;
        struct s2n_config *client_config;

        struct s2n_connection *server_conn;
        struct s2n_connection *client_conn;

        struct s2n_cert_chain_and_key *tls13_chain_and_key;
        char tls13_cert_chain[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        char tls13_private_key[S2N_MAX_TEST_PEM_SIZE] = { 0 };

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(client_config = s2n_config_new());

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        EXPECT_NOT_NULL(tls13_chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, tls13_cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, tls13_private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(tls13_chain_and_key, tls13_cert_chain, tls13_private_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, tls13_chain_and_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, tls13_chain_and_key));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "20190801")); /* contains x25519 */
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "20190802")); /* does not contain x25519 */

        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        server_conn->x509_validator.skip_cert_validation = 1;
        client_conn->x509_validator.skip_cert_validation = 1;

        /* Force the HRR path */
        client_conn->security_policy_override = &security_policy_test_tls13_retry;

        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Negotiate handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        /* Ensure the handshake included a hello retry request */
        EXPECT_TRUE(IS_HELLO_RETRY_HANDSHAKE(client_conn));
        EXPECT_TRUE(IS_HELLO_RETRY_HANDSHAKE(server_conn));

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls13_chain_and_key));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    }

    /**
     * Ensure the client aborts the handshake if more than one
     * HelloRetryRequest is received
     *
     *= https://tools.ietf.org/rfc/rfc8446#4.1.4
     *= type=test
     *# If a client receives a second
     *# HelloRetryRequest in the same connection (i.e., where the ClientHello
     *# was itself in response to a HelloRetryRequest), it MUST abort the
     *# handshake with an "unexpected_message" alert.
     **/
    {
        struct s2n_config *server_config;
        struct s2n_config *client_config;

        struct s2n_connection *server_conn;
        struct s2n_connection *client_conn;

        struct s2n_cert_chain_and_key *tls13_chain_and_key;
        char tls13_cert_chain[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        char tls13_private_key[S2N_MAX_TEST_PEM_SIZE] = { 0 };

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(client_config = s2n_config_new());

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        EXPECT_NOT_NULL(tls13_chain_and_key = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, tls13_cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, tls13_private_key, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(tls13_chain_and_key, tls13_cert_chain, tls13_private_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, tls13_chain_and_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, tls13_chain_and_key));

        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Force the HRR path */
        client_conn->security_policy_override = &security_policy_test_tls13_retry;

        /* ClientHello 1 */
        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                s2n_stuffer_data_available(&client_conn->handshake.io)));
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));
        EXPECT_TRUE(s2n_is_hello_retry_handshake(server_conn));
        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(server_conn));

        /* Server HelloRetryRequest 1 */
        EXPECT_SUCCESS(s2n_server_hello_retry_send(server_conn));
        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(server_conn));

        EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                s2n_stuffer_data_available(&server_conn->handshake.io)));
        client_conn->handshake.message_number = HELLO_RETRY_MSG_NO;
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));

        /* ClientHello 2 */
        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&server_conn->handshake.io));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                s2n_stuffer_data_available(&client_conn->handshake.io)));
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

        /* Server HelloRetryRequest 2 */
        EXPECT_SUCCESS(s2n_server_hello_retry_send(server_conn));

        EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                s2n_stuffer_data_available(&server_conn->handshake.io)));

        EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_recv(client_conn), S2N_ERR_INVALID_HELLO_RETRY);

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls13_chain_and_key));
    };

    /**
     * Ensure that s2n_random_value_is_hello_retry returns true for hello
     * retry random values, and false otherwise
     *
     *= https://tools.ietf.org/rfc/rfc8446#4.1.3
     *= type=test
     *# Upon receiving a message with type server_hello, implementations MUST
     *# first examine the Random value and, if it matches this value, process
     *# it as described in Section 4.1.4).
     **/
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        const uint8_t not_hello_retry_request_random[S2N_TLS_RANDOM_DATA_LEN] = { 0 };
        EXPECT_MEMCPY_SUCCESS(conn->handshake_params.server_random, not_hello_retry_request_random,
                S2N_TLS_RANDOM_DATA_LEN);

        EXPECT_FAILURE_WITH_ERRNO(s2n_random_value_is_hello_retry(conn), S2N_ERR_INVALID_HELLO_RETRY);

        EXPECT_MEMCPY_SUCCESS(conn->handshake_params.server_random, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN);
        EXPECT_SUCCESS(s2n_random_value_is_hello_retry(conn));

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /**
     *= https://tools.ietf.org/rfc/rfc8446#4.1.4
     *= type=test
     *# Upon receiving
     *# the ServerHello, clients MUST check that the cipher suite supplied in
     *# the ServerHello is the same as that in the HelloRetryRequest and
     *# otherwise abort the handshake with an "illegal_parameter" alert.
     **/
    {
        struct s2n_connection *server_conn;
        struct s2n_connection *client_conn;

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        /* A Hello Retry Request has been processed */
        EXPECT_SUCCESS(s2n_set_hello_retry_required(client_conn));
        client_conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
        client_conn->server_protocol_version = S2N_TLS13;
        client_conn->handshake.handshake_type |= NEGOTIATED;
        client_conn->handshake.handshake_type |= FULL_HANDSHAKE;
        client_conn->handshake.message_number = SERVER_HELLO_MSG_NO;

        /* Server Hello with cipher suite that does not match Hello Retry Request cipher suite */
        server_conn->secure->cipher_suite = &s2n_tls13_chacha20_poly1305_sha256;
        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));

        EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                s2n_stuffer_data_available(&server_conn->handshake.io)));

        EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_recv(client_conn), S2N_ERR_CIPHER_NOT_SUPPORTED);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    };

    /*
     * Self-Talk
     *
     *= https://tools.ietf.org/rfc/rfc8446#section-4.1.2
     *= type=test
     *# The client will also send a
     *# ClientHello when the server has responded to its ClientHello with a
     *# HelloRetryRequest.  In that case, the client MUST send the same
     *# ClientHello without modification
     */
    if (s2n_is_tls13_fully_supported()) {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));

        /* Sanity Check: The server accepts an unchanged ClientHello */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Force the HRR path */
            client_conn->security_policy_override = &security_policy_test_tls13_retry;

            /* Send ClientHello */
            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, SERVER_HELLO));

            /* Finish handshake */
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        };

        /* Test: The server rejects a second ClientHello with changed message fields */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Force the HRR path */
            client_conn->security_policy_override = &security_policy_test_tls13_retry;

            /* Send ClientHello */
            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, SERVER_HELLO));

            /* Change session id */
            client_conn->session_id[0]++;

            /* Expect failure because second client hello doesn't match */
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                    S2N_ERR_BAD_MESSAGE);
        };

        /* Test: The server rejects a second ClientHello with changed client random */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Force the HRR path */
            client_conn->security_policy_override = &security_policy_test_tls13_retry;

            /* Send ClientHello */
            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, SERVER_HELLO));

            /* Change client random */
            client_conn->handshake_params.client_random[0]++;

            /* Expect failure because second client hello doesn't match */
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                    S2N_ERR_BAD_MESSAGE);
        };

        /* Test: outside of testing, the server accepts an incorrectly updated ClientHello */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Force the HRR path */
            client_conn->security_policy_override = &security_policy_test_tls13_retry;

            /* Send ClientHello */
            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, SERVER_HELLO));

            /* Change client random */
            client_conn->handshake_params.client_random[0]++;

            /* Expect success if we pretend that this isn't a unit test */
            EXPECT_SUCCESS(s2n_in_unit_test_set(false));
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_SUCCESS(s2n_in_unit_test_set(true));
        }

        /* Test: The server rejects a second ClientHello with a changed extension */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Force the HRR path */
            client_conn->security_policy_override = &security_policy_test_tls13_retry;

            /* Send ClientHello */
            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, SERVER_HELLO));

            /* Change server name */
            client_conn->server_name[0]++;

            /* Expect failure because second client hello doesn't match */
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                    S2N_ERR_BAD_MESSAGE);
        };

        /* Test: The server rejects a second ClientHello with a removed extension */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Force the HRR path */
            client_conn->security_policy_override = &security_policy_test_tls13_retry;

            /* Send ClientHello */
            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, SERVER_HELLO));

            /* Clear server name.
             * Without a server name, we don't send the server name extension. */
            client_conn->server_name[0] = '\0';

            /* Expect failure because second client hello doesn't match */
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                    S2N_ERR_BAD_MESSAGE);
        };

        /* Test: The server rejects a second ClientHello with an added extension */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Force the HRR path */
            client_conn->security_policy_override = &security_policy_test_tls13_retry;

            /* Send ClientHello */
            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, SERVER_HELLO));

            /* Add a server name.
             * Without a server name, we don't send the server name extension. */
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));

            /* Expect failure because second client hello doesn't match */
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                    S2N_ERR_BAD_MESSAGE);
        };

        /*
         * Test: If the initial ClientHello includes all extensions, so does the second ClientHello.
         *
         * This includes TLS1.2 extensions, since the ClientHello is sent before
         * the client knows what version the server will negotiate.
         *
         * We have to test with all extensions to ensure that an s2n server will never reject
         * an s2n client's second ClientHello.
         *
         * TLS1.2 and TLS1.3 session tickets are mutually exclusive and use different
         * extensions, so we test once with each.
         */
        for (size_t tls13_tickets = 0; tls13_tickets < 2; tls13_tickets++) {
            DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(),
                    s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Force the HRR path */
            const struct s2n_security_policy security_policy_test_tls13_retry_with_pq = {
                .minimum_protocol_version = S2N_TLS11,
                .cipher_preferences = &cipher_preferences_pq_tls_1_1_2021_05_21,
                .kem_preferences = &kem_preferences_pq_tls_1_0_2021_05,
                .signature_preferences = &s2n_signature_preferences_20200207,
                .ecc_preferences = &ecc_preferences_for_retry,
            };
            client_conn->security_policy_override = &security_policy_test_tls13_retry_with_pq;

            /* Setup all extensions */
            uint8_t apn[] = "https";
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "PQ-TLS-1-1-2021-05-21"));
            EXPECT_SUCCESS(s2n_config_set_status_request_type(client_config, S2N_STATUS_REQUEST_OCSP));
            EXPECT_SUCCESS(s2n_config_set_ct_support_level(client_config, S2N_CT_SUPPORT_REQUEST));
            EXPECT_SUCCESS(s2n_config_send_max_fragment_length(client_config, S2N_TLS_MAX_FRAG_LEN_4096));
            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(client_config, 1));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));
            EXPECT_SUCCESS(s2n_connection_append_protocol_preference(client_conn, apn, sizeof(apn)));
            EXPECT_SUCCESS(s2n_connection_set_early_data_expected(client_conn));
            client_conn->config->npn_supported = true;
            if (tls13_tickets) {
                EXPECT_OK(s2n_append_test_psk_with_early_data(client_conn, 1, &s2n_tls13_aes_256_gcm_sha384));
            }
            EXPECT_SUCCESS(s2n_connection_enable_quic(client_conn));
            /* Need to enable quic on both sides so they can communicate */
            EXPECT_SUCCESS(s2n_connection_enable_quic(server_conn));

            /* Send and receive ClientHello */
            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, SERVER_HELLO));
            EXPECT_OK(s2n_negotiate_until_message(server_conn, &blocked, HELLO_RETRY_MSG));

            /* All ClientHello extensions must be present (except very specific exceptions)  */
            s2n_extension_type_list *extensions = NULL;
            EXPECT_SUCCESS(s2n_extension_type_list_get(S2N_EXTENSION_LIST_CLIENT_HELLO, &extensions));
            for (size_t i = 0; i < extensions->count; i++) {
                uint16_t iana = extensions->extension_types[i]->iana_value;

                /* The cookie is a special case and only appears AFTER the retry */
                if (iana == TLS_EXTENSION_COOKIE) {
                    continue;
                }

                /* No pq extension if pq not enabled for the build */
                if (iana == TLS_EXTENSION_PQ_KEM_PARAMETERS && !s2n_pq_is_enabled()) {
                    continue;
                }

                /* TLS1.2 session tickets and TLS1.3 session tickets are mutually exclusive */
                if (tls13_tickets && iana == TLS_EXTENSION_SESSION_TICKET) {
                    continue;
                } else if (!tls13_tickets
                        && (iana == TLS_EXTENSION_PRE_SHARED_KEY
                                || iana == TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES
                                || iana == TLS_EXTENSION_EARLY_DATA)) {
                    continue;
                }

                /* No extension is sent for an initial handshake,
                 * and TLS1.3 doesn't support renegotiation handshakes.
                 */
                if (iana == TLS_EXTENSION_RENEGOTIATION_INFO) {
                    continue;
                }

                bool extension_exists = false;
                EXPECT_SUCCESS(s2n_client_hello_has_extension(&server_conn->client_hello,
                        iana, &extension_exists));
                EXPECT_TRUE(extension_exists);
            }

            /* Expect successful retry */
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        }

        /* Processing an extension early does not affect the extension matching check.
         *
         * This test exists because of a previously released bug. Triggering the bug
         * required a specific series of events:
         * - The first ClientHello is received.
         * - The extensions are parsed.
         * - The ClientHello callback triggers.
         * - The customer's ClientHello callback implementation calls the s2n_get_server_name API.
         *   - To retrieve the server name, s2n_get_server_name processes the server name extension early.
         *     - The server name extension is wiped. Before the "processed" flag, we wiped extensions
         *       to mark that they had been processed.
         * - The server sends a HelloRetryRequest, triggering a retry.
         * - The second ClientHello is received.
         * - The extensions are parsed.
         * - The customer's ClientHello callback does NOT trigger this time. The callback only
         *   triggers after the first ClientHello.
         *   - Therefore, s2n_get_server_name is not called and the server name extension is not
         *     processed early or wiped.
         * - The first ClientHello is compared to the second ClientHello. The second ClientHello
         *   appears to contain a server name extension not present in the first ClientHello.
         * - The handshake fails because the ClientHellos must match.
         */
        {
            char server_name[] = "test server name";

            DEFER_CLEANUP(struct s2n_config *config_with_cb = s2n_config_new(),
                    s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config_with_cb, chain_and_key));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config_with_cb, "default_tls13"));
            EXPECT_SUCCESS(s2n_config_disable_x509_verification(config_with_cb));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config_with_cb));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config_with_cb));

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Setup server name and client hello callback */
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, server_name));
            EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config_with_cb,
                    s2n_client_hello_cb_with_get_server_name, server_name));

            /* Force the HRR path */
            client_conn->security_policy_override = &security_policy_test_tls13_retry;

            /* Handshake should complete as expected */
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_EQUAL(strcmp(s2n_get_server_name(server_conn), server_name), 0);
            EXPECT_TRUE(IS_HELLO_RETRY_HANDSHAKE(client_conn));
            EXPECT_TRUE(IS_HELLO_RETRY_HANDSHAKE(server_conn));
        };
    }

    /**
     * Ensure all hello retry extensions sent by the server will have first
     * been sent by the client.
     *
     *= https://tools.ietf.org/rfc/rfc8446#4.1.4
     *= type=test
     *# As with the ServerHello, a HelloRetryRequest MUST NOT contain any
     *# extensions that were not first offered by the client in its
     *# ClientHello, with the exception of optionally the "cookie" (see
     *# Section 4.2.2) extension.
     **/
    {
        s2n_extension_type_list *hello_retry_extension_types = 0;
        POSIX_GUARD(s2n_extension_type_list_get(S2N_EXTENSION_LIST_HELLO_RETRY_REQUEST, &hello_retry_extension_types));

        for (int i = 0; i < hello_retry_extension_types->count; ++i) {
            const s2n_extension_type *const extension_type = hello_retry_extension_types->extension_types[i];

            /* with the exception of optionally the "cookie" extension. */
            if (extension_type->iana_value == TLS_EXTENSION_COOKIE) {
                continue;
            }

            EXPECT_TRUE(extension_type->is_response);
        }
    };

    /**
     * Ensure each of the following are checked: legacy_version,
     * legacy_session_id_echo, cipher_suite, and
     * legacy_compression_method
     *
     *= https://tools.ietf.org/rfc/rfc8446#4.1.4
     *= type=test
     *# Upon receipt of a HelloRetryRequest, the client MUST check the
     *# legacy_version, legacy_session_id_echo, cipher_suite, and
     *# legacy_compression_method as specified in Section 4.1.3 and then
     *# process the extensions, starting with determining the version using
     *# "supported_versions".
     **/
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));

        /* The client MUST check the legacy_version */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Force the HRR path */
            client_conn->security_policy_override = &security_policy_test_tls13_retry;

            /* ClientHello 1 */
            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                    s2n_stuffer_data_available(&client_conn->handshake.io)));

            /* Server receives ClientHello 1 */
            EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));
            EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(server_conn));

            /* Force the server to send an erroneous legacy protocol version in the HelloRetryRequest message */
            server_conn->actual_protocol_version = S2N_TLS11;

            /* Server sends HelloRetryRequest */
            EXPECT_SUCCESS(s2n_server_hello_retry_send(server_conn));

            EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                    s2n_stuffer_data_available(&server_conn->handshake.io)));
            client_conn->handshake.message_number = HELLO_RETRY_MSG_NO;

            /* Client receives HelloRetryRequest */
            EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_recv(client_conn),
                    S2N_ERR_INVALID_HELLO_RETRY);
        };

        /* The client MUST check the legacy_session_id_echo */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Force the HRR path */
            client_conn->security_policy_override = &security_policy_test_tls13_retry;

            /* ClientHello 1 */
            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                    s2n_stuffer_data_available(&client_conn->handshake.io)));

            /* Server receives ClientHello 1 */
            EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));
            EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(server_conn));

            /* Set a session id that's different from the client hello */
            POSIX_CHECKED_MEMSET(&server_conn->session_id, 0, S2N_TLS_SESSION_ID_MAX_LEN);

            /* Server sends HelloRetryRequest */
            EXPECT_SUCCESS(s2n_server_hello_retry_send(server_conn));

            EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                    s2n_stuffer_data_available(&server_conn->handshake.io)));
            client_conn->handshake.message_number = HELLO_RETRY_MSG_NO;

            /* Client receives HelloRetryRequest */
            EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_recv(client_conn),
                    S2N_ERR_BAD_MESSAGE);
        };

        /**
         * The client MUST check the cipher_suite
         *
         *= https://tools.ietf.org/rfc/rfc8446#4.1.4
         *= type=test
         *# A client which receives a cipher suite that was not offered MUST
         *# abort the handshake.
         **/
        {
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20200207"));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Force the HRR path */
            client_conn->security_policy_override = &security_policy_test_tls13_retry;

            /* Send ClientHello */
            s2n_blocked_status blocked = 0;
            EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, SERVER_HELLO));

            /* Receive ClientHello */
            EXPECT_OK(s2n_negotiate_until_message(server_conn, &blocked, HELLO_RETRY_MSG));

            /*
             * Pick a cipher that wasn't offered in the CH, and should cause the
             * handshake to abort.
             */
            server_conn->secure->cipher_suite = &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384;

            /* Finish handshake */
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                    S2N_ERR_CIPHER_NOT_SUPPORTED);
        };

        /* The client MUST check the legacy_compression_method */
        {
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Force the HRR path */
            client_conn->security_policy_override = &security_policy_test_tls13_retry;

            /* ClientHello 1 */
            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                    s2n_stuffer_data_available(&client_conn->handshake.io)));

            /* Server receives ClientHello 1 */
            EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));
            EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(server_conn));

            /* Server sends HelloRetryRequest */
            POSIX_CHECKED_MEMCPY(server_conn->handshake_params.server_random, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN);
            EXPECT_SUCCESS(s2n_server_hello_write_message(server_conn));

            /* Overwrite compression method to 1 */
            struct s2n_stuffer *io = &server_conn->handshake.io;
            io->write_cursor -= 1;
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, 1));

            /* Write the extensions */
            EXPECT_SUCCESS(s2n_server_extensions_send(server_conn, &server_conn->handshake.io));

            EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                    s2n_stuffer_data_available(&server_conn->handshake.io)));
            client_conn->handshake.message_number = HELLO_RETRY_MSG_NO;

            /* Client receives HelloRetryRequest */
            EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_recv(client_conn),
                    S2N_ERR_BAD_MESSAGE);
        };
    };

    /**
     *= https://tools.ietf.org/rfc/rfc8446#4.1.4
     *= type=test
     *# The server's extensions MUST contain "supported_versions".
     **/
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Force the HRR path */
        client_conn->security_policy_override = &security_policy_test_tls13_retry;

        /* ClientHello 1 */
        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));

        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                s2n_stuffer_data_available(&client_conn->handshake.io)));

        /* Server receives ClientHello 1 */
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));
        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(server_conn));

        POSIX_CHECKED_MEMCPY(server_conn->handshake_params.server_random, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN);
        POSIX_GUARD(s2n_server_hello_write_message(server_conn));
        struct s2n_stuffer_reservation total_extensions_size = { 0 };
        POSIX_GUARD(s2n_stuffer_reserve_uint16(&server_conn->handshake.io, &total_extensions_size));

        /* Only send key share extension - exclude supported_versions */
        s2n_extension_send(&s2n_server_key_share_extension, server_conn, &server_conn->handshake.io);

        POSIX_GUARD(s2n_stuffer_write_vector_size(&total_extensions_size));

        EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                s2n_stuffer_data_available(&server_conn->handshake.io)));
        client_conn->handshake.message_number = HELLO_RETRY_MSG_NO;

        /* Client receives HelloRetryRequest */
        EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_recv(client_conn),
                S2N_ERR_MISSING_EXTENSION);
    };

    /**
     *= https://tools.ietf.org/rfc/rfc8446#4.1.4
     *= type=test
     *# Servers MUST ensure that they negotiate the
     *# same cipher suite when receiving a conformant updated ClientHello (if
     *# the server selects the cipher suite as the first step in the
     *# negotiation, then this will happen automatically).
     **/
    {
        /* Create a custom security policy so it can be changed mid-handshake */
        struct s2n_cipher_suite *test_cipher_suites[] = {
            &s2n_tls13_aes_128_gcm_sha256,
            &s2n_tls13_aes_256_gcm_sha384
        };
        struct s2n_cipher_preferences test_cipher_preferences = {
            .count = s2n_array_len(test_cipher_suites),
            .suites = test_cipher_suites,
        };
        struct s2n_security_policy security_policy_test_tls13_retry_temp = {
            .minimum_protocol_version = S2N_TLS10,
            .cipher_preferences = &test_cipher_preferences,
            .kem_preferences = &kem_preferences_null,
            .signature_preferences = &s2n_signature_preferences_20200207,
            .certificate_signature_preferences = &s2n_certificate_signature_preferences_20201110,
            .ecc_preferences = &ecc_preferences_for_retry,
        };

        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Force the HRR path */
        client_conn->security_policy_override = &security_policy_test_tls13_retry_temp;

        /* Send ClientHello */
        s2n_blocked_status blocked = 0;
        EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, SERVER_HELLO));

        /* Receive ClientHello */
        EXPECT_OK(s2n_negotiate_until_message(server_conn, &blocked, HELLO_RETRY_MSG));

        /* Rearrange the cipher preference order so that a different cipher will be
          * picked by the server */
        server_conn->config->security_policy->cipher_preferences->suites[0] = &s2n_tls13_aes_256_gcm_sha384;

        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                S2N_ERR_BAD_MESSAGE);
    };

    /**
      * Ensure that the client aborts the handshake if selected_version
      * differs in the received server hellos
      *
      *= https://tools.ietf.org/rfc/rfc8446#4.1.4
      *= type=test
      *# The value of selected_version in the HelloRetryRequest
      *# "supported_versions" extension MUST be retained in the ServerHello,
      *# and a client MUST abort the handshake with an "illegal_parameter"
      *# alert if the value changes.
      **/
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Force the HRR path */
        client_conn->security_policy_override = &security_policy_test_tls13_retry;

        /* Send ClientHello */
        s2n_blocked_status blocked = 0;
        EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, SERVER_HELLO));

        /* Receive ClientHello */
        EXPECT_OK(s2n_negotiate_until_message(server_conn, &blocked, HELLO_RETRY_MSG));

        /* Skip to before server sends ServerHello */
        EXPECT_OK(s2n_negotiate_until_message(server_conn, &blocked, CLIENT_HELLO));
        EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, CLIENT_HELLO));

        /* Change the server_protocol_version so the value found in the ServerHello
          * differs from the value found in the HelloRetryRequest */
        server_conn->server_protocol_version = S2N_TLS13 + 10;

        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                S2N_ERR_BAD_MESSAGE);
    };

    /**
     *= https://tools.ietf.org/rfc/rfc8446#4.2.8
     *= type=test
     *# Upon receipt of this extension in a HelloRetryRequest, the client
     *# MUST verify that (1) the selected_group field corresponds to a group
     *# which was provided in the "supported_groups" extension in the
     *# original ClientHello
     **/
    {
        /* Create a custom security policy without secp521r1 */
        const struct s2n_ecc_named_curve *const test_ecc_pref_list_for_retry[] = {
            &s2n_ecc_curve_secp256r1,
            &s2n_ecc_curve_secp384r1,
        };
        const struct s2n_ecc_preferences test_ecc_preferences_for_retry = {
            .count = s2n_array_len(test_ecc_pref_list_for_retry),
            .ecc_curves = test_ecc_pref_list_for_retry,
        };
        struct s2n_security_policy security_policy_test_tls13_retry_temp = {
            .minimum_protocol_version = S2N_TLS10,
            .cipher_preferences = &cipher_preferences_20190801,
            .kem_preferences = &kem_preferences_null,
            .signature_preferences = &s2n_signature_preferences_20200207,
            .certificate_signature_preferences = &s2n_certificate_signature_preferences_20201110,
            .ecc_preferences = &test_ecc_preferences_for_retry,
        };

        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN,
                S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Force the HRR path */
        client_conn->security_policy_override = &security_policy_test_tls13_retry_temp;

        /* ClientHello 1 */
        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                s2n_stuffer_data_available(&client_conn->handshake.io)));

        /* Server receives ClientHello 1 */
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));
        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(server_conn));

        /* Server sends HelloRetryRequest */
        EXPECT_SUCCESS(s2n_server_hello_retry_send(server_conn));

        EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                s2n_stuffer_data_available(&server_conn->handshake.io)));
        client_conn->handshake.message_number = HELLO_RETRY_MSG_NO;

        /* Set the curve to secp521r1, which was not provided in supported_groups */
        client_conn->kex_params.server_ecc_evp_params.negotiated_curve = &s2n_ecc_curve_secp521r1;

        /* Client receives HelloRetryRequest */
        EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_recv(client_conn),
                S2N_ERR_INVALID_HELLO_RETRY);
    };

    /**
     *= https://tools.ietf.org/rfc/rfc8446#4.2.8
     *= type=test
     *# If using (EC)DHE key establishment and a HelloRetryRequest containing a
     *# "key_share" extension was received by the client, the client MUST
     *# verify that the selected NamedGroup in the ServerHello is the same as
     *# that in the HelloRetryRequest. If this check fails, the client MUST
     *# abort the handshake with an "illegal_parameter" alert.
     **/
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN,
                S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Force the HRR path */
        client_conn->security_policy_override = &security_policy_test_tls13_retry;

        /* Skip to before client receives ServerHello 2 */
        s2n_blocked_status blocked = 0;
        EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, SERVER_HELLO));
        EXPECT_OK(s2n_negotiate_until_message(server_conn, &blocked, HELLO_RETRY_MSG));
        EXPECT_OK(s2n_negotiate_until_message(server_conn, &blocked, CLIENT_HELLO));
        EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, CLIENT_HELLO));
        EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, SERVER_HELLO));
        EXPECT_OK(s2n_negotiate_until_message(server_conn, &blocked, SERVER_HELLO));
        EXPECT_OK(s2n_negotiate_until_message(server_conn, &blocked, ENCRYPTED_EXTENSIONS));

        /* Set the negotiated curve to something other than what was sent in the HRR */
        client_conn->kex_params.server_ecc_evp_params.negotiated_curve = &s2n_ecc_curve_secp521r1;

        /* Client receives ServerHello 2 */
        EXPECT_ERROR_WITH_ERRNO(s2n_negotiate_until_message(client_conn, &blocked, ENCRYPTED_EXTENSIONS),
                S2N_ERR_BAD_MESSAGE);
    };

    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    END_TEST();
}
