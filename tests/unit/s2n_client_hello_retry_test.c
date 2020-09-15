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

#include "tls/extensions/s2n_server_supported_versions.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_tls13_handshake.h"
#include "tls/s2n_connection.h"
#include "crypto/s2n_fips.h"

/* This include is required to access static function s2n_server_hello_parse */
#include "tls/s2n_server_hello.c"

#include "error/s2n_errno.h"

#define HELLO_RETRY_MSG_NO 1
#define SERVER_HELLO_MSG_NO 5

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13());

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
            GUARD(s2n_connection_get_ecc_preferences(conn, &ecc_pref));
            EXPECT_NOT_NULL(ecc_pref);

            conn->actual_protocol_version = S2N_TLS13;
            conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
            conn->secure.client_ecc_evp_params[0].negotiated_curve = ecc_pref->ecc_curves[0];

            EXPECT_NULL(conn->secure.client_ecc_evp_params->evp_pkey);
            EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->secure.client_ecc_evp_params[0]));
            EXPECT_NOT_NULL(conn->secure.client_ecc_evp_params->evp_pkey);

            EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_retry_recv(conn), S2N_ERR_INVALID_HELLO_RETRY);

            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* s2n_server_hello_retry_recv must fail when a matching curve is not found, i.e the selected_group field
         * does not correspond to a group which was provided in the "supported_groups" extension in the original ClientHello */
        if (s2n_is_evp_apis_supported()) {
            struct s2n_config *config;
            struct s2n_connection *conn;

            EXPECT_NOT_NULL(config = s2n_config_new());
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20190802")); /* does not contain x25519 */

            conn->actual_protocol_version = S2N_TLS13;
            conn->secure.server_ecc_evp_params.negotiated_curve = &s2n_ecc_curve_x25519;

            EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_retry_recv(conn), S2N_ERR_INVALID_HELLO_RETRY);

            EXPECT_SUCCESS(s2n_config_free(config));
            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

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
        }

        /* Test ECC success case for s2n_server_hello_retry_recv */
        {
            struct s2n_config *server_config;
            struct s2n_config *client_config;

            struct s2n_connection *server_conn;
            struct s2n_connection *client_conn;

            struct s2n_cert_chain_and_key *tls13_chain_and_key;
            char tls13_cert_chain[S2N_MAX_TEST_PEM_SIZE] = {0};
            char tls13_private_key[S2N_MAX_TEST_PEM_SIZE] = {0};

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

            /* Force the HRR path by sending an empty list of keyshares */
            EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(client_conn, "none"));

            /* ClientHello 1 */
            EXPECT_SUCCESS(s2n_client_hello_send(client_conn));

            EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                                            s2n_stuffer_data_available(&client_conn->handshake.io)));

            /* Server receives ClientHello 1 */
            EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

            server_conn->secure.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];
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
        }
#if !defined(S2N_NO_PQ)
        {
            const struct s2n_kem_group *test_kem_groups[] = {
                &s2n_secp256r1_sike_p434_r2,
                &s2n_secp256r1_bike1_l1_r2,
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

            if (s2n_is_in_fips_mode()) {
                struct s2n_connection *conn;
                EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                conn->actual_protocol_version = S2N_TLS13;
                conn->security_policy_override = &test_security_policy;

                const struct s2n_kem_preferences *kem_pref = NULL;
                GUARD(s2n_connection_get_kem_preferences(conn, &kem_pref));
                EXPECT_NOT_NULL(kem_pref);

                conn->secure.server_kem_group_params.kem_group = kem_pref->tls13_kem_groups[0];
                EXPECT_NULL(conn->secure.server_ecc_evp_params.negotiated_curve);

                EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_retry_recv(conn), S2N_ERR_PQ_KEMS_DISALLOWED_IN_FIPS);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            } else {
                /* s2n_server_hello_retry_recv must fail when a keyshare for a matching PQ KEM was already present */
                {
                    struct s2n_connection *conn;
                    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                    conn->actual_protocol_version = S2N_TLS13;
                    conn->security_policy_override = &test_security_policy;

                    const struct s2n_kem_preferences *kem_pref = NULL;
                    GUARD(s2n_connection_get_kem_preferences(conn, &kem_pref));
                    EXPECT_NOT_NULL(kem_pref);

                    conn->secure.server_kem_group_params.kem_group = kem_pref->tls13_kem_groups[0];
                    EXPECT_NULL(conn->secure.server_ecc_evp_params.negotiated_curve);

                    struct s2n_kem_group_params *client_params = &conn->secure.client_kem_group_params[0];
                    client_params->kem_group = kem_pref->tls13_kem_groups[0];
                    client_params->kem_params.kem = kem_pref->tls13_kem_groups[0]->kem;
                    client_params->ecc_params.negotiated_curve = kem_pref->tls13_kem_groups[0]->curve;

                    EXPECT_NULL(client_params->ecc_params.evp_pkey);
                    EXPECT_NULL(client_params->kem_params.private_key.data);

                    kem_public_key_size public_key_size = kem_pref->tls13_kem_groups[0]->kem->public_key_length;
                    EXPECT_SUCCESS(s2n_alloc(&client_params->kem_params.public_key, public_key_size));

                    EXPECT_SUCCESS(s2n_kem_generate_keypair(&client_params->kem_params));
                    EXPECT_NOT_NULL(client_params->kem_params.private_key.data);
                    EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_params->ecc_params));
                    EXPECT_NOT_NULL(client_params->ecc_params.evp_pkey);

                    EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_retry_recv(conn), S2N_ERR_INVALID_HELLO_RETRY);

                    EXPECT_SUCCESS(s2n_free(&client_params->kem_params.public_key));
                    EXPECT_SUCCESS(s2n_connection_free(conn));
                }
                /* s2n_server_hello_retry_recv must fail if the server chose a PQ KEM
                 * that wasn't in the client's supported_groups */
                {
                    struct s2n_connection *conn;
                    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                    conn->actual_protocol_version = S2N_TLS13;
                    conn->security_policy_override = &test_security_policy;

                    /* test_security_policy does not include kyber */
                    conn->secure.server_kem_group_params.kem_group = &s2n_secp256r1_kyber_512_r2;
                    EXPECT_NULL(conn->secure.server_ecc_evp_params.negotiated_curve);

                    EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_retry_recv(conn), S2N_ERR_INVALID_HELLO_RETRY);

                    EXPECT_SUCCESS(s2n_connection_free(conn));
                }
                /* Test failure if exactly one of {named_curve, kem_group} isn't non-null */
                {
                    struct s2n_connection *conn;
                    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                    conn->actual_protocol_version = S2N_TLS13;
                    conn->security_policy_override = &test_security_policy;

                    conn->secure.server_kem_group_params.kem_group = &s2n_secp256r1_sike_p434_r2;
                    conn->secure.server_ecc_evp_params.negotiated_curve = &s2n_ecc_curve_secp256r1;

                    EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_retry_recv(conn), S2N_ERR_INVALID_HELLO_RETRY);

                    conn->secure.server_kem_group_params.kem_group = NULL;
                    conn->secure.server_ecc_evp_params.negotiated_curve = NULL;

                    EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_retry_recv(conn), S2N_ERR_INVALID_HELLO_RETRY);

                    EXPECT_SUCCESS(s2n_connection_free(conn));
                }
                /* Test PQ KEM success case for s2n_server_hello_retry_recv. */
                {
                    struct s2n_config *config;
                    struct s2n_connection *conn;

                    struct s2n_cert_chain_and_key *tls13_chain_and_key;
                    char tls13_cert_chain[S2N_MAX_TEST_PEM_SIZE] = {0};
                    char tls13_private_key[S2N_MAX_TEST_PEM_SIZE] = {0};

                    EXPECT_NOT_NULL(config = s2n_config_new());
                    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
                    conn->security_policy_override = &test_security_policy;

                    EXPECT_NOT_NULL(tls13_chain_and_key = s2n_cert_chain_and_key_new());
                    EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_CERT_CHAIN, tls13_cert_chain, S2N_MAX_TEST_PEM_SIZE));
                    EXPECT_SUCCESS(s2n_read_test_pem(S2N_ECDSA_P384_PKCS1_KEY, tls13_private_key, S2N_MAX_TEST_PEM_SIZE));
                    EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(tls13_chain_and_key, tls13_cert_chain, tls13_private_key));
                    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, tls13_chain_and_key));

                    /* Client sends ClientHello containing key share for p256+SIKE
                     * (but indicates support for p256+BIKE in supported_groups) */
                    EXPECT_SUCCESS(s2n_client_hello_send(conn));

                    EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->handshake.io));
                    conn->session_id_len = 0; /* Wipe the session id to match the HRR hex */

                    /* Server responds with HRR indicating p256+BIKE as choice for negotiation;
                     * the last 6 bytes (0033 0002 2F23) are the key share extension with p256+BIKE */
                    DEFER_CLEANUP(struct s2n_stuffer hrr = {0}, s2n_stuffer_free);
                    EXPECT_SUCCESS(s2n_stuffer_alloc_ro_from_hex_string(&hrr,
                            "0303CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C00130200000C002B00020304003300022F23"));

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
        }
#endif
    }

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
        char tls13_cert_chain[S2N_MAX_TEST_PEM_SIZE] = {0};
        char tls13_private_key[S2N_MAX_TEST_PEM_SIZE] = {0};

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

        /* Force the HRR path by sending an empty list of keyshares */
        EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(client_conn, "none"));

        /* ClientHello 1 */
        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));

        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                                        s2n_stuffer_data_available(&client_conn->handshake.io)));

        /* Server receives ClientHello 1 */
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));
        EXPECT_TRUE(s2n_is_hello_retry_handshake(server_conn));
        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(server_conn));

        server_conn->secure.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];

        /* Server sends HelloRetryRequest message, note that s2n_server_hello_retry_recreate_transcript
         * is called within the s2n_server_hello_retry_send function */
        EXPECT_SUCCESS(s2n_server_hello_retry_send(server_conn));

        s2n_tls13_connection_keys(server_keys, server_conn);
        uint8_t hash_digest_length = server_keys.size;

        /* Obtain the transcript hash recreated within the HelloRetryRequest message */
        struct s2n_hash_state server_hash, server_hash_state;
        uint8_t server_digest_out[S2N_MAX_DIGEST_LEN];
        GUARD(s2n_handshake_get_hash_state(server_conn, server_keys.hash_algorithm, &server_hash_state));

        GUARD(s2n_hash_new(&server_hash));
        GUARD(s2n_hash_copy(&server_hash, &server_hash_state));
        GUARD(s2n_hash_digest(&server_hash, server_digest_out, hash_digest_length));
        GUARD(s2n_hash_free(&server_hash));

        struct s2n_blob server_blob;
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
        struct s2n_hash_state client_hash, client_hash_state;
        uint8_t client_digest_out[S2N_MAX_DIGEST_LEN];
        GUARD(s2n_handshake_get_hash_state(client_conn, client_keys.hash_algorithm, &client_hash_state));

        GUARD(s2n_hash_new(&client_hash));
        GUARD(s2n_hash_copy(&client_hash, &client_hash_state));
        GUARD(s2n_hash_digest(&client_hash, client_digest_out, hash_digest_length));
        GUARD(s2n_hash_free(&client_hash));

        struct s2n_blob client_blob;
        EXPECT_SUCCESS(s2n_blob_init(&client_blob, client_digest_out, hash_digest_length));

        /* Test that the transcript hash recreated MUST be the same on the server and client side */
        S2N_BLOB_EXPECT_EQUAL(client_blob, server_blob);

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls13_chain_and_key));
    }

    /* Self-Talk test: the client initiates a handshake with an empty list of keyshares.
     * The server sends a HelloRetryRequest that requires the client to generate a
     * key share on the server negotiated curve. */
    {
        struct s2n_config *server_config;
        struct s2n_config *client_config;

        struct s2n_connection *server_conn;
        struct s2n_connection *client_conn;

        struct s2n_cert_chain_and_key *tls13_chain_and_key;
        char tls13_cert_chain[S2N_MAX_TEST_PEM_SIZE] = {0};
        char tls13_private_key[S2N_MAX_TEST_PEM_SIZE] = {0};

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


        /* Generate keyshare only for Curve x25519 */
        EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(client_conn, "none"));

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
    }

    /* Self-Talk test: the client initiates a handshake with an X25519 share.
     * The server, however does not support x25519 and prefers P-256.
     * The server then sends a HelloRetryRequest that requires the
     * client to generate a key share on the P-256 curve. */
    if (s2n_is_evp_apis_supported()) {
        struct s2n_config *server_config;
        struct s2n_config *client_config;

        struct s2n_connection *server_conn;
        struct s2n_connection *client_conn;

        struct s2n_cert_chain_and_key *tls13_chain_and_key;
        char tls13_cert_chain[S2N_MAX_TEST_PEM_SIZE] = {0};
        char tls13_private_key[S2N_MAX_TEST_PEM_SIZE] = {0};

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


        /* Generate keyshare only for Curve x25519 */
        EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(client_conn, "x25519"));

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
    }

    /* If a client receives a second HelloRetryRequest in the same connection
     * (i.e., where the ClientHello was itself in response to a HelloRetryRequest),
     * it MUST raise an error and abort the handshake. */
    {
        struct s2n_config *server_config;
        struct s2n_config *client_config;

        struct s2n_connection *server_conn;
        struct s2n_connection *client_conn;

        struct s2n_cert_chain_and_key *tls13_chain_and_key;
        char tls13_cert_chain[S2N_MAX_TEST_PEM_SIZE] = {0};
        char tls13_private_key[S2N_MAX_TEST_PEM_SIZE] = {0};

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

        /* Force the client to send an empty list of keyshares */
        EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(client_conn, "none"));

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
    }

    /* Test s2n_hello_retry_validate raises a S2N_ERR_INVALID_HELLO_RETRY error when
     * when conn->secure.server_random is not set to the correct hello retry random value
     * specified in the RFC: https://tools.ietf.org/html/rfc8446#section-4.1.3 */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));
        /* From RFC: https://tools.ietf.org/html/rfc8446#section-4.1.3 */
        const uint8_t not_hello_retry_request_random[S2N_TLS_RANDOM_DATA_LEN] = { 0 };
        EXPECT_MEMCPY_SUCCESS(conn->secure.server_random, not_hello_retry_request_random,
                              S2N_TLS_RANDOM_DATA_LEN);

        EXPECT_FAILURE_WITH_ERRNO(s2n_hello_retry_validate(conn), S2N_ERR_INVALID_HELLO_RETRY);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test server_hello_receive raises a S2N_ERR_CIPHER_NOT_SUPPORTED error when the cipher suite supplied
     * by the Server Hello does not match the cipher suite supplied by the Hello Retry Request */
    {
        struct s2n_connection *server_conn;
        struct s2n_connection *client_conn;

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        
        /* A Hello Retry Request has been processed */
        EXPECT_SUCCESS(s2n_set_hello_retry_required(client_conn));
        client_conn->secure.cipher_suite = &s2n_tls13_aes_256_gcm_sha384;
        client_conn->server_protocol_version = S2N_TLS13;
        client_conn->handshake.handshake_type |= NEGOTIATED;
        client_conn->handshake.handshake_type |= FULL_HANDSHAKE;
        client_conn->handshake.message_number = SERVER_HELLO_MSG_NO;

        /* Server Hello with cipher suite that does not match Hello Retry Request cipher suite */
        server_conn->secure.cipher_suite = &s2n_tls13_chacha20_poly1305_sha256;
        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));

        EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                                        s2n_stuffer_data_available(&server_conn->handshake.io)));

        EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_recv(client_conn), S2N_ERR_CIPHER_NOT_SUPPORTED);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    }

    EXPECT_SUCCESS(s2n_disable_tls13());

    END_TEST();
}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
