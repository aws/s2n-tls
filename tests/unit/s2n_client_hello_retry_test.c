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

#include "tests/testlib/s2n_testlib.h"

#include "tls/extensions/s2n_key_share.h"
#include "tls/extensions/s2n_server_supported_versions.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_tls13_handshake.h"
#include "tls/s2n_connection.h"

#include "tls/extensions/s2n_server_key_share.h"
#include "tls/extensions/s2n_client_key_share.h"

#include "error/s2n_errno.h"

/* from RFC: https://tools.ietf.org/html/rfc8446#section-4.1.3 */
const uint8_t hello_retry_request_random_test_buffer[S2N_TLS_RANDOM_DATA_LEN] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
};

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13());

    /* For HelloRetryRequests, test that s2n_client_key_share_extension.send replaces the list of keyshares,
     * with a list containing a single KeyShareEntry for the server selected group. */
    {
        struct s2n_connection *conn;
        struct s2n_stuffer key_share_extension;

        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

        /* Setup the client to have received a HelloRetryRequest */
        memcpy_check(conn->secure.server_random, hello_retry_request_random_test_buffer, S2N_TLS_RANDOM_DATA_LEN);
        conn->server_protocol_version = S2N_TLS13;
        conn->client_protocol_version = S2N_TLS13;
        conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE | HELLO_RETRY_REQUEST;
        conn->handshake.message_number = 1;
        conn->secure.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];

        EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

        const struct s2n_ecc_preferences *ecc_preferences = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
        EXPECT_NOT_NULL(ecc_preferences);

        /* should contain keyshare for only server negotiated curve */
        for (size_t i = 0; i < ecc_preferences->count; i++) {
            struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
            if (ecc_evp_params->negotiated_curve == conn->secure.server_ecc_evp_params.negotiated_curve) {
                EXPECT_NOT_NULL(ecc_evp_params->negotiated_curve);
                EXPECT_NOT_NULL(ecc_evp_params->evp_pkey);
            } else {
                EXPECT_NULL(ecc_evp_params->negotiated_curve);
                EXPECT_NULL(ecc_evp_params->evp_pkey);
            }
        }

        uint16_t key_shares_size;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &key_shares_size));
        EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), key_shares_size);

        /* should contain keyshare for only server negotiated curve */
        uint32_t bytes_processed = 0;
        EXPECT_EQUAL(key_shares_size, conn->secure.server_ecc_evp_params.negotiated_curve->share_size
                                          + S2N_SIZE_OF_NAMED_GROUP + S2N_SIZE_OF_KEY_SHARE_SIZE);

        uint16_t iana_value, share_size;
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &iana_value));
        EXPECT_SUCCESS(s2n_stuffer_read_uint16(&key_share_extension, &share_size));
        bytes_processed += conn->secure.server_ecc_evp_params.negotiated_curve->share_size + S2N_SIZE_OF_NAMED_GROUP
                           + S2N_SIZE_OF_KEY_SHARE_SIZE;

        EXPECT_EQUAL(iana_value, conn->secure.server_ecc_evp_params.negotiated_curve->iana_id);
        EXPECT_EQUAL(share_size, conn->secure.server_ecc_evp_params.negotiated_curve->share_size);
        EXPECT_SUCCESS(s2n_stuffer_skip_read(&key_share_extension, share_size));
        EXPECT_EQUAL(bytes_processed, key_shares_size);

        EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* For HelloRetryRequests, test that s2n_client_key_share_extension.recv can read and parse 
     * the result of s2n_client_key_share_extension.send */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;
        struct s2n_stuffer key_share_extension;

        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

        /* Setup the client to have received a HelloRetryRequest */
        memcpy_check(client_conn->secure.server_random, hello_retry_request_random_test_buffer, S2N_TLS_RANDOM_DATA_LEN);
        client_conn->server_protocol_version = S2N_TLS13;
        client_conn->client_protocol_version = S2N_TLS13;
        client_conn->actual_protocol_version = S2N_TLS13;
        client_conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE | HELLO_RETRY_REQUEST;
        client_conn->handshake.message_number = 1;
        client_conn->secure.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];

        /* During HRR, A key_share list with a single key_share entry, 
         * corresponding to the server negotiated curve is sent by the client */
        EXPECT_SUCCESS(s2n_client_key_share_extension.send(client_conn, &key_share_extension));

        server_conn->secure.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];
        server_conn->server_protocol_version = S2N_TLS13;
        server_conn->client_protocol_version = S2N_TLS13;
        server_conn->actual_protocol_version = S2N_TLS13;

        EXPECT_SUCCESS(s2n_client_key_share_extension.recv(server_conn, &key_share_extension));
        /* should read all data */
        EXPECT_EQUAL(s2n_stuffer_data_available(&key_share_extension), 0);

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(server_conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        for (int i = 0; i < ecc_pref->count; i++) {
            struct s2n_ecc_evp_params *ecc_evp_params = &server_conn->secure.client_ecc_evp_params[i];
            if (ecc_evp_params->negotiated_curve == server_conn->secure.server_ecc_evp_params.negotiated_curve) {
                EXPECT_NOT_NULL(ecc_evp_params->negotiated_curve);
                EXPECT_NOT_NULL(ecc_evp_params->evp_pkey);
            } else {
                EXPECT_NULL(ecc_evp_params->negotiated_curve);
                EXPECT_NULL(ecc_evp_params->evp_pkey);
            }
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Test that s2n_client_key_share_extension.send handles HelloRetryRequests correctly,
     * for a client with TLS1.2 version */
    {
        struct s2n_connection *conn;
        struct s2n_stuffer key_share_extension;

        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

        /* Setup the client to have received a HelloRetryRequest */
        memcpy_check(conn->secure.server_random, hello_retry_request_random_test_buffer, S2N_TLS_RANDOM_DATA_LEN);
        conn->server_protocol_version = S2N_TLS13;
        conn->client_protocol_version = S2N_TLS12;
        conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE | HELLO_RETRY_REQUEST;
        conn->handshake.message_number = 1;
        conn->secure.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];

        EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

        const struct s2n_ecc_preferences *ecc_preferences = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
        EXPECT_NOT_NULL(ecc_preferences);

        for (size_t i = 0; i < ecc_preferences->count; i++) {
            struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
            EXPECT_NOT_NULL(ecc_evp_params->negotiated_curve);
            EXPECT_NOT_NULL(ecc_evp_params->evp_pkey);
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test that s2n_client_key_share_extension.send handles HelloRetryRequests correctly,
     * for a server version set to TLS1.2 */
    {
        struct s2n_connection *conn;
        struct s2n_stuffer key_share_extension;

        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

        /* Setup the client to have received a HelloRetryRequest */
        memcpy_check(conn->secure.server_random, hello_retry_request_random_test_buffer, S2N_TLS_RANDOM_DATA_LEN);
        conn->server_protocol_version = S2N_TLS12;
        conn->client_protocol_version = S2N_TLS13;
        conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE | HELLO_RETRY_REQUEST;
        conn->handshake.message_number = 1;
        conn->secure.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];

        EXPECT_SUCCESS(s2n_client_key_share_extension.send(conn, &key_share_extension));

        const struct s2n_ecc_preferences *ecc_preferences = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
        EXPECT_NOT_NULL(ecc_preferences);

        for (size_t i = 0; i < ecc_preferences->count; i++) {
            struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
            EXPECT_NOT_NULL(ecc_evp_params->negotiated_curve);
            EXPECT_NOT_NULL(ecc_evp_params->evp_pkey);
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* For HelloRetryRequests, test that s2n_client_key_share_extension.send fails, 
     * if the server negotiated_curve is not set. */
    {
        struct s2n_connection *conn;
        struct s2n_stuffer key_share_extension;

        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_CLIENT));

        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&key_share_extension, 0));

        /* Setup the client to have received a HelloRetryRequest */
        memcpy_check(conn->secure.server_random, hello_retry_request_random_test_buffer, S2N_TLS_RANDOM_DATA_LEN);
        conn->server_protocol_version = S2N_TLS13;
        conn->client_protocol_version = S2N_TLS13;
        conn->handshake.handshake_type = NEGOTIATED | FULL_HANDSHAKE | HELLO_RETRY_REQUEST;
        conn->handshake.message_number = 1;
        conn->secure.server_ecc_evp_params.negotiated_curve = NULL;

        EXPECT_FAILURE_WITH_ERRNO(s2n_client_key_share_extension.send(conn, &key_share_extension), S2N_ERR_BAD_KEY_SHARE);

        const struct s2n_ecc_preferences *ecc_preferences = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(conn, &ecc_preferences));
        EXPECT_NOT_NULL(ecc_preferences);

        for (size_t i = 0; i < ecc_preferences->count; i++) {
            struct s2n_ecc_evp_params *ecc_evp_params = &conn->secure.client_ecc_evp_params[i];
            EXPECT_NULL(ecc_evp_params->negotiated_curve);
            EXPECT_NULL(ecc_evp_params->evp_pkey);
        }

        EXPECT_SUCCESS(s2n_stuffer_free(&key_share_extension));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Test the s2n_server_key_share_extension.recv handles HelloRetryRequests correctly */
    {
        struct s2n_connection *client_conn;
        struct s2n_connection *server_conn;

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_stuffer *key_share_extension = &server_conn->handshake.io;

        server_conn->server_protocol_version = S2N_TLS13;
        server_conn->client_protocol_version = S2N_TLS13;
        server_conn->secure.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];
        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(server_conn, 1));
        memcpy_check(server_conn->secure.server_random, hello_retry_request_random_test_buffer, S2N_TLS_RANDOM_DATA_LEN);
        EXPECT_SUCCESS(s2n_server_key_share_extension.send(server_conn, key_share_extension));

        /* Setup the client to receive a HelloRetryRequest */
        memcpy_check(client_conn->secure.server_random, hello_retry_request_random_test_buffer, S2N_TLS_RANDOM_DATA_LEN);
        client_conn->server_protocol_version = S2N_TLS13;
        client_conn->client_protocol_version = S2N_TLS13;

        /* Setup the handshake type and message number to simulate a condition where a HelloRetry should be sent */
        client_conn->handshake.handshake_type = NEGOTIATED | HELLO_RETRY_REQUEST | FULL_HANDSHAKE;
        EXPECT_SUCCESS(s2n_set_hello_retry_required(client_conn));
        client_conn->handshake.message_number = 1;

        /* Parse the key share */
        EXPECT_SUCCESS(s2n_server_key_share_extension.recv(client_conn, key_share_extension));
        EXPECT_EQUAL(s2n_stuffer_data_available(key_share_extension), 0);

        EXPECT_EQUAL(server_conn->secure.server_ecc_evp_params.negotiated_curve, client_conn->secure.server_ecc_evp_params.negotiated_curve);
        EXPECT_NULL(client_conn->secure.server_ecc_evp_params.evp_pkey);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
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

        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(server_conn, 1));

        server_conn->secure.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];

        /* Server sends HelloRetryRequest message, s2n_server_hello_retry_recreate_transcript
         * is called within this function */
        EXPECT_SUCCESS(s2n_server_hello_retry_send(server_conn));

        s2n_tls13_connection_keys(server_keys, server_conn);
        uint8_t hash_digest_length = server_keys.size;

        /* Obtain the recreated transcript hash */
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

        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(client_conn, 1));
        /* Client receives the HelloRetryRequest mesage, s2n_server_hello_retry_recreate_transcript
         * is called within this function */
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));

        s2n_tls13_connection_keys(client_keys, client_conn);
        hash_digest_length = client_keys.size;

        /* Obtain the recreated transcript hash */
        struct s2n_hash_state client_hash, client_hash_state;
        uint8_t client_digest_out[S2N_MAX_DIGEST_LEN];
        GUARD(s2n_handshake_get_hash_state(client_conn, client_keys.hash_algorithm, &client_hash_state));

        GUARD(s2n_hash_new(&client_hash));
        GUARD(s2n_hash_copy(&client_hash, &client_hash_state));
        GUARD(s2n_hash_digest(&client_hash, client_digest_out, hash_digest_length));
        GUARD(s2n_hash_free(&client_hash));

        struct s2n_blob client_blob;
        EXPECT_SUCCESS(s2n_blob_init(&client_blob, client_digest_out, hash_digest_length));

        /* The transcript hash recreated MUST be the same */
        S2N_BLOB_EXPECT_EQUAL(client_blob, server_blob);

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls13_chain_and_key));
    }

    /* In this test, the client initiates a handshake with an X25519 share.
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

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "20190801")); /* contains x25519 */
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "20190802")); /* doesnot contain x25519 */

        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Generate keyshare only for Curve x25519 */
        EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(client_conn, "x25519"));

        /* ClientHello 1 */
        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(client_conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        /* Verify that only x25519 keyshares is sent in ClientHello */
        for (int i = 0; i < ecc_pref->count; i++) {
            if (client_conn->secure.client_ecc_evp_params[i].negotiated_curve == &s2n_ecc_curve_x25519) {
                EXPECT_NOT_NULL(client_conn->secure.client_ecc_evp_params[i].evp_pkey);
            }
            else {
                EXPECT_NULL(client_conn->secure.client_ecc_evp_params[i].evp_pkey);
            }
        }

        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                                        s2n_stuffer_data_available(&client_conn->handshake.io)));

        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

        EXPECT_TRUE(s2n_is_hello_retry_required(server_conn));
        /* There was no matching key share received with a supported group, we should send a retry */
        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(server_conn, 1));
        EXPECT_TRUE(s2n_is_hello_retry_message(server_conn));
        
        /* Verify server negotiated group is secp256r1 */
        EXPECT_EQUAL(server_conn->secure.server_ecc_evp_params.negotiated_curve, &s2n_ecc_curve_secp256r1);

        /* Server HelloRetryRequest */
        EXPECT_SUCCESS(s2n_server_hello_retry_send(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                                        s2n_stuffer_data_available(&server_conn->handshake.io)));

        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(client_conn, 1));
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));
        /* Verify that a Server HelloRetryRequest message was received */
        EXPECT_TRUE(s2n_is_hello_retry_required(client_conn));
        EXPECT_EQUAL(s2n_stuffer_data_available(&client_conn->handshake.io), 0);

        /* ClientHello 2 */
        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));

        /* Verify keyshare is sent only for negotiated curve in HRR */
        for (int i = 0; i < ecc_pref->count; i++) {
            if (server_conn->secure.server_ecc_evp_params.negotiated_curve == &s2n_ecc_curve_secp256r1) {
                EXPECT_NOT_NULL(&client_conn->secure.client_ecc_evp_params[i].evp_pkey);
            } else {
                EXPECT_NULL(&client_conn->secure.client_ecc_evp_params[i].evp_pkey);
            }
        }

        EXPECT_SUCCESS(s2n_stuffer_wipe(&server_conn->handshake.io));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                                        s2n_stuffer_data_available(&client_conn->handshake.io)));

        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));
        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(server_conn, 5));
        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls13_chain_and_key));
    }

    /* In this test, the client initiates a handshake with an empty list of keyshares.
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

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(client_conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        /* Verify that no keyshares are sent in ClientHello */
        for (int i = 0; i < ecc_pref->count; i++) {
                EXPECT_NULL(client_conn->secure.client_ecc_evp_params[i].evp_pkey);
        }

        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                                        s2n_stuffer_data_available(&client_conn->handshake.io)));

        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

        /* There was no matching key share received, we should send a retry */
        EXPECT_TRUE(s2n_is_hello_retry_required(server_conn));
        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(server_conn, 1));
        EXPECT_TRUE(s2n_is_hello_retry_message(server_conn));

        server_conn->secure.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
        server_conn->secure.mutually_supported_groups[0] = ecc_pref->ecc_curves[0];

        EXPECT_SUCCESS(s2n_extensions_server_key_share_select(server_conn));

        EXPECT_EQUAL(server_conn->secure.server_ecc_evp_params.negotiated_curve, ecc_pref->ecc_curves[0]);

        /* Server HelloRetryRequest 1 */
        EXPECT_SUCCESS(s2n_server_hello_retry_send(server_conn));

        EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                                        s2n_stuffer_data_available(&server_conn->handshake.io)));

        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(client_conn, 1));
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));
        /* Verify that a Server HelloRetryRequest message was received */
        EXPECT_TRUE(s2n_is_hello_retry_required(client_conn));

        /* ClientHello 2 */
        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));

        /* Verify keyshare is sent only for negotiated curve in HRR */
        for (int i = 0; i < ecc_pref->count; i++) {
            if (server_conn->secure.server_ecc_evp_params.negotiated_curve == ecc_pref->ecc_curves[0]) {
                EXPECT_NOT_NULL(&client_conn->secure.client_ecc_evp_params[i].evp_pkey);
            } else {
                EXPECT_NULL(&client_conn->secure.client_ecc_evp_params[i].evp_pkey);
            }
        }

        /* If a client receives a second HelloRetryRequest in the same connection 
         * (i.e., where the ClientHello was itself in response to a HelloRetryRequest), it MUST abort the handshake. 
         */

        /* Server HelloRetryRequest 2 */
        EXPECT_SUCCESS(s2n_server_hello_retry_send(server_conn));

        EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                                        s2n_stuffer_data_available(&server_conn->handshake.io)));

        EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_recv(client_conn), S2N_ERR_BAD_MESSAGE);

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
        struct s2n_test_piped_io piped_io;
        EXPECT_SUCCESS(s2n_piped_io_init_non_blocking(&piped_io));

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

        server_conn->server_protocol_version = S2N_TLS13;
        server_conn->client_protocol_version = S2N_TLS13;
        server_conn->actual_protocol_version = S2N_TLS13;

        client_conn->server_protocol_version = S2N_TLS13;
        client_conn->client_protocol_version = S2N_TLS13;
        client_conn->actual_protocol_version = S2N_TLS13;

        /* Generate keyshare only for Curve x25519 */
        EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(client_conn, "none"));

        EXPECT_SUCCESS(s2n_connections_set_piped_io(client_conn, server_conn, &piped_io));

        /* Negotiate handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls13_chain_and_key));
        EXPECT_SUCCESS(s2n_piped_io_close(&piped_io));
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
        struct s2n_test_piped_io piped_io;
        EXPECT_SUCCESS(s2n_piped_io_init_non_blocking(&piped_io));

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
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "20190802")); /* doesnot contain x25519 */

        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        server_conn->x509_validator.skip_cert_validation = 1;
        client_conn->x509_validator.skip_cert_validation = 1;

        server_conn->server_protocol_version = S2N_TLS13;
        server_conn->client_protocol_version = S2N_TLS13;
        server_conn->actual_protocol_version = S2N_TLS13;

        client_conn->server_protocol_version = S2N_TLS13;
        client_conn->client_protocol_version = S2N_TLS13;
        client_conn->actual_protocol_version = S2N_TLS13;

        /* Generate keyshare only for Curve x25519 */
        EXPECT_SUCCESS(s2n_connection_set_keyshare_by_name_for_testing(client_conn, "x25519"));

        EXPECT_SUCCESS(s2n_connections_set_piped_io(client_conn, server_conn, &piped_io));

        /* Negotiate handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls13_chain_and_key));
        EXPECT_SUCCESS(s2n_piped_io_close(&piped_io));
    }

    EXPECT_SUCCESS(s2n_disable_tls13());

    END_TEST();
}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
