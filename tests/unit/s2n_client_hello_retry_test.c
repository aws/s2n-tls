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

#include "tls/extensions/s2n_key_share.h"
#include "tls/extensions/s2n_server_supported_versions.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_tls13_handshake.h"
#include "tls/s2n_connection.h"

#include "tls/extensions/s2n_server_key_share.h"

#include "error/s2n_errno.h"

const uint8_t SESSION_ID_SIZE = 1;
const uint8_t COMPRESSION_METHOD_SIZE = 1;

/* from RFC: https://tools.ietf.org/html/rfc8446#section-4.1.3 */
const uint8_t hello_retry_request_random_test_buffer[S2N_TLS_RANDOM_DATA_LEN] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
};

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13());

    struct s2n_config *server_config;
    struct s2n_config *client_config;

    struct s2n_connection *server_conn;
    struct s2n_connection *client_conn;

    struct s2n_cert_chain_and_key *tls13_chain_and_key;
    char tls13_cert_chain[S2N_MAX_TEST_PEM_SIZE] = {0};
    char tls13_private_key[S2N_MAX_TEST_PEM_SIZE] = {0};

    if (s2n_is_evp_apis_supported())
    {
        /* In this test, the client initiates a handshake with an X25519 share.
        * The server, however does not support x25519 and prefers P-256.
        * The server then sends a HelloRetryRequest that requires the
        * client to generate a key share on the P-256 curve.
        */
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

        uint16_t curve_x25519 = TLS_EC_CURVE_ECDH_X25519;

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "20190801")); /* contains x25519 */
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "20190802")); /* doesnot contain x25519 */

        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Generate keyshare only for Curve x25519 */
        EXPECT_SUCCESS(s2n_connection_set_keyshare_by_group_for_testing(client_conn, curve_x25519));

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

        /* There was no matching key share received with a supported group, we should send a retry */
        EXPECT_TRUE(s2n_is_hello_retry_handshake(server_conn));
        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(server_conn));
        EXPECT_TRUE(s2n_is_hello_retry_message(server_conn));
        
        /* Verify server negotiated group is secp256r1 */
        EXPECT_EQUAL(server_conn->secure.server_ecc_evp_params.negotiated_curve, &s2n_ecc_curve_secp256r1);

        /* Server HelloRetryRequest */
        EXPECT_SUCCESS(s2n_server_hello_retry_send(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                                        s2n_stuffer_data_available(&server_conn->handshake.io)));
        
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));
        /* Verify that a Server HelloRetryRequest message was received */
        EXPECT_TRUE(s2n_is_hello_retry_handshake(client_conn));
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
        s2n_set_connection_server_hello_flags(server_conn);
        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls13_chain_and_key));
    }
    {
        /* In this test, the client initiates a handshake with an empty list of keyshares.  
         * The server sends a HelloRetryRequest that requires the client to generate a 
         * key share on the server negotiated curve.
         */

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
        uint16_t iana_value = 0;
        EXPECT_SUCCESS(s2n_connection_set_keyshare_by_group_for_testing(client_conn, iana_value));

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
        EXPECT_TRUE(s2n_is_hello_retry_handshake(server_conn));
        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(server_conn));
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

        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));
        /* Verify that a Server HelloRetryRequest message was received */
        EXPECT_TRUE(s2n_is_hello_retry_handshake(client_conn));

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

    EXPECT_SUCCESS(s2n_disable_tls13());

    END_TEST();
}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
