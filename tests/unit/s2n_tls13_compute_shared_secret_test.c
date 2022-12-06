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

#include <stdlib.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13_handshake.c"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    struct s2n_cert_chain_and_key *cert_chain = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&cert_chain,
            S2N_ECDSA_P384_PKCS1_CERT_CHAIN, S2N_ECDSA_P384_PKCS1_KEY));
    EXPECT_NOT_NULL(cert_chain);

    struct s2n_config *config = s2n_config_new();
    EXPECT_NOT_NULL(config);
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, cert_chain));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));

    struct s2n_connection *client_conn;

    /* This test ensures that if the server did not send a keyshare extension in the server hello function,
     * a null pointer error is correctly thrown.
     */
    {
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        client_conn->actual_protocol_version = S2N_TLS13;

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(client_conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        /* Select curve and generate key for client */
        client_conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_conn->kex_params.client_ecc_evp_params));
        /* Recreating conditions where negotiated curve was not set */
        struct s2n_ecc_evp_params missing_params = { NULL, NULL };
        client_conn->kex_params.server_ecc_evp_params = missing_params;
        DEFER_CLEANUP(struct s2n_blob client_shared_secret = { 0 }, s2n_free);
        /* Compute fails because server's curve and public key are missing. */
        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_shared_secret(client_conn, &client_shared_secret), S2N_ERR_NULL);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    };

    /* This test ensures that if a server sent a keyshare extension without a public key, a null pointer
     * error is correctly thrown.
     */
    {
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        client_conn->actual_protocol_version = S2N_TLS13;

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(client_conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        /* Select curve and generate key for client */
        client_conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_conn->kex_params.client_ecc_evp_params));

        /* Set curve server sent in server hello */
        client_conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];

        DEFER_CLEANUP(struct s2n_blob client_shared_secret = { 0 }, s2n_free);
        /* Compute fails because server's public key is missing */
        EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_compute_shared_secret(client_conn, &client_shared_secret), S2N_ERR_NULL);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    };

    /* This test ensures that if a server sent a keyshare extension with a public key and curve, a client can
     * generate a shared secret from it.
     */
    {
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        const struct s2n_ecc_preferences *ecc_pref = NULL;
        EXPECT_SUCCESS(s2n_connection_get_ecc_preferences(client_conn, &ecc_pref));
        EXPECT_NOT_NULL(ecc_pref);

        client_conn->actual_protocol_version = S2N_TLS13;

        /* Select curve and generate key for client */
        client_conn->kex_params.client_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_conn->kex_params.client_ecc_evp_params));

        /* Set curve server sent in server hello */
        client_conn->kex_params.server_ecc_evp_params.negotiated_curve = ecc_pref->ecc_curves[0];

        /* Generate public key server sent in server hello */
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_conn->kex_params.server_ecc_evp_params));
        DEFER_CLEANUP(struct s2n_blob client_shared_secret = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_tls13_compute_shared_secret(client_conn, &client_shared_secret));

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    };

    /* This test ensures that the shared secrets computed by a client and server after negotiation match */
    {
        client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                s2n_stuffer_data_available(&client_conn->handshake.io)));
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));

        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                s2n_stuffer_data_available(&server_conn->handshake.io)));
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));

        DEFER_CLEANUP(struct s2n_blob client_shared_secret = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_tls13_compute_shared_secret(client_conn, &client_shared_secret));
        EXPECT_TRUE(client_shared_secret.size > 0);

        DEFER_CLEANUP(struct s2n_blob server_shared_secret = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_tls13_compute_shared_secret(server_conn, &server_shared_secret));
        EXPECT_TRUE(server_shared_secret.size > 0);

        S2N_BLOB_EXPECT_EQUAL(server_shared_secret, client_shared_secret);

        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(cert_chain));
    EXPECT_SUCCESS(s2n_config_free(config));

    END_TEST();
}
