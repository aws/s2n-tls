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
#include "tls/s2n_tls.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_config *ecdsa_config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(ecdsa_config);
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(ecdsa_config));
    DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_cert_chain = NULL, s2n_cert_chain_and_key_ptr_free);

    /* Note that this certificate will only be able to produce signatures with the secp256r1 curve */
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_cert_chain, S2N_ECDSA_P256_PKCS1_CERT_CHAIN,
            S2N_ECDSA_P256_PKCS1_KEY));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(ecdsa_config, ecdsa_cert_chain));

    /* This testfile includes various scenarios where the signature writer ignores the curve preferences of the
     * peer when creating the transcript signature. The setup is slightly different depending on the protocol
     * version being negotiated.
     *
     * In TLS1.2, an endpoint advertised its supported curves list through the supported curves extension.
     * In TLS1.2, we error when the peer's public key curve type is not in our supported
     * curves list.
     * In TLS1.3, signature algorithms now imply a specific curve.
     * In TLS1.3 we error if the curve in the peer's public key doesn't match the signature algorithm's
     * intended curve.
     */

    /* Test TLS1.3 codepaths */
    if (s2n_is_tls13_fully_supported()) {
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);

            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
            EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

            EXPECT_SUCCESS(s2n_connection_set_config(server, ecdsa_config));
            EXPECT_SUCCESS(s2n_connection_set_config(client, ecdsa_config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server, "test_all_tls13"));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client, "test_all_tls13"));

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server, client, SERVER_CERT_VERIFY));

            /* Set an ECDSA signature scheme. This results in the wire bytes signifying ecdsa_secp384r1_sha384
            * but because the only cert key available is secp256r1 the actual signature produced will be
            * ecdsa with a 384 hash alg and a secp256r1 key. */
            server->handshake_params.server_cert_sig_scheme = &s2n_ecdsa_sha384;

            /* Send cert verify */
            EXPECT_SUCCESS(s2n_tls13_cert_verify_send(server));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server->handshake.io, &client->handshake.io,
                    s2n_stuffer_data_available(&server->handshake.io)));

            /* Sanity check that we actually did write the intended iana id */
            uint16_t iana_id = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&client->handshake.io, &iana_id));
            EXPECT_EQUAL(iana_id, TLS_SIGNATURE_SCHEME_ECDSA_SHA384);
            EXPECT_SUCCESS(s2n_stuffer_reread(&client->handshake.io));

            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_cert_verify_recv(client), S2N_ERR_INVALID_SIGNATURE_ALGORITHM);
        };

        /* MTLS codepath */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);

            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
            EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

            EXPECT_SUCCESS(s2n_connection_set_config(server, ecdsa_config));
            EXPECT_SUCCESS(s2n_connection_set_config(client, ecdsa_config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server, "test_all_tls13"));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client, "test_all_tls13"));
            EXPECT_SUCCESS(s2n_connection_set_client_auth_type(server, S2N_CERT_AUTH_REQUIRED));
            EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client, S2N_CERT_AUTH_REQUIRED));

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server, client, CLIENT_CERT_VERIFY));

            /* Set an ECDSA signature scheme. This results in the wire bytes signifying ecdsa_secp384r1_sha384
            * but because the only cert key available is secp256r1 the actual signature produced will be
            * ecdsa with a sha384 hash and a secp256r1 key. */
            client->handshake_params.client_cert_sig_scheme = &s2n_ecdsa_sha384;

            /* Send cert verify */
            EXPECT_SUCCESS(s2n_tls13_cert_verify_send(client));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client->handshake.io, &server->handshake.io,
                    s2n_stuffer_data_available(&client->handshake.io)));

            /* Sanity check that we actually did write the intended iana id */
            uint16_t iana_id = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint16(&server->handshake.io, &iana_id));
            EXPECT_EQUAL(iana_id, TLS_SIGNATURE_SCHEME_ECDSA_SHA384);
            EXPECT_SUCCESS(s2n_stuffer_reread(&server->handshake.io));

            EXPECT_FAILURE_WITH_ERRNO(s2n_tls13_cert_verify_recv(server), S2N_ERR_INVALID_SIGNATURE_ALGORITHM);
        };
    }

    /* Test TLS1.2 codepaths */
    {
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);

            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
            EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

            EXPECT_SUCCESS(s2n_connection_set_config(server, ecdsa_config));
            EXPECT_SUCCESS(s2n_connection_set_config(client, ecdsa_config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server, "test_all_tls12"));
            /* This policy only supports curve secp384r1 in its ECC list */
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client, "20210816"));

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server, client, SERVER_KEY));

            /* Send cert verify */
            EXPECT_SUCCESS(s2n_server_key_send(server));
            EXPECT_SUCCESS(s2n_stuffer_copy(&server->handshake.io, &client->handshake.io,
                    s2n_stuffer_data_available(&server->handshake.io)));

            EXPECT_FAILURE_WITH_ERRNO(s2n_server_key_recv(client), S2N_ERR_INVALID_SIGNATURE_ALGORITHM);
        };

        /* MTLS codepath */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);

            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
            EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

            EXPECT_SUCCESS(s2n_connection_set_config(server, ecdsa_config));
            EXPECT_SUCCESS(s2n_connection_set_config(client, ecdsa_config));

            EXPECT_SUCCESS(s2n_connection_set_client_auth_type(server, S2N_CERT_AUTH_REQUIRED));
            EXPECT_SUCCESS(s2n_connection_set_client_auth_type(client, S2N_CERT_AUTH_REQUIRED));

            /* This policy only supports curve secp384r1 in its ECC list */
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(server, "20210816"));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(client, "test_all_tls12"));

            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server, client, CLIENT_CERT_VERIFY));

            /* Send cert verify */
            EXPECT_SUCCESS(s2n_client_cert_verify_send(client));
            EXPECT_SUCCESS(s2n_stuffer_copy(&client->handshake.io, &server->handshake.io,
                    s2n_stuffer_data_available(&client->handshake.io)));

            EXPECT_FAILURE_WITH_ERRNO(s2n_client_cert_verify_recv(server), S2N_ERR_INVALID_SIGNATURE_ALGORITHM);
        };
    };

    END_TEST();
}
