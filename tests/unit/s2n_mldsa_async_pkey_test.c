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

#include "crypto/s2n_mldsa.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_tls13.h"

/* Holds the private key outside of the TLS config, as a hardware keystore would */
static struct s2n_cert_chain_and_key *keystore = NULL;

static int async_pkey_sign_with_keystore(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    POSIX_GUARD(s2n_async_pkey_op_perform(op, s2n_cert_chain_and_key_get_private_key(keystore)));
    POSIX_GUARD(s2n_async_pkey_op_apply(op, conn));
    POSIX_GUARD(s2n_async_pkey_op_free(op));
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_mldsa_is_supported() || !s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    const char *test_certs[][2] = {
        { S2N_MLDSA44_CERT, S2N_MLDSA44_KEY },
        { S2N_MLDSA87_CERT, S2N_MLDSA87_KEY },
    };

    for (size_t i = 0; i < s2n_array_len(test_certs); i++) {
        const char *cert_path = test_certs[i][0];
        const char *key_path = test_certs[i][1];

        DEFER_CLEANUP(struct s2n_cert_chain_and_key *private_chain = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&private_chain, cert_path, key_path));
        keystore = private_chain;

        /* The chain used for the handshake has no private key */
        uint8_t cert_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        uint32_t cert_pem_len = 0;
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(cert_path, cert_pem, &cert_pem_len, sizeof(cert_pem)));
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *public_chain = s2n_cert_chain_and_key_new(),
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_NOT_NULL(public_chain);
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_public_pem_bytes(public_chain, cert_pem, cert_pem_len));

        /* Test: server signs CertificateVerify with ML-DSA through the async pkey callback */
        {
            DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(server_config);
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "20250512"));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, public_chain));
            EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(server_config, async_pkey_sign_with_keystore));

            DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(client_config);
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "20250512"));
            EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);
            EXPECT_EQUAL(client_conn->handshake_params.server_cert_sig_scheme->sig_alg, S2N_SIGNATURE_MLDSA);
        };

        /* Test: client signs CertificateVerify with ML-DSA through the async pkey callback (mutual auth) */
        {
            DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(server_config);
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "20250512"));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, private_chain));
            EXPECT_SUCCESS(s2n_config_set_client_auth_type(server_config, S2N_CERT_AUTH_REQUIRED));
            EXPECT_SUCCESS(s2n_config_disable_x509_verification(server_config));

            DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(client_config);
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "20250512"));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, public_chain));
            EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(client_config, async_pkey_sign_with_keystore));
            EXPECT_SUCCESS(s2n_config_set_client_auth_type(client_config, S2N_CERT_AUTH_REQUIRED));
            EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);
            EXPECT_EQUAL(server_conn->handshake_params.client_cert_sig_scheme->sig_alg, S2N_SIGNATURE_MLDSA);
        };
    }

    END_TEST();
}
