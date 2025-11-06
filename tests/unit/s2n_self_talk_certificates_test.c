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

#include "crypto/s2n_rsa_pss.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_tls.h"

static uint8_t s2n_noop_verify_host_fn(const char *name, size_t len, void *data)
{
    return 1;
}

static S2N_RESULT s2n_test_load_certificate(struct s2n_cert_chain_and_key **chain_out,
        char *chain_pem_out, const char *chain_pem_path, const char *key_pem_path)
{
    RESULT_ENSURE_REF(chain_out);

    char key_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    RESULT_GUARD_POSIX(s2n_read_test_pem(chain_pem_path, chain_pem_out, S2N_MAX_TEST_PEM_SIZE));
    RESULT_GUARD_POSIX(s2n_read_test_pem(key_pem_path, key_pem, S2N_MAX_TEST_PEM_SIZE));

    *chain_out = s2n_cert_chain_and_key_new();
    RESULT_ENSURE_REF(*chain_out);
    RESULT_GUARD_POSIX(s2n_cert_chain_and_key_load_pem(*chain_out, chain_pem_out, key_pem));

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_is_rsa_pss_certs_supported() || !s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    const uint8_t test_versions[] = { S2N_TLS13, S2N_TLS12, S2N_TLS11, S2N_TLS10 };
    struct {
        const char *cert;
        const char *key;
        uint8_t min_version;
    } test_certs[] = {
        {
                .cert = S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                .key = S2N_RSA_2048_PKCS1_SHA256_CERT_KEY,
        },
        {
                .cert = S2N_ECDSA_P384_PKCS1_CERT_CHAIN,
                .key = S2N_ECDSA_P384_PKCS1_KEY,
        },
        {
                .cert = S2N_ECDSA_P512_CERT_CHAIN,
                .key = S2N_ECDSA_P512_KEY,
        },
        {
                .cert = S2N_RSA_PSS_2048_SHA256_LEAF_CERT,
                .key = S2N_RSA_PSS_2048_SHA256_LEAF_KEY,
                .min_version = S2N_TLS12,
        },
    };

    for (size_t cert_i = 0; cert_i < s2n_array_len(test_certs); cert_i++) {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL,
                s2n_cert_chain_and_key_ptr_free);
        char pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        EXPECT_OK(s2n_test_load_certificate(&chain, pem,
                test_certs[cert_i].cert, test_certs[cert_i].key));

        for (size_t version_i = 0; version_i < s2n_array_len(test_versions); version_i++) {
            uint8_t version = test_versions[version_i];
            bool expect_success = (version >= test_certs[cert_i].min_version);

            /* 20240501 only supports up to TLS1.2 */
            const char *security_policy = "20240501";
            if (version >= S2N_TLS13) {
                security_policy = "default_tls13";
            } else if (version < S2N_TLS12) {
                /* The default policies don't support legacy versions */
                security_policy = "test_all";
            }

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain));
            EXPECT_SUCCESS(s2n_config_add_pem_to_trust_store(config, pem));
            EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config, s2n_noop_verify_host_fn, NULL));
            EXPECT_SUCCESS(s2n_config_set_max_blinding_delay(config, 0));
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, security_policy));

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server);
            EXPECT_SUCCESS(s2n_connection_set_config(server, config));
            server->server_protocol_version = version;

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client);
            EXPECT_SUCCESS(s2n_connection_set_config(client, config));
            client->client_protocol_version = version;

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

            bool handshake_success =
                    (s2n_negotiate_test_server_and_client(server, client) == S2N_SUCCESS);
            if (handshake_success) {
                EXPECT_EQUAL(server->actual_protocol_version, version);
                EXPECT_EQUAL(client->actual_protocol_version, version);
            }

            const char *error_message = "Handshake failed";
            if (!expect_success) {
                error_message = "Handshake unexpectedly succeeded";
            }
            if (handshake_success != expect_success) {
                fprintf(stderr, "%s version=%i cert=%s\n",
                        error_message, version, test_certs[cert_i].cert);
                FAIL_MSG(error_message);
            }
        }
    }

    END_TEST();
}
