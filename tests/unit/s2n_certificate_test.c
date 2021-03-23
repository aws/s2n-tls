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

#include <s2n.h>
#include "utils/s2n_safety.h"
#include "crypto/s2n_crypto.h"
#include "crypto/s2n_openssl_x509.h"

#define S2N_DEFAULT_TEST_CERT_CHAIN_LENGTH 3
#define S2N_CERT_DER_SIZE 2048

struct host_verify_data {
    bool callback_invoked;
    bool allow;
};

static uint8_t verify_host_fn(const char *host_name, size_t host_name_len, void *data)
{
    struct host_verify_data *verify_data = (struct host_verify_data *) data;
    verify_data->callback_invoked = 1;
    return verify_data->allow;
}

static S2N_RESULT s2n_compare_cert_chain(struct s2n_connection *conn, struct s2n_cert_chain_and_key *test_peer_chain)
{
    ENSURE_REF(conn);
    ENSURE_REF(test_peer_chain);
    uint32_t cert_chain_length = 0;
    RESULT_GUARD_POSIX(s2n_get_cert_chain_length(test_peer_chain, &cert_chain_length));
    DEFER_CLEANUP(STACK_OF(X509) *cert_chain_validated = X509_STORE_CTX_get1_chain(conn->x509_validator.store_ctx),
                  s2n_openssl_x509_stack_pop_free);
    ENSURE_REF(cert_chain_validated);
    ENSURE_EQ(cert_chain_length, sk_X509_num(cert_chain_validated));
    struct s2n_cert *cur_cert = NULL;

    for (size_t cert_idx = 0; cert_idx < cert_chain_length; cert_idx++) {
        X509 *cert = sk_X509_value(cert_chain_validated, cert_idx);
        ENSURE_REF(cert);
        DEFER_CLEANUP(uint8_t *cert_data_from_validator = NULL, s2n_crypto_free);
        int cert_size_from_validator = i2d_X509(cert, &cert_data_from_validator);
        ENSURE_REF(cert_data_from_validator);
        ENSURE_GT(cert_size_from_validator, 0);

        RESULT_GUARD_POSIX(s2n_get_cert_from_cert_chain(test_peer_chain, &cur_cert, cert_idx));
        ENSURE_REF(cur_cert);
        ENSURE_EQ(cert_size_from_validator, cur_cert->raw.size);
        ENSURE_EQ(memcmp(cert_data_from_validator, cur_cert->raw.data, cur_cert->raw.size), 0);
    }

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_cert_chain_and_key *chain_and_key = NULL;
    EXPECT_SUCCESS(
        s2n_test_cert_chain_and_key_new(&chain_and_key, S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    /* Test s2n_get_cert_chain_length */ 
    {
        uint32_t length = 0;

        /* Safety checks */
        {
            EXPECT_FAILURE_WITH_ERRNO(s2n_get_cert_chain_length(NULL, &length), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_get_cert_chain_length(chain_and_key, NULL), S2N_ERR_NULL);
        }

        /* Test success case */
        EXPECT_SUCCESS(s2n_get_cert_chain_length(chain_and_key, &length));
        EXPECT_EQUAL(length, S2N_DEFAULT_TEST_CERT_CHAIN_LENGTH);

    }

    /* Test s2n_get_cert_from_cert_chain */
    {
        struct s2n_cert *out_cert = NULL;
        uint32_t cert_idx = 0;

        /* Safety checks */
        {
            EXPECT_FAILURE_WITH_ERRNO(s2n_get_cert_from_cert_chain(NULL, &out_cert, cert_idx), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_get_cert_from_cert_chain(chain_and_key, NULL, cert_idx), S2N_ERR_NULL);
        }

        struct s2n_cert *cur_cert = chain_and_key->cert_chain->head;

        /* Test error case for invalid cert_idx, the valid range of cert_idx is 0 to cert_chain_length - 1 */  
        cert_idx = S2N_DEFAULT_TEST_CERT_CHAIN_LENGTH;
        EXPECT_FAILURE_WITH_ERRNO(s2n_get_cert_from_cert_chain(chain_and_key, &out_cert, cert_idx), S2N_ERR_NO_CERT_FOUND);

        /* Test success case */
        for (size_t i = 0; i < S2N_DEFAULT_TEST_CERT_CHAIN_LENGTH; i++)
        {
            EXPECT_SUCCESS(s2n_get_cert_from_cert_chain(chain_and_key, &out_cert, i));
            EXPECT_NOT_NULL(cur_cert);
            EXPECT_EQUAL(out_cert, cur_cert);
            cur_cert = cur_cert->next;
        }

    }

    /* Test s2n_get_cert_der */ 
    {
        struct s2n_cert *cert = chain_and_key->cert_chain->head;
        const uint8_t *out_cert_der = NULL;
        uint32_t cert_len = 0;

        /* Safety checks */
        {
            EXPECT_FAILURE_WITH_ERRNO(s2n_get_cert_der(NULL, &out_cert_der, &cert_len), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_get_cert_der(cert, NULL, &cert_len), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_get_cert_der(cert, &out_cert_der, NULL), S2N_ERR_NULL);
        }

        EXPECT_SUCCESS(s2n_get_cert_der(cert, &out_cert_der, &cert_len));
        EXPECT_EQUAL(cert_len, cert->raw.size); 
        EXPECT_BYTEARRAY_EQUAL(out_cert_der, cert->raw.data, cert_len);
    }

    /* Test s2n_connection_get_peer_cert_chain */
    {
        /* Setup connections */
        struct s2n_connection *client_conn = NULL;
        struct s2n_connection *server_conn = NULL;
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        struct s2n_cert_chain_and_key *s2n_chain_and_key = NULL;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&s2n_chain_and_key, S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN,
                                                       S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

        struct s2n_config *config_skip_x509_verification = s2n_config_new();
        EXPECT_NOT_NULL(config_skip_x509_verification);
        /* Skip x509 verification */
        EXPECT_SUCCESS(s2n_config_disable_x509_verification(config_skip_x509_verification));
        EXPECT_SUCCESS(s2n_config_set_check_stapled_ocsp_response(config_skip_x509_verification, 0));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config_skip_x509_verification, "test_all"));
        EXPECT_SUCCESS(s2n_config_set_client_auth_type(config_skip_x509_verification, S2N_CERT_AUTH_OPTIONAL));
        struct host_verify_data verify_data = {.allow = 1, .callback_invoked = 0};
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config_skip_x509_verification, verify_host_fn, &verify_data));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config_skip_x509_verification, S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, NULL));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config_skip_x509_verification, s2n_chain_and_key));

        struct s2n_config *config_with_x509_verification = s2n_config_new();
        EXPECT_NOT_NULL(config_with_x509_verification);
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config_with_x509_verification, "test_all"));
        EXPECT_SUCCESS(s2n_config_set_client_auth_type(config_with_x509_verification, S2N_CERT_AUTH_REQUIRED));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config_with_x509_verification, verify_host_fn, &verify_data));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config_with_x509_verification, S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, NULL));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config_with_x509_verification, s2n_chain_and_key));

        /* Test s2n_connection_get_peer_cert_chain failure cases with error codes */
        {            
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config_skip_x509_verification));
            EXPECT_EQUAL(client_conn->x509_validator.skip_cert_validation, 1);

            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config_with_x509_verification));
            EXPECT_EQUAL(server_conn->x509_validator.skip_cert_validation, 0);

            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Negotiate handshake */
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_EQUAL(server_conn->x509_validator.state, VALIDATED);
            EXPECT_NOT_EQUAL(client_conn->x509_validator.state, VALIDATED);

            struct s2n_cert_chain_and_key *test_peer_chain = s2n_cert_chain_and_key_new();
            EXPECT_NOT_NULL(test_peer_chain);

            /* Safety checks */
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_peer_cert_chain(NULL, chain_and_key), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_peer_cert_chain(server_conn, NULL), S2N_ERR_NULL);

            /* Input certificate chain is not empty */
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_peer_cert_chain(server_conn, chain_and_key),
                                      S2N_ERR_INVALID_ARGUMENT);

            /* x509 verification is skipped on client side */
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_peer_cert_chain(client_conn, test_peer_chain),
                                      S2N_ERR_CERT_NOT_VALIDATED);

            EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

            /* Clean-up */
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(test_peer_chain));
            EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
            EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        }

        /* Test s2n_connection_get_peer_cert_chain success on the server side */
        {
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config_skip_x509_verification));
            EXPECT_EQUAL(client_conn->x509_validator.skip_cert_validation, 1);  
    
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config_with_x509_verification));
            EXPECT_EQUAL(server_conn->x509_validator.skip_cert_validation, 0);  

            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Negotiate handshake */
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_EQUAL(server_conn->x509_validator.state, VALIDATED);

            struct s2n_cert_chain_and_key *test_peer_chain = s2n_cert_chain_and_key_new();
            EXPECT_NOT_NULL(test_peer_chain);

            EXPECT_SUCCESS(s2n_connection_get_peer_cert_chain(server_conn, test_peer_chain));

            EXPECT_OK(s2n_compare_cert_chain(server_conn, test_peer_chain));

            EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

            /* Clean-up */
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(test_peer_chain));
            EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
            EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        }

        /* Test s2n_connection_get_peer_cert_chain success on the client side */
        {
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config_skip_x509_verification));
            EXPECT_EQUAL(server_conn->x509_validator.skip_cert_validation, 1);  
    
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config_with_x509_verification));
            EXPECT_EQUAL(client_conn->x509_validator.skip_cert_validation, 0);  

            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Negotiate handshake */
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_EQUAL(client_conn->x509_validator.state, VALIDATED);

            struct s2n_cert_chain_and_key *test_peer_chain = s2n_cert_chain_and_key_new();
            EXPECT_NOT_NULL(test_peer_chain);

            EXPECT_SUCCESS(s2n_connection_get_peer_cert_chain(client_conn, test_peer_chain));

            EXPECT_OK(s2n_compare_cert_chain(client_conn, test_peer_chain));

            EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

            /* Clean-up */
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(test_peer_chain));
            EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
            EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        }

        /* Clean-up */
        EXPECT_SUCCESS(s2n_config_free(config_skip_x509_verification));
        EXPECT_SUCCESS(s2n_config_free(config_with_x509_verification));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(s2n_chain_and_key));
    }

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    END_TEST();
}
