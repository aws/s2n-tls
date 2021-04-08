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

#define S2N_RSA_2048_SHA256_INTERMEDIATE_CA_KEY "../pems/rsa_2048_sha256_intermediate_ca_key.pem"
#define S2N_RSA_2048_SHA256_INTERMEDIATE_CERT_CUSTOM_OID "../pems/rsa_2048_sha256_intermediate_cert_custom_oid.pem"

#define ext_value_MAX_LEN UINT16_MAX
#define OFFSET_INSUFFICIENT_MEM_SIZE 3

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
    RESULT_GUARD_POSIX(s2n_cert_chain_get_length(test_peer_chain, &cert_chain_length));
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

        RESULT_GUARD_POSIX(s2n_cert_chain_get_cert(test_peer_chain, &cur_cert, cert_idx));
        ENSURE_REF(cur_cert);
        ENSURE_EQ(cert_size_from_validator, cur_cert->raw.size);
        ENSURE_EQ(memcmp(cert_data_from_validator, cur_cert->raw.data, cur_cert->raw.size), 0);
    }

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_compare_utf8_strings(struct s2n_blob *input_der, const char *expected_utf8_str, uint32_t utf8_len_in, uint32_t expected_utf8_len)
{
    ENSURE_REF(input_der);
    ENSURE_REF(expected_utf8_str);
    ENSURE_GT(expected_utf8_len, 0);

    DEFER_CLEANUP(struct s2n_blob utf8_str = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&utf8_str, utf8_len_in));

    RESULT_GUARD_POSIX(s2n_cert_get_utf8_string_from_extension_data(input_der->data, input_der->size, utf8_str.data, &utf8_str.size));

    ENSURE_EQ(utf8_str.size, expected_utf8_len);
    ENSURE_EQ(memcmp(utf8_str.data, expected_utf8_str, utf8_str.size), 0);

    RESULT_GUARD_POSIX(s2n_free(&utf8_str));
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_cert_chain_and_key *chain_and_key = NULL;
    EXPECT_SUCCESS(
        s2n_test_cert_chain_and_key_new(&chain_and_key, S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    /* Test s2n_cert_chain_get_length */ 
    {
        uint32_t length = 0;

        /* Safety checks */
        {
            EXPECT_FAILURE_WITH_ERRNO(s2n_cert_chain_get_length(NULL, &length), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_cert_chain_get_length(chain_and_key, NULL), S2N_ERR_NULL);
        }

        /* Test success case */
        EXPECT_SUCCESS(s2n_cert_chain_get_length(chain_and_key, &length));
        EXPECT_EQUAL(length, S2N_DEFAULT_TEST_CERT_CHAIN_LENGTH);

    }

    /* Test s2n_cert_chain_get_cert */
    {
        struct s2n_cert *out_cert = NULL;
        uint32_t cert_idx = 0;

        /* Safety checks */
        {
            EXPECT_FAILURE_WITH_ERRNO(s2n_cert_chain_get_cert(NULL, &out_cert, cert_idx), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_cert_chain_get_cert(chain_and_key, NULL, cert_idx), S2N_ERR_NULL);
        }

        struct s2n_cert *cur_cert = chain_and_key->cert_chain->head;

        /* Test error case for invalid cert_idx, the valid range of cert_idx is 0 to cert_chain_length - 1 */  
        cert_idx = S2N_DEFAULT_TEST_CERT_CHAIN_LENGTH;
        EXPECT_FAILURE_WITH_ERRNO(s2n_cert_chain_get_cert(chain_and_key, &out_cert, cert_idx), S2N_ERR_NO_CERT_FOUND);

        /* Test success case */
        for (size_t i = 0; i < S2N_DEFAULT_TEST_CERT_CHAIN_LENGTH; i++)
        {
            EXPECT_SUCCESS(s2n_cert_chain_get_cert(chain_and_key, &out_cert, i));
            EXPECT_NOT_NULL(cur_cert);
            EXPECT_EQUAL(out_cert, cur_cert);
            cur_cert = cur_cert->next;
        }

    }

    /* Test s2n_cert_get_der */ 
    {
        struct s2n_cert *cert = chain_and_key->cert_chain->head;
        const uint8_t *out_cert_der = NULL;
        uint32_t cert_len = 0;

        /* Safety checks */
        {
            EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_der(NULL, &out_cert_der, &cert_len), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_der(cert, NULL, &cert_len), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_der(cert, &out_cert_der, NULL), S2N_ERR_NULL);
        }

        EXPECT_SUCCESS(s2n_cert_get_der(cert, &out_cert_der, &cert_len));
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

    /* Test X509 Extension helper functions */
    {
        struct s2n_blob ext_value = { 0 };
        struct s2n_blob utf8_str = { 0 };
        bool critical = false;
        size_t i = 0;

        struct s2n_cert_chain_and_key *custom_cert_chain = NULL;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&custom_cert_chain,
                                                       S2N_RSA_2048_SHA256_INTERMEDIATE_CERT_CUSTOM_OID,
                                                       S2N_RSA_2048_SHA256_INTERMEDIATE_CA_KEY));
        struct s2n_cert *cert = custom_cert_chain->cert_chain->head;
        EXPECT_NOT_NULL(cert);

        S2N_BLOB_FROM_HEX(subject_key_id_blob, "04 14 F9 19 58 9D 9E 97 89 9C 27 67 5B 62 19 \
                                                2A 1E 27 D6 4E 1E F6");
        S2N_BLOB_FROM_HEX(authority_key_id_blob, "30 16 80 14 56 9E 26 B6 09 4C 2E AC C8 4E 51 \
                                                E1 AD 7F E7 92 84 28 D4 3E");
        S2N_BLOB_FROM_HEX(basic_constraints_blob, "30 06 01 01 FF 02 01 00");
        S2N_BLOB_FROM_HEX(key_usage_blob, "03 02 01 86");
        S2N_BLOB_FROM_HEX(custom_oid_1_blob, "0C 41 6B 65 79 69 64 3A 33 \
                                              36 3A 36 31 3A 33 46 3A 31 42 3A 30 32 3A 43 37 \
                                              3A 31 32 3A 32 42 3A 35 33 3A 30 41 3A 32 32 3A \
                                              42 41 3A 35 38 3A 42 36 3A 41 38 3A 38 30 3A 31 \
                                              39 3A 45 45 3A 35 31 3A 38 35");
        S2N_BLOB_FROM_HEX(custom_oid_2_blob, "0C 18 49 50 20 41 64 64 72 65 73 73 3A 31 32 2E \
                                              33 34 35 2E 36 37 2E 38 39 30");
        S2N_BLOB_FROM_HEX(custom_oid_3_blob, "0C 28 44 4E 53 3A 31 32 2E 33 34 35 2E 36 37 2E \
                                              38 39 30 2E 61 75 74 6F 2E 70 64 78 2E 65 63 32 \
                                              2E 73 75 62 73 74 72 61 74 65");

        struct {
            const char *oid;
            uint32_t ext_value_len;
            const char *expected_utf8;
            uint32_t utf8_len;
            struct s2n_blob expected_der;
            struct s2n_blob returned_der;
            bool critical;
        } test_cases[] = {
            {
                .oid = "X509v3 Subject Key Identifier",
                .expected_der = subject_key_id_blob,
                .critical = false
            },
            {
                .oid = "X509v3 Authority Key Identifier",
                .expected_der = authority_key_id_blob,
                .critical = false
            },
            {
                .oid = "X509v3 Basic Constraints",
                .expected_der = basic_constraints_blob,
                .critical = true
            },
            {
                .oid = "X509v3 Key Usage",
                .expected_der = key_usage_blob,
                .critical = true
            },
            {
                .oid = "1.2.3.4.5.6.7890.1.2.100.1",
                .expected_utf8 = "keyid:36:61:3F:1B:02:C7:12:2B:53:0A:22:BA:58:B6:A8:80:19:EE:51:85",
                .expected_der = custom_oid_1_blob,
                .critical = false
            },
            {
                .oid = "1.2.3.4.5.6.7890.1.2.100.2",
                .expected_utf8 = "IP Address:12.345.67.890",
                .expected_der = custom_oid_2_blob,
                .critical = false 
            },
            {   .oid = "1.2.3.4.5.6.7890.1.2.100.3",
                .expected_utf8 = "DNS:12.345.67.890.auto.pdx.ec2.substrate",
                .expected_der = custom_oid_3_blob,
                .critical = false 
            },
            {   .oid = "1.2.3.4.5.6.7890.1.2.100",
                .critical = false
            },
        };

        /* Test s2n_cert_get_x509_extension_value_length */ 
        {
            /* Safety checks */ 
            {
                const uint8_t oid[] = "Example X509 extension OID";
                uint32_t ext_value_len = 0;

                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_x509_extension_value_length(NULL, oid, &ext_value_len), S2N_ERR_NULL);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_x509_extension_value_length(cert, NULL, &ext_value_len), S2N_ERR_NULL);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_x509_extension_value_length(cert, oid, NULL), S2N_ERR_NULL);
            }

            /* Test success cases */
            for (i = 0; i < s2n_array_len(test_cases) - 1; i++) {
                EXPECT_SUCCESS(s2n_cert_get_x509_extension_value_length(cert, (const uint8_t *)test_cases[i].oid, &test_cases[i].ext_value_len));
                EXPECT_EQUAL(test_cases[i].ext_value_len, test_cases[i].expected_der.size);
            }

            /* Test failure case for invalid X509 extension OID */
            {
                size_t invalid_test_case = s2n_array_len(test_cases) - 1;
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_x509_extension_value_length(cert, (const uint8_t *)test_cases[invalid_test_case].oid,
                                                     &test_cases[i].ext_value_len), S2N_ERR_X509_EXTENSION_VALUE_NOT_FOUND);
            }

        }

        /* Test s2n_cert_get_x509_extension_value */
        {
            /* Safety checks */ 
            {
                const uint8_t oid[] = "Example X509 extension OID";
                EXPECT_SUCCESS(s2n_alloc(&ext_value, ext_value_MAX_LEN));

                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_x509_extension_value(NULL, oid,
                                                    ext_value.data, &ext_value.size, &critical), S2N_ERR_NULL);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_x509_extension_value(cert, NULL,
                                                    ext_value.data, &ext_value.size, &critical), S2N_ERR_NULL);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_x509_extension_value(cert, oid, 
                                                    NULL, &ext_value.size, &critical), S2N_ERR_NULL);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_x509_extension_value(cert, oid,
                                                    ext_value.data, NULL, &critical), S2N_ERR_NULL);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_x509_extension_value(cert, oid,
                                                    ext_value.data, &ext_value.size, NULL), S2N_ERR_NULL);

                EXPECT_SUCCESS(s2n_free(&ext_value));
            }

            /* Test success cases for s2n_cert_get_x509_extension_value */
            for (i = 0; i < s2n_array_len(test_cases) - 1; i++) {
                EXPECT_SUCCESS(s2n_alloc(&test_cases[i].returned_der, test_cases[i].ext_value_len));
                EXPECT_SUCCESS(s2n_cert_get_x509_extension_value(cert, (const uint8_t *)test_cases[i].oid,
                                                                 test_cases[i].returned_der.data,
                                                                 &test_cases[i].returned_der.size, &critical));
                EXPECT_BYTEARRAY_EQUAL(test_cases[i].returned_der.data, test_cases[i].expected_der.data, test_cases[i].expected_der.size);
                EXPECT_EQUAL(critical, test_cases[i].critical);
            }

            /* Test failure case for insufficient amount of memory allocated */
            {
                size_t insuf_test_case = 0;
                EXPECT_SUCCESS(s2n_alloc(&ext_value, test_cases[insuf_test_case].returned_der.size - OFFSET_INSUFFICIENT_MEM_SIZE));
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_x509_extension_value(cert, (const uint8_t *)test_cases[insuf_test_case].oid,
                                                    ext_value.data, &ext_value.size, &critical), S2N_ERR_INSUFFICIENT_MEM_SIZE);
                EXPECT_SUCCESS(s2n_free(&ext_value));
            }

            /* Test failure case for invalid X509 extension OID */
            {
                size_t invalid_test_case = s2n_array_len(test_cases) - 1;
                EXPECT_SUCCESS(s2n_alloc(&test_cases[invalid_test_case].returned_der, ext_value_MAX_LEN));
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_x509_extension_value(cert, (const uint8_t *)test_cases[invalid_test_case].oid,
                                                    test_cases[invalid_test_case].returned_der.data,
                                                    &test_cases[invalid_test_case].returned_der.size, &critical), 
                                                    S2N_ERR_X509_EXTENSION_VALUE_NOT_FOUND);
            }
        }

        /* Test s2n_cert_get_utf8_string_from_extension_data_length */
        {
            /* Safety checks */ 
            {
                const uint8_t der_ext_value[] = "DER encoded X509 extension value";
                size_t der_ext_value_len = strlen((const char *)der_ext_value);
                uint32_t utf8_len = 0;

                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_utf8_string_from_extension_data_length(NULL, der_ext_value_len, &utf8_len), S2N_ERR_NULL);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_utf8_string_from_extension_data_length(der_ext_value, 0, &utf8_len), S2N_ERR_SAFETY);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_utf8_string_from_extension_data_length(der_ext_value, der_ext_value_len, 0), S2N_ERR_NULL);
            }

            /* Test success and failure cases */
            for (i = 0; i < s2n_array_len(test_cases) - 1; i++) {
                if (i > 3) {
                    EXPECT_SUCCESS(s2n_cert_get_utf8_string_from_extension_data_length(test_cases[i].returned_der.data,
                                                                                  test_cases[i].returned_der.size,
                                                                                  &test_cases[i].utf8_len));
                    EXPECT_EQUAL(test_cases[i].utf8_len, strlen((const char *)test_cases[i].expected_utf8));
                } else {
                    EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_utf8_string_from_extension_data_length(
                                                  test_cases[i].returned_der.data, 
                                                  test_cases[i].returned_der.size,
                                                  &test_cases[i].utf8_len), S2N_ERR_INVALID_X509_EXTENSION_TYPE);
                }
            }

            /* Test failure case for insufficient amount of memory allocated */
            {
                size_t insuf_test_case = 4;
                EXPECT_SUCCESS(s2n_alloc(&utf8_str, test_cases[insuf_test_case].returned_der.size - OFFSET_INSUFFICIENT_MEM_SIZE));
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_utf8_string_from_extension_data(
                                                                        test_cases[insuf_test_case].returned_der.data,
                                                                        test_cases[insuf_test_case].returned_der.size,
                                                                        utf8_str.data, &utf8_str.size), 
                                                                        S2N_ERR_INSUFFICIENT_MEM_SIZE);
                EXPECT_SUCCESS(s2n_free(&utf8_str));
            }

        }

        /* Test s2n_cert_get_utf8_string_from_extension_data */
        {
            /* Safety checks */ 
            {
                const uint8_t der_ext_value[] = "DER encoded X509 extension value";
                size_t der_ext_value_len = strlen((const char *)der_ext_value);
                EXPECT_SUCCESS(s2n_alloc(&utf8_str, ext_value_MAX_LEN));

                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_utf8_string_from_extension_data(NULL, der_ext_value_len, utf8_str.data,
                                                                        &utf8_str.size), S2N_ERR_NULL);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_utf8_string_from_extension_data(der_ext_value, 0, utf8_str.data,
                                                                        &utf8_str.size), S2N_ERR_SAFETY);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_utf8_string_from_extension_data(der_ext_value, der_ext_value_len, NULL,
                                                                        &utf8_str.size), S2N_ERR_NULL);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_utf8_string_from_extension_data(der_ext_value, der_ext_value_len,
                                                                        utf8_str.data, NULL), S2N_ERR_NULL);

                EXPECT_SUCCESS(s2n_free(&utf8_str));
            }

            /* Test success and failure cases for s2n_cert_get_utf8_string_from_extension_data */
            for (i = 0; i < s2n_array_len(test_cases) - 1; i++) {
                if (i > 3) {
                    EXPECT_OK(s2n_compare_utf8_strings(&test_cases[i].returned_der, test_cases[i].expected_utf8,
                                                       test_cases[i].utf8_len, strlen((const char *)test_cases[i].expected_utf8)));
                } else {
                    EXPECT_ERROR_WITH_ERRNO(s2n_compare_utf8_strings(
                        &test_cases[i].returned_der, (const char *)test_cases[i].expected_der.data, ext_value_MAX_LEN,
                        test_cases[i].expected_der.size), S2N_ERR_INVALID_X509_EXTENSION_TYPE);
                }
            }

            /* Test failure case for insufficient amount of memory allocated */
            {
                size_t insuf_test_case = 4;
                EXPECT_SUCCESS(s2n_alloc(&utf8_str, test_cases[insuf_test_case].returned_der.size - OFFSET_INSUFFICIENT_MEM_SIZE));
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_utf8_string_from_extension_data(
                                                                        test_cases[insuf_test_case].returned_der.data,
                                                                        test_cases[insuf_test_case].returned_der.size,
                                                                        utf8_str.data, &utf8_str.size), 
                                                                        S2N_ERR_INSUFFICIENT_MEM_SIZE);
                EXPECT_SUCCESS(s2n_free(&utf8_str));
            }
        }

        /* Cleanup */
        for (i = 0; i < s2n_array_len(test_cases); i++) {
            EXPECT_SUCCESS(s2n_free(&test_cases[i].returned_der));
        }
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(custom_cert_chain));
    }

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    END_TEST();
}
