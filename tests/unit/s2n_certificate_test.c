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

#include "api/s2n.h"
#include "crypto/s2n_crypto.h"
#include "crypto/s2n_openssl_x509.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

#define S2N_DEFAULT_TEST_CERT_CHAIN_LENGTH 3
#define S2N_CERT_DER_SIZE                  2048

#define S2N_RSA_2048_SHA256_INTERMEDIATE_CA_KEY          "../pems/rsa_2048_sha256_intermediate_ca_key.pem"
#define S2N_RSA_2048_SHA256_INTERMEDIATE_CERT_CUSTOM_OID "../pems/rsa_2048_sha256_intermediate_cert_custom_oid.pem"

#define ext_value_MAX_LEN            UINT16_MAX
#define OFFSET_INSUFFICIENT_MEM_SIZE 3

DEFINE_POINTER_CLEANUP_FUNC(X509_NAME *, X509_NAME_free);

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

static uint8_t always_verify_host_fn(const char *host_name, size_t host_name_len, void *data)
{
    return true;
}

static int s2n_noop_async_pkey_fn(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    return S2N_SUCCESS;
}

static S2N_RESULT s2n_compare_cert_chain(struct s2n_connection *conn, struct s2n_cert_chain_and_key *test_peer_chain)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(test_peer_chain);
    uint32_t cert_chain_length = 0;
    RESULT_GUARD_POSIX(s2n_cert_chain_get_length(test_peer_chain, &cert_chain_length));
    DEFER_CLEANUP(STACK_OF(X509) *cert_chain_validated = X509_STORE_CTX_get1_chain(conn->x509_validator.store_ctx),
            s2n_openssl_x509_stack_pop_free);
    RESULT_ENSURE_REF(cert_chain_validated);
    RESULT_ENSURE_EQ(cert_chain_length, sk_X509_num(cert_chain_validated));
    struct s2n_cert *cur_cert = NULL;

    for (size_t cert_idx = 0; cert_idx < cert_chain_length; cert_idx++) {
        X509 *cert = sk_X509_value(cert_chain_validated, cert_idx);
        RESULT_ENSURE_REF(cert);
        DEFER_CLEANUP(uint8_t *cert_data_from_validator = NULL, s2n_crypto_free);
        int cert_size_from_validator = i2d_X509(cert, &cert_data_from_validator);
        RESULT_ENSURE_REF(cert_data_from_validator);
        RESULT_ENSURE_GT(cert_size_from_validator, 0);

        RESULT_GUARD_POSIX(s2n_cert_chain_get_cert(test_peer_chain, &cur_cert, cert_idx));
        RESULT_ENSURE_REF(cur_cert);
        RESULT_ENSURE_EQ(cert_size_from_validator, cur_cert->raw.size);
        RESULT_ENSURE_EQ(memcmp(cert_data_from_validator, cur_cert->raw.data, cur_cert->raw.size), 0);
    }

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_compare_utf8_strings(struct s2n_blob *input_der, const char *expected_utf8_str, uint32_t utf8_len_in, uint32_t expected_utf8_len)
{
    RESULT_ENSURE_REF(input_der);
    RESULT_ENSURE_REF(expected_utf8_str);
    RESULT_ENSURE_GT(expected_utf8_len, 0);

    DEFER_CLEANUP(struct s2n_blob utf8_str = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&utf8_str, utf8_len_in));

    RESULT_GUARD_POSIX(s2n_cert_get_utf8_string_from_extension_data(input_der->data, input_der->size, utf8_str.data, &utf8_str.size));

    RESULT_ENSURE_EQ(utf8_str.size, expected_utf8_len);
    RESULT_ENSURE_EQ(memcmp(utf8_str.data, expected_utf8_str, utf8_str.size), 0);

    RESULT_GUARD_POSIX(s2n_free(&utf8_str));
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const uint8_t ocsp_data[] = "ocsp data";

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    /* Test s2n_cert_chain_and_key_new */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = s2n_cert_chain_and_key_new(),
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_NOT_NULL(chain);

        /* Sanity check some fields */
        EXPECT_NOT_NULL(chain->cert_chain);
        EXPECT_NOT_NULL(chain->private_key);
        EXPECT_NOT_NULL(chain->cn_names);
        EXPECT_NOT_NULL(chain->san_names);
        EXPECT_EQUAL(chain->cert_chain->chain_size, 0);
        EXPECT_NULL(chain->cert_chain->head);
        EXPECT_NULL(chain->private_key->pkey);
        EXPECT_NULL(chain->private_key->sign);
        EXPECT_NULL(chain->context);
    };

    /* Test s2n_cert_chain_and_key_load_public_pem_bytes */
    {
        uint32_t pem_len = 0;
        uint8_t pem[S2N_CERT_DER_SIZE] = { 0 };
        EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, pem, &pem_len, sizeof(pem)));

        /* Load only a public certificate */
        struct s2n_cert_chain_and_key *cert_only_chain = s2n_cert_chain_and_key_new();
        EXPECT_NOT_NULL(cert_only_chain);
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_public_pem_bytes(cert_only_chain, pem, pem_len));
        EXPECT_FAILURE(s2n_pkey_check_key_exists(cert_only_chain->private_key));

        /* Add cert chain to config */
        struct s2n_config *config = s2n_config_new();
        EXPECT_FALSE(config->no_signing_key);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, cert_only_chain));
        EXPECT_TRUE(config->no_signing_key);

        /* Add config to connection */
        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_config(conn, config), S2N_ERR_NO_PRIVATE_KEY);
        EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(config, s2n_noop_async_pkey_fn));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        EXPECT_SUCCESS(s2n_connection_free(conn));
        EXPECT_SUCCESS(s2n_config_free(config));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(cert_only_chain));
    };

    /* Test s2n_cert_chain_get_length */
    {
        uint32_t length = 0;

        /* Safety checks */
        {
            EXPECT_FAILURE_WITH_ERRNO(s2n_cert_chain_get_length(NULL, &length), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_cert_chain_get_length(chain_and_key, NULL), S2N_ERR_NULL);
        };

        /* Test success case */
        EXPECT_SUCCESS(s2n_cert_chain_get_length(chain_and_key, &length));
        EXPECT_EQUAL(length, S2N_DEFAULT_TEST_CERT_CHAIN_LENGTH);
    };

    /* Test s2n_cert_chain_get_cert */
    {
        struct s2n_cert *out_cert = NULL;
        uint32_t cert_idx = 0;

        /* Safety checks */
        {
            EXPECT_FAILURE_WITH_ERRNO(s2n_cert_chain_get_cert(NULL, &out_cert, cert_idx), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_cert_chain_get_cert(chain_and_key, NULL, cert_idx), S2N_ERR_NULL);
        };

        struct s2n_cert *cur_cert = chain_and_key->cert_chain->head;

        /* Test error case for invalid cert_idx, the valid range of cert_idx is 0 to cert_chain_length - 1 */
        cert_idx = S2N_DEFAULT_TEST_CERT_CHAIN_LENGTH;
        EXPECT_FAILURE_WITH_ERRNO(s2n_cert_chain_get_cert(chain_and_key, &out_cert, cert_idx), S2N_ERR_NO_CERT_FOUND);

        /* Test success case */
        for (size_t i = 0; i < S2N_DEFAULT_TEST_CERT_CHAIN_LENGTH; i++) {
            EXPECT_SUCCESS(s2n_cert_chain_get_cert(chain_and_key, &out_cert, i));
            EXPECT_NOT_NULL(cur_cert);
            EXPECT_EQUAL(out_cert, cur_cert);
            cur_cert = cur_cert->next;
        }
    };

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
        };

        EXPECT_SUCCESS(s2n_cert_get_der(cert, &out_cert_der, &cert_len));
        EXPECT_EQUAL(cert_len, cert->raw.size);
        EXPECT_BYTEARRAY_EQUAL(out_cert_der, cert->raw.data, cert_len);
    };

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
        struct host_verify_data verify_data = { .allow = 1, .callback_invoked = 0 };
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
        EXPECT_SUCCESS(s2n_config_set_check_stapled_ocsp_response(config_with_x509_verification, false));

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

            /* Safety checks */
            {
                DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = s2n_cert_chain_and_key_new(),
                        s2n_cert_chain_and_key_ptr_free);
                EXPECT_NOT_NULL(chain);
                EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_peer_cert_chain(NULL, chain), S2N_ERR_NULL);
                EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_peer_cert_chain(server_conn, NULL), S2N_ERR_NULL);
            }

            /* Input certificate chain is not empty */
            {
                DEFER_CLEANUP(struct s2n_cert_chain_and_key *input = NULL, s2n_cert_chain_and_key_ptr_free);
                EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&input,
                        S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
                EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_peer_cert_chain(server_conn, input),
                        S2N_ERR_INVALID_ARGUMENT);

                /* Validate that the original cert chain was not modified */
                EXPECT_NOT_NULL(input->cert_chain);
                EXPECT_NOT_NULL(input->cert_chain->head);
                EXPECT_EQUAL(input->cert_chain->head->pkey_type, S2N_PKEY_TYPE_ECDSA);
            }

            /* x509 verification is skipped on client side */
            {
                DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = s2n_cert_chain_and_key_new(),
                        s2n_cert_chain_and_key_ptr_free);
                EXPECT_NOT_NULL(chain);
                EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_peer_cert_chain(client_conn, chain),
                        S2N_ERR_CERT_NOT_VALIDATED);
            }

            EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

            /* Clean-up */
            EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
            EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        };

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
        };

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
        };

        /* Test s2n_connection_get_peer_cert_chain with OCSP */
        if (s2n_x509_ocsp_stapling_supported()) {
            EXPECT_SUCCESS(s2n_cert_chain_and_key_set_ocsp_data(s2n_chain_and_key,
                    ocsp_data, s2n_array_len(ocsp_data)));
            EXPECT_SUCCESS(s2n_config_set_status_request_type(config_with_x509_verification, S2N_STATUS_REQUEST_OCSP));

            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config_skip_x509_verification));
            EXPECT_EQUAL(server_conn->x509_validator.skip_cert_validation, 1);

            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config_with_x509_verification));
            EXPECT_EQUAL(client_conn->x509_validator.skip_cert_validation, 0);

            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Negotiate handshake */
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_EQUAL(client_conn->x509_validator.state, OCSP_VALIDATED);

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
    };

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
            { .oid = "X509v3 Subject Key Identifier",
                    .expected_der = subject_key_id_blob,
                    .critical = false },
            { .oid = "X509v3 Authority Key Identifier",
                    .expected_der = authority_key_id_blob,
                    .critical = false },
            { .oid = "X509v3 Basic Constraints",
                    .expected_der = basic_constraints_blob,
                    .critical = true },
            { .oid = "X509v3 Key Usage",
                    .expected_der = key_usage_blob,
                    .critical = true },
            { .oid = "1.2.3.4.5.6.7890.1.2.100.1",
                    .expected_utf8 = "keyid:36:61:3F:1B:02:C7:12:2B:53:0A:22:BA:58:B6:A8:80:19:EE:51:85",
                    .expected_der = custom_oid_1_blob,
                    .critical = false },
            { .oid = "1.2.3.4.5.6.7890.1.2.100.2",
                    .expected_utf8 = "IP Address:12.345.67.890",
                    .expected_der = custom_oid_2_blob,
                    .critical = false },
            { .oid = "1.2.3.4.5.6.7890.1.2.100.3",
                    .expected_utf8 = "DNS:12.345.67.890.auto.pdx.ec2.substrate",
                    .expected_der = custom_oid_3_blob,
                    .critical = false },
            { .oid = "1.2.3.4.5.6.7890.1.2.100",
                    .critical = false },
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
            };

            /* Test success cases */
            for (i = 0; i < s2n_array_len(test_cases) - 1; i++) {
                EXPECT_SUCCESS(s2n_cert_get_x509_extension_value_length(cert, (const uint8_t *) test_cases[i].oid, &test_cases[i].ext_value_len));
                EXPECT_EQUAL(test_cases[i].ext_value_len, test_cases[i].expected_der.size);
            }

            /* Test failure case for invalid X509 extension OID */
            {
                size_t invalid_test_case = s2n_array_len(test_cases) - 1;
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_x509_extension_value_length(cert, (const uint8_t *) test_cases[invalid_test_case].oid,
                                                  &test_cases[i].ext_value_len),
                        S2N_ERR_X509_EXTENSION_VALUE_NOT_FOUND);
            };
        };

        /* Test s2n_cert_get_x509_extension_value */
        {
            /* Safety checks */
            {
                const uint8_t oid[] = "Example X509 extension OID";
                EXPECT_SUCCESS(s2n_alloc(&ext_value, ext_value_MAX_LEN));

                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_x509_extension_value(NULL, oid,
                                                  ext_value.data, &ext_value.size, &critical),
                        S2N_ERR_NULL);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_x509_extension_value(cert, NULL,
                                                  ext_value.data, &ext_value.size, &critical),
                        S2N_ERR_NULL);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_x509_extension_value(cert, oid,
                                                  NULL, &ext_value.size, &critical),
                        S2N_ERR_NULL);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_x509_extension_value(cert, oid,
                                                  ext_value.data, NULL, &critical),
                        S2N_ERR_NULL);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_x509_extension_value(cert, oid,
                                                  ext_value.data, &ext_value.size, NULL),
                        S2N_ERR_NULL);

                EXPECT_SUCCESS(s2n_free(&ext_value));
            };

            /* Test success cases for s2n_cert_get_x509_extension_value */
            for (i = 0; i < s2n_array_len(test_cases) - 1; i++) {
                EXPECT_SUCCESS(s2n_alloc(&test_cases[i].returned_der, test_cases[i].ext_value_len));
                EXPECT_SUCCESS(s2n_cert_get_x509_extension_value(cert, (const uint8_t *) test_cases[i].oid,
                        test_cases[i].returned_der.data,
                        &test_cases[i].returned_der.size, &critical));
                EXPECT_BYTEARRAY_EQUAL(test_cases[i].returned_der.data, test_cases[i].expected_der.data, test_cases[i].expected_der.size);
                EXPECT_EQUAL(critical, test_cases[i].critical);
            }

            /* Test failure case for insufficient amount of memory allocated */
            {
                size_t insuf_test_case = 0;
                EXPECT_SUCCESS(s2n_alloc(&ext_value, test_cases[insuf_test_case].returned_der.size - OFFSET_INSUFFICIENT_MEM_SIZE));
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_x509_extension_value(cert, (const uint8_t *) test_cases[insuf_test_case].oid,
                                                  ext_value.data, &ext_value.size, &critical),
                        S2N_ERR_INSUFFICIENT_MEM_SIZE);
                EXPECT_SUCCESS(s2n_free(&ext_value));
            };

            /* Test failure case for invalid X509 extension OID */
            {
                size_t invalid_test_case = s2n_array_len(test_cases) - 1;
                EXPECT_SUCCESS(s2n_alloc(&test_cases[invalid_test_case].returned_der, ext_value_MAX_LEN));
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_x509_extension_value(cert, (const uint8_t *) test_cases[invalid_test_case].oid,
                                                  test_cases[invalid_test_case].returned_der.data,
                                                  &test_cases[invalid_test_case].returned_der.size, &critical),
                        S2N_ERR_X509_EXTENSION_VALUE_NOT_FOUND);
            };
        };

        /* Test s2n_cert_get_utf8_string_from_extension_data_length */
        {
            /* Safety checks */
            {
                const uint8_t der_ext_value[] = "DER encoded X509 extension value";
                size_t der_ext_value_len = strlen((const char *) der_ext_value);
                uint32_t utf8_len = 0;

                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_utf8_string_from_extension_data_length(NULL, der_ext_value_len, &utf8_len), S2N_ERR_NULL);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_utf8_string_from_extension_data_length(der_ext_value, 0, &utf8_len), S2N_ERR_SAFETY);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_utf8_string_from_extension_data_length(der_ext_value, der_ext_value_len, 0), S2N_ERR_NULL);
            };

            /* Test success and failure cases */
            for (i = 0; i < s2n_array_len(test_cases) - 1; i++) {
                if (i > 3) {
                    EXPECT_SUCCESS(s2n_cert_get_utf8_string_from_extension_data_length(test_cases[i].returned_der.data,
                            test_cases[i].returned_der.size,
                            &test_cases[i].utf8_len));
                    EXPECT_EQUAL(test_cases[i].utf8_len, strlen((const char *) test_cases[i].expected_utf8));
                } else {
                    EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_utf8_string_from_extension_data_length(
                                                      test_cases[i].returned_der.data,
                                                      test_cases[i].returned_der.size,
                                                      &test_cases[i].utf8_len),
                            S2N_ERR_INVALID_X509_EXTENSION_TYPE);
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
            };
        };

        /* Test s2n_cert_get_utf8_string_from_extension_data */
        {
            /* Safety checks */
            {
                const uint8_t der_ext_value[] = "DER encoded X509 extension value";
                size_t der_ext_value_len = strlen((const char *) der_ext_value);
                EXPECT_SUCCESS(s2n_alloc(&utf8_str, ext_value_MAX_LEN));

                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_utf8_string_from_extension_data(NULL, der_ext_value_len, utf8_str.data,
                                                  &utf8_str.size),
                        S2N_ERR_NULL);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_utf8_string_from_extension_data(der_ext_value, 0, utf8_str.data,
                                                  &utf8_str.size),
                        S2N_ERR_SAFETY);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_utf8_string_from_extension_data(der_ext_value, der_ext_value_len, NULL,
                                                  &utf8_str.size),
                        S2N_ERR_NULL);
                EXPECT_FAILURE_WITH_ERRNO(s2n_cert_get_utf8_string_from_extension_data(der_ext_value, der_ext_value_len,
                                                  utf8_str.data, NULL),
                        S2N_ERR_NULL);

                EXPECT_SUCCESS(s2n_free(&utf8_str));
            };

            /* Test success and failure cases for s2n_cert_get_utf8_string_from_extension_data */
            for (i = 0; i < s2n_array_len(test_cases) - 1; i++) {
                if (i > 3) {
                    EXPECT_OK(s2n_compare_utf8_strings(&test_cases[i].returned_der, test_cases[i].expected_utf8,
                            test_cases[i].utf8_len, strlen((const char *) test_cases[i].expected_utf8)));
                } else {
                    EXPECT_ERROR_WITH_ERRNO(s2n_compare_utf8_strings(
                                                    &test_cases[i].returned_der, (const char *) test_cases[i].expected_der.data, ext_value_MAX_LEN,
                                                    test_cases[i].expected_der.size),
                            S2N_ERR_INVALID_X509_EXTENSION_TYPE);
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
            };
        };

        /* Cleanup */
        for (i = 0; i < s2n_array_len(test_cases); i++) {
            EXPECT_SUCCESS(s2n_free(&test_cases[i].returned_der));
        }
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(custom_cert_chain));
    };

    /* Test s2n_connection_get_client_cert_chain */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_set_client_auth_type(config, S2N_CERT_AUTH_REQUIRED));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config, always_verify_host_fn, NULL));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, NULL));

        DEFER_CLEANUP(struct s2n_connection *tls12_client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *tls12_server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *tls13_client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *tls13_server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);

        /* Should error before the handshake is performed.
         * This method is intended to be called after the handshake is complete and requires
         * state set during the handshake.
         */
        {
            uint8_t *output = NULL;
            uint32_t output_len = 0;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_client_cert_chain(tls12_server_conn, &output, &output_len),
                    S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_client_cert_chain(tls13_server_conn, &output, &output_len),
                    S2N_ERR_NULL);
            EXPECT_NULL(output);
            EXPECT_EQUAL(output_len, 0);
        };

        /* Perform TLS1.2 handshake and verify cert chain is available */
        {
            EXPECT_SUCCESS(s2n_connection_set_config(tls12_client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_config(tls12_server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(tls12_client_conn, "test_all_tls12"));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(tls12_server_conn, "test_all_tls12"));

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(tls12_client_conn, tls12_server_conn, &io_pair));
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(tls12_server_conn, tls12_client_conn));

            EXPECT_EQUAL(tls12_server_conn->actual_protocol_version, S2N_TLS12);
            EXPECT_NOT_NULL(tls12_server_conn->handshake_params.client_cert_chain.data);
            EXPECT_NOT_EQUAL(tls12_server_conn->handshake_params.client_cert_chain.size, 0);
        };

        /* Perform TLS1.3 handshake and verify cert chain is available.
         *
         * The TLS1.3 handshake is only possible if TLS1.3 is fully supported because of client auth:
         * the server doesn't know whether the client will offer a RSA-PSS certificate or not.
         */
        if (s2n_is_tls13_fully_supported()) {
            EXPECT_SUCCESS(s2n_connection_set_config(tls13_client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_config(tls13_server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(tls13_client_conn, "default_tls13"));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(tls13_server_conn, "default_tls13"));

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(tls13_client_conn, tls13_server_conn, &io_pair));
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(tls13_server_conn, tls13_client_conn));

            EXPECT_EQUAL(tls13_server_conn->actual_protocol_version, S2N_TLS13);
            EXPECT_NOT_NULL(tls13_server_conn->handshake_params.client_cert_chain.data);
            EXPECT_NOT_EQUAL(tls13_server_conn->handshake_params.client_cert_chain.size, 0);
        };

        /* Should error if called by client */
        {
            uint8_t *output = NULL;
            uint32_t output_len = 0;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_client_cert_chain(tls12_client_conn, &output, &output_len),
                    S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_client_cert_chain(tls13_client_conn, &output, &output_len),
                    S2N_ERR_NULL);
            EXPECT_NULL(output);
            EXPECT_EQUAL(output_len, 0);
        };

        /* Should produce same result for TLS1.2 and TLS1.3
         * (Both connections used the same certificate chain for the handshake)
         */
        if (s2n_is_tls13_fully_supported()) {
            uint8_t *tls12_output = NULL;
            uint32_t tls12_output_len = 0;
            EXPECT_SUCCESS(s2n_connection_get_client_cert_chain(tls12_server_conn, &tls12_output, &tls12_output_len));

            uint8_t *tls13_output = NULL;
            uint32_t tls13_output_len = 0;
            EXPECT_SUCCESS(s2n_connection_get_client_cert_chain(tls13_server_conn, &tls13_output, &tls13_output_len));

            EXPECT_EQUAL(tls12_output_len, tls13_output_len);
            EXPECT_BYTEARRAY_EQUAL(tls12_output, tls13_output, tls13_output_len);
        };

        /* Test: Certificate that skips validation still available */
        {
            DEFER_CLEANUP(struct s2n_config *unsafe_config = s2n_config_new(),
                    s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_set_client_auth_type(unsafe_config, S2N_CERT_AUTH_REQUIRED));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(unsafe_config, chain_and_key));

            /* Disable certificate verification */
            EXPECT_SUCCESS(s2n_config_disable_x509_verification(unsafe_config));

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client, unsafe_config));

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(server, unsafe_config));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server, client));
            EXPECT_NOT_EQUAL(server->handshake_params.client_cert_chain.size, 0);
            EXPECT_NOT_NULL(server->handshake_params.client_cert_chain.data);
        };

        /* Test: Certificate that fails validation still available */
        {
            DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(),
                    s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_set_client_auth_type(client_config, S2N_CERT_AUTH_REQUIRED));
            EXPECT_SUCCESS(s2n_config_set_verify_host_callback(client_config, always_verify_host_fn, NULL));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, chain_and_key));

            DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(),
                    s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_set_client_auth_type(server_config, S2N_CERT_AUTH_REQUIRED));
            EXPECT_SUCCESS(s2n_config_set_verify_host_callback(server_config, always_verify_host_fn, NULL));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));

            /* Disable client verification of the server cert.
             * Do not disable server verification of the client cert, but also
             * don't provide any trust store to successfully perform the verification.
             */
            EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));

            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_blinding(client, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));
            EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client, server, &io_pair));

            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server, client),
                    S2N_ERR_CERT_UNTRUSTED);
            /* Both the client and server could produce S2N_ERR_CERT_UNTRUSTED.
             * Verify that only the server encountered an error and therefore only
             * the server closed the connection.
             */
            EXPECT_TRUE(s2n_connection_check_io_status(server, S2N_IO_CLOSED));
            EXPECT_FALSE(s2n_connection_check_io_status(client, S2N_IO_CLOSED));

            EXPECT_NOT_EQUAL(server->handshake_params.client_cert_chain.size, 0);
            EXPECT_NOT_NULL(server->handshake_params.client_cert_chain.data);
        };

        /* Test: Certificate that fails parsing is still available in TLS1.2 */
        {
            DEFER_CLEANUP(struct s2n_stuffer input, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));

            /* Generate a completely malformed certificate chain, with no
             * properly formed certificates.
             *
             * We don't parse pre-TLS1.3 chains before storing them, so don't
             * care whether or not they're malformed.
             */
            const uint32_t chain_size = 24;
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&input, chain_size));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&input, chain_size));

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            server->actual_protocol_version = S2N_TLS12;
            EXPECT_SUCCESS(s2n_stuffer_copy(&input, &server->handshake.io,
                    s2n_stuffer_data_available(&input)));

            EXPECT_FAILURE_WITH_ERRNO(s2n_client_cert_recv(server), S2N_ERR_CERT_INVALID);
            EXPECT_NOT_EQUAL(server->handshake_params.client_cert_chain.size, 0);
            EXPECT_NOT_NULL(server->handshake_params.client_cert_chain.data);
        };

        /* Test: Certificate that fails parsing is not available in TLS1.3 */
        {
            DEFER_CLEANUP(struct s2n_stuffer input, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));

            /* Since it's TLS1.3, we also need a zero-length request context */
            EXPECT_SUCCESS(s2n_stuffer_write_uint8(&input, 0));

            /* Generate a well-formed certificate chain.
             *
             * Unlike in TLS1.2, in TLS1.3 we must parse chains before storing
             * them to remove the per-certificate TLS extension lists. Chains
             * we cannot parse should not be stored.
             *
             * We could generate a completely invalid chain to test this case,
             * like we do for TLS1.2. However, we want to ensure that a partially
             * parsed chain is not partially stored. To do that, we need to
             * generated a partially correct chain.
             *
             * We start with a completely parseable chain and then modify it
             * to create a malformed chain.
             */
            struct s2n_stuffer_reservation total_size = { 0 };
            const uint32_t cert_size = 24, extensions_size = 20;
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint24(&input, &total_size));
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&input, cert_size));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&input, cert_size));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&input, extensions_size));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&input, extensions_size));
            EXPECT_SUCCESS(s2n_stuffer_write_uint24(&input, cert_size));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&input, cert_size));
            EXPECT_SUCCESS(s2n_stuffer_write_uint16(&input, extensions_size));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&input, extensions_size));
            EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&total_size));

            /* Validate that the certificate chain we generated is parseable.
             * The chain will still ultimately fail validation, but it will be
             * parsed and stored on the connection.
             */
            {
                DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                        s2n_connection_ptr_free);
                server->actual_protocol_version = S2N_TLS13;
                EXPECT_SUCCESS(s2n_stuffer_copy(&input, &server->handshake.io,
                        s2n_stuffer_data_available(&input)));

                EXPECT_FAILURE_WITH_ERRNO(s2n_client_cert_recv(server), S2N_ERR_CERT_INVALID);
                EXPECT_NOT_EQUAL(server->handshake_params.client_cert_chain.size, 0);
                EXPECT_NOT_NULL(server->handshake_params.client_cert_chain.data);
            }

            /* Modify the last certificate's TLS extension list to be malformed.
             *
             * We want the parsing error to occur as late as possible (on the last
             * extension list) to test that the cert chain is not partially stored.
             */
            EXPECT_SUCCESS(s2n_stuffer_reread(&input));
            EXPECT_SUCCESS(s2n_stuffer_wipe_n(&input, 1));
            EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&total_size));

            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            server->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_stuffer_copy(&input, &server->handshake.io,
                    s2n_stuffer_data_available(&input)));

            /* Assert that no part of the certificate chain is stored */
            EXPECT_FAILURE_WITH_ERRNO(s2n_client_cert_recv(server), S2N_ERR_BAD_MESSAGE);
            EXPECT_EQUAL(server->handshake_params.client_cert_chain.size, 0);
            EXPECT_NULL(server->handshake_params.client_cert_chain.data);
        };
    };

    /* Test s2n_cert_chain_and_key_set_ocsp_data */
    {
        uint8_t more_ocsp_data[] = "more ocsp data";

        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

        /* Safety checks */
        EXPECT_FAILURE(s2n_cert_chain_and_key_set_ocsp_data(NULL, ocsp_data, sizeof(ocsp_data)));

        /* Set ocsp data */
        EXPECT_SUCCESS(s2n_cert_chain_and_key_set_ocsp_data(chain, ocsp_data, sizeof(ocsp_data)));
        EXPECT_EQUAL(chain->ocsp_status.size, sizeof(ocsp_data));
        EXPECT_BYTEARRAY_EQUAL(chain->ocsp_status.data, ocsp_data, sizeof(ocsp_data));

        /* Change oscp data */
        EXPECT_SUCCESS(s2n_cert_chain_and_key_set_ocsp_data(chain, more_ocsp_data, sizeof(more_ocsp_data)));
        EXPECT_EQUAL(chain->ocsp_status.size, sizeof(more_ocsp_data));
        EXPECT_BYTEARRAY_EQUAL(chain->ocsp_status.data, more_ocsp_data, sizeof(more_ocsp_data));

        /* Free ocsp data */
        EXPECT_SUCCESS(s2n_cert_chain_and_key_set_ocsp_data(chain, NULL, 0));
        EXPECT_EQUAL(chain->ocsp_status.size, 0);

        /* Set ocsp data again */
        EXPECT_SUCCESS(s2n_cert_chain_and_key_set_ocsp_data(chain, ocsp_data, sizeof(ocsp_data)));
        EXPECT_EQUAL(chain->ocsp_status.size, sizeof(ocsp_data));
        EXPECT_BYTEARRAY_EQUAL(chain->ocsp_status.data, ocsp_data, sizeof(ocsp_data));
    };

    /* Test s2n_cert_chain_and_key_set_sct_list */
    {
        uint8_t sct_list[] = "sct list";
        uint8_t other_sct_list[] = "other sct list";

        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

        /* Safety checks */
        EXPECT_FAILURE(s2n_cert_chain_and_key_set_sct_list(NULL, sct_list, sizeof(sct_list)));

        /* Set sct list */
        EXPECT_SUCCESS(s2n_cert_chain_and_key_set_sct_list(chain, sct_list, sizeof(sct_list)));
        EXPECT_EQUAL(chain->sct_list.size, sizeof(sct_list));
        EXPECT_BYTEARRAY_EQUAL(chain->sct_list.data, sct_list, sizeof(sct_list));

        /* Change sct list */
        EXPECT_SUCCESS(s2n_cert_chain_and_key_set_sct_list(chain, other_sct_list, sizeof(other_sct_list)));
        EXPECT_EQUAL(chain->sct_list.size, sizeof(other_sct_list));
        EXPECT_BYTEARRAY_EQUAL(chain->sct_list.data, other_sct_list, sizeof(other_sct_list));

        /* Free sct list */
        EXPECT_SUCCESS(s2n_cert_chain_and_key_set_sct_list(chain, NULL, 0));
        EXPECT_EQUAL(chain->sct_list.size, 0);

        /* Set sct list again */
        EXPECT_SUCCESS(s2n_cert_chain_and_key_set_sct_list(chain, sct_list, sizeof(sct_list)));
        EXPECT_EQUAL(chain->sct_list.size, sizeof(sct_list));
        EXPECT_BYTEARRAY_EQUAL(chain->sct_list.data, sct_list, sizeof(sct_list));
    };

    /* Test s2n_cert_chain_and_key_load_cns */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL,
                s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain,
                S2N_DEFAULT_TEST_CERT_CHAIN,
                S2N_DEFAULT_TEST_PRIVATE_KEY));
        POSIX_ENSURE_REF(chain->cert_chain);

        struct s2n_cert *head = chain->cert_chain->head;
        POSIX_ENSURE_REF(head);

        struct s2n_blob *leaf_bytes = &head->raw;
        const unsigned char *leaf_der = leaf_bytes->data;
        EXPECT_NOT_NULL(leaf_der);

        DEFER_CLEANUP(X509 *cert = NULL, X509_free_pointer);
        cert = d2i_X509(NULL, &leaf_der, leaf_bytes->size);
        EXPECT_NOT_NULL(cert);

        DEFER_CLEANUP(X509_NAME *x509_name = NULL, X509_NAME_free_pointer);
        x509_name = X509_NAME_new();
        EXPECT_NOT_NULL(x509_name);

        /* We start with one CN name already */
        uint32_t len = 0;
        EXPECT_OK(s2n_array_num_elements(chain->cn_names, &len));
        EXPECT_EQUAL(len, 1);

        /* Try loading a zero length CN name */
        EXPECT_SUCCESS(X509_NAME_add_entry_by_NID(x509_name, NID_commonName, V_ASN1_IA5STRING,
                (unsigned char *) (uintptr_t) "", -1, -1, 1));
        EXPECT_EQUAL(X509_set_subject_name(cert, x509_name), 1);
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_cns(chain, cert));

        /* No CN name has been added */
        EXPECT_OK(s2n_array_num_elements(chain->cn_names, &len));
        EXPECT_EQUAL(len, 1);

        /* Try loading an invalid CN name */
        EXPECT_SUCCESS(X509_NAME_add_entry_by_NID(x509_name, NID_commonName, 29,
                (unsigned char *) (uintptr_t) "invalid", -1, -1, 1));
        EXPECT_EQUAL(X509_set_subject_name(cert, x509_name), 1);
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_cns(chain, cert));

        /* No CN name has been added */
        EXPECT_OK(s2n_array_num_elements(chain->cn_names, &len));
        EXPECT_EQUAL(len, 1);

        /* Add a valid CN name */
        EXPECT_SUCCESS(X509_NAME_add_entry_by_NID(x509_name, NID_commonName, V_ASN1_IA5STRING,
                (unsigned char *) (uintptr_t) "valid", -1, -1, 1));
        EXPECT_EQUAL(X509_set_subject_name(cert, x509_name), 1);
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_cns(chain, cert));

        /* 1 more CN name has been added */
        EXPECT_OK(s2n_array_num_elements(chain->cn_names, &len));
        EXPECT_EQUAL(len, 2);
    };

    END_TEST();
}
