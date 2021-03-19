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

#include <openssl/crypto.h>
#if defined(OPENSSL_IS_AWSLC)
#include <openssl/mem.h>
#endif

struct host_verify_data {
    const char *name;
    uint8_t found_name;
    uint8_t callback_invoked;
};

uint32_t write_pem_file_to_stuffer_as_chain(struct s2n_stuffer *chain_out_stuffer, const char *pem_data, uint8_t protocol_version) {
    struct s2n_stuffer chain_in_stuffer = {0}, cert_stuffer = {0};
    s2n_stuffer_alloc_ro_from_string(&chain_in_stuffer, pem_data);
    s2n_stuffer_growable_alloc(&cert_stuffer, 4096);
    s2n_stuffer_growable_alloc(chain_out_stuffer, 4096);

    uint32_t chain_size = 0;
    do {
        s2n_stuffer_certificate_from_pem(&chain_in_stuffer, &cert_stuffer);
        uint32_t cert_len = s2n_stuffer_data_available(&cert_stuffer);
        uint8_t *raw_cert_data = s2n_stuffer_raw_read(&cert_stuffer, cert_len);

        if (cert_len) {
            struct s2n_blob cert_data = {.data = raw_cert_data, .size = cert_len};
            chain_size += cert_data.size + 3;
            s2n_stuffer_write_uint24(chain_out_stuffer, cert_data.size);
            s2n_stuffer_write(chain_out_stuffer, &cert_data);
            /* Add an extra uint8_t to represent 0 length certificate extensions in tls13 */
            if (protocol_version >= S2N_TLS13) {
                s2n_stuffer_write_uint16(chain_out_stuffer, 0);
                chain_size += 2;
            }
        }
    } while (s2n_stuffer_data_available(&chain_in_stuffer));

    s2n_stuffer_free(&cert_stuffer);
    s2n_stuffer_free(&chain_in_stuffer);
    return chain_size;
}

uint8_t verify_host_accept_everything(const char *host_name, size_t host_name_len, void *data) {
    struct host_verify_data *verify_data = (struct host_verify_data *) data;
    verify_data->callback_invoked = 1;
    return 1;
}

#define S2N_DEFAULT_TEST_CERT_CHAIN_LENGTH 3
#define S2N_CERT_DER_SIZE 2048

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
        /* Disable TLS 1.3 to work around cert validation setup as it is not required for the following tests. 
         * Note that for TLS1.3 Certificate extensions is a field https://tools.ietf.org/html/rfc8446#section-4.4.2 
         * and requires additional setup. */
        EXPECT_SUCCESS(s2n_disable_tls13());
        struct s2n_x509_trust_store trust_store = { 0 };
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_EQUAL(0, s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));
        struct host_verify_data verify_data = { .callback_invoked = 0, .found_name = 0, .name = NULL };
        uint8_t cert_chain_pem[S2N_MAX_TEST_PEM_SIZE];
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, (char *) cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        struct s2n_stuffer chain_stuffer =  { 0 };
        uint32_t chain_len = write_pem_file_to_stuffer_as_chain(&chain_stuffer, (const char *) cert_chain_pem, S2N_TLS12);
        EXPECT_TRUE(chain_len > 0);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, (uint32_t) chain_len);
        EXPECT_NOT_NULL(chain_data);

        /* Test s2n_connection_get_peer_cert_chain to fail when x509 validation is skipped */
        {
            struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(connection);
            EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

            struct s2n_pkey public_key_out = { 0 };
            EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
            s2n_pkey_type pkey_type = { 0 };

            s2n_x509_validator_wipe(&connection->x509_validator);
            EXPECT_SUCCESS(s2n_x509_validator_init(&connection->x509_validator, &trust_store, 1));
            connection->x509_validator.skip_cert_validation = 1;

            struct s2n_cert_chain_and_key *test_peer_chain = s2n_cert_chain_and_key_new();
            EXPECT_NOT_NULL(test_peer_chain);

            EXPECT_EQUAL(S2N_CERT_OK,
                        s2n_x509_validator_validate_cert_chain(&connection->x509_validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
            EXPECT_EQUAL(0, verify_data.callback_invoked);
            EXPECT_EQUAL(connection->x509_validator.state, INIT);

            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_peer_cert_chain(connection, test_peer_chain), S2N_ERR_CERT_NOT_VALIDATED);

            s2n_x509_validator_wipe(&connection->x509_validator);
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(test_peer_chain));
            EXPECT_SUCCESS(s2n_pkey_free(&public_key_out));
            EXPECT_SUCCESS(s2n_connection_free(connection));
        }

        /* Test s2n_connection_get_peer_cert_chain failure cases with error codes */
        {
            struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(connection);
            EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

            struct s2n_pkey public_key_out = { 0 };
            EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
            s2n_pkey_type pkey_type = { 0 };

            s2n_x509_validator_wipe(&connection->x509_validator);
            EXPECT_SUCCESS(s2n_x509_validator_init(&connection->x509_validator, &trust_store, 1));

            EXPECT_EQUAL(S2N_CERT_OK,
                        s2n_x509_validator_validate_cert_chain(&connection->x509_validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));

            /* Safety checks */
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_peer_cert_chain(NULL, chain_and_key), S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_peer_cert_chain(connection, NULL), S2N_ERR_NULL);

            /* Input certificate chain is not empty */
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_peer_cert_chain(connection, chain_and_key), S2N_ERR_INVALID_CERT_CHAIN);

            s2n_x509_validator_wipe(&connection->x509_validator);
            EXPECT_SUCCESS(s2n_pkey_free(&public_key_out));
            EXPECT_SUCCESS(s2n_connection_free(connection));
        }

        /* Test s2n_connection_get_peer_cert_chain success */
        {
            struct s2n_connection *connection = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(connection);
            EXPECT_SUCCESS(s2n_connection_set_verify_host_callback(connection, verify_host_accept_everything, &verify_data));

            struct s2n_pkey public_key_out = { 0 };
            EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key_out));
            s2n_pkey_type pkey_type = { 0 };

            s2n_x509_validator_wipe(&connection->x509_validator);
            EXPECT_SUCCESS(s2n_x509_validator_init(&connection->x509_validator, &trust_store, 1));

            struct s2n_cert_chain_and_key *test_peer_chain = s2n_cert_chain_and_key_new();
            EXPECT_NOT_NULL(test_peer_chain);

            EXPECT_EQUAL(S2N_CERT_OK,
                        s2n_x509_validator_validate_cert_chain(&connection->x509_validator, connection, chain_data, chain_len, &pkey_type, &public_key_out));
            EXPECT_EQUAL(1, verify_data.callback_invoked);
            EXPECT_EQUAL(connection->x509_validator.state, VALIDATED);

            EXPECT_SUCCESS(s2n_connection_get_peer_cert_chain(connection, test_peer_chain));

            uint32_t cert_chain_length = 0;
            EXPECT_SUCCESS(s2n_get_cert_chain_length(test_peer_chain, &cert_chain_length));
            STACK_OF(X509) *cert_chain_validated = X509_STORE_CTX_get1_chain(connection->x509_validator.store_ctx);
            EXPECT_NOT_NULL(cert_chain_validated);
            EXPECT_EQUAL(cert_chain_length, sk_X509_num(cert_chain_validated));
            struct s2n_cert *cur_cert = NULL;

            for (size_t cert_idx = 0; cert_idx < cert_chain_length; cert_idx++) {
                X509 *cert = sk_X509_value(cert_chain_validated, cert_idx);
                EXPECT_NOT_NULL(cert);
                uint8_t *cert_data_from_validator = NULL;
                int cert_size_from_validator = i2d_X509(cert, &cert_data_from_validator);
                EXPECT_TRUE(cert_size_from_validator > 0 && cert_data_from_validator != NULL);

                EXPECT_SUCCESS(s2n_get_cert_from_cert_chain(test_peer_chain, &cur_cert, cert_idx));
                EXPECT_NOT_NULL(cur_cert);
                EXPECT_EQUAL(cert_size_from_validator, cur_cert->raw.size);
                EXPECT_BYTEARRAY_EQUAL(cert_data_from_validator, cur_cert->raw.data, cur_cert->raw.size);
                OPENSSL_free(cert_data_from_validator);
            }

            sk_X509_pop_free(cert_chain_validated, X509_free);
            s2n_x509_validator_wipe(&connection->x509_validator);
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(test_peer_chain));
            EXPECT_SUCCESS(s2n_pkey_free(&public_key_out));
            EXPECT_SUCCESS(s2n_connection_free(connection));
        }

        s2n_x509_trust_store_wipe(&trust_store);
        EXPECT_SUCCESS(s2n_stuffer_free(&chain_stuffer));
    }

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    END_TEST();
}
