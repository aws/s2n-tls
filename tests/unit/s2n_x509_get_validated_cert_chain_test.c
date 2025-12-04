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

#include "crypto/s2n_libcrypto.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_x509_validator.h"

bool s2n_libcrypto_supports_get0_chain()
{
#if S2N_LIBCRYPTO_SUPPORTS_GET0_CHAIN
    return true;
#else
    return false;
#endif
}

int main(int argc, char *argv[])
{
    BEGIN_TEST();

    /* Test the GET0_CHAIN feature probe. Modern libcryptos such as AWS-LC should support
     * X509_STORE_CTX_get0_chain().
     */
    if (s2n_libcrypto_is_awslc()) {
        EXPECT_TRUE(s2n_libcrypto_supports_get0_chain());
    }

    /* Test s2n_x509_validator_get_validated_cert_chain(). */
    {
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new_minimal(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        /* An error should be raised if there's no validated cert chain to get. */
        struct s2n_validated_cert_chain validated_cert_chain = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_x509_validator_get_validated_cert_chain(
                                        &client_conn->x509_validator, &validated_cert_chain),
                S2N_ERR_INVALID_CERT_STATE);
        EXPECT_NULL(validated_cert_chain.stack);

        /* Perform a handshake to validate a cert chain. */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Get and free the validated cert chain repeatedly. This ensures that the internal state
         * of the X509_STORE_CTX isn't accidentally freed.
         */
        for (size_t i = 0; i < 10; i++) {
            EXPECT_OK(s2n_x509_validator_get_validated_cert_chain(&client_conn->x509_validator, &validated_cert_chain));
            EXPECT_NOT_NULL(validated_cert_chain.stack);

            EXPECT_OK(s2n_x509_validator_validated_cert_chain_free(&validated_cert_chain));
            EXPECT_NULL(validated_cert_chain.stack);
        }
    }

    END_TEST();
}
