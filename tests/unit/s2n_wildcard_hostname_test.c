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

#include <stdio.h>
#include <string.h>

#include "api/s2n.h"
#include "crypto/s2n_certificate.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_safety.h"

struct wildcardify_test_case {
    const char *hostname;
    const char *output;
};

struct wildcardify_test_case wildcardify_test_cases[] = {
    { .hostname = "foo.bar.com", .output = "*.bar.com" },
    { .hostname = "localhost", .output = NULL },
    { .hostname = "one.com", .output = "*.com" },
    { .hostname = "foo*.bar*.com*", .output = "*.bar*.com*" },
    { .hostname = "foo.bar.com.", .output = "*.bar.com." },
    { .hostname = "*.a.c", .output = "*.a.c" },
    { .hostname = "*", .output = NULL },
    { .hostname = "foo.", .output = "*." },
};

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const int num_wildcardify_tests = s2n_array_len(wildcardify_test_cases);
    for (size_t i = 0; i < num_wildcardify_tests; i++) {
        const char *hostname = wildcardify_test_cases[i].hostname;
        struct s2n_blob hostname_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&hostname_blob, (uint8_t *) (uintptr_t) hostname, strlen(hostname)));
        uint8_t output[S2N_MAX_SERVER_NAME] = { 0 };
        struct s2n_blob output_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&output_blob, (uint8_t *) (uintptr_t) output, sizeof(output)));
        struct s2n_stuffer hostname_stuffer = { 0 };
        struct s2n_stuffer output_stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_init(&hostname_stuffer, &hostname_blob));
        EXPECT_SUCCESS(s2n_stuffer_skip_write(&hostname_stuffer, hostname_blob.size));
        EXPECT_SUCCESS(s2n_stuffer_init(&output_stuffer, &output_blob));
        EXPECT_SUCCESS(s2n_create_wildcard_hostname(&hostname_stuffer, &output_stuffer));

        /* Make sure the wildcard generated matches the output we expect. */
        const uint32_t wildcard_len = s2n_stuffer_data_available(&output_stuffer);
        const char *expected_output = wildcardify_test_cases[i].output;
        if (wildcard_len > 0) {
            EXPECT_EQUAL(wildcard_len, strlen(expected_output));
            EXPECT_SUCCESS(memcmp(output, expected_output, wildcard_len));
        } else {
            EXPECT_EQUAL(expected_output, NULL);
        }
    }

    /* s2n_connection_get_certificate_match */
    {
        /* Safety checks */
        {
            s2n_cert_sni_match match_status = 0;
            struct s2n_connection *conn = NULL;
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_certificate_match(NULL, &match_status),
                    S2N_ERR_NULL);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_certificate_match(conn, NULL),
                    S2N_ERR_NULL);

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_certificate_match(client_conn, &match_status),
                    S2N_ERR_CLIENT_MODE);
        }

        /* Client did not send SNI extension */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                    s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                    S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));
            EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
            EXPECT_OK(s2n_connections_set_io_stuffer_pair(server_conn, client_conn, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_NULL(s2n_get_server_name(server_conn));

            s2n_cert_sni_match match_status = 0;
            EXPECT_SUCCESS(s2n_connection_get_certificate_match(server_conn, &match_status));
            EXPECT_EQUAL(match_status, S2N_SNI_NONE);
        }

        /* Server had a certificate that matched the client's SNI extension */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                    s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                    S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));
            EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
            EXPECT_OK(s2n_connections_set_io_stuffer_pair(server_conn, client_conn, &io_pair));

            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_NOT_NULL(s2n_get_server_name(server_conn));

            s2n_cert_sni_match match_status = 0;
            EXPECT_SUCCESS(s2n_connection_get_certificate_match(server_conn, &match_status));
            EXPECT_EQUAL(match_status, S2N_SNI_EXACT_MATCH);
        }

        /* Server had a certificate with a domain name containing a wildcard character
         * that was able to be matched to the client's SNI extension */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                    s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                    S2N_RSA_2048_SHA256_WILDCARD_CERT, S2N_RSA_2048_SHA256_WILDCARD_KEY));
            EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
            EXPECT_OK(s2n_connections_set_io_stuffer_pair(server_conn, client_conn, &io_pair));

            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "alligator.localhost"));
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_NOT_NULL(s2n_get_server_name(server_conn));

            s2n_cert_sni_match match_status = 0;
            EXPECT_SUCCESS(s2n_connection_get_certificate_match(server_conn, &match_status));
            EXPECT_EQUAL(match_status, S2N_SNI_WILDCARD_MATCH);
        }

        /* Server did not have a certificate that could be matched to the client's
         * SNI extension. */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(server_conn);

            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL,
                    s2n_cert_chain_and_key_ptr_free);
            EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                    S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));
            EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
            EXPECT_OK(s2n_connections_set_io_stuffer_pair(server_conn, client_conn, &io_pair));

            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "This cert name is unlikely to exist."));
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                    S2N_ERR_CERT_UNTRUSTED);
            EXPECT_NOT_NULL(s2n_get_server_name(server_conn));

            s2n_cert_sni_match match_status = 0;
            EXPECT_SUCCESS(s2n_connection_get_certificate_match(server_conn, &match_status));
            EXPECT_EQUAL(match_status, S2N_SNI_NO_MATCH);
        }
    }

    END_TEST();
}
