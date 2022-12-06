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
#include "error/s2n_errno.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_extension_list.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

s2n_cert_public_key public_key;
s2n_pkey_type actual_cert_pkey_type;

static int s2n_skip_cert_chain_size(struct s2n_stuffer *stuffer)
{
    uint32_t cert_chain_size;
    POSIX_GUARD(s2n_stuffer_read_uint24(stuffer, &cert_chain_size));
    POSIX_ENSURE_EQ(cert_chain_size, s2n_stuffer_data_available(stuffer));
    return S2N_SUCCESS;
}

static int s2n_skip_cert(struct s2n_stuffer *stuffer)
{
    uint32_t cert_size;
    POSIX_GUARD(s2n_stuffer_read_uint24(stuffer, &cert_size));
    POSIX_GUARD(s2n_stuffer_skip_read(stuffer, cert_size));
    return S2N_SUCCESS;
}

static int s2n_x509_validator_validate_cert_chain_test(struct s2n_connection *conn, struct s2n_stuffer *stuffer)
{
    POSIX_GUARD(s2n_skip_cert_chain_size(stuffer));
    uint32_t cert_chain_size = s2n_stuffer_data_available(stuffer);

    uint8_t *cert_chain_data;
    POSIX_ENSURE_REF(cert_chain_data = s2n_stuffer_raw_read(stuffer, cert_chain_size));

    POSIX_GUARD_RESULT(s2n_x509_validator_validate_cert_chain(&conn->x509_validator, conn,
            cert_chain_data, cert_chain_size, &actual_cert_pkey_type, &public_key));

    POSIX_GUARD(s2n_pkey_free(&public_key));
    return S2N_SUCCESS;
}

static int s2n_write_test_cert(struct s2n_stuffer *stuffer, struct s2n_cert_chain_and_key *chain_and_key)
{
    struct s2n_blob *cert = &chain_and_key->cert_chain->head->raw;
    POSIX_GUARD(s2n_stuffer_write_uint24(stuffer, cert->size));
    POSIX_GUARD(s2n_stuffer_write_bytes(stuffer, cert->data, cert->size));
    return S2N_SUCCESS;
}

static int s2n_setup_connection_for_ocsp_validate_test(struct s2n_connection **conn, struct s2n_cert_chain_and_key *chain_and_key)
{
    struct s2n_connection *nconn;

    POSIX_ENSURE_REF(nconn = s2n_connection_new(S2N_SERVER));
    nconn->actual_protocol_version = S2N_TLS13;
    nconn->handshake_params.our_chain_and_key = chain_and_key;

    POSIX_GUARD(s2n_connection_allow_all_response_extensions(nconn));
    nconn->status_type = S2N_STATUS_REQUEST_OCSP;

    *conn = nconn;
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13_in_test());

    struct s2n_config *config;
    EXPECT_NOT_NULL(config = s2n_config_new());

    EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key));

    /* Initialize cert chain */
    struct s2n_cert_chain_and_key *chain_and_key;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

    /* Initialize cert extension data */
    uint8_t data[] = "extension data";
    EXPECT_SUCCESS(s2n_cert_chain_and_key_set_ocsp_data(chain_and_key, data, s2n_array_len(data)));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_set_sct_list(chain_and_key, data, s2n_array_len(data)));

    /* Test: s2n_send_cert_chain sends extensions */
    {
        /* Test: extensions only sent for >= TLS1.3 */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->handshake_params.our_chain_and_key = chain_and_key;

            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(conn));
            conn->status_type = S2N_STATUS_REQUEST_OCSP;

            /* TLS1.2 does NOT send extensions */
            {
                DEFER_CLEANUP(struct s2n_stuffer stuffer, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

                conn->actual_protocol_version = S2N_TLS12;
                EXPECT_SUCCESS(s2n_send_cert_chain(conn, &stuffer, chain_and_key));

                s2n_parsed_extensions_list extensions;
                EXPECT_SUCCESS(s2n_skip_cert_chain_size(&stuffer));
                EXPECT_SUCCESS(s2n_skip_cert(&stuffer));

                EXPECT_FAILURE_WITH_ERRNO(s2n_extension_list_parse(&stuffer, &extensions),
                        S2N_ERR_BAD_MESSAGE);
            };

            /* TLS1.3 DOES send extensions */
            {
                DEFER_CLEANUP(struct s2n_stuffer stuffer, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

                conn->actual_protocol_version = S2N_TLS13;
                EXPECT_SUCCESS(s2n_send_cert_chain(conn, &stuffer, chain_and_key));

                s2n_parsed_extensions_list extensions;
                EXPECT_SUCCESS(s2n_skip_cert_chain_size(&stuffer));
                EXPECT_SUCCESS(s2n_skip_cert(&stuffer));

                EXPECT_SUCCESS(s2n_extension_list_parse(&stuffer, &extensions));
                EXPECT_PARSED_EXTENSION_LIST_NOT_EMPTY(extensions);
            };

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test: extensions only sent on first certificate */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->handshake_params.our_chain_and_key = chain_and_key;

            DEFER_CLEANUP(struct s2n_stuffer stuffer, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(conn));
            conn->status_type = S2N_STATUS_REQUEST_OCSP;

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_SUCCESS(s2n_send_cert_chain(conn, &stuffer, chain_and_key));

            s2n_parsed_extensions_list extensions;
            EXPECT_SUCCESS(s2n_skip_cert_chain_size(&stuffer));

            /* First cert includes extensions */
            EXPECT_SUCCESS(s2n_skip_cert(&stuffer));
            EXPECT_SUCCESS(s2n_extension_list_parse(&stuffer, &extensions));
            EXPECT_PARSED_EXTENSION_LIST_NOT_EMPTY(extensions);

            /* Other certs do not include extensions */
            do {
                EXPECT_SUCCESS(s2n_skip_cert(&stuffer));
                EXPECT_SUCCESS(s2n_extension_list_parse(&stuffer, &extensions));
                EXPECT_PARSED_EXTENSION_LIST_EMPTY(extensions);
            } while (s2n_stuffer_data_available(&stuffer));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* Test: s2n_x509_validator_validate_cert_chain handles the output of s2n_send_cert_chain */
    {
        /* Test: with no extensions */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
            conn->handshake_params.our_chain_and_key = chain_and_key;

            DEFER_CLEANUP(struct s2n_stuffer stuffer, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            EXPECT_SUCCESS(s2n_send_cert_chain(conn, &stuffer, chain_and_key));
            EXPECT_SUCCESS(s2n_x509_validator_validate_cert_chain_test(conn, &stuffer));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Test: with extensions */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
            conn->actual_protocol_version = S2N_TLS13;
            conn->handshake_params.our_chain_and_key = chain_and_key;

            DEFER_CLEANUP(struct s2n_stuffer stuffer, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(conn));
            conn->status_type = S2N_STATUS_REQUEST_OCSP;
            conn->ct_level_requested = S2N_CT_SUPPORT_REQUEST;

            EXPECT_SUCCESS(s2n_send_cert_chain(conn, &stuffer, chain_and_key));
            EXPECT_SUCCESS(s2n_x509_validator_validate_cert_chain_test(conn, &stuffer));

            /* OCSP extension processed */
            EXPECT_EQUAL(conn->status_response.size, s2n_array_len(data));
            EXPECT_BYTEARRAY_EQUAL(conn->status_response.data, data, s2n_array_len(data));

            /* SCT extension processed */
            EXPECT_EQUAL(conn->ct_response.size, s2n_array_len(data));
            EXPECT_BYTEARRAY_EQUAL(conn->ct_response.data, data, s2n_array_len(data));

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    /* Test: s2n_x509_validator_validate_cert_chain receives extensions */
    {
        /* Test: extensions only processed for >= TLS1.3 */
        {
            struct s2n_connection *setup_conn;
            POSIX_GUARD(s2n_setup_connection_for_ocsp_validate_test(&setup_conn, chain_and_key));

            DEFER_CLEANUP(struct s2n_stuffer stuffer, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

            struct s2n_stuffer_reservation size = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_reserve_uint24(&stuffer, &size));
            EXPECT_SUCCESS(s2n_write_test_cert(&stuffer, chain_and_key));
            EXPECT_SUCCESS(s2n_extension_list_send(S2N_EXTENSION_LIST_CERTIFICATE, setup_conn, &stuffer));
            EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&size));

            /* TLS1.2 does NOT process extensions */
            {
                struct s2n_connection *conn;
                POSIX_GUARD(s2n_setup_connection_for_ocsp_validate_test(&conn, chain_and_key));

                EXPECT_SUCCESS(s2n_stuffer_reread(&stuffer));
                conn->actual_protocol_version = S2N_TLS12;

                EXPECT_FAILURE(s2n_x509_validator_validate_cert_chain_test(conn, &stuffer));

                EXPECT_EQUAL(conn->status_response.size, 0);
                EXPECT_EQUAL(conn->status_response.data, NULL);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            };

            /* TLS1.3 DOES process extensions */
            {
                struct s2n_connection *conn;
                POSIX_GUARD(s2n_setup_connection_for_ocsp_validate_test(&conn, chain_and_key));

                EXPECT_SUCCESS(s2n_stuffer_reread(&stuffer));
                conn->actual_protocol_version = S2N_TLS13;

                EXPECT_SUCCESS(s2n_x509_validator_validate_cert_chain_test(conn, &stuffer));

                EXPECT_EQUAL(conn->status_response.size, s2n_array_len(data));
                EXPECT_BYTEARRAY_EQUAL(conn->status_response.data, data, s2n_array_len(data));

                EXPECT_SUCCESS(s2n_connection_free(conn));
            };

            EXPECT_SUCCESS(s2n_connection_free(setup_conn));
        };

        /* Test: extensions only processed on first certificate */
        {
            struct s2n_stuffer_reservation size = { 0 };

            /* Extensions on second cert ignored */
            {
                struct s2n_connection *conn;
                POSIX_GUARD(s2n_setup_connection_for_ocsp_validate_test(&conn, chain_and_key));

                DEFER_CLEANUP(struct s2n_stuffer stuffer, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

                EXPECT_SUCCESS(s2n_stuffer_reserve_uint24(&stuffer, &size));
                EXPECT_SUCCESS(s2n_write_test_cert(&stuffer, chain_and_key));
                EXPECT_SUCCESS(s2n_extension_list_send(S2N_EXTENSION_LIST_EMPTY, conn, &stuffer));
                EXPECT_SUCCESS(s2n_write_test_cert(&stuffer, chain_and_key));
                EXPECT_SUCCESS(s2n_extension_list_send(S2N_EXTENSION_LIST_CERTIFICATE, conn, &stuffer));
                EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&size));

                EXPECT_SUCCESS(s2n_x509_validator_validate_cert_chain_test(conn, &stuffer));

                EXPECT_EQUAL(conn->status_response.size, 0);
                EXPECT_EQUAL(conn->status_response.data, NULL);

                EXPECT_SUCCESS(s2n_connection_free(conn));
            };

            /* Extensions on first cert processed */
            {
                struct s2n_connection *conn;
                POSIX_GUARD(s2n_setup_connection_for_ocsp_validate_test(&conn, chain_and_key));

                DEFER_CLEANUP(struct s2n_stuffer stuffer, s2n_stuffer_free);
                EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&stuffer, 0));

                EXPECT_SUCCESS(s2n_stuffer_reserve_uint24(&stuffer, &size));
                EXPECT_SUCCESS(s2n_write_test_cert(&stuffer, chain_and_key));
                EXPECT_SUCCESS(s2n_extension_list_send(S2N_EXTENSION_LIST_CERTIFICATE, conn, &stuffer));
                EXPECT_SUCCESS(s2n_write_test_cert(&stuffer, chain_and_key));
                EXPECT_SUCCESS(s2n_extension_list_send(S2N_EXTENSION_LIST_EMPTY, conn, &stuffer));
                EXPECT_SUCCESS(s2n_stuffer_write_vector_size(&size));

                EXPECT_SUCCESS(s2n_x509_validator_validate_cert_chain_test(conn, &stuffer));

                EXPECT_EQUAL(conn->status_response.size, s2n_array_len(data));
                EXPECT_BYTEARRAY_EQUAL(conn->status_response.data, data, s2n_array_len(data));

                EXPECT_SUCCESS(s2n_connection_free(conn));
            };
        };
    };

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    EXPECT_SUCCESS(s2n_config_free(config));

    END_TEST();

    return 0;
}
