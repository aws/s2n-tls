/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <fcntl.h>
#include <errno.h>

#include <s2n.h>

#include "crypto/s2n_fips.h"
#include "utils/s2n_safety.h"

/* For testing s2n_choose_tls13_sig_scheme_and_set_cert() */
#include "tls/s2n_client_hello.c"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* default s2n_sig_scheme_list  */
    const struct s2n_signature_scheme* const client_sig_scheme_pref_list[] = {
        /* RSA PSS */
        /* &s2n_rsa_pss_pss_sha256, */
        /* &s2n_rsa_pss_pss_sha384, */
        /* &s2n_rsa_pss_pss_sha512, */

        /* RSA PSS RSAE */
        &s2n_rsa_pss_rsae_sha256,
        &s2n_rsa_pss_rsae_sha384,
        &s2n_rsa_pss_rsae_sha512,

        /* RSA PKCS1 */
        &s2n_rsa_pkcs1_sha256,
        &s2n_rsa_pkcs1_sha384,
        &s2n_rsa_pkcs1_sha512,
        &s2n_rsa_pkcs1_sha224,

        /* ECDSA - TLS 1.2 */
        &s2n_ecdsa_sha256,
        &s2n_ecdsa_sha384,
        &s2n_ecdsa_sha512,
        &s2n_ecdsa_sha224,

        /* SHA-1 Legacy */
        &s2n_rsa_pkcs1_sha1,
        &s2n_ecdsa_sha1,
    };

    struct s2n_sig_scheme_list default_client_sig_scheme_pref_list = {0};

    default_client_sig_scheme_pref_list.len = s2n_array_len(client_sig_scheme_pref_list);
    for (int i = 0; i < default_client_sig_scheme_pref_list.len; i++) {
        default_client_sig_scheme_pref_list.iana_list[i] = client_sig_scheme_pref_list[i]->iana_value;
    }

    /* Without any certs, s2n_choose_tls13_sig_scheme_and_set_cert() fails */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        EXPECT_NULL(server_conn->handshake_params.our_chain_and_key);
        struct s2n_signature_scheme sig_scheme_out = {0};

        /* test we guard s2n_choose_tls13_sig_scheme_and_set_cert() against non tls13 misuse */
        EXPECT_FAILURE_WITH_ERRNO(s2n_choose_tls13_sig_scheme_and_set_cert(server_conn, &default_client_sig_scheme_pref_list, &sig_scheme_out), S2N_ERR_BAD_MESSAGE);

        server_conn->actual_protocol_version = S2N_TLS13;
        EXPECT_FAILURE_WITH_ERRNO(s2n_choose_tls13_sig_scheme_and_set_cert(server_conn, &default_client_sig_scheme_pref_list, &sig_scheme_out), S2N_ERR_SIGNATURE_SCHEME_MISMATCH);
        EXPECT_EQUAL(sig_scheme_out.iana_value, 0);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    struct test_config {
        char cert_chain[1024];
        char private_key[1024];
        uint16_t iana_value;
    };

    const struct test_config test_cases[] = {
        { S2N_RSA_2048_PKCS1_CERT_CHAIN, S2N_RSA_2048_PKCS1_KEY, TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256 },
        { S2N_ECDSA_P384_PKCS1_CERT_CHAIN, S2N_ECDSA_P384_PKCS1_KEY, TLS_SIGNATURE_SCHEME_ECDSA_SHA256 },
    };

    /* Happy path - when client sends a comprehensive sigalg list, server matches on a scheme based on configured certs */
    {
        for (int i = 0; i < s2n_array_len(test_cases); i++) {
            const struct test_config test = test_cases[i];

            char *cert_chain = NULL;
            char *private_key = NULL;
            EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
            EXPECT_NOT_NULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));

            EXPECT_SUCCESS(s2n_read_test_pem(test.cert_chain, cert_chain, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_read_test_pem(test.private_key, private_key, S2N_MAX_TEST_PEM_SIZE));

            struct s2n_config *server_config;
            EXPECT_NOT_NULL(server_config = s2n_config_new());

            struct s2n_cert_chain_and_key *default_cert;
            EXPECT_NOT_NULL(default_cert = s2n_cert_chain_and_key_new());
            EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(default_cert, cert_chain, private_key));
            EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, default_cert));

            struct s2n_connection *server_conn;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
            server_conn->actual_protocol_version = S2N_TLS13;
            EXPECT_NULL(server_conn->handshake_params.our_chain_and_key);

            struct s2n_signature_scheme sig_scheme_out = {0};
            EXPECT_SUCCESS(s2n_choose_tls13_sig_scheme_and_set_cert(server_conn, &default_client_sig_scheme_pref_list, &sig_scheme_out));
            /* test that signature scheme is set correctly */
            EXPECT_EQUAL(sig_scheme_out.iana_value, test.iana_value);
            /* test that our_chain_and_key is populated */
            EXPECT_NOT_NULL(server_conn->handshake_params.our_chain_and_key);

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_cert_chain_and_key_free(default_cert));
            EXPECT_SUCCESS(s2n_config_free(server_config));

            free(private_key);
            free(cert_chain);
        }
    }

    /* matching on empty client sig scheme list */
    {
        struct s2n_sig_scheme_list empty_client_sig_scheme_pref_list = {0};

        char *cert_chain = NULL;
        char *private_key = NULL;
        EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));

        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key, S2N_MAX_TEST_PEM_SIZE));

        struct s2n_config *server_config;
        EXPECT_NOT_NULL(server_config = s2n_config_new());

        struct s2n_cert_chain_and_key *default_cert;
        EXPECT_NOT_NULL(default_cert = s2n_cert_chain_and_key_new());
        EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(default_cert, cert_chain, private_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, default_cert));

        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        server_conn->actual_protocol_version = S2N_TLS13;

        EXPECT_NULL(server_conn->handshake_params.our_chain_and_key);

        struct s2n_signature_scheme sig_scheme_out = {0};
        EXPECT_FAILURE_WITH_ERRNO(s2n_choose_tls13_sig_scheme_and_set_cert(server_conn, &empty_client_sig_scheme_pref_list, &sig_scheme_out), S2N_ERR_EMPTY_SIGNATURE_SCHEME);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(default_cert));
        EXPECT_SUCCESS(s2n_config_free(server_config));

        free(private_key);
        free(cert_chain);
    }

     /* Test with both rsa and ecdsa certs */
    {
        struct s2n_cert_chain_and_key *rsa_and_ecdsa_certs[2] = {0};

        for (int i = 0; i < s2n_array_len(test_cases); i++) {
            const struct test_config test = test_cases[i];

            char *cert_chain = NULL;
            char *private_key = NULL;
            EXPECT_NOT_NULL(cert_chain = malloc(S2N_MAX_TEST_PEM_SIZE));
            EXPECT_NOT_NULL(private_key = malloc(S2N_MAX_TEST_PEM_SIZE));

            EXPECT_SUCCESS(s2n_read_test_pem(test.cert_chain, cert_chain, S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_read_test_pem(test.private_key, private_key, S2N_MAX_TEST_PEM_SIZE));

            EXPECT_NOT_NULL(rsa_and_ecdsa_certs[i] = s2n_cert_chain_and_key_new());
            EXPECT_SUCCESS(s2n_cert_chain_and_key_load_pem(rsa_and_ecdsa_certs[i], cert_chain, private_key));

            free(private_key);
            free(cert_chain);
        }

        /* based on server preference, test scheme uses preferred cert */
        {
            struct s2n_config *server_config;
            struct s2n_connection *server_conn;
            EXPECT_NOT_NULL(server_config = s2n_config_new());

            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
            server_conn->actual_protocol_version = S2N_TLS13;

            for (int i = 0; i < s2n_array_len(test_cases); i++) {
                EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, rsa_and_ecdsa_certs[i]));
            }

            EXPECT_NULL(server_conn->handshake_params.our_chain_and_key);

            /* test that our_chain_and_key is populated */
            struct s2n_signature_scheme sig_scheme_out = {0};
            EXPECT_SUCCESS(s2n_choose_tls13_sig_scheme_and_set_cert(server_conn, &default_client_sig_scheme_pref_list, &sig_scheme_out));
            EXPECT_EQUAL(sig_scheme_out.iana_value, TLS_SIGNATURE_SCHEME_ECDSA_SHA256);
            EXPECT_NOT_NULL(server_conn->handshake_params.our_chain_and_key);

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_config_free(server_config));
        }

        /* if client requests only ecdsa, check that server sends a ecdsa cert */
        {
            struct s2n_config *server_config;
            struct s2n_connection *server_conn;
            EXPECT_NOT_NULL(server_config = s2n_config_new());

            struct s2n_sig_scheme_list ecdsa_only_client_sig_scheme_pref_list = {
                .iana_list = { TLS_SIGNATURE_SCHEME_ECDSA_SHA256 },
                .len = 1
            };

            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
            server_conn->actual_protocol_version = S2N_TLS13;

            for (int i = 0; i < s2n_array_len(test_cases); i++) {
                EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, rsa_and_ecdsa_certs[i]));
            }

            EXPECT_NULL(server_conn->handshake_params.our_chain_and_key);

            /* test that our_chain_and_key is populated */
            struct s2n_signature_scheme sig_scheme_out = {0};
            EXPECT_SUCCESS(s2n_choose_tls13_sig_scheme_and_set_cert(server_conn, &ecdsa_only_client_sig_scheme_pref_list, &sig_scheme_out));
            EXPECT_EQUAL(sig_scheme_out.iana_value, TLS_SIGNATURE_SCHEME_ECDSA_SHA256);
            EXPECT_NOT_NULL(server_conn->handshake_params.our_chain_and_key);

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_config_free(server_config));
        }

        /* if client requests only rsa, check that server sends a rsa pss rsae signature scheme */
        {
            struct s2n_config *server_config;
            struct s2n_connection *server_conn;
            EXPECT_NOT_NULL(server_config = s2n_config_new());

            struct s2n_sig_scheme_list ecdsa_only_client_sig_scheme_pref_list = {
                .iana_list = { TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256 },
                .len = 1
            };

            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
            server_conn->actual_protocol_version = S2N_TLS13;

            for (int i = 0; i < s2n_array_len(test_cases); i++) {
                EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, rsa_and_ecdsa_certs[i]));
            }

            EXPECT_NULL(server_conn->handshake_params.our_chain_and_key);

            /* test that our_chain_and_key is populated */
            struct s2n_signature_scheme sig_scheme_out = {0};
            EXPECT_SUCCESS(s2n_choose_tls13_sig_scheme_and_set_cert(server_conn, &ecdsa_only_client_sig_scheme_pref_list, &sig_scheme_out));
            EXPECT_EQUAL(sig_scheme_out.iana_value, TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256);
            EXPECT_NOT_NULL(server_conn->handshake_params.our_chain_and_key);

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_config_free(server_config));
        }

        /* if client requests only rsa pkcs1, check that server does not match */
        {
            struct s2n_config *server_config;
            struct s2n_connection *server_conn;
            EXPECT_NOT_NULL(server_config = s2n_config_new());

            struct s2n_sig_scheme_list pkcs1_only_client_sig_scheme_pref_list = {
                .iana_list = { TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA256 },
                .len = 1
            };

            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
            server_conn->actual_protocol_version = S2N_TLS13;

            for (int i = 0; i < s2n_array_len(test_cases); i++) {
                EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, rsa_and_ecdsa_certs[i]));
            }

            /* test that our_chain_and_key is populated */
            EXPECT_NULL(server_conn->handshake_params.our_chain_and_key);

            struct s2n_signature_scheme sig_scheme_out = {0};
            EXPECT_FAILURE_WITH_ERRNO(s2n_choose_tls13_sig_scheme_and_set_cert(server_conn, &pkcs1_only_client_sig_scheme_pref_list, &sig_scheme_out), S2N_ERR_SIGNATURE_SCHEME_MISMATCH);
            EXPECT_NULL(server_conn->handshake_params.our_chain_and_key);

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_config_free(server_config));
        }

        for (int i = 0; i < s2n_array_len(test_cases); i++) {
            s2n_cert_chain_and_key_free(rsa_and_ecdsa_certs[i]);
        }
    }

    END_TEST();
    return 0;
}
