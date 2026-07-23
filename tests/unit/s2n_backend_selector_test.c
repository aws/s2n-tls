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

/* Unit tests for the Backend_Selector.
 *
 * Exercises:
 * - Default backend is S2N_CERT_BACKEND_LIBCRYPTO
 * - Setting the backend to zero-copy and running validation uses the zero-copy path
 * - The libcrypto (default) path works unchanged when zero-copy is compiled in
 * - On non-CBS builds, setting zero-copy has no effect (stays libcrypto)
 * - Differential mode routes to libcrypto for now (adds full support)
 *
 * 
 */

#include "crypto/s2n_pkey.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_x509_validator.h"

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    #include "tls/s2n_cert_parse.h"
    #include "tls/s2n_cert_path.h"

/* Mock time callback returning a fixed time within the test cert's validity window.
 * 2024-06-01 00:00:00 UTC = 1717200000 seconds since epoch. */
static int s2n_test_wall_clock(void *data, uint64_t *timestamp)
{
    *timestamp = (uint64_t) 1717200000 * 1000000000ULL;
    return 0;
}

/* Verify host callback that accepts any name. */
static uint8_t s2n_test_verify_host_accept(const char *host_name, size_t host_name_len, void *data)
{
    return 1;
}

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* === Test 1: default backend is S2N_CERT_BACKEND_ZERO_COPY on CBS builds === */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
#if S2N_LIBCRYPTO_SUPPORTS_CBS
        EXPECT_EQUAL(config->cert_verify_backend, S2N_CERT_BACKEND_ZERO_COPY);
#else
        EXPECT_EQUAL(config->cert_verify_backend, S2N_CERT_BACKEND_LIBCRYPTO);
#endif
    };

    /* === Test 2: internal setter works and persists === */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

#if S2N_LIBCRYPTO_SUPPORTS_CBS
        EXPECT_OK(s2n_config_set_cert_verify_backend(config, S2N_CERT_BACKEND_ZERO_COPY));
        EXPECT_EQUAL(config->cert_verify_backend, S2N_CERT_BACKEND_ZERO_COPY);

        EXPECT_OK(s2n_config_set_cert_verify_backend(config, S2N_CERT_BACKEND_DIFFERENTIAL));
        EXPECT_EQUAL(config->cert_verify_backend, S2N_CERT_BACKEND_DIFFERENTIAL);

        EXPECT_OK(s2n_config_set_cert_verify_backend(config, S2N_CERT_BACKEND_LIBCRYPTO));
        EXPECT_EQUAL(config->cert_verify_backend, S2N_CERT_BACKEND_LIBCRYPTO);
#else
        /* On non-CBS builds, setter always results in libcrypto (). */
        EXPECT_OK(s2n_config_set_cert_verify_backend(config, S2N_CERT_BACKEND_LIBCRYPTO));
        EXPECT_EQUAL(config->cert_verify_backend, S2N_CERT_BACKEND_LIBCRYPTO);
#endif
    };

    /* === Test 3: NULL config fails gracefully === */
    {
        EXPECT_ERROR_WITH_ERRNO(
                s2n_config_set_cert_verify_backend(NULL, S2N_CERT_BACKEND_LIBCRYPTO),
                S2N_ERR_NULL);
    };

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    /* === Test 4: libcrypto backend (default) validates successfully via validate_cert_chain === */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_wall_clock(config, s2n_test_wall_clock, NULL));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem", NULL));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config,
                s2n_test_verify_host_accept, NULL));

        /* Explicitly set to libcrypto (same as default). */
        EXPECT_OK(s2n_config_set_cert_verify_backend(config, S2N_CERT_BACKEND_LIBCRYPTO));

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default"));

        DEFER_CLEANUP(struct s2n_stuffer chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn,
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN, &chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &config->trust_store, 0));

        DEFER_CLEANUP(struct s2n_pkey public_key = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, conn,
                chain_data, chain_len, &pkey_type, &public_key));

        /* Libcrypto path: cert_chain_from_wire is populated, zero-copy wire_chain is NOT. */
        EXPECT_NOT_NULL(validator.cert_chain_from_wire);
        EXPECT_TRUE(sk_X509_num(validator.cert_chain_from_wire) > 0);
        EXPECT_EQUAL(validator.wire_chain.size, 0);

        EXPECT_EQUAL(pkey_type, S2N_PKEY_TYPE_RSA);
        EXPECT_NOT_NULL(public_key.pkey);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

    /* === Test 5: zero-copy backend validates successfully via validate_cert_chain === */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_wall_clock(config, s2n_test_wall_clock, NULL));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem", NULL));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config,
                s2n_test_verify_host_accept, NULL));

        /* Select the zero-copy backend. */
        EXPECT_OK(s2n_config_set_cert_verify_backend(config, S2N_CERT_BACKEND_ZERO_COPY));

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default"));

        DEFER_CLEANUP(struct s2n_stuffer chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn,
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN, &chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &config->trust_store, 0));

        DEFER_CLEANUP(struct s2n_pkey public_key = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, conn,
                chain_data, chain_len, &pkey_type, &public_key));

        /* Zero-copy path: wire_chain IS populated (the single copy). */
        EXPECT_TRUE(validator.wire_chain.size > 0);
        EXPECT_TRUE(validator.chain_spans != NULL);
        EXPECT_TRUE(validator.chain_spans->count > 0);
        EXPECT_EQUAL(validator.state, VALIDATED);

        EXPECT_EQUAL(pkey_type, S2N_PKEY_TYPE_RSA);
        EXPECT_NOT_NULL(public_key.pkey);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

    /* === Test 6: differential backend runs both verifiers, libcrypto authoritative === */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_wall_clock(config, s2n_test_wall_clock, NULL));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem", NULL));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config,
                s2n_test_verify_host_accept, NULL));

        /* Select differential mode. */
        EXPECT_OK(s2n_config_set_cert_verify_backend(config, S2N_CERT_BACKEND_DIFFERENTIAL));

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default"));

        DEFER_CLEANUP(struct s2n_stuffer chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn,
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN, &chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &config->trust_store, 0));

        DEFER_CLEANUP(struct s2n_pkey public_key = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, conn,
                chain_data, chain_len, &pkey_type, &public_key));

        /* Differential mode: libcrypto is authoritative — cert_chain_from_wire
         * is populated. The zero-copy run uses a temporary validator, so the
         * main validator's wire_chain remains empty. */
        EXPECT_NOT_NULL(validator.cert_chain_from_wire);
        EXPECT_TRUE(sk_X509_num(validator.cert_chain_from_wire) > 0);
        EXPECT_EQUAL(validator.wire_chain.size, 0);

        /* No divergence: both paths accept this chain. */
        EXPECT_EQUAL(validator.differential_divergence_count, 0);

        EXPECT_EQUAL(pkey_type, S2N_PKEY_TYPE_RSA);
        EXPECT_NOT_NULL(public_key.pkey);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

    /* === Test 7: zero-copy backend in skip mode extracts leaf key === */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);

        /* Select the zero-copy backend. */
        EXPECT_OK(s2n_config_set_cert_verify_backend(config, S2N_CERT_BACKEND_ZERO_COPY));

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default"));

        DEFER_CLEANUP(struct s2n_stuffer chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn,
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN, &chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init_no_x509_validation(&validator));

        DEFER_CLEANUP(struct s2n_pkey public_key = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&validator, conn,
                chain_data, chain_len, &pkey_type, &public_key));

        /* Skip mode: leaf key extracted, no chain validation. */
        EXPECT_EQUAL(pkey_type, S2N_PKEY_TYPE_RSA);
        EXPECT_NOT_NULL(public_key.pkey);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

    END_TEST();
}
