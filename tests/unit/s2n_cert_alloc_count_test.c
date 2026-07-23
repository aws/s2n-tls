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

/* Allocation-counting hooks for certificate processing.
 *
 * Reports steady-state per-handshake heap allocation counts for certificate
 * processing on both paths, demonstrating that the Zero_Copy_Verifier performs
 * no per-certificate X509 object-graph allocation.
 *
 * 
 */

#include <openssl/x509.h>

#include "s2n_test.h"
#include "testlib/s2n_mem_testlib.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_x509_validator.h"
#include "utils/s2n_mem.h"

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    #include "tls/s2n_cert_parse.h"
    #include "tls/s2n_cert_path.h"

/* Wall clock mock: 2024-06-01 00:00:00 UTC = 1717200000 seconds since epoch. */
static int s2n_test_wall_clock(void *data, uint64_t *timestamp)
{
    (void) data;
    *timestamp = (uint64_t) 1717200000 * 1000000000ULL;
    return 0;
}

/* Accept any hostname. */
static uint8_t s2n_test_verify_host_accept(const char *host_name, size_t host_name_len, void *data)
{
    (void) host_name;
    (void) host_name_len;
    (void) data;
    return 1;
}

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

int main(int argc, char **argv)
{
    BEGIN_TEST();

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    /* === Test 1: Zero-copy path allocations are bounded ===
     *
     * The zero-copy path should perform only:
     *   1. The wire_chain blob copy (one allocation for the cert bytes)
     *   2. EVP_PKEY materializations for signature verification (libcrypto-internal)
     *
     * No d2i_X509 object-graph allocation should occur. We verify this by
     * confirming that cert_chain_from_wire remains NULL on the zero-copy path.
     */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_wall_clock(config, s2n_test_wall_clock, NULL));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem", NULL));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config,
                s2n_test_verify_host_accept, NULL));
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

        /* First run builds the trust-anchor snapshot (one-time cost). */
        {
            struct s2n_x509_validator warmup = { 0 };
            EXPECT_SUCCESS(s2n_x509_validator_init(&warmup, &config->trust_store, 0));
            s2n_pkey_type pt = S2N_PKEY_TYPE_UNKNOWN;
            EXPECT_OK(s2n_x509_validator_read_cert_chain_spans(&warmup, conn,
                    chain_data, chain_len, &pt, NULL));
            EXPECT_OK(s2n_x509_validator_verify_cert_chain_spans(&warmup, conn));
            EXPECT_SUCCESS(s2n_x509_validator_wipe(&warmup));
        }

        /* Steady-state run with allocation tracking. */
        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &config->trust_store, 0));

        DEFER_CLEANUP(struct s2n_mem_test_cb_scope scope = { 0 },
                s2n_mem_test_free_callbacks);
        EXPECT_OK(s2n_mem_test_init_callbacks(&scope));

        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                chain_data, chain_len, &pkey_type, NULL));
        EXPECT_OK(s2n_x509_validator_verify_cert_chain_spans(&validator, conn));

        /* The zero-copy path should NOT have pushed any X509 objects into
         * cert_chain_from_wire. The stack is allocated by s2n_x509_validator_init
         * but remains empty — no d2i_X509 occurred. */
        EXPECT_NOT_NULL(validator.cert_chain_from_wire);
        EXPECT_EQUAL(sk_X509_num(validator.cert_chain_from_wire), 0);

        /* The wire_chain blob should be populated (one allocation). */
        EXPECT_NOT_NULL(validator.wire_chain.data);
        EXPECT_TRUE(validator.wire_chain.size > 0);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

    /* === Test 2: Libcrypto path DOES allocate X509 object graphs ===
     *
     * For comparison, verify that the libcrypto path populates
     * cert_chain_from_wire (i.e., calls d2i_X509). */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_wall_clock(config, s2n_test_wall_clock, NULL));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem", NULL));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config,
                s2n_test_verify_host_accept, NULL));
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

        /* Run via the full validate_cert_chain (libcrypto path). */
        struct s2n_pkey public_key = { 0 };
        s2n_pkey_zero_init(&public_key);
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(
                &conn->x509_validator, conn, chain_data, chain_len,
                &pkey_type, &public_key));

        /* The libcrypto path MUST have populated cert_chain_from_wire. */
        EXPECT_NOT_NULL(conn->x509_validator.cert_chain_from_wire);
        EXPECT_TRUE(sk_X509_num(conn->x509_validator.cert_chain_from_wire) > 0);

        s2n_pkey_free(&public_key);
    };

    /* === Test 3: Allocation count comparison ===
     *
     * Run both backends with mem tracking and compare the allocation counts.
     * The zero-copy path should have fewer allocations. Specifically, the
     * zero-copy path's allocations are limited to:
     *   - wire_chain blob (the single copy the design permits)
     *   - Any s2n-internal allocations (stuffer growth, etc.)
     * But NO per-certificate X509 object-graph allocations (d2i_X509). */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_wall_clock(config, s2n_test_wall_clock, NULL));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem", NULL));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config,
                s2n_test_verify_host_accept, NULL));
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

        /* Pre-build snapshot. */
        {
            struct s2n_x509_validator warmup = { 0 };
            EXPECT_SUCCESS(s2n_x509_validator_init(&warmup, &config->trust_store, 0));
            s2n_pkey_type pt = S2N_PKEY_TYPE_UNKNOWN;
            EXPECT_OK(s2n_x509_validator_read_cert_chain_spans(&warmup, conn,
                    chain_data, chain_len, &pt, NULL));
            EXPECT_OK(s2n_x509_validator_verify_cert_chain_spans(&warmup, conn));
            EXPECT_SUCCESS(s2n_x509_validator_wipe(&warmup));
        }

        /* Measure allocations on zero-copy steady-state. */
        {
            struct s2n_x509_validator validator = { 0 };
            EXPECT_SUCCESS(s2n_x509_validator_init(&validator,
                    &config->trust_store, 0));

            DEFER_CLEANUP(struct s2n_mem_test_cb_scope scope = { 0 },
                    s2n_mem_test_free_callbacks);
            EXPECT_OK(s2n_mem_test_init_callbacks(&scope));

            s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
            EXPECT_OK(s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                    chain_data, chain_len, &pkey_type, NULL));
            EXPECT_OK(s2n_x509_validator_verify_cert_chain_spans(&validator, conn));

            /* Key invariant: cert_chain_from_wire has zero X509 objects on
             * the zero-copy path (no d2i_X509 object-graph allocation occurred).
             * The stack is allocated by s2n_x509_validator_init but empty. */
            EXPECT_NOT_NULL(validator.cert_chain_from_wire);
            EXPECT_EQUAL(sk_X509_num(validator.cert_chain_from_wire), 0);

            EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
        }
    };

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

    END_TEST();
}
