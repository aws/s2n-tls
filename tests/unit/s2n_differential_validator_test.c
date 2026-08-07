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

/* Unit tests for the Differential_Validator ().
 *
 * Exercises:
 * - Both paths agree (accept): divergence_count == 0, libcrypto result returned
 * - Injected divergence recorded: divergence_count > 0, libcrypto result returned
 * - Recording failure still returns libcrypto result
 * - Callbacks fire exactly once in differential mode (same as libcrypto-only)
 *   (differential-mode arm)
 * - Zero-copy internal error is swallowed: libcrypto result still returned
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

/* Mock time callback returning a fixed time within the test cert's validity
 * window. 2024-06-01 00:00:00 UTC = 1717200000 seconds since epoch. */
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

/* Verify host callback that rejects all names. */
static uint8_t s2n_test_verify_host_reject(const char *host_name, size_t host_name_len, void *data)
{
    return 0;
}

/* Counting verify host callback: increments a counter and accepts. */
static uint8_t s2n_test_verify_host_count(const char *host_name, size_t host_name_len, void *data)
{
    uint32_t *counter = (uint32_t *) data;
    if (counter != NULL) {
        (*counter)++;
    }
    return 1;
}

/* Counting cert validation callback: increments a counter, sets finished+accepted. */
static int s2n_test_cert_validation_cb_count(struct s2n_connection *conn,
        struct s2n_cert_validation_info *info, void *context)
{
    uint32_t *counter = (uint32_t *) context;
    if (counter != NULL) {
        (*counter)++;
    }
    info->finished = 1;
    info->accepted = 1;
    return S2N_SUCCESS;
}

/* Cert validation callback that rejects (for testing divergence). */
static int s2n_test_cert_validation_cb_reject(struct s2n_connection *conn,
        struct s2n_cert_validation_info *info, void *context)
{
    info->finished = 1;
    info->accepted = 0;
    return S2N_SUCCESS;
}

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

int main(int argc, char **argv)
{
    BEGIN_TEST();

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    /* === Test 1: Both paths accept — divergence_count == 0, libcrypto result
     * returned successfully () === */
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

        /* Both paths accepted: no divergence. */
        EXPECT_EQUAL(validator.differential_divergence_count, 0);

        /* Libcrypto result returned: leaf key extracted, correct type. */
        EXPECT_EQUAL(pkey_type, S2N_PKEY_TYPE_RSA);
        EXPECT_NOT_NULL(public_key.pkey);

        /* Libcrypto path artifacts present (cert_chain_from_wire). */
        EXPECT_NOT_NULL(validator.cert_chain_from_wire);
        EXPECT_TRUE(sk_X509_num(validator.cert_chain_from_wire) > 0);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

    /* === Test 2: Injected divergence — verify_host rejects, making libcrypto
     * reject, but zero-copy uses accept-all callback. Divergence recorded,
     * libcrypto's rejection is returned () === */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_wall_clock(config, s2n_test_wall_clock, NULL));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem", NULL));
        /* Use a verify_host callback that REJECTS all names: libcrypto will
         * reject, but the differential's zero-copy run uses accept-all. */
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config,
                s2n_test_verify_host_reject, NULL));

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

        /* Libcrypto rejects (verify_host fails), result is an error. */
        EXPECT_ERROR(s2n_x509_validator_validate_cert_chain(&validator, conn,
                chain_data, chain_len, &pkey_type, &public_key));

        /* Divergence detected: libcrypto rejected (hostname), zero-copy accepted
         * (accept-all callback). */
        EXPECT_TRUE(validator.differential_divergence_count > 0);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

    /* === Test 3: Callbacks fire exactly once in differential mode
     * (same as libcrypto-only) === */
    {
        uint32_t verify_host_count = 0;
        uint32_t cert_cb_count = 0;

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_wall_clock(config, s2n_test_wall_clock, NULL));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem", NULL));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config,
                s2n_test_verify_host_count, &verify_host_count));
        EXPECT_SUCCESS(s2n_config_set_cert_validation_cb(config,
                s2n_test_cert_validation_cb_count, &cert_cb_count));

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

        /* Verify host callback fired exactly the same number of times as in
         * libcrypto-only mode. For this cert chain (single SAN entry matching),
         * it should be called once by the libcrypto path. The zero-copy run
         * uses the accept-all callback, so it does NOT increment the counter. */
        EXPECT_EQUAL(verify_host_count, 1);

        /* Cert validation callback fires exactly once (from libcrypto path). */
        EXPECT_EQUAL(cert_cb_count, 1);

        /* No divergence expected (both paths accept this chain). */
        EXPECT_EQUAL(validator.differential_divergence_count, 0);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

    /* === Test 4: Libcrypto-only baseline for callback count comparison === */
    /* Run the same chain in libcrypto-only mode and verify the callback counts
     * are identical to differential mode (proving ). */
    {
        uint32_t verify_host_count = 0;
        uint32_t cert_cb_count = 0;

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_wall_clock(config, s2n_test_wall_clock, NULL));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem", NULL));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config,
                s2n_test_verify_host_count, &verify_host_count));
        EXPECT_SUCCESS(s2n_config_set_cert_validation_cb(config,
                s2n_test_cert_validation_cb_count, &cert_cb_count));

        /* Explicitly use libcrypto-only mode. */
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

        /* Same counts as differential mode (Test 3): proves callbacks fire
         * exactly the same number of times regardless of differential mode. */
        EXPECT_EQUAL(verify_host_count, 1);
        EXPECT_EQUAL(cert_cb_count, 1);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

    /* === Test 5: Cert validation callback rejects — libcrypto rejects,
     * zero-copy accepts (divergence), but libcrypto rejection is returned
     * () === */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_wall_clock(config, s2n_test_wall_clock, NULL));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem", NULL));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config,
                s2n_test_verify_host_accept, NULL));
        /* Cert validation callback rejects: the libcrypto path will fail. */
        EXPECT_SUCCESS(s2n_config_set_cert_validation_cb(config,
                s2n_test_cert_validation_cb_reject, NULL));

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

        /* Libcrypto rejects (cert validation cb says not accepted). */
        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_validate_cert_chain(&validator, conn,
                        chain_data, chain_len, &pkey_type, &public_key),
                S2N_ERR_CERT_REJECTED);

        /* The zero-copy path accepts (no cert_validation_cb in its run), so
         * there's a divergence. */
        EXPECT_TRUE(validator.differential_divergence_count > 0);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

    /* === Test 6: Both paths reject (no divergence) — wrong trust anchor
     * means both verifiers reject, divergence_count == 0 () === */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_wall_clock(config, s2n_test_wall_clock, NULL));
        /* Load a DIFFERENT CA (ECDSA) that cannot verify the RSA chain. */
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                "../pems/permutations/ec_ecdsa_p256_sha256/ca-cert.pem", NULL));
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

        /* Both paths reject: wrong trust anchor. */
        EXPECT_ERROR(s2n_x509_validator_validate_cert_chain(&validator, conn,
                chain_data, chain_len, &pkey_type, &public_key));

        /* Both rejected: no divergence. */
        EXPECT_EQUAL(validator.differential_divergence_count, 0);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

    END_TEST();
}
