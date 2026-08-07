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

/* Unit tests for the zero-copy validator state machine, skip mode, and
 * empty-trust-store behavior ().
 *
 * Exercises:
 * - State transitions per backend: out-of-order calls yield S2N_ERR_INVALID_CERT_STATE
 * - Skip-mode leaf-key extraction without READY_TO_VERIFY transition
 * - Empty trust store on the zero-copy path yields S2N_ERR_CERT_UNTRUSTED
 * - Normal full flow: INIT -> READY_TO_VERIFY -> VALIDATED
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

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    /* === Test 1: calling verify before read (state == INIT) -> S2N_ERR_INVALID_CERT_STATE === */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem", NULL));

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &config->trust_store, 0));

        /* Validator is in INIT state — calling verify without calling read first must fail. */
        EXPECT_EQUAL(validator.state, INIT);
        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_verify_cert_chain_spans(&validator, conn),
                S2N_ERR_INVALID_CERT_STATE);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

    /* === Test 2: calling read twice -> S2N_ERR_INVALID_CERT_STATE (state no longer INIT) === */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_wall_clock(config, s2n_test_wall_clock, NULL));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem", NULL));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config,
                s2n_test_verify_host_accept, NULL));

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
        EXPECT_EQUAL(validator.state, INIT);

        /* First read succeeds and transitions to READY_TO_VERIFY. */
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                chain_data, chain_len, &pkey_type, NULL));
        EXPECT_EQUAL(validator.state, READY_TO_VERIFY);

        /* Second read must fail: state is READY_TO_VERIFY, not INIT. */
        s2n_pkey_type pkey_type2 = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                        chain_data, chain_len, &pkey_type2, NULL),
                S2N_ERR_INVALID_CERT_STATE);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

    /* === Test 3: skip mode extracts leaf key without transitioning to READY_TO_VERIFY === */
    {
        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init_no_x509_validation(&validator));
        EXPECT_EQUAL(validator.state, INIT);

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default"));

        DEFER_CLEANUP(struct s2n_stuffer chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn,
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN, &chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        DEFER_CLEANUP(struct s2n_pkey public_key = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

        EXPECT_OK(s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                chain_data, chain_len, &pkey_type, &public_key));

        /* In skip mode: state remains INIT (no chain validation will follow). */
        EXPECT_EQUAL(validator.state, INIT);

        /* But the leaf key IS extracted. */
        EXPECT_EQUAL(pkey_type, S2N_PKEY_TYPE_RSA);
        EXPECT_NOT_NULL(public_key.pkey);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

    /* === Test 4: empty trust store on zero-copy path -> S2N_ERR_CERT_UNTRUSTED === */
    /* The read_cert_chain_spans function checks s2n_x509_trust_store_has_certs()
     * which only tests whether the X509_STORE pointer is non-NULL (it doesn't
     * count certificates). The actual empty-store rejection happens when the
     * trust-anchor snapshot is built during verification. We exercise both
     * cases: a completely NULL store (caught at read) and an allocated-but-empty
     * store (caught at verify via snapshot_acquire). */
    {
        /* Case A: NULL trust store pointer -> caught at read time. */
        struct s2n_x509_trust_store null_store = { 0 };
        s2n_x509_trust_store_init_empty(&null_store);
        /* trust_store pointer is NULL after init_empty. */

        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &null_store, 0));

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default"));

        DEFER_CLEANUP(struct s2n_stuffer chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn,
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN, &chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                        chain_data, chain_len, &pkey_type, NULL),
                S2N_ERR_CERT_UNTRUSTED);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

    /* === Test 4b: allocated-but-empty trust store -> S2N_ERR_CERT_UNTRUSTED at verify === */
    /* The X509_STORE is allocated (has_certs returns true) but contains zero
     * certificates. Read passes; the snapshot build at verify time fails. */
    {
        struct s2n_x509_trust_store trust_store = { 0 };
        s2n_x509_trust_store_init_empty(&trust_store);
        trust_store.trust_store = X509_STORE_new();
        EXPECT_NOT_NULL(trust_store.trust_store);

        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_wall_clock(config, s2n_test_wall_clock, NULL));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config,
                s2n_test_verify_host_accept, NULL));

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

        /* Read succeeds (has_certs just checks non-NULL pointer). */
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                chain_data, chain_len, &pkey_type, NULL));
        EXPECT_EQUAL(validator.state, READY_TO_VERIFY);

        /* Verification fails: snapshot_acquire finds zero certs -> S2N_ERR_CERT_UNTRUSTED. */
        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_verify_cert_chain_spans(&validator, conn),
                S2N_ERR_CERT_UNTRUSTED);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
        s2n_x509_trust_store_wipe(&trust_store);
    };

    /* === Test 4c: empty trust store after store mutation -> S2N_ERR_CERT_UNTRUSTED at verify === */
    /* Simulates a trust store that was populated at read time but wiped before
     * verification (concurrent mutation). */
    {
        struct s2n_x509_trust_store trust_store = { 0 };
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem", NULL));

        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_wall_clock(config, s2n_test_wall_clock, NULL));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config,
                s2n_test_verify_host_accept, NULL));

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

        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                chain_data, chain_len, &pkey_type, NULL));
        EXPECT_EQUAL(validator.state, READY_TO_VERIFY);

        /* Wipe and replace with an empty store — simulating mutation. */
        s2n_x509_trust_store_wipe(&trust_store);
        s2n_x509_trust_store_init_empty(&trust_store);
        trust_store.trust_store = X509_STORE_new();
        EXPECT_NOT_NULL(trust_store.trust_store);
        validator.trust_store = &trust_store;

        /* Verification must fail: snapshot build finds zero certs. */
        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_verify_cert_chain_spans(&validator, conn),
                S2N_ERR_CERT_UNTRUSTED);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
        s2n_x509_trust_store_wipe(&trust_store);
    };

    /* === Test 5: normal flow INIT -> READY_TO_VERIFY -> VALIDATED === */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_wall_clock(config, s2n_test_wall_clock, NULL));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem", NULL));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config,
                s2n_test_verify_host_accept, NULL));

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
        EXPECT_EQUAL(validator.state, INIT);

        /* read transitions to READY_TO_VERIFY */
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                chain_data, chain_len, &pkey_type, NULL));
        EXPECT_EQUAL(validator.state, READY_TO_VERIFY);
        EXPECT_TRUE(validator.chain_spans != NULL);
        EXPECT_TRUE(validator.chain_spans->count > 0);

        /* verify transitions to VALIDATED */
        EXPECT_OK(s2n_x509_validator_verify_cert_chain_spans(&validator, conn));
        EXPECT_EQUAL(validator.state, VALIDATED);

        /* Calling verify again after already VALIDATED must fail. */
        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_verify_cert_chain_spans(&validator, conn),
                S2N_ERR_INVALID_CERT_STATE);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

    /* === Test 6: verify from VALIDATED state -> S2N_ERR_INVALID_CERT_STATE === */
    /* Verifies that calling verify in other invalid states (besides INIT) also fails. */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem", NULL));

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &config->trust_store, 0));

        /* Force state to VALIDATED directly. */
        validator.state = VALIDATED;
        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_verify_cert_chain_spans(&validator, conn),
                S2N_ERR_INVALID_CERT_STATE);

        /* Force state to OCSP_VALIDATED. */
        validator.state = OCSP_VALIDATED;
        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_verify_cert_chain_spans(&validator, conn),
                S2N_ERR_INVALID_CERT_STATE);

        /* Force state to AWAITING_CRL_CALLBACK. */
        validator.state = AWAITING_CRL_CALLBACK;
        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_verify_cert_chain_spans(&validator, conn),
                S2N_ERR_INVALID_CERT_STATE);

        /* Restore state for clean wipe. */
        validator.state = INIT;
        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

    /* === Test 7: read from non-INIT states -> S2N_ERR_INVALID_CERT_STATE === */
    {
        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init_no_x509_validation(&validator));

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        uint8_t dummy = 0;
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        DEFER_CLEANUP(struct s2n_pkey public_key = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key));

        /* Force state to READY_TO_VERIFY. */
        validator.state = READY_TO_VERIFY;
        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                        &dummy, 0, &pkey_type, &public_key),
                S2N_ERR_INVALID_CERT_STATE);

        /* Force state to VALIDATED. */
        validator.state = VALIDATED;
        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                        &dummy, 0, &pkey_type, &public_key),
                S2N_ERR_INVALID_CERT_STATE);

        /* Restore state for clean wipe. */
        validator.state = INIT;
        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

    END_TEST();
}
