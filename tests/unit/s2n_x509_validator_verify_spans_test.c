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

/* Unit test for s2n_x509_validator_verify_cert_chain_spans ():
 * exercises the full zero-copy chain-validation flow with a real cert chain
 * and matching trust store, including hostname verification and the cert
 * validation callback. */

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_x509_validator.h"

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    #include "tls/s2n_cert_parse.h"
    #include "tls/s2n_cert_path.h"

/* Mock time callback returning a fixed time that is within the test cert's
 * validity window. 2024-06-01 00:00:00 UTC in nanoseconds. */
static int s2n_test_wall_clock(void *data, uint64_t *timestamp)
{
    /* 2024-06-01 00:00:00 UTC = 1717200000 seconds since epoch */
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

/* Cert validation callback that accepts immediately. */
static int s2n_test_cert_validation_accept(struct s2n_connection *conn,
        struct s2n_cert_validation_info *info, void *context)
{
    uint32_t *count = (uint32_t *) context;
    if (count != NULL) {
        (*count)++;
    }
    info->accepted = 1;
    info->finished = 1;
    return S2N_SUCCESS;
}

/* Cert validation callback that rejects. */
static int s2n_test_cert_validation_reject(struct s2n_connection *conn,
        struct s2n_cert_validation_info *info, void *context)
{
    info->accepted = 0;
    info->finished = 1;
    return S2N_SUCCESS;
}

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

int main(int argc, char **argv)
{
    BEGIN_TEST();

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    /* Test: Full zero-copy chain-validation flow succeeds with a valid chain. */
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

        DEFER_CLEANUP(struct s2n_stuffer chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn,
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN, &chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &config->trust_store, 0));

        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        struct s2n_pkey public_key = { 0 };
        EXPECT_OK(s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                chain_data, chain_len, &pkey_type, &public_key));
        EXPECT_EQUAL(validator.state, READY_TO_VERIFY);
        EXPECT_TRUE(validator.chain_spans != NULL);
        EXPECT_TRUE(validator.chain_spans->count > 0);

        EXPECT_OK(s2n_x509_validator_verify_cert_chain_spans(&validator, conn));
        EXPECT_EQUAL(validator.state, VALIDATED);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

    /* Test: Validation fails when the trust store does not contain the CA. */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_wall_clock(config, s2n_test_wall_clock, NULL));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, NULL));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config,
                s2n_test_verify_host_accept, NULL));

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        DEFER_CLEANUP(struct s2n_stuffer chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn,
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN, &chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &config->trust_store, 0));

        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        struct s2n_pkey public_key = { 0 };
        EXPECT_OK(s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                chain_data, chain_len, &pkey_type, &public_key));

        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_verify_cert_chain_spans(&validator, conn),
                S2N_ERR_CERT_UNTRUSTED);
        EXPECT_EQUAL(validator.state, READY_TO_VERIFY);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

    /* Test: Hostname verification failure rejects the chain. */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_wall_clock(config, s2n_test_wall_clock, NULL));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem", NULL));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config,
                s2n_test_verify_host_reject, NULL));

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        DEFER_CLEANUP(struct s2n_stuffer chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn,
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN, &chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &config->trust_store, 0));

        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        struct s2n_pkey public_key = { 0 };
        EXPECT_OK(s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                chain_data, chain_len, &pkey_type, &public_key));

        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_verify_cert_chain_spans(&validator, conn),
                S2N_ERR_CERT_INVALID_HOSTNAME);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

    /* Test: Cert validation callback is invoked exactly once. */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_wall_clock(config, s2n_test_wall_clock, NULL));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem", NULL));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config,
                s2n_test_verify_host_accept, NULL));

        uint32_t cb_count = 0;
        config->cert_validation_cb = s2n_test_cert_validation_accept;
        config->cert_validation_ctx = &cb_count;

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        DEFER_CLEANUP(struct s2n_stuffer chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn,
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN, &chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &config->trust_store, 0));

        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        struct s2n_pkey public_key = { 0 };
        EXPECT_OK(s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                chain_data, chain_len, &pkey_type, &public_key));
        EXPECT_OK(s2n_x509_validator_verify_cert_chain_spans(&validator, conn));

        EXPECT_EQUAL(cb_count, 1);
        EXPECT_EQUAL(validator.state, VALIDATED);
        EXPECT_TRUE(validator.cert_validation_cb_invoked);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

    /* Test: Cert validation callback rejection fails the chain. */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_wall_clock(config, s2n_test_wall_clock, NULL));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem", NULL));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config,
                s2n_test_verify_host_accept, NULL));
        config->cert_validation_cb = s2n_test_cert_validation_reject;
        config->cert_validation_ctx = NULL;

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        DEFER_CLEANUP(struct s2n_stuffer chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn,
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN, &chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &config->trust_store, 0));

        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        struct s2n_pkey public_key = { 0 };
        EXPECT_OK(s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                chain_data, chain_len, &pkey_type, &public_key));

        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_verify_cert_chain_spans(&validator, conn),
                S2N_ERR_CERT_REJECTED);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

    /* Test: Calling verify when not in READY_TO_VERIFY state fails. */
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

        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_verify_cert_chain_spans(&validator, conn),
                S2N_ERR_INVALID_CERT_STATE);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

    /* Test: Validation with disabled time verification succeeds. */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(config);
        EXPECT_SUCCESS(s2n_config_set_wall_clock(config, s2n_test_wall_clock, NULL));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(config,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem", NULL));
        EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config,
                s2n_test_verify_host_accept, NULL));
        config->disable_x509_time_validation = true;

        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        DEFER_CLEANUP(struct s2n_stuffer chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn,
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN, &chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &config->trust_store, 0));

        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        struct s2n_pkey public_key = { 0 };
        EXPECT_OK(s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                chain_data, chain_len, &pkey_type, &public_key));

        EXPECT_OK(s2n_x509_validator_verify_cert_chain_spans(&validator, conn));
        EXPECT_EQUAL(validator.state, VALIDATED);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
    };

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

    END_TEST();
}
