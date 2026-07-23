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

/* Unit tests for s2n_x509_validator_read_cert_chain_spans ().
 *
 * Exercises:
 * - Normal mode: TLS 1.2 cert chain -> READY_TO_VERIFY transition
 * - Skip mode: leaf public key extraction without chain validation
 * - Max chain depth enforcement
 * - Empty chain rejection
 * - Comparison of extracted leaf key between zero-copy and libcrypto paths
 */

#include "crypto/s2n_pkey.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_x509_validator.h"

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    #include "crypto/s2n_pkey.h"
    #include "tls/s2n_cert_parse.h"
    #include "tls/s2n_connection.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    /* Test: read_cert_chain_spans in skip mode extracts the leaf public key */
    {
        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init_no_x509_validation(&validator));

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default"));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn, S2N_DEFAULT_TEST_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        DEFER_CLEANUP(struct s2n_pkey public_key = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

        EXPECT_OK(s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                chain_data, chain_len, &pkey_type, &public_key));

        /* In skip mode, the function should NOT transition to READY_TO_VERIFY. */
        EXPECT_EQUAL(validator.state, INIT);

        /* The leaf key should be RSA. */
        EXPECT_EQUAL(pkey_type, S2N_PKEY_TYPE_RSA);
        EXPECT_NOT_NULL(public_key.pkey);

        /* Compare with the libcrypto-path key: both must yield the same key. */
        DEFER_CLEANUP(struct s2n_pkey libcrypto_key = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&libcrypto_key));
        s2n_pkey_type libcrypto_pkey_type = S2N_PKEY_TYPE_UNKNOWN;

        struct s2n_x509_validator libcrypto_validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init_no_x509_validation(&libcrypto_validator));
        EXPECT_OK(s2n_x509_validator_validate_cert_chain(&libcrypto_validator, conn,
                chain_data, chain_len, &libcrypto_pkey_type, &libcrypto_key));

        EXPECT_EQUAL(pkey_type, libcrypto_pkey_type);

        /* Compare the encoded public keys are byte-for-byte equal. */
        uint8_t zc_buf[4096] = { 0 };
        uint8_t lc_buf[4096] = { 0 };
        uint8_t *zc_ptr = zc_buf;
        uint8_t *lc_ptr = lc_buf;
        int zc_len = i2d_PUBKEY(public_key.pkey, &zc_ptr);
        int lc_len = i2d_PUBKEY(libcrypto_key.pkey, &lc_ptr);
        EXPECT_EQUAL(zc_len, lc_len);
        EXPECT_BYTEARRAY_EQUAL(zc_buf, lc_buf, zc_len);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&libcrypto_validator));
        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: read_cert_chain_spans in normal mode transitions to READY_TO_VERIFY */
    {
        struct s2n_x509_trust_store trust_store = { 0 };
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default"));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn, S2N_DEFAULT_TEST_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

        EXPECT_OK(s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                chain_data, chain_len, &pkey_type, NULL));

        /* Normal mode transitions to READY_TO_VERIFY. */
        EXPECT_EQUAL(validator.state, READY_TO_VERIFY);

        /* wire_chain must be allocated and spans parsed. */
        EXPECT_NOT_NULL(validator.wire_chain.data);
        EXPECT_TRUE(validator.wire_chain.size > 0);
        EXPECT_TRUE(validator.chain_spans != NULL);
        EXPECT_TRUE(validator.chain_spans->count > 0);

        /* Verify the span views borrow from wire_chain. */
        for (uint32_t i = 0; i < validator.chain_spans->count; i++) {
            const struct s2n_cert_span_view *view = &validator.chain_spans->views[i];
            EXPECT_TRUE(view->raw.data >= validator.wire_chain.data);
            EXPECT_TRUE(view->raw.data + view->raw.size <= validator.wire_chain.data + validator.wire_chain.size);
        }

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
        s2n_x509_trust_store_wipe(&trust_store);
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: max_chain_depth is enforced in non-skip mode */
    {
        struct s2n_x509_trust_store trust_store = { 0 };
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));
        /* Set max depth to 1 — a multi-cert chain should be rejected. */
        EXPECT_SUCCESS(s2n_x509_validator_set_max_chain_depth(&validator, 1));

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default"));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn, S2N_DEFAULT_TEST_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                        chain_data, chain_len, &pkey_type, NULL),
                S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
        s2n_x509_trust_store_wipe(&trust_store);
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: skip mode tolerates max_chain_depth being exceeded */
    {
        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init_no_x509_validation(&validator));
        EXPECT_SUCCESS(s2n_x509_validator_set_max_chain_depth(&validator, 1));

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default"));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn, S2N_DEFAULT_TEST_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        DEFER_CLEANUP(struct s2n_pkey public_key = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

        /* Skip mode should still succeed (only reads the first cert). */
        EXPECT_OK(s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                chain_data, chain_len, &pkey_type, &public_key));

        EXPECT_EQUAL(pkey_type, S2N_PKEY_TYPE_RSA);
        EXPECT_NOT_NULL(public_key.pkey);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: state must be INIT */
    {
        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init_no_x509_validation(&validator));
        /* Force an invalid state. */
        validator.state = VALIDATED;

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        DEFER_CLEANUP(struct s2n_pkey public_key = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key));

        uint8_t dummy = 0;
        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                        &dummy, 0, &pkey_type, &public_key),
                S2N_ERR_INVALID_CERT_STATE);

        /* Restore state for clean wipe. */
        validator.state = INIT;
        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: empty chain body is rejected */
    {
        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init_no_x509_validation(&validator));

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);

        DEFER_CLEANUP(struct s2n_pkey public_key = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

        /* Pass a zero-length chain. */
        uint8_t empty_buf[1] = { 0 };
        EXPECT_ERROR_WITH_ERRNO(
                s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                        empty_buf, 0, &pkey_type, &public_key),
                S2N_ERR_NO_CERT_FOUND);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: ECDSA cert chain also works (algorithm agility) */
    {
        const char *ecdsa_chain = "../pems/permutations/ec_ecdsa_p256_sha256/server-chain.pem";

        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init_no_x509_validation(&validator));

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default"));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn, ecdsa_chain, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        DEFER_CLEANUP(struct s2n_pkey public_key = { 0 }, s2n_pkey_free);
        EXPECT_SUCCESS(s2n_pkey_zero_init(&public_key));
        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;

        EXPECT_OK(s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                chain_data, chain_len, &pkey_type, &public_key));

        EXPECT_EQUAL(pkey_type, S2N_PKEY_TYPE_ECDSA);
        EXPECT_NOT_NULL(public_key.pkey);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test: wire_chain contains exact concatenation of DER cert bytes */
    {
        struct s2n_x509_trust_store trust_store = { 0 };
        s2n_x509_trust_store_init_empty(&trust_store);
        EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        struct s2n_x509_validator validator = { 0 };
        EXPECT_SUCCESS(s2n_x509_validator_init(&validator, &trust_store, 0));

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default"));

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn, S2N_DEFAULT_TEST_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);
        uint8_t *chain_data = s2n_stuffer_raw_read(&cert_chain_stuffer, chain_len);
        EXPECT_NOT_NULL(chain_data);

        s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_x509_validator_read_cert_chain_spans(&validator, conn,
                chain_data, chain_len, &pkey_type, NULL));

        /* Manually extract DER certs from the TLS-framed data and compare. */
        struct s2n_blob manual_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&manual_blob, chain_data, chain_len));
        struct s2n_stuffer manual_in = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_init(&manual_in, &manual_blob));
        EXPECT_SUCCESS(s2n_stuffer_skip_write(&manual_in, chain_len));

        uint32_t wire_offset = 0;
        while (s2n_stuffer_data_available(&manual_in) > 0) {
            uint32_t cert_size = 0;
            EXPECT_SUCCESS(s2n_stuffer_read_uint24(&manual_in, &cert_size));
            uint8_t *cert_ptr = s2n_stuffer_raw_read(&manual_in, cert_size);
            EXPECT_NOT_NULL(cert_ptr);

            /* Compare against wire_chain at the expected offset. */
            EXPECT_BYTEARRAY_EQUAL(validator.wire_chain.data + wire_offset, cert_ptr, cert_size);
            wire_offset += cert_size;
        }
        EXPECT_EQUAL(wire_offset, validator.wire_chain.size);

        EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
        s2n_x509_trust_store_wipe(&trust_store);
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    END_TEST();
}

#else /* !S2N_LIBCRYPTO_SUPPORTS_CBS */

int main(int argc, char **argv)
{
    BEGIN_TEST();
    /* This test exercises CBS-gated zero-copy code; nothing to test on builds
     * without CBS support (system OpenSSL). */
    END_TEST();
}

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */
