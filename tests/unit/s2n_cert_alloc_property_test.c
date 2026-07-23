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

/* Zero per-certificate object-graph allocation — for all validated
 * chains on the zero-copy path, no per-certificate X509 object-graph allocation
 * occurs during parse+verify (allocations limited to the single wire_chain copy
 * and the EVP_PKEY materializations for signature verify).
 *
 * 
 *
 * Generator: libcrypto-signed valid-chain generator (algorithm-parameterized).
 * Minimum 100 iterations. */

#include "crypto/s2n_openssl_x509.h"
#include "s2n_test.h"
#include "testlib/s2n_mem_testlib.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cert_parse.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_x509_validator.h"

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    #include <openssl/bn.h>
    #include <openssl/bytestring.h>
    #include <openssl/ec.h>
    #include <openssl/ec_key.h>
    #include <openssl/evp.h>
    #include <openssl/rand.h>
    #include <openssl/x509.h>
    #include <stdint.h>
    #include <string.h>
    #include <time.h>

    #include "tls/s2n_cert_path.h"

    /* Number of property-test iterations. Valgrind slows this test down ~30x,
     * risking the ctest timeout, so scale down under Valgrind; every other
     * job runs the full count. */
    #define PROPERTY_TEST_ITERATIONS (getenv("S2N_VALGRIND") ? 10 : 100)

/* Algorithm families exercised by the generator. */
typedef enum {
    ALG_RSA_2048 = 0,
    ALG_ECDSA_P256,
    ALG_ECDSA_P384,
    ALG_FAMILY_COUNT,
} s2n_test_alg_family;

/* Generate an EVP_PKEY for the given algorithm family. */
static EVP_PKEY *s2n_test_generate_key(s2n_test_alg_family alg)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    switch (alg) {
        case ALG_RSA_2048: {
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
            if (!ctx) {
                return NULL;
            }
            if (EVP_PKEY_keygen_init(ctx) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                return NULL;
            }
            if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                return NULL;
            }
            if (EVP_PKEY_keygen(ctx, &key) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                return NULL;
            }
            EVP_PKEY_CTX_free(ctx);
            return key;
        }
        case ALG_ECDSA_P256:
        case ALG_ECDSA_P384: {
            int nid = (alg == ALG_ECDSA_P256) ? NID_X9_62_prime256v1 : NID_secp384r1;
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
            if (!ctx) {
                return NULL;
            }
            if (EVP_PKEY_keygen_init(ctx) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                return NULL;
            }
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                return NULL;
            }
            if (EVP_PKEY_keygen(ctx, &key) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                return NULL;
            }
            EVP_PKEY_CTX_free(ctx);
            return key;
        }
        default:
            return NULL;
    }
}

/* Build a self-signed X509 CA certificate with the given key. */
static X509 *s2n_test_build_ca_cert(EVP_PKEY *ca_key, s2n_test_alg_family alg)
{
    X509 *cert = X509_new();
    if (!cert) {
        return NULL;
    }

    X509_set_version(cert, 2); /* v3 */
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    /* Validity: 2023-01-01 to 2033-01-01. Our mock clock is 2024-06-01, so
     * these certs are within their validity window. */
    ASN1_TIME_set(X509_get_notBefore(cert), (time_t) 1672531200); /* 2023-01-01 */
    ASN1_TIME_set(X509_get_notAfter(cert), (time_t) 1988150400);  /* 2033-01-01 */

    X509_set_pubkey(cert, ca_key);

    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char *) "Test CA", -1, -1, 0);
    X509_set_issuer_name(cert, name);

    /* Basic constraints: CA:TRUE */
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_nconf_nid(NULL, &ctx, NID_basic_constraints, "critical,CA:TRUE");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    /* Key usage: keyCertSign, cRLSign */
    ext = X509V3_EXT_nconf_nid(NULL, &ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    /* Subject Key Identifier */
    ext = X509V3_EXT_nconf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    const EVP_MD *md = NULL;
    if (alg == ALG_RSA_2048) {
        md = EVP_sha256();
    } else if (alg == ALG_ECDSA_P256) {
        md = EVP_sha256();
    } else {
        md = EVP_sha384();
    }
    X509_sign(cert, ca_key, md);
    return cert;
}

/* Build a leaf certificate signed by the given CA. */
static X509 *s2n_test_build_leaf_cert(EVP_PKEY *leaf_key, EVP_PKEY *ca_key,
        X509 *ca_cert, s2n_test_alg_family alg, int serial)
{
    X509 *cert = X509_new();
    if (!cert) {
        return NULL;
    }

    X509_set_version(cert, 2); /* v3 */
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);

    /* Validity: 2023-01-01 to 2033-01-01. Our mock clock is 2024-06-01. */
    ASN1_TIME_set(X509_get_notBefore(cert), (time_t) 1672531200); /* 2023-01-01 */
    ASN1_TIME_set(X509_get_notAfter(cert), (time_t) 1988150400);  /* 2033-01-01 */

    X509_set_pubkey(cert, leaf_key);

    X509_NAME *subject = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
            (const unsigned char *) "localhost", -1, -1, 0);
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    /* SAN: dNSName = localhost */
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca_cert, cert, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_nconf_nid(NULL, &ctx, NID_subject_alt_name, "DNS:localhost");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    /* EKU: serverAuth */
    ext = X509V3_EXT_nconf_nid(NULL, &ctx, NID_ext_key_usage, "serverAuth");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    const EVP_MD *md = NULL;
    if (alg == ALG_RSA_2048) {
        md = EVP_sha256();
    } else if (alg == ALG_ECDSA_P256) {
        md = EVP_sha256();
    } else {
        md = EVP_sha384();
    }
    X509_sign(cert, ca_key, md);
    return cert;
}

/* Convert X509 to DER bytes in a newly-allocated buffer. Caller frees. */
static int s2n_test_x509_to_der(X509 *cert, uint8_t **out, int *out_len)
{
    *out = NULL;
    *out_len = i2d_X509(cert, out);
    return (*out_len > 0) ? 0 : -1;
}

/* Build a TLS-framed cert chain (3-byte length prefix per cert, plus TLS 1.3
 * 2-byte extensions length of 0 per cert) from an array of X509* certs.
 * Output in `chain_buf`. */
static S2N_RESULT s2n_test_build_tls_chain(X509 **certs, int cert_count,
        struct s2n_stuffer *chain_buf)
{
    for (int i = 0; i < cert_count; i++) {
        uint8_t *der = NULL;
        int der_len = 0;
        RESULT_ENSURE(s2n_test_x509_to_der(certs[i], &der, &der_len) == 0,
                S2N_ERR_ALLOC);
        /* 3-byte length prefix */
        RESULT_GUARD_POSIX(s2n_stuffer_write_uint24(chain_buf, (uint32_t) der_len));
        RESULT_GUARD_POSIX(s2n_stuffer_write_bytes(chain_buf, der, (uint32_t) der_len));
        /* TLS 1.3 per-cert extensions: empty (2 bytes = 0x0000). */
        RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(chain_buf, 0));
        OPENSSL_free(der);
    }
    return S2N_RESULT_OK;
}

/* Wall clock mock: 2024-06-01 00:00:00 UTC = 1717200000 seconds since epoch. */
static int s2n_test_wall_clock(void *data, uint64_t *timestamp)
{
    (void) data;
    *timestamp = (uint64_t) 1717200000 * 1000000000ULL;
    return 0;
}

/* Accept any hostname. */
static uint8_t s2n_test_verify_host_accept(const char *host_name,
        size_t host_name_len, void *data)
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

    /* Zero per-certificate object-graph allocation.
     *
     * For all validated chains on the zero-copy path, steady-state processing
     * (parse through path verification, excluding on-demand materialization and
     * the one-time snapshot build) performs zero libcrypto X509 object-graph
     * allocations. We verify this by checking that cert_chain_from_wire remains
     * NULL after zero-copy validation.
     */
    {
        uint32_t passed = 0;
        uint32_t total = PROPERTY_TEST_ITERATIONS;

        for (uint32_t iter = 0; iter < total; iter++) {
            /* Pick a random algorithm family for this iteration. */
            uint8_t rand_byte = 0;
            EXPECT_SUCCESS(RAND_bytes(&rand_byte, 1));
            s2n_test_alg_family alg = (s2n_test_alg_family) (rand_byte % ALG_FAMILY_COUNT);

            /* Generate a fresh CA key + cert. */
            EVP_PKEY *ca_key = s2n_test_generate_key(alg);
            EXPECT_NOT_NULL(ca_key);
            X509 *ca_cert = s2n_test_build_ca_cert(ca_key, alg);
            EXPECT_NOT_NULL(ca_cert);

            /* Generate a fresh leaf key + cert signed by the CA. */
            EVP_PKEY *leaf_key = s2n_test_generate_key(alg);
            EXPECT_NOT_NULL(leaf_key);
            X509 *leaf_cert = s2n_test_build_leaf_cert(leaf_key, ca_key, ca_cert,
                    alg, (int) (iter + 100));
            EXPECT_NOT_NULL(leaf_cert);

            /* Build a trust store with the CA. */
            DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(),
                    s2n_config_ptr_free);
            EXPECT_NOT_NULL(config);
            EXPECT_SUCCESS(s2n_config_set_wall_clock(config, s2n_test_wall_clock, NULL));
            EXPECT_SUCCESS(s2n_config_set_verify_host_callback(config,
                    s2n_test_verify_host_accept, NULL));
            EXPECT_OK(s2n_config_set_cert_verify_backend(config,
                    S2N_CERT_BACKEND_ZERO_COPY));

            /* Add the CA cert to the trust store. */
            uint8_t *ca_der = NULL;
            int ca_der_len = 0;
            EXPECT_SUCCESS(s2n_test_x509_to_der(ca_cert, &ca_der, &ca_der_len));
            {
                const uint8_t *p = ca_der;
                X509 *ca_for_store = d2i_X509(NULL, &p, ca_der_len);
                EXPECT_NOT_NULL(ca_for_store);
                X509_STORE_add_cert(config->trust_store.trust_store, ca_for_store);
                X509_free(ca_for_store);
            }
            OPENSSL_free(ca_der);

            /* Build a TLS-framed cert chain: [leaf]. */
            DEFER_CLEANUP(struct s2n_stuffer chain_stuffer = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&chain_stuffer, 4096));
            X509 *chain_certs[] = { leaf_cert };
            EXPECT_OK(s2n_test_build_tls_chain(chain_certs, 1, &chain_stuffer));

            uint32_t chain_len = s2n_stuffer_data_available(&chain_stuffer);
            uint8_t *chain_data = s2n_stuffer_raw_read(&chain_stuffer, chain_len);
            EXPECT_NOT_NULL(chain_data);

            /* Set up connection. */
            DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                    s2n_connection_ptr_free);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "default"));

            /* First run to build snapshot (one-time cost excluded from property). */
            {
                struct s2n_x509_validator warmup = { 0 };
                EXPECT_SUCCESS(s2n_x509_validator_init(&warmup,
                        &config->trust_store, 0));
                s2n_pkey_type pt = S2N_PKEY_TYPE_UNKNOWN;
                /* If this fails (e.g., key/chain mismatch), skip to cleanup. */
                s2n_result r = s2n_x509_validator_read_cert_chain_spans(&warmup,
                        conn, chain_data, chain_len, &pt, NULL);
                if (s2n_result_is_ok(r)) {
                    r = s2n_x509_validator_verify_cert_chain_spans(&warmup, conn);
                }
                EXPECT_SUCCESS(s2n_x509_validator_wipe(&warmup));
                if (!s2n_result_is_ok(r)) {
                    /* Chain didn't validate (possible with random generation
                     * timing windows). Still clean up and skip this iter. */
                    EVP_PKEY_free(ca_key);
                    EVP_PKEY_free(leaf_key);
                    X509_free(ca_cert);
                    X509_free(leaf_cert);
                    continue;
                }
            }

            /* Steady-state validation: assert no d2i_X509 allocation. */
            {
                struct s2n_x509_validator validator = { 0 };
                EXPECT_SUCCESS(s2n_x509_validator_init(&validator,
                        &config->trust_store, 0));

                s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
                EXPECT_OK(s2n_x509_validator_read_cert_chain_spans(&validator,
                        conn, chain_data, chain_len, &pkey_type, NULL));
                EXPECT_OK(s2n_x509_validator_verify_cert_chain_spans(&validator,
                        conn));

                /* PROPERTY ASSERTION: cert_chain_from_wire is empty on the
                 * zero-copy path. No d2i_X509 object-graph allocation occurred.
                 * The stack is allocated by s2n_x509_validator_init but no X509
                 * objects were pushed. The only significant allocation is the
                 * wire_chain blob copy. */
                EXPECT_NOT_NULL(validator.cert_chain_from_wire);
                EXPECT_EQUAL(sk_X509_num(validator.cert_chain_from_wire), 0);
                EXPECT_NOT_NULL(validator.wire_chain.data);
                EXPECT_TRUE(validator.wire_chain.size > 0);

                EXPECT_SUCCESS(s2n_x509_validator_wipe(&validator));
            }

            /* Cleanup for this iteration. */
            EVP_PKEY_free(ca_key);
            EVP_PKEY_free(leaf_key);
            X509_free(ca_cert);
            X509_free(leaf_cert);

            passed++;
        }

        /* Every iteration must pass. The generated certs use wide validity
         * windows, so the skip path (a chain failing to validate) is not
         * expected in practice. Compare against the actual iteration count,
         * which is reduced under Valgrind. */
        EXPECT_EQUAL(passed, total);
    };

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

    END_TEST();
}
