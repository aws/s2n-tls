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

/* Span parse round-trip and provenance — for all well-formed DER
 * certificates in a wire chain, every span is an exact in-bounds sub-range of
 * the retained wire blob (no copies) and re-reading spans reproduces the
 * original DER bytes.
 *
 * 
 *
 * Generator: libcrypto-signed valid-chain generator (algorithm-parameterized).
 * Minimum 100 iterations. */

#include "crypto/s2n_openssl_x509.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cert_parse.h"

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    #include <openssl/bn.h>
    #include <openssl/bytestring.h>
    #include <openssl/ec.h>
    #include <openssl/ec_key.h>
    #include <openssl/evp.h>
    #include <openssl/obj.h>
    #include <openssl/rand.h>
    #include <openssl/x509.h>
    #include <stdint.h>
    #include <string.h>

    /* Mirror the validator's default max chain depth. */
    #define S2N_TEST_MAX_CHAIN_DEPTH 7

    /* Number of property-test iterations. Each iteration generates a fresh
     * certificate chain with a random algorithm family. Valgrind slows this
     * down ~30x, risking the ctest timeout, so scale down under Valgrind;
     * every other job runs the full count. */
    #define PROPERTY_TEST_ITERATIONS (getenv("S2N_VALGRIND") ? 10 : 100)

/* Algorithm families exercised by the generator. */
typedef enum {
    ALG_RSA_2048 = 0,
    ALG_RSA_4096,
    ALG_ECDSA_P256,
    ALG_ECDSA_P384,
    ALG_FAMILY_COUNT,
} s2n_test_alg_family;

/* Generate an EVP_PKEY for the given algorithm family. Returns NULL on failure. */
static EVP_PKEY *s2n_test_generate_key(s2n_test_alg_family alg)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    switch (alg) {
        case ALG_RSA_2048:
        case ALG_RSA_4096: {
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
            if (ctx == NULL) {
                return NULL;
            }
            if (EVP_PKEY_keygen_init(ctx) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                return NULL;
            }
            int bits = (alg == ALG_RSA_2048) ? 2048 : 4096;
            if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
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
            if (ctx == NULL) {
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

/* Get the appropriate digest for signing based on algorithm family. */
static const EVP_MD *s2n_test_get_digest(s2n_test_alg_family alg)
{
    switch (alg) {
        case ALG_RSA_2048:
        case ALG_RSA_4096:
        case ALG_ECDSA_P256:
            return EVP_sha256();
        case ALG_ECDSA_P384:
            return EVP_sha384();
        default:
            return EVP_sha256();
    }
}

/* Create a self-signed CA certificate with the given key. The caller must
 * free the returned X509. Returns NULL on failure. */
static X509 *s2n_test_create_ca_cert(EVP_PKEY *ca_key, s2n_test_alg_family alg,
        uint32_t serial_num)
{
    X509 *cert = X509_new();
    if (cert == NULL) {
        return NULL;
    }

    /* Version 3 (value 2) */
    X509_set_version(cert, 2);

    /* Serial number */
    ASN1_INTEGER_set(X509_get_serialNumber(cert), (long) serial_num);

    /* Validity: 1 year from now */
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 3600);

    /* Subject and issuer (self-signed) */
    X509_NAME *name = X509_get_subject_name(cert);
    const unsigned char ca_cn[] = "Test CA";
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            ca_cn, -1, -1, 0);
    X509_set_issuer_name(cert, name);

    /* Public key */
    X509_set_pubkey(cert, ca_key);

    /* Basic Constraints: CA:TRUE */
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_nconf_nid(NULL, &ctx,
            NID_basic_constraints, "critical,CA:TRUE");
    if (ext != NULL) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    /* Subject Key Identifier */
    ext = X509V3_EXT_nconf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
    if (ext != NULL) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    /* Sign */
    const EVP_MD *md = s2n_test_get_digest(alg);
    if (X509_sign(cert, ca_key, md) == 0) {
        X509_free(cert);
        return NULL;
    }

    return cert;
}

/* Create a leaf certificate signed by the CA. The caller must free the
 * returned X509. Returns NULL on failure. */
static X509 *s2n_test_create_leaf_cert(EVP_PKEY *leaf_key, EVP_PKEY *ca_key,
        X509 *ca_cert, s2n_test_alg_family alg, uint32_t serial_num)
{
    X509 *cert = X509_new();
    if (cert == NULL) {
        return NULL;
    }

    /* Version 3 */
    X509_set_version(cert, 2);

    /* Serial number */
    ASN1_INTEGER_set(X509_get_serialNumber(cert), (long) serial_num);

    /* Validity: 1 year from now */
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 3600);

    /* Subject */
    X509_NAME *name = X509_get_subject_name(cert);
    const unsigned char leaf_cn[] = "Test Leaf";
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            leaf_cn, -1, -1, 0);

    /* Issuer from CA */
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    /* Public key */
    X509_set_pubkey(cert, leaf_key);

    /* Subject Alternative Name */
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, ca_cert, cert, NULL, NULL, 0);
    X509_EXTENSION *ext = X509V3_EXT_nconf_nid(NULL, &ctx,
            NID_subject_alt_name, "DNS:localhost");
    if (ext != NULL) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    /* Basic Constraints: CA:FALSE (explicitly) */
    ext = X509V3_EXT_nconf_nid(NULL, &ctx, NID_basic_constraints, "CA:FALSE");
    if (ext != NULL) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    /* Sign with CA key */
    const EVP_MD *md = s2n_test_get_digest(alg);
    if (X509_sign(cert, ca_key, md) == 0) {
        X509_free(cert);
        return NULL;
    }

    return cert;
}

/* Export an X509 as DER bytes into an s2n_blob. The blob must be freed by the
 * caller with s2n_free. Returns S2N_RESULT_OK on success. */
static S2N_RESULT s2n_test_x509_to_der(X509 *cert, struct s2n_blob *der_out)
{
    RESULT_ENSURE_REF(cert);
    RESULT_ENSURE_REF(der_out);

    unsigned char *buf = NULL;
    int len = i2d_X509(cert, &buf);
    RESULT_ENSURE_GT(len, 0);
    RESULT_ENSURE_REF(buf);

    RESULT_GUARD_POSIX(s2n_alloc(der_out, (uint32_t) len));
    RESULT_CHECKED_MEMCPY(der_out->data, buf, len);
    OPENSSL_free(buf);
    return S2N_RESULT_OK;
}

/* Assert that `span` is an exact in-bounds sub-range of `base` (provenance).
 * The span's data pointer must be >= base->data and span must not extend past
 * base->data + base->size. */
static S2N_RESULT s2n_test_assert_span_provenance(const struct s2n_blob *span,
        const struct s2n_blob *base)
{
    RESULT_ENSURE_REF(span->data);
    RESULT_ENSURE_REF(base->data);
    RESULT_ENSURE_GTE((uintptr_t) span->data, (uintptr_t) base->data);
    RESULT_ENSURE_LTE((uintptr_t) (span->data + span->size),
            (uintptr_t) (base->data + base->size));
    return S2N_RESULT_OK;
}

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

int main(int argc, char **argv)
{
    BEGIN_TEST();

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    /* Span parse round-trip and provenance — for all well-formed
     * DER certificates in a wire chain, every span is an exact in-bounds
     * sub-range of the retained wire blob (no copies) and re-reading spans
     * reproduces the original DER bytes. */
    for (uint32_t iter = 0; iter < PROPERTY_TEST_ITERATIONS; iter++) {
        /* Pick an algorithm family for this iteration (round-robin). */
        s2n_test_alg_family alg = (s2n_test_alg_family) (iter % ALG_FAMILY_COUNT);

        /* Generate CA key and self-signed CA cert. */
        EVP_PKEY *ca_key = s2n_test_generate_key(alg);
        EXPECT_NOT_NULL(ca_key);

        X509 *ca_cert = s2n_test_create_ca_cert(ca_key, alg, iter * 2 + 1);
        EXPECT_NOT_NULL(ca_cert);

        /* Generate leaf key and leaf cert signed by the CA. */
        EVP_PKEY *leaf_key = s2n_test_generate_key(alg);
        EXPECT_NOT_NULL(leaf_key);

        X509 *leaf_cert = s2n_test_create_leaf_cert(leaf_key, ca_key, ca_cert, alg, iter * 2 + 2);
        EXPECT_NOT_NULL(leaf_cert);

        /* Export both certs as DER. */
        DEFER_CLEANUP(struct s2n_blob leaf_der = { 0 }, s2n_free);
        EXPECT_OK(s2n_test_x509_to_der(leaf_cert, &leaf_der));

        DEFER_CLEANUP(struct s2n_blob ca_der = { 0 }, s2n_free);
        EXPECT_OK(s2n_test_x509_to_der(ca_cert, &ca_der));

        /* Concatenate into a wire chain (leaf first, then CA). */
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&wire_chain, leaf_der.size + ca_der.size));
        EXPECT_MEMCPY_SUCCESS(wire_chain.data, leaf_der.data, leaf_der.size);
        EXPECT_MEMCPY_SUCCESS(wire_chain.data + leaf_der.size, ca_der.data, ca_der.size);

        /* Parse the wire chain. */
        struct s2n_cert_chain_spans chain = { 0 };
        EXPECT_OK(s2n_cert_chain_spans_parse(&chain, &wire_chain, S2N_TEST_MAX_CHAIN_DEPTH));
        EXPECT_EQUAL(chain.count, 2);

        /* For each certificate view, verify the provenance and round-trip
         * properties. */
        uint8_t *cursor = wire_chain.data;
        for (uint32_t i = 0; i < chain.count; i++) {
            struct s2n_cert_span_view *view = &chain.views[i];

            /* raw span covers the expected position in the wire chain. */
            EXPECT_EQUAL(view->raw.data, cursor);
            EXPECT_TRUE(view->raw.size > 0);
            EXPECT_OK(s2n_test_assert_span_provenance(&view->raw, &wire_chain));

            /* Round-trip: raw bytes in the wire chain match the original DER. */
            const struct s2n_blob *expected_der = (i == 0) ? &leaf_der : &ca_der;
            EXPECT_EQUAL(view->raw.size, expected_der->size);
            EXPECT_BYTEARRAY_EQUAL(view->raw.data, expected_der->data, expected_der->size);

            /* Every mandatory span is non-empty and borrows from the raw span
             * (which itself is in the wire blob). */
            const struct s2n_blob *mandatory_spans[] = {
                &view->tbs, &view->outer_sig_alg, &view->inner_sig_alg,
                &view->sig, &view->serial, &view->issuer, &view->validity,
                &view->subject, &view->spki
            };
            for (size_t j = 0; j < s2n_array_len(mandatory_spans); j++) {
                EXPECT_TRUE(mandatory_spans[j]->size > 0);
                EXPECT_OK(s2n_test_assert_span_provenance(mandatory_spans[j], &view->raw));
            }

            /* The TBS span keeps its TLV header (SEQUENCE tag 0x30). */
            EXPECT_EQUAL(view->tbs.data[0], 0x30);

            /* Outer and inner AlgorithmIdentifier must be byte-for-byte equal
             * in a well-formed certificate. */
            EXPECT_EQUAL(view->outer_sig_alg.size, view->inner_sig_alg.size);
            EXPECT_BYTEARRAY_EQUAL(view->outer_sig_alg.data,
                    view->inner_sig_alg.data, view->outer_sig_alg.size);

            /* Version 3 certificates (both CA and leaf). */
            EXPECT_EQUAL(view->version, 2);

            /* Validity times: notBefore < notAfter and both are non-zero (we
             * just created them with not-before = now). */
            EXPECT_TRUE(view->not_before > 0);
            EXPECT_TRUE(view->not_after > view->not_before);

            /* Extensions span must be present (our certs are v3 with extensions). */
            EXPECT_NOT_NULL(view->extensions.data);
            EXPECT_OK(s2n_test_assert_span_provenance(&view->extensions, &view->raw));

            /* Optional extension spans that we know are present: */
            if (i == 0) {
                /* Leaf has SAN */
                EXPECT_NOT_NULL(view->san.data);
                EXPECT_OK(s2n_test_assert_span_provenance(&view->san, &view->raw));
            }
            if (i == 1) {
                /* CA has basicConstraints */
                EXPECT_TRUE(view->basic_constraints_present);
                EXPECT_TRUE(view->basic_constraints_is_ca);
                /* CA has SKID */
                EXPECT_NOT_NULL(view->skid.data);
                EXPECT_OK(s2n_test_assert_span_provenance(&view->skid, &view->raw));
            }

            cursor += view->raw.size;
        }

        /* The chain consumed the wire blob exactly (no gaps, no trailing bytes). */
        EXPECT_EQUAL(cursor, wire_chain.data + wire_chain.size);

        /* Also verify single-cert parse round-trip: parse each cert independently
         * and confirm the spans match those from the chain parse. */
        {
            struct s2n_cert_span_view single_view = { 0 };
            DEFER_CLEANUP(struct s2n_blob leaf_copy = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&leaf_copy, leaf_der.size));
            EXPECT_MEMCPY_SUCCESS(leaf_copy.data, leaf_der.data, leaf_der.size);
            EXPECT_OK(s2n_cert_span_view_parse(&single_view, &leaf_copy));

            /* Sizes must match. */
            EXPECT_EQUAL(single_view.raw.size, chain.views[0].raw.size);
            EXPECT_EQUAL(single_view.tbs.size, chain.views[0].tbs.size);
            EXPECT_EQUAL(single_view.sig.size, chain.views[0].sig.size);
            EXPECT_EQUAL(single_view.serial.size, chain.views[0].serial.size);
            EXPECT_EQUAL(single_view.issuer.size, chain.views[0].issuer.size);
            EXPECT_EQUAL(single_view.subject.size, chain.views[0].subject.size);
            EXPECT_EQUAL(single_view.spki.size, chain.views[0].spki.size);

            /* Content round-trip: the bytes in the standalone parse match the
             * original DER. */
            EXPECT_BYTEARRAY_EQUAL(single_view.tbs.data, leaf_copy.data + (chain.views[0].tbs.data - chain.views[0].raw.data),
                    single_view.tbs.size);
        }

        /* Cleanup OpenSSL objects. */
        X509_free(leaf_cert);
        X509_free(ca_cert);
        EVP_PKEY_free(leaf_key);
        EVP_PKEY_free(ca_key);
    }

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

    END_TEST();
}
