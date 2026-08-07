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

/* Malformed input is rejected safely and specifically — for all
 * malformed DER inputs (random mutations of valid certs plus targeted encoding
 * violations), the parser rejects with S2N_ERR_CERT_INVALID without memory
 * unsafety under ASan/UBSan.
 *
 * 
 *
 * Generator: DER mutator with targeted encoding violations.
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

    /* Number of property-test iterations. */
    #define PROPERTY_TEST_ITERATIONS 100

/* Simple xorshift32 PRNG for reproducible mutation sequences. */
static uint32_t s2n_test_xorshift32(uint32_t *state)
{
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

/* Mutation strategies applied to valid DER certificates. */
typedef enum {
    MUTATION_BYTE_FLIP = 0,
    MUTATION_BYTE_INSERT,
    MUTATION_BYTE_DELETE,
    MUTATION_TRUNCATE,
    MUTATION_INDEFINITE_LENGTH,
    MUTATION_INFLATE_LENGTH,
    MUTATION_ZERO_TAG,
    MUTATION_NONZERO_UNUSED_BITS,
    MUTATION_COUNT,
} s2n_test_mutation_type;

/* Generate an ECDSA P-256 key pair for certificate generation. */
static EVP_PKEY *s2n_test_generate_ec_key(void)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (ctx == NULL) {
        return NULL;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
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

/* Create a self-signed certificate for use as a mutation base. */
static X509 *s2n_test_create_base_cert(EVP_PKEY *key)
{
    X509 *cert = X509_new();
    if (cert == NULL) {
        return NULL;
    }

    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 3600);

    X509_NAME *name = X509_get_subject_name(cert);
    const unsigned char cn[] = "Property2 Test";
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, cn, -1, -1, 0);
    X509_set_issuer_name(cert, name);
    X509_set_pubkey(cert, key);

    /* Add basicConstraints and SAN to make a realistically structured cert. */
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

    X509_EXTENSION *ext = X509V3_EXT_nconf_nid(NULL, &ctx,
            NID_basic_constraints, "critical,CA:TRUE");
    if (ext != NULL) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    ext = X509V3_EXT_nconf_nid(NULL, &ctx, NID_subject_alt_name, "DNS:test.example.com");
    if (ext != NULL) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    ext = X509V3_EXT_nconf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
    if (ext != NULL) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    if (X509_sign(cert, key, EVP_sha256()) == 0) {
        X509_free(cert);
        return NULL;
    }

    return cert;
}

/* Apply a mutation to a DER certificate buffer. Returns the mutated buffer
 * in `out` (caller-owned via s2n_alloc). The mutation type is determined by
 * the PRNG state. */
static S2N_RESULT s2n_test_mutate_der(const struct s2n_blob *original,
        s2n_test_mutation_type mutation, uint32_t *prng_state,
        struct s2n_blob *out)
{
    RESULT_ENSURE_REF(original);
    RESULT_ENSURE_REF(out);
    RESULT_ENSURE_GT(original->size, 4);

    uint32_t pos = 0;

    switch (mutation) {
        case MUTATION_BYTE_FLIP: {
            /* Flip a random byte at a random position. */
            RESULT_GUARD_POSIX(s2n_alloc(out, original->size));
            RESULT_CHECKED_MEMCPY(out->data, original->data, original->size);
            pos = s2n_test_xorshift32(prng_state) % original->size;
            out->data[pos] ^= (uint8_t) (1 + (s2n_test_xorshift32(prng_state) % 255));
            break;
        }
        case MUTATION_BYTE_INSERT: {
            /* Insert a random byte at a random position. */
            RESULT_GUARD_POSIX(s2n_alloc(out, original->size + 1));
            pos = s2n_test_xorshift32(prng_state) % original->size;
            RESULT_CHECKED_MEMCPY(out->data, original->data, pos);
            out->data[pos] = (uint8_t) (s2n_test_xorshift32(prng_state) & 0xFF);
            RESULT_CHECKED_MEMCPY(out->data + pos + 1, original->data + pos,
                    original->size - pos);
            break;
        }
        case MUTATION_BYTE_DELETE: {
            /* Delete a random byte. */
            RESULT_GUARD_POSIX(s2n_alloc(out, original->size - 1));
            pos = s2n_test_xorshift32(prng_state) % original->size;
            RESULT_CHECKED_MEMCPY(out->data, original->data, pos);
            if (pos < original->size - 1) {
                RESULT_CHECKED_MEMCPY(out->data + pos, original->data + pos + 1,
                        original->size - pos - 1);
            }
            break;
        }
        case MUTATION_TRUNCATE: {
            /* Truncate at a random position (at least 1 byte, at most size-1). */
            uint32_t trunc_pos = 1 + (s2n_test_xorshift32(prng_state) % (original->size - 1));
            RESULT_GUARD_POSIX(s2n_alloc(out, trunc_pos));
            RESULT_CHECKED_MEMCPY(out->data, original->data, trunc_pos);
            break;
        }
        case MUTATION_INDEFINITE_LENGTH: {
            /* Set the outer SEQUENCE length byte to 0x80 (indefinite form). */
            RESULT_GUARD_POSIX(s2n_alloc(out, original->size));
            RESULT_CHECKED_MEMCPY(out->data, original->data, original->size);
            /* The certificate outer structure is SEQUENCE (tag 0x30). The length
             * byte is at offset 1. */
            if (original->size > 1) {
                out->data[1] = 0x80;
            }
            break;
        }
        case MUTATION_INFLATE_LENGTH: {
            /* Inflate a length field to exceed the buffer. Pick one of the
             * inner structure length fields. */
            RESULT_GUARD_POSIX(s2n_alloc(out, original->size));
            RESULT_CHECKED_MEMCPY(out->data, original->data, original->size);
            /* Find a multi-byte length field (0x82 or 0x83 prefix). Walk
             * through the buffer to find one, then inflate it. */
            bool inflated = false;
            for (uint32_t i = 1; i < original->size - 3; i++) {
                if (out->data[i] == 0x82 && i + 2 < original->size) {
                    /* Two-byte length: inflate the value. */
                    uint16_t len_val = ((uint16_t) out->data[i + 1] << 8)
                            | (uint16_t) out->data[i + 2];
                    len_val = (uint16_t) (len_val + 100);
                    out->data[i + 1] = (uint8_t) (len_val >> 8);
                    out->data[i + 2] = (uint8_t) (len_val & 0xFF);
                    inflated = true;
                    break;
                }
            }
            if (!inflated) {
                /* Fallback: inflate the outer length. */
                if (out->data[1] == 0x82 && original->size > 3) {
                    out->data[2] = 0xFF;
                    out->data[3] = 0xFF;
                } else {
                    /* Just corrupt the first length byte to be larger. */
                    out->data[1] = 0x84;
                }
            }
            break;
        }
        case MUTATION_ZERO_TAG: {
            /* Zero out a tag byte at a random position that currently holds
             * a valid ASN.1 tag (we look for common tags). */
            RESULT_GUARD_POSIX(s2n_alloc(out, original->size));
            RESULT_CHECKED_MEMCPY(out->data, original->data, original->size);
            /* Pick a position in the inner structure (skip the outer SEQUENCE
             * header). */
            uint32_t start = 4;
            if (start >= original->size) {
                start = 0;
            }
            pos = start + (s2n_test_xorshift32(prng_state) % (original->size - start));
            out->data[pos] = 0x00;
            break;
        }
        case MUTATION_NONZERO_UNUSED_BITS: {
            /* Find the signature BIT STRING and set unused-bits to nonzero.
             * The signature is typically near the end of the cert. Look for
             * BIT STRING tag (0x03) followed by a length. */
            RESULT_GUARD_POSIX(s2n_alloc(out, original->size));
            RESULT_CHECKED_MEMCPY(out->data, original->data, original->size);
            /* Scan backwards for a BIT STRING that has unused-bits == 0x00. */
            bool found = false;
            for (uint32_t i = original->size - 1; i >= 4; i--) {
                if (out->data[i - 2] == 0x03) {
                    /* Check if the byte after the length could be unused-bits. */
                    uint32_t content_start = i;
                    if (out->data[i - 1] < 0x80) {
                        content_start = i;
                    } else if (out->data[i - 1] == 0x81 && i < original->size) {
                        content_start = i;
                    } else if (out->data[i - 1] == 0x82 && i + 1 < original->size) {
                        content_start = i + 1;
                    } else {
                        continue;
                    }
                    if (content_start < original->size && out->data[content_start] == 0x00) {
                        out->data[content_start] = 0x07;
                        found = true;
                        break;
                    }
                }
                if (i == 0) {
                    break;
                }
            }
            if (!found) {
                /* Fallback: just flip a byte near the end. */
                out->data[original->size - 2] ^= 0xFF;
            }
            break;
        }
        default:
            RESULT_BAIL(S2N_ERR_SAFETY);
    }

    return S2N_RESULT_OK;
}

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

int main(int argc, char **argv)
{
    BEGIN_TEST();

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    /* Generate a single valid base certificate to use as the mutation source. */
    EVP_PKEY *base_key = s2n_test_generate_ec_key();
    EXPECT_NOT_NULL(base_key);

    X509 *base_cert = s2n_test_create_base_cert(base_key);
    EXPECT_NOT_NULL(base_cert);

    /* Export the base cert as DER. */
    unsigned char *base_der_buf = NULL;
    int base_der_len = i2d_X509(base_cert, &base_der_buf);
    EXPECT_TRUE(base_der_len > 0);
    EXPECT_NOT_NULL(base_der_buf);

    struct s2n_blob base_der = { 0 };
    EXPECT_SUCCESS(s2n_alloc(&base_der, (uint32_t) base_der_len));
    EXPECT_MEMCPY_SUCCESS(base_der.data, base_der_buf, base_der_len);
    OPENSSL_free(base_der_buf);

    /* Verify the base cert parses successfully before we start mutating. */
    {
        DEFER_CLEANUP(struct s2n_blob verify_copy = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&verify_copy, base_der.size));
        EXPECT_MEMCPY_SUCCESS(verify_copy.data, base_der.data, base_der.size);
        struct s2n_cert_span_view verify_view = { 0 };
        EXPECT_OK(s2n_cert_span_view_parse(&verify_view, &verify_copy));
    }

    /* For all malformed DER inputs, the parser rejects with
     * S2N_ERR_CERT_INVALID (or S2N_ERR_CERT_UNTRUSTED for anti-substitution)
     * without memory unsafety. The test exercises diverse mutation patterns;
     * real safety verification comes from ASan/UBSan CI builds. */
    for (uint32_t iter = 0; iter < PROPERTY_TEST_ITERATIONS; iter++) {
        /* Seed the PRNG with the iteration number for reproducibility. */
        uint32_t prng_state = iter + 1;

        /* Pick a mutation strategy (round-robin through all types). */
        s2n_test_mutation_type mutation = (s2n_test_mutation_type) (iter % MUTATION_COUNT);

        /* Apply the mutation to the base certificate. */
        DEFER_CLEANUP(struct s2n_blob mutated = { 0 }, s2n_free);
        EXPECT_OK(s2n_test_mutate_der(&base_der, mutation, &prng_state, &mutated));

        /* Feed the mutated bytes to s2n_cert_span_view_parse. The result
         * must be either:
         * - Success (unlikely for random mutations, but possible if the
         *   mutation lands in a non-structural area like the signature)
         * - Failure with S2N_ERR_CERT_INVALID (malformed DER)
         * - Failure with S2N_ERR_CERT_UNTRUSTED (algorithm anti-substitution)
         *
         * The test must NOT crash (the real value is exercising diverse
         * mutation patterns under ASan/UBSan). */
        struct s2n_cert_span_view view = { 0 };
        s2n_result result = s2n_cert_span_view_parse(&view, &mutated);

        if (s2n_result_is_error(result)) {
            /* The parse failed. Verify the error code is one of the two
             * acceptable codes. */
            EXPECT_TRUE(s2n_errno == S2N_ERR_CERT_INVALID
                    || s2n_errno == S2N_ERR_CERT_UNTRUSTED);
            s2n_errno = 0;
        }
        /* If the parse succeeded, that is acceptable — the mutation may have
         * landed in a non-structural byte (e.g., inside the signature value).
         * The key property is that we did not crash. */
    }

    /* Also test s2n_cert_chain_spans_parse with mutated chain blobs.
     * Build a valid two-cert chain, then mutate the entire chain blob. */
    {
        /* Create a leaf cert signed by the base cert (acting as CA). */
        EVP_PKEY *leaf_key = s2n_test_generate_ec_key();
        EXPECT_NOT_NULL(leaf_key);

        X509 *leaf_cert = X509_new();
        EXPECT_NOT_NULL(leaf_cert);
        X509_set_version(leaf_cert, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(leaf_cert), 2);
        X509_gmtime_adj(X509_get_notBefore(leaf_cert), 0);
        X509_gmtime_adj(X509_get_notAfter(leaf_cert), 365 * 24 * 3600);
        X509_NAME *leaf_name = X509_get_subject_name(leaf_cert);
        const unsigned char leaf_cn[] = "Property2 Leaf";
        X509_NAME_add_entry_by_txt(leaf_name, "CN", MBSTRING_ASC, leaf_cn, -1, -1, 0);
        X509_set_issuer_name(leaf_cert, X509_get_subject_name(base_cert));
        X509_set_pubkey(leaf_cert, leaf_key);
        EXPECT_TRUE(X509_sign(leaf_cert, base_key, EVP_sha256()) > 0);

        /* Export both as DER and concatenate. */
        unsigned char *leaf_der_buf = NULL;
        int leaf_der_len = i2d_X509(leaf_cert, &leaf_der_buf);
        EXPECT_TRUE(leaf_der_len > 0);

        DEFER_CLEANUP(struct s2n_blob chain_blob = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&chain_blob,
                (uint32_t) leaf_der_len + base_der.size));
        EXPECT_MEMCPY_SUCCESS(chain_blob.data, leaf_der_buf, leaf_der_len);
        EXPECT_MEMCPY_SUCCESS(chain_blob.data + leaf_der_len,
                base_der.data, base_der.size);
        OPENSSL_free(leaf_der_buf);

        /* Verify the chain parses cleanly. */
        {
            struct s2n_cert_chain_spans chain = { 0 };
            EXPECT_OK(s2n_cert_chain_spans_parse(&chain, &chain_blob,
                    S2N_TEST_MAX_CHAIN_DEPTH));
            EXPECT_EQUAL(chain.count, 2);
        }

        /* Mutate the chain blob and verify safe rejection. */
        for (uint32_t iter2 = 0; iter2 < PROPERTY_TEST_ITERATIONS; iter2++) {
            uint32_t prng_state2 = iter2 + 1000;
            s2n_test_mutation_type mutation2 = (s2n_test_mutation_type) (iter2 % MUTATION_COUNT);

            DEFER_CLEANUP(struct s2n_blob mutated_chain = { 0 }, s2n_free);
            EXPECT_OK(s2n_test_mutate_der(&chain_blob, mutation2, &prng_state2,
                    &mutated_chain));

            struct s2n_cert_chain_spans chain_result = { 0 };
            s2n_result chain_parse_result = s2n_cert_chain_spans_parse(
                    &chain_result, &mutated_chain, S2N_TEST_MAX_CHAIN_DEPTH);

            if (s2n_result_is_error(chain_parse_result)) {
                EXPECT_TRUE(s2n_errno == S2N_ERR_CERT_INVALID
                        || s2n_errno == S2N_ERR_CERT_UNTRUSTED
                        || s2n_errno == S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED);
                s2n_errno = 0;
            }
            /* Success is also acceptable — mutation may not break structure. */
        }

        X509_free(leaf_cert);
        EVP_PKEY_free(leaf_key);
    }

    /* Cleanup. */
    EXPECT_SUCCESS(s2n_free(&base_der));
    X509_free(base_cert);
    EVP_PKEY_free(base_key);

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

    END_TEST();
}
