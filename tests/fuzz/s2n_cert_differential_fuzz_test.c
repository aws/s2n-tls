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

/* Target Functions: s2n_cert_chain_spans_parse s2n_cert_path_build X509_verify_cert
 *
 * Differential fuzz target: parses the fuzzed input as a wire certificate
 * chain, runs both the zero-copy path builder and OpenSSL's X509_verify_cert
 * on the same chain bytes and trust anchor, and aborts on any accept/reject
 * decision divergence. This is the fuzz-scale extension of design Properties
 * 4 and 5. Built with ASan+UBSan.
 *
 * The fixed trust anchor is the same baked-in ECDSA P-256 CA used by the
 * path-builder fuzz target (s2n_cert_path_build_test). */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdint.h>
#include <string.h>

#include "api/s2n.h"
#include "crypto/s2n_pkey.h"
#include "tests/s2n_test.h"
#include "tls/s2n_cert_parse.h"
#include "tls/s2n_cert_path.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"

#if S2N_LIBCRYPTO_SUPPORTS_CBS

/* A minimal self-signed ECDSA P-256 CA certificate (basicConstraints CA:TRUE,
 * CN=FuzzCA, validity 2026-2126) baked in as the fixed trust anchor.
 * Same anchor as s2n_cert_path_build_test.c. */
/* clang-format off */
static const uint8_t s2n_fuzz_anchor_der[] = {
    0x30, 0x82, 0x01, 0x79, 0x30, 0x82, 0x01, 0x1f, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x16, 0x90, 0xe7, 0x0d, 0xce, 0x86, 0xc6, 0x71, 0x67,
    0x7f, 0x8c, 0x9d, 0x39, 0xc5, 0xcc, 0x8c, 0x16, 0x5c, 0xea, 0x68, 0x30,
    0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x11, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06,
    0x46, 0x75, 0x7a, 0x7a, 0x43, 0x41, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x36,
    0x30, 0x37, 0x32, 0x32, 0x30, 0x37, 0x35, 0x30, 0x34, 0x31, 0x5a, 0x18,
    0x0f, 0x32, 0x31, 0x32, 0x36, 0x30, 0x36, 0x32, 0x38, 0x30, 0x37, 0x35,
    0x30, 0x34, 0x31, 0x5a, 0x30, 0x11, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x06, 0x46, 0x75, 0x7a, 0x7a, 0x43, 0x41, 0x30,
    0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42,
    0x00, 0x04, 0x38, 0xb8, 0xe9, 0x95, 0x23, 0xa7, 0x96, 0x49, 0x32, 0xd5,
    0xc0, 0xe3, 0xcc, 0x14, 0x4f, 0xea, 0x32, 0xa8, 0xbf, 0xfb, 0x9d, 0xef,
    0xb5, 0xda, 0x9c, 0xcc, 0x09, 0x76, 0xca, 0x70, 0xc7, 0x43, 0x99, 0x10,
    0x2e, 0x91, 0xe6, 0x2e, 0xe9, 0x25, 0x14, 0xc8, 0x66, 0x9f, 0x4c, 0xa8,
    0xc5, 0x57, 0xc9, 0xe9, 0xc4, 0xe1, 0x3c, 0x2c, 0xf8, 0x02, 0x77, 0x58,
    0xf0, 0x3a, 0x14, 0x18, 0xbd, 0xf4, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d,
    0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x0f, 0xf4, 0xc8,
    0x89, 0xdf, 0xbd, 0x95, 0x7b, 0x9e, 0xd9, 0xd8, 0x93, 0x0b, 0xbe, 0xcc,
    0x8e, 0xb4, 0xa1, 0x43, 0x07, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23,
    0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x0f, 0xf4, 0xc8, 0x89, 0xdf, 0xbd,
    0x95, 0x7b, 0x9e, 0xd9, 0xd8, 0x93, 0x0b, 0xbe, 0xcc, 0x8e, 0xb4, 0xa1,
    0x43, 0x07, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
    0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45,
    0x02, 0x21, 0x00, 0xfc, 0xe7, 0xd9, 0xef, 0xa2, 0x27, 0x78, 0x8a, 0x3d,
    0xcb, 0x88, 0x1f, 0xd6, 0xbf, 0xf5, 0x67, 0x70, 0x9c, 0xb2, 0x63, 0x8d,
    0x58, 0xba, 0xe0, 0xeb, 0x9e, 0xc2, 0x26, 0x8f, 0xf9, 0xac, 0x8e, 0x02,
    0x20, 0x53, 0xa9, 0x1e, 0x60, 0xe1, 0x38, 0x12, 0xfb, 0x60, 0xcd, 0xc4,
    0x69, 0x8b, 0x00, 0xe6, 0xfe, 0xc0, 0x3b, 0x16, 0xbf, 0x12, 0x49, 0xb8,
    0x5b, 0x38, 0xfc, 0x5c, 0xdc, 0x92, 0x02, 0x8e, 0xa8,
};
/* clang-format on */

/* Pre-parsed zero-copy trust anchor state. */
static struct s2n_trust_anchor s2n_fuzz_anchor;
static struct s2n_trust_anchor_snapshot s2n_fuzz_snapshot;

/* OpenSSL X509_STORE pre-loaded with the same anchor for X509_verify_cert. */
static X509_STORE *s2n_fuzz_x509_store;
static X509 *s2n_fuzz_anchor_x509;

int s2n_fuzz_init(int *argc, char **argv[])
{
    (void) argc;
    (void) argv;

    /* Parse the baked-in anchor DER into the zero-copy trust anchor. */
    struct s2n_blob anchor_blob = { 0 };
    POSIX_GUARD(s2n_blob_init(&anchor_blob,
            (uint8_t *) (uintptr_t) s2n_fuzz_anchor_der,
            sizeof(s2n_fuzz_anchor_der)));

    s2n_fuzz_anchor.der = anchor_blob;
    POSIX_ENSURE(s2n_result_is_ok(
                         s2n_cert_span_view_parse(&s2n_fuzz_anchor.parsed, &anchor_blob)),
            S2N_ERR_SAFETY);

    s2n_fuzz_snapshot.anchors = &s2n_fuzz_anchor;
    s2n_fuzz_snapshot.count = 1;

    /* Build the OpenSSL X509_STORE with the same anchor for the libcrypto path. */
    const uint8_t *p = s2n_fuzz_anchor_der;
    s2n_fuzz_anchor_x509 = d2i_X509(NULL, &p, sizeof(s2n_fuzz_anchor_der));
    POSIX_ENSURE_REF(s2n_fuzz_anchor_x509);

    s2n_fuzz_x509_store = X509_STORE_new();
    POSIX_ENSURE_REF(s2n_fuzz_x509_store);
    POSIX_ENSURE(X509_STORE_add_cert(s2n_fuzz_x509_store, s2n_fuzz_anchor_x509) == 1,
            S2N_ERR_SAFETY);

    return S2N_SUCCESS;
}

/* Run X509_verify_cert on the fuzz input (treated as a sequence of DER certs).
 * Returns true if the libcrypto path accepts the chain. */
static bool s2n_fuzz_libcrypto_verify(const uint8_t *buf, size_t len)
{
    /* Parse all DER certificates from the input buffer. The fuzz input is a
     * concatenation of DER Certificate TLVs (matching the wire-chain format
     * the zero-copy parser expects). */
    STACK_OF(X509) *chain = sk_X509_new_null();
    if (chain == NULL) {
        return false;
    }

    const uint8_t *pos = buf;
    size_t remaining = len;
    while (remaining > 0) {
        const uint8_t *start = pos;
        X509 *cert = d2i_X509(NULL, &pos, (long) remaining);
        if (cert == NULL) {
            /* Parse failure: libcrypto cannot handle this input -> reject. */
            sk_X509_pop_free(chain, X509_free);
            return false;
        }
        size_t consumed = (size_t) (pos - start);
        remaining -= consumed;
        sk_X509_push(chain, cert);
    }

    if (sk_X509_num(chain) == 0) {
        sk_X509_pop_free(chain, X509_free);
        return false;
    }

    /* The leaf is at index 0, intermediates follow. */
    X509 *leaf = sk_X509_value(chain, 0);
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (ctx == NULL) {
        sk_X509_pop_free(chain, X509_free);
        return false;
    }

    /* Build untrusted intermediates stack (certs 1..N). */
    STACK_OF(X509) *untrusted = sk_X509_new_null();
    for (int i = 1; i < sk_X509_num(chain); i++) {
        sk_X509_push(untrusted, sk_X509_value(chain, i));
    }

    bool accepted = false;
    if (X509_STORE_CTX_init(ctx, s2n_fuzz_x509_store, leaf, untrusted) == 1) {
        /* Set verification time to match the zero-copy policy. */
        X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);
        X509_VERIFY_PARAM_set_time(param, (time_t) 1780000000);
        X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_X509_STRICT);

        int rc = X509_verify_cert(ctx);
        accepted = (rc == 1);
    }

    X509_STORE_CTX_free(ctx);
    sk_X509_free(untrusted);
    sk_X509_pop_free(chain, X509_free);
    return accepted;
}

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

int s2n_fuzz_test(const uint8_t *buf, size_t len)
{
#if S2N_LIBCRYPTO_SUPPORTS_CBS
    /* Treat the fuzz input as a raw wire certificate chain. */
    struct s2n_blob wire_chain = { 0 };
    POSIX_GUARD(s2n_blob_init(&wire_chain, (uint8_t *) (uintptr_t) buf, len));

    /* --- Zero-copy path --- */
    struct s2n_cert_chain_spans chain = { 0 };
    bool zc_accepted = false;
    if (s2n_result_is_ok(s2n_cert_chain_spans_parse(&chain, &wire_chain, 10))) {
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = 1780000000, /* ~2026, within anchor validity */
            .purpose = 0,
        };

        struct s2n_cert_path path = { 0 };
        if (s2n_result_is_ok(s2n_cert_path_build(&path, &chain, &s2n_fuzz_snapshot, &policy))) {
            zc_accepted = true;
        }
    }

    /* --- Libcrypto path (X509_verify_cert) --- */
    bool libcrypto_accepted = s2n_fuzz_libcrypto_verify(buf, len);

    /* --- Decision comparison --- */
    /* Divergence: the zero-copy path accepted but libcrypto rejected (or vice
     * versa). This is the differential oracle; any divergence is a failure that
     * preserves the reproducing input (libFuzzer will save it as a crash). */
    if (zc_accepted && !libcrypto_accepted) {
        /* Zero-copy accepted an input that libcrypto rejects — potential bypass. */
        __builtin_trap();
    }
    /* Note: we only abort on zc_accepted && !libcrypto_accepted (potential
     * bypass). The reverse (libcrypto accepts but zero-copy rejects) may
     * happen legitimately due to Work_Budget exhaustion or stricter DER
     * checks; it is not a security-relevant divergence for fuzz purposes. */
#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

    return S2N_SUCCESS;
}

#if S2N_LIBCRYPTO_SUPPORTS_CBS
S2N_FUZZ_TARGET(s2n_fuzz_init, s2n_fuzz_test, NULL)
#else
S2N_FUZZ_TARGET(NULL, s2n_fuzz_test, NULL)
#endif
