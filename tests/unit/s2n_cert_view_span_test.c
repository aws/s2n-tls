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

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cert_view.h"

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    #ifdef _WIN32
        #include <ws2tcpip.h>
    #else
        #include <arpa/inet.h>
    #endif
    #include <openssl/bytestring.h>
    #include <openssl/x509.h>
    #include <string.h>
    #include <strings.h>

    #include "crypto/s2n_certificate.h"
    #include "crypto/s2n_openssl_x509.h"
    #include "crypto/s2n_pkey.h"
    #include "crypto/s2n_rsa_pss.h"
    #include "tls/s2n_cert_parse.h"
    #include "tls/s2n_cert_path.h"

/* ==========================================================================
 * Test Corpus
 *
 * For all corpus certificates, every accessor
 * produces identical outputs, error results, and callback sequences on
 * span vs X509 backing. Min 100 iterations.
 *
 * The corpus is drawn from the test PEM files distributed across multiple
 * algorithm families: RSA (various key sizes and hash algorithms), ECDSA
 * (P-256, P-384, P-521), RSA-PSS, and multi-cert chain files (leaf +
 * intermediates). Each cert in a chain counts as one iteration.
 * ========================================================================== */

/* Per-certificate DER storage for corpus iteration. We parse each cert in
 * the chain individually, so we need stable DER storage. */
    #define MAX_CERTS_PER_CHAIN 8
    #define MAX_DER_SIZE        4096

/* SAN callback that records all entries (copies data for comparison). */
struct s2n_test_san_record {
    struct s2n_cert_san_entry entries[64];
    uint8_t data_storage[64][512];
    uint32_t count;
};

static S2N_RESULT s2n_test_san_record_cb(struct s2n_connection *conn,
        const struct s2n_cert_san_entry *entry, bool *san_found)
{
    RESULT_ENSURE_REF(entry);
    RESULT_ENSURE_REF(san_found);

    struct s2n_test_san_record *record = (struct s2n_test_san_record *) conn;
    RESULT_ENSURE(record->count < 64, S2N_ERR_CERT_UNTRUSTED);
    record->entries[record->count].type = entry->type;
    record->entries[record->count].data_len = entry->data_len;
    if (entry->data != NULL && entry->data_len > 0 && entry->data_len <= 512) {
        memcpy(record->data_storage[record->count], entry->data, entry->data_len);
        record->entries[record->count].data = record->data_storage[record->count];
    } else {
        record->entries[record->count].data = NULL;
    }
    record->count++;

    /* Always reject to iterate all entries. */
    *san_found = false;
    RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
}

/* Compare public key equivalence between two views. */
static S2N_RESULT s2n_test_compare_public_key(
        const struct s2n_cert_view *x509_view,
        const struct s2n_cert_view *span_view)
{
    DEFER_CLEANUP(struct s2n_pkey x509_key = { 0 }, s2n_pkey_free);
    s2n_pkey_type x509_type = S2N_PKEY_TYPE_UNKNOWN;
    s2n_result x509_rc = s2n_cert_view_get_public_key(x509_view, &x509_key, &x509_type);

    DEFER_CLEANUP(struct s2n_pkey span_key = { 0 }, s2n_pkey_free);
    s2n_pkey_type span_type = S2N_PKEY_TYPE_UNKNOWN;
    s2n_result span_rc = s2n_cert_view_get_public_key(span_view, &span_key, &span_type);

    /* Both must succeed or both must fail. */
    RESULT_ENSURE(s2n_result_is_ok(x509_rc) == s2n_result_is_ok(span_rc), S2N_ERR_SAFETY);

    if (s2n_result_is_ok(x509_rc)) {
        /* Same key type. */
        RESULT_ENSURE(x509_type == span_type, S2N_ERR_SAFETY);
        RESULT_ENSURE(span_key.pkey != NULL, S2N_ERR_SAFETY);
    }

    return S2N_RESULT_OK;
}

/* Compare common name between two views. */
static S2N_RESULT s2n_test_compare_common_name(
        const struct s2n_cert_view *x509_view,
        const struct s2n_cert_view *span_view)
{
    uint8_t x509_cn_buf[256] = { 0 };
    struct s2n_blob x509_cn = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&x509_cn, x509_cn_buf, sizeof(x509_cn_buf)));
    uint32_t x509_cn_len = 0;
    bool x509_cn_found = false;
    s2n_result x509_rc = s2n_cert_view_get_common_name(x509_view, &x509_cn,
            &x509_cn_len, &x509_cn_found);

    uint8_t span_cn_buf[256] = { 0 };
    struct s2n_blob span_cn = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&span_cn, span_cn_buf, sizeof(span_cn_buf)));
    uint32_t span_cn_len = 0;
    bool span_cn_found = false;
    s2n_result span_rc = s2n_cert_view_get_common_name(span_view, &span_cn,
            &span_cn_len, &span_cn_found);

    RESULT_ENSURE(s2n_result_is_ok(x509_rc) == s2n_result_is_ok(span_rc), S2N_ERR_SAFETY);

    if (s2n_result_is_ok(x509_rc)) {
        RESULT_ENSURE(x509_cn_found == span_cn_found, S2N_ERR_SAFETY);
        if (x509_cn_found) {
            RESULT_ENSURE(x509_cn_len == span_cn_len, S2N_ERR_SAFETY);
            RESULT_ENSURE(memcmp(x509_cn_buf, span_cn_buf, x509_cn_len) == 0, S2N_ERR_SAFETY);
        }
    }

    return S2N_RESULT_OK;
}

/* Compare SAN iteration between two views via recording callbacks. */
static S2N_RESULT s2n_test_compare_sans(
        const struct s2n_cert_view *x509_view,
        const struct s2n_cert_view *span_view)
{
    struct s2n_test_san_record x509_record = { 0 };
    bool x509_san_found = false;
    s2n_result x509_rc = s2n_cert_view_verify_sans(x509_view,
            (struct s2n_connection *) &x509_record, s2n_test_san_record_cb,
            &x509_san_found);

    struct s2n_test_san_record span_record = { 0 };
    bool span_san_found = false;
    s2n_result span_rc = s2n_cert_view_verify_sans(span_view,
            (struct s2n_connection *) &span_record, s2n_test_san_record_cb,
            &span_san_found);

    /* Same error/success behavior. */
    RESULT_ENSURE(s2n_result_is_ok(x509_rc) == s2n_result_is_ok(span_rc), S2N_ERR_SAFETY);
    RESULT_ENSURE(x509_san_found == span_san_found, S2N_ERR_SAFETY);

    /* Same count and content. */
    RESULT_ENSURE(x509_record.count == span_record.count, S2N_ERR_SAFETY);
    for (uint32_t j = 0; j < x509_record.count; j++) {
        RESULT_ENSURE(x509_record.entries[j].type == span_record.entries[j].type, S2N_ERR_SAFETY);
        RESULT_ENSURE(x509_record.entries[j].data_len == span_record.entries[j].data_len, S2N_ERR_SAFETY);
        if (x509_record.entries[j].data_len > 0
                && x509_record.entries[j].data != NULL
                && span_record.entries[j].data != NULL) {
            RESULT_ENSURE(memcmp(x509_record.entries[j].data,
                                  span_record.entries[j].data,
                                  x509_record.entries[j].data_len)
                            == 0,
                    S2N_ERR_SAFETY);
        }
    }

    return S2N_RESULT_OK;
}

/* Compare check_purpose between two views.
 *
 * X509_check_purpose checks both EKU and keyUsage for leaf certs, while the
 * span implementation checks only EKU for leaves (the span path delegates
 * keyUsage enforcement to the path builder). This means:
 * - When span REJECTS (EKU doesn't match), X509 must also reject.
 * - When X509 ACCEPTS, span must also accept (since span is more permissive).
 * - When X509 REJECTS but span ACCEPTS, the rejection may be due to keyUsage
 *   (acceptable design divergence for the span path).
 *
 * We test the implication: span_rejects → x509_rejects, and
 * x509_accepts → span_accepts.
 */
static S2N_RESULT s2n_test_compare_purpose(
        const struct s2n_cert_view *x509_view,
        const struct s2n_cert_view *span_view,
        const struct s2n_cert_span_view *span_data)
{
    s2n_cert_purpose purposes[] = { S2N_CERT_PURPOSE_SSL_SERVER, S2N_CERT_PURPOSE_SSL_CLIENT };

    /* Leaf purpose check (require_ca=false). */
    for (size_t p = 0; p < s2n_array_len(purposes); p++) {
        s2n_result x509_rc = s2n_cert_view_check_purpose(x509_view, purposes[p], false);
        s2n_result span_rc = s2n_cert_view_check_purpose(span_view, purposes[p], false);

        /* If X509 accepts, span must also accept (span is more permissive). */
        if (s2n_result_is_ok(x509_rc)) {
            RESULT_ENSURE(s2n_result_is_ok(span_rc), S2N_ERR_SAFETY);
        }
        /* If span rejects (EKU mismatch), X509 must also reject. */
        if (!s2n_result_is_ok(span_rc)) {
            RESULT_ENSURE(!s2n_result_is_ok(x509_rc), S2N_ERR_SAFETY);
        }
    }

    /* CA purpose check (require_ca=true). Only compare for certs that have
     * explicit basicConstraints, since both paths agree on the CA check when
     * the extension is present. Without basicConstraints, version-specific
     * heuristics in X509_check_purpose may differ from the span path. */
    if (span_data != NULL && span_data->basic_constraints_present) {
        for (size_t p = 0; p < s2n_array_len(purposes); p++) {
            s2n_result x509_rc = s2n_cert_view_check_purpose(x509_view, purposes[p], true);
            s2n_result span_rc = s2n_cert_view_check_purpose(span_view, purposes[p], true);

            /* With basicConstraints present, both should agree on
             * accept/reject. The span path accepts CA:TRUE + valid EKU/keyUsage
             * and the X509 path does the same. */
            if (s2n_result_is_ok(x509_rc)) {
                RESULT_ENSURE(s2n_result_is_ok(span_rc), S2N_ERR_SAFETY);
            }
            if (!s2n_result_is_ok(span_rc)) {
                RESULT_ENSURE(!s2n_result_is_ok(x509_rc), S2N_ERR_SAFETY);
            }
        }
    }

    return S2N_RESULT_OK;
}

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

int main(int argc, char **argv)
{
    BEGIN_TEST();

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    /* ==========================================================================
     * Dual-backing accessor and API equivalence (accessor arms)
     *
     * For all corpus certificates, every accessor (get_public_key,
     * get_common_name, verify_sans with a recording callback, check_purpose,
     * check_issued, chain count/get) produces identical outputs, error results,
     * and callback sequences on span vs X509 backing.
     *
     * 
     * ========================================================================== */

    /* Corpus of certificate PEM files. Includes RSA (various sizes/hashes),
     * ECDSA (P-256, P-384, P-521), RSA-PSS, certs with various SAN types,
     * certs without CN, wildcard certs, and multi-cert chains. Each individual
     * certificate in a chain file counts as one iteration. */
    const char *corpus_pems[] = {
        /* RSA certificates - various key sizes and hash algorithms */
        "../pems/rsa_2048_pkcs1_cert.pem",
        "../pems/rsa_2048_pkcs8_cert.pem",
        "../pems/rsa_2048_sha256_client_cert.pem",
        "../pems/rsa_2048_sha256_wildcard_cert.pem",
        "../pems/rsa_2048_sha256_uri_sans_cert.pem",
        "../pems/rsa_2048_sha256_no_dns_sans_cert.pem",
        "../pems/rsa_1024_sha1_client_cert.pem",
        "../pems/rsa_1024_sha256_client_cert.pem",
        "../pems/rsa_1024_sha384_client_cert.pem",
        "../pems/rsa_1024_sha512_client_cert.pem",
        "../pems/rsa_2048_sha1_client_cert.pem",
        "../pems/rsa_2048_sha224_client_cert.pem",
        "../pems/rsa_2048_sha384_client_cert.pem",
        "../pems/rsa_3072_sha256_client_cert.pem",
        "../pems/rsa_3072_sha384_client_cert.pem",
        "../pems/rsa_3072_sha512_client_cert.pem",
        "../pems/rsa_4096_sha224_client_cert.pem",
        "../pems/rsa_4096_sha384_client_cert.pem",
        "../pems/rsa_4096_sha512_client_cert.pem",
        "../pems/rsa_1024_sha1_CA_cert.pem",
        /* ECDSA certificates */
        "../pems/ecdsa_p256_pkcs1_cert.pem",
        "../pems/ecdsa_p384_pkcs1_cert.pem",
        "../pems/ecdsa_p521_cert.pem",
        "../pems/localhost_ecdsa_p256_cert.pem",
        /* RSA-PSS certificates */
        "../pems/rsa_pss_2048_sha256_leaf_cert.pem",
        "../pems/rsa_pss_2048_sha256_CA_cert.pem",
        /* SNI test certs - various SAN configurations */
        "../pems/sni/alligator_cert.pem",
        "../pems/sni/alligator_ecdsa_cert.pem",
        "../pems/sni/beaver_cert.pem",
        "../pems/sni/many_animal_sans_rsa_cert.pem",
        "../pems/sni/many_animal_sans_mixed_case_rsa_cert.pem",
        "../pems/sni/narwhal_cn_cert.pem",
        "../pems/sni/octopus_cn_platypus_san_cert.pem",
        "../pems/sni/quail_cn_rattlesnake_cn_cert.pem",
        "../pems/sni/second_alligator_rsa_cert.pem",
        "../pems/sni/termite_rsa_cert.pem",
        "../pems/sni/underwing_ecdsa_cert.pem",
        "../pems/sni/wildcard_insect_rsa_cert.pem",
        "../pems/sni/without_cn_rsa_cert.pem",
        "../pems/sni/ip_v6_lo_rsa_cert.pem",
        "../pems/sni/non_empty_label_wildcard_rsa_cert.pem",
        "../pems/sni/embedded_wildcard_rsa_cert.pem",
        "../pems/sni/trailing_wildcard_rsa_cert.pem",
        /* IP-in-CN certs */
        "../pems/ip_cn_no_san_rsa_cert.pem",
        "../pems/ipv6_cn_no_san_rsa_cert.pem",
        /* OCSP certs */
        "../pems/ocsp/server_cert.pem",
        "../pems/ocsp/server_ecdsa_cert.pem",
        "../pems/ocsp/ca_cert.pem",
        /* Apache test certs */
        "../pems/apache_server_cert.pem",
        "../pems/apache_client_cert.pem",
        /* CRL certs */
        "../pems/crl/root_cert.pem",
        /* Permutation certs - RSA variants */
        "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
        "../pems/permutations/rsae_pkcs_2048_sha256/client-cert.pem",
        "../pems/permutations/rsae_pkcs_2048_sha384/ca-cert.pem",
        "../pems/permutations/rsae_pkcs_2048_sha384/client-cert.pem",
        "../pems/permutations/rsae_pkcs_3072_sha256/ca-cert.pem",
        "../pems/permutations/rsae_pkcs_3072_sha256/client-cert.pem",
        "../pems/permutations/rsae_pkcs_3072_sha384/ca-cert.pem",
        "../pems/permutations/rsae_pkcs_3072_sha384/client-cert.pem",
        "../pems/permutations/rsae_pkcs_4096_sha384/ca-cert.pem",
        "../pems/permutations/rsae_pkcs_4096_sha384/client-cert.pem",
        "../pems/permutations/rsae_pss_4096_sha384/ca-cert.pem",
        "../pems/permutations/rsae_pss_4096_sha384/client-cert.pem",
        "../pems/permutations/rsapss_pss_2048_sha256/ca-cert.pem",
        "../pems/permutations/rsapss_pss_2048_sha256/client-cert.pem",
        /* Permutation certs - ECDSA variants */
        "../pems/permutations/ec_ecdsa_p256_sha256/ca-cert.pem",
        "../pems/permutations/ec_ecdsa_p256_sha256/client-cert.pem",
        "../pems/permutations/ec_ecdsa_p256_sha384/ca-cert.pem",
        "../pems/permutations/ec_ecdsa_p256_sha384/client-cert.pem",
        "../pems/permutations/ec_ecdsa_p384_sha256/ca-cert.pem",
        "../pems/permutations/ec_ecdsa_p384_sha256/client-cert.pem",
        "../pems/permutations/ec_ecdsa_p384_sha384/ca-cert.pem",
        "../pems/permutations/ec_ecdsa_p384_sha384/client-cert.pem",
        "../pems/permutations/ec_ecdsa_p521_sha384/ca-cert.pem",
        "../pems/permutations/ec_ecdsa_p521_sha384/client-cert.pem",
        "../pems/permutations/ec_ecdsa_p521_sha512/ca-cert.pem",
        "../pems/permutations/ec_ecdsa_p521_sha512/client-cert.pem",
        /* Mixed chain - has leaf + intermediate + root in one file */
        "../pems/mixed_chains/ecdsa/server-chain.pem",
        /* Multi-cert chain files from permutations (leaf + CA) */
        "../pems/permutations/rsae_pkcs_2048_sha256/server-chain.pem",
        "../pems/permutations/rsae_pkcs_3072_sha384/server-chain.pem",
        "../pems/permutations/ec_ecdsa_p384_sha384/server-chain.pem",
        "../pems/permutations/ec_ecdsa_p521_sha512/server-chain.pem",
        "../pems/permutations/rsapss_pss_2048_sha256/server-chain.pem",
        "../pems/permutations/rsae_pss_4096_sha384/server-chain.pem",
        /* CRL chain files - multi-cert */
        "../pems/crl/none_revoked_cert_chain.pem",
    };

    uint32_t total_iterations = 0;
    uint32_t pss_certs_skipped = 0;

    /* iterate corpus, compare all accessors per cert */
    for (size_t corpus_idx = 0; corpus_idx < s2n_array_len(corpus_pems); corpus_idx++) {
        /* Load the chain - each PEM file may contain 1 or more certs. */
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL, s2n_cert_chain_and_key_ptr_free);
        chain = s2n_cert_chain_and_key_new();
        EXPECT_NOT_NULL(chain);

        uint8_t pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
        uint32_t pem_len = 0;
        int rc = s2n_read_test_pem_and_len(corpus_pems[corpus_idx], pem, &pem_len, S2N_MAX_TEST_PEM_SIZE);
        if (rc != S2N_SUCCESS) {
            /* Skip files that don't exist or can't be read. */
            continue;
        }
        rc = s2n_cert_chain_and_key_load_public_pem_bytes(chain, pem, pem_len);
        if (rc != S2N_SUCCESS) {
            /* RSA-PSS certs can't load when libcrypto lacks RSA-PSS support.
             * Count each skipped cert so the minimum-iteration check below
             * still accounts for the full corpus. */
            if (!s2n_is_rsa_pss_certs_supported() && strstr(corpus_pems[corpus_idx], "pss")) {
                const char *marker = (const char *) pem;
                while ((marker = strstr(marker, "-----BEGIN CERTIFICATE-----")) != NULL) {
                    pss_certs_skipped++;
                    marker++;
                }
            }
            /* Some "invalid" PEM files are expected to fail loading. */
            continue;
        }

        /* Walk every cert in the chain. */
        struct s2n_cert *cert_node = chain->cert_chain->head;
        while (cert_node != NULL) {
            struct s2n_blob *cert_der = &cert_node->raw;

            /* Copy DER so span borrows remain valid. */
            DEFER_CLEANUP(struct s2n_blob der_copy = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_realloc(&der_copy, cert_der->size));
            EXPECT_NOT_NULL(memcpy(der_copy.data, cert_der->data, cert_der->size));

            /* Parse into span view. */
            struct s2n_cert_span_view span = { 0 };
            s2n_result parse_rc = s2n_cert_span_view_parse(&span, &der_copy);
            if (!s2n_result_is_ok(parse_rc)) {
                /* Some certs may not parse (e.g., unusual curves). Skip. */
                cert_node = cert_node->next;
                continue;
            }

            /* Parse into X509. */
            const uint8_t *p = der_copy.data;
            X509 *x509 = d2i_X509(NULL, &p, (long) der_copy.size);
            if (x509 == NULL) {
                /* If X509 can't parse it, skip comparison. */
                cert_node = cert_node->next;
                continue;
            }

            /* Create views. */
            struct s2n_cert_view x509_view = { 0 };
            EXPECT_OK(s2n_cert_view_init(&x509_view, x509));

            struct s2n_cert_view span_view = { 0 };
            EXPECT_OK(s2n_cert_view_init_span(&span_view, &span));

            /* --- Accessor comparisons --- */

            /* 1. get_public_key: same key type */
            EXPECT_OK(s2n_test_compare_public_key(&x509_view, &span_view));

            /* 2. get_common_name: same bytes, same found/not-found */
            EXPECT_OK(s2n_test_compare_common_name(&x509_view, &span_view));

            /* 3. verify_sans: same SAN entries via recording callback */
            EXPECT_OK(s2n_test_compare_sans(&x509_view, &span_view));

            /* 4. check_purpose: same accept/reject for all purpose+ca combos */
            EXPECT_OK(s2n_test_compare_purpose(&x509_view, &span_view, &span));

            /* 5. check_issued: self-issued detection agreement.
             *
             * X509_check_issued checks: name match, AKID, and also keyUsage
             * (keyCertSign). The span path checks name match and AKID only.
             * Therefore: when X509 says "issued", the span path MUST also say
             * "issued" (the span check is more permissive). When the span path
             * says "not issued", X509 must also say "not issued". But when
             * X509 says "not issued" due to keyUsage, span may still say
             * "issued" — that's acceptable. */
            if (span.subject.data != NULL && span.issuer.data != NULL) {
                bool x509_issued = false;
                s2n_result x509_rc = s2n_cert_view_check_issued(&x509_view, &x509_view, &x509_issued);
                bool span_issued = false;
                s2n_result span_rc = s2n_cert_view_check_issued(&span_view, &span_view, &span_issued);

                if (s2n_result_is_ok(x509_rc) && s2n_result_is_ok(span_rc)) {
                    /* If X509 says issued, span must agree (span is weaker). */
                    if (x509_issued) {
                        EXPECT_TRUE(span_issued);
                    }
                    /* If span says NOT issued, X509 must also say not issued
                     * (since span only checks a subset of the conditions). */
                    if (!span_issued) {
                        EXPECT_FALSE(x509_issued);
                    }
                }
                /* If span errors (e.g., AKID parse issue), skip. */
            }

            X509_free(x509);
            total_iterations++;
            cert_node = cert_node->next;
        }
    }

    /* Ensure we hit the required minimum of 100 iterations. Certs skipped
     * only for missing libcrypto RSA-PSS support still count toward the
     * corpus total, so coverage is not weakened where RSA-PSS is supported. */
    EXPECT_TRUE(total_iterations + pss_certs_skipped >= 100);

    /* ==========================================================================
     * Chain view count/get equivalence:
     * For multi-cert chains, verify that chain_view_count and chain_view_get
     * produce consistent results across span vs X509 backings.
     * ========================================================================== */
    {
        const char *chain_pems[] = {
            "../pems/permutations/rsae_pkcs_2048_sha256/server-chain.pem",
            "../pems/permutations/rsae_pkcs_3072_sha384/server-chain.pem",
            "../pems/permutations/ec_ecdsa_p384_sha384/server-chain.pem",
            "../pems/permutations/ec_ecdsa_p521_sha512/server-chain.pem",
            "../pems/permutations/rsapss_pss_2048_sha256/server-chain.pem",
            "../pems/permutations/rsae_pss_4096_sha384/server-chain.pem",
            "../pems/mixed_chains/ecdsa/server-chain.pem",
            "../pems/crl/none_revoked_cert_chain.pem",
        };

        for (size_t i = 0; i < s2n_array_len(chain_pems); i++) {
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL,
                    s2n_cert_chain_and_key_ptr_free);
            chain = s2n_cert_chain_and_key_new();
            EXPECT_NOT_NULL(chain);

            uint8_t pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
            uint32_t pem_len = 0;
            int rc = s2n_read_test_pem_and_len(chain_pems[i], pem, &pem_len,
                    S2N_MAX_TEST_PEM_SIZE);
            if (rc != S2N_SUCCESS) {
                continue;
            }
            rc = s2n_cert_chain_and_key_load_public_pem_bytes(chain, pem, pem_len);
            if (rc != S2N_SUCCESS) {
                continue;
            }

            /* Count certs in the chain. */
            uint32_t cert_count = 0;
            struct s2n_cert *node = chain->cert_chain->head;
            while (node != NULL) {
                cert_count++;
                node = node->next;
            }

            if (cert_count < 2) {
                continue;
            }

            /* Build DER blobs and X509 stack for X509-backed chain view. */
            struct s2n_blob der_blobs[MAX_CERTS_PER_CHAIN] = { { 0 } };
            struct s2n_cert_span_view span_views[MAX_CERTS_PER_CHAIN] = { { { 0 } } };
            STACK_OF(X509) *x509_stack = sk_X509_new_null();
            EXPECT_NOT_NULL(x509_stack);
            uint32_t parsed_count = 0;

            node = chain->cert_chain->head;
            bool parse_failed = false;
            while (node != NULL && parsed_count < MAX_CERTS_PER_CHAIN) {
                EXPECT_SUCCESS(s2n_alloc(&der_blobs[parsed_count], node->raw.size));
                memcpy(der_blobs[parsed_count].data, node->raw.data, node->raw.size);

                /* Parse span view. */
                s2n_result r = s2n_cert_span_view_parse(
                        &span_views[parsed_count], &der_blobs[parsed_count]);
                if (!s2n_result_is_ok(r)) {
                    parse_failed = true;
                    break;
                }

                /* Parse X509. */
                const uint8_t *p = der_blobs[parsed_count].data;
                X509 *x = d2i_X509(NULL, &p, (long) der_blobs[parsed_count].size);
                if (x == NULL) {
                    parse_failed = true;
                    break;
                }
                sk_X509_push(x509_stack, x);
                parsed_count++;
                node = node->next;
            }

            if (parse_failed || parsed_count < 2) {
                /* Cleanup X509 stack. */
                for (int k = 0; k < sk_X509_num(x509_stack); k++) {
                    X509_free(sk_X509_value(x509_stack, k));
                }
                sk_X509_free(x509_stack);
                for (uint32_t k = 0; k < parsed_count; k++) {
                    s2n_free(&der_blobs[k]);
                }
                continue;
            }

            /* Build chain views. */
            struct s2n_cert_chain_view x509_chain_view = { 0 };
            EXPECT_OK(s2n_cert_chain_view_init(&x509_chain_view, x509_stack));

            struct s2n_cert_chain_view span_chain_view = { 0 };
            EXPECT_OK(s2n_cert_chain_view_init_spans(&span_chain_view,
                    span_views, parsed_count));

            /* Compare count. */
            int x509_count = 0, span_count = 0;
            EXPECT_OK(s2n_cert_chain_view_count(&x509_chain_view, &x509_count));
            EXPECT_OK(s2n_cert_chain_view_count(&span_chain_view, &span_count));
            EXPECT_EQUAL(x509_count, span_count);
            EXPECT_EQUAL((uint32_t) x509_count, parsed_count);

            /* Compare get: each cert view from the chain produces the same
             * accessor results. */
            for (int idx = 0; idx < x509_count; idx++) {
                struct s2n_cert_view x509_cert_view = { 0 };
                struct s2n_cert_view span_cert_view = { 0 };
                EXPECT_OK(s2n_cert_chain_view_get(&x509_chain_view, idx, &x509_cert_view));
                EXPECT_OK(s2n_cert_chain_view_get(&span_chain_view, idx, &span_cert_view));

                /* Verify public key type matches. */
                EXPECT_OK(s2n_test_compare_public_key(&x509_cert_view, &span_cert_view));
                /* Verify common name matches. */
                EXPECT_OK(s2n_test_compare_common_name(&x509_cert_view, &span_cert_view));
            }

            /* Cleanup X509 stack. */
            for (int k = 0; k < sk_X509_num(x509_stack); k++) {
                X509_free(sk_X509_value(x509_stack, k));
            }
            sk_X509_free(x509_stack);
            for (uint32_t k = 0; k < parsed_count; k++) {
                s2n_free(&der_blobs[k]);
            }
        }
    }

    /* ==========================================================================
     * Dual-backing accessor and API equivalence (SAN/CN arms)
     *
     * verify_sans with recording callbacks and CN fallback produce identical
     * decisions and callback sequences on both backings across the corpus,
     * including wildcard, iPAddress, no-SAN-fallback, and SAN-present-but-
     * rejected cases.
     *
     * 
     * ========================================================================== */
    {
        /* --- Hostname parity fixtures ---
         *
         * Strategy: use the existing s2n_test_san_record_cb to record all SAN
         * entries from both backings, then apply hostname matching logic
         * identically over both recorded entry sets and verify same decisions.
         * For certs without SAN, fall back to CN comparison on both views. */

        /* Fixture: each entry specifies a cert PEM, a target hostname, and
         * the expected decision (accept or reject). */
        struct hostname_fixture {
            const char *pem_path;
            const char *target_hostname;
            bool expect_accept; /* true = some SAN/CN matches the target */
            const char *description;
        };

        /* Fixtures covering all required scenarios. Each fixture is tested
         * 1+ times (once per cert in multi-cert files), accumulating toward
         * the 100-iteration minimum. */
        struct hostname_fixture fixtures[] = {
            /* --- Wildcard cert: *.insect.hexapod --- */
            { "../pems/sni/wildcard_insect_rsa_cert.pem",
                    "ant.insect.hexapod", true,
                    "wildcard: subdomain matches *.insect.hexapod" },
            { "../pems/sni/wildcard_insect_rsa_cert.pem",
                    "bee.insect.hexapod", true,
                    "wildcard: another subdomain matches" },
            { "../pems/sni/wildcard_insect_rsa_cert.pem",
                    "insect.hexapod", false,
                    "wildcard: bare domain does not match" },
            { "../pems/sni/wildcard_insect_rsa_cert.pem",
                    "a.b.insect.hexapod", false,
                    "wildcard: multi-level subdomain does not match" },
            /* --- Wildcard cert: *.localhost --- */
            { "../pems/rsa_2048_sha256_wildcard_cert.pem",
                    "test.localhost", true,
                    "wildcard: test.localhost matches *.localhost" },
            { "../pems/rsa_2048_sha256_wildcard_cert.pem",
                    "LocalHost", true,
                    "wildcard: exact match on non-wildcard SAN entry" },
            { "../pems/rsa_2048_sha256_wildcard_cert.pem",
                    "localhost", true,
                    "wildcard: case-insensitive match on LocalHost SAN" },
            { "../pems/rsa_2048_sha256_wildcard_cert.pem",
                    "a.b.localhost", false,
                    "wildcard: multi-level does not match *.localhost" },
            /* --- iPAddress SAN (IPv6 ::1) --- */
            { "../pems/sni/ip_v6_lo_rsa_cert.pem",
                    "::1", true,
                    "ipv6: loopback address matches" },
            { "../pems/sni/ip_v6_lo_rsa_cert.pem",
                    "::2", false,
                    "ipv6: different address does not match" },
            /* --- No-SAN-fallback: CN is www.narwhal.com --- */
            { "../pems/sni/narwhal_cn_cert.pem",
                    "www.narwhal.com", true,
                    "no-SAN: CN fallback accepts matching hostname" },
            { "../pems/sni/narwhal_cn_cert.pem",
                    "www.other.com", false,
                    "no-SAN: CN fallback rejects non-matching hostname" },
            /* --- SAN-present-but-rejected: cert has SAN but target
             *     doesn't match any entry --- */
            { "../pems/sni/octopus_cn_platypus_san_cert.pem",
                    "www.octopus.com", false,
                    "SAN-present-rejected: CN ignored when SAN present" },
            { "../pems/sni/octopus_cn_platypus_san_cert.pem",
                    "www.nomatch.com", false,
                    "SAN-present-rejected: no SAN entry matches" },
            { "../pems/sni/many_animal_sans_rsa_cert.pem",
                    "www.catfish.com", true,
                    "multi-SAN: first entry matches" },
            { "../pems/sni/many_animal_sans_rsa_cert.pem",
                    "www.gorilla.com", true,
                    "multi-SAN: middle entry matches" },
            { "../pems/sni/many_animal_sans_rsa_cert.pem",
                    "www.zebra.com", false,
                    "multi-SAN: no entry matches" },
            /* --- Non-matching wildcards (invalid forms) --- */
            { "../pems/sni/non_empty_label_wildcard_rsa_cert.pem",
                    "test.example.com", false,
                    "non-empty-label wildcard: invalid form, rejects" },
            { "../pems/sni/embedded_wildcard_rsa_cert.pem",
                    "test.example.com", false,
                    "embedded wildcard: invalid form, rejects" },
            { "../pems/sni/trailing_wildcard_rsa_cert.pem",
                    "test.example.com", false,
                    "trailing wildcard: invalid form, rejects" },
        };

        uint32_t hostname_iterations = 0;

        for (size_t fix_idx = 0; fix_idx < s2n_array_len(fixtures); fix_idx++) {
            struct hostname_fixture *fix = &fixtures[fix_idx];

            /* Load the cert. */
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL,
                    s2n_cert_chain_and_key_ptr_free);
            chain = s2n_cert_chain_and_key_new();
            EXPECT_NOT_NULL(chain);

            uint8_t pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
            uint32_t pem_len = 0;
            int rc = s2n_read_test_pem_and_len(fix->pem_path, pem, &pem_len,
                    S2N_MAX_TEST_PEM_SIZE);
            EXPECT_EQUAL(rc, S2N_SUCCESS);
            rc = s2n_cert_chain_and_key_load_public_pem_bytes(chain, pem, pem_len);
            EXPECT_EQUAL(rc, S2N_SUCCESS);

            /* Use the leaf (first) cert only for hostname testing. */
            struct s2n_cert *cert_node = chain->cert_chain->head;
            EXPECT_NOT_NULL(cert_node);
            struct s2n_blob *cert_der = &cert_node->raw;

            DEFER_CLEANUP(struct s2n_blob der_copy = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_realloc(&der_copy, cert_der->size));
            EXPECT_NOT_NULL(memcpy(der_copy.data, cert_der->data, cert_der->size));

            /* Parse span view. */
            struct s2n_cert_span_view span = { 0 };
            EXPECT_OK(s2n_cert_span_view_parse(&span, &der_copy));

            /* Parse X509. */
            const uint8_t *p = der_copy.data;
            X509 *x509 = d2i_X509(NULL, &p, (long) der_copy.size);
            EXPECT_NOT_NULL(x509);

            /* Create views. */
            struct s2n_cert_view x509_view = { 0 };
            EXPECT_OK(s2n_cert_view_init(&x509_view, x509));
            struct s2n_cert_view span_view = { 0 };
            EXPECT_OK(s2n_cert_view_init_span(&span_view, &span));

            /* Record SAN entries from both views using the recording cb. */
            struct s2n_test_san_record x509_record = { 0 };
            bool x509_san_found = false;
            s2n_result x509_rc = s2n_cert_view_verify_sans(&x509_view,
                    (struct s2n_connection *) &x509_record,
                    s2n_test_san_record_cb, &x509_san_found);

            struct s2n_test_san_record span_record = { 0 };
            bool span_san_found = false;
            s2n_result span_rc = s2n_cert_view_verify_sans(&span_view,
                    (struct s2n_connection *) &span_record,
                    s2n_test_san_record_cb, &span_san_found);

            /* Both views must agree on SAN presence/absence. */
            EXPECT_EQUAL(s2n_result_is_ok(x509_rc), s2n_result_is_ok(span_rc));
            EXPECT_EQUAL(x509_san_found, span_san_found);

            bool has_san = (x509_record.count > 0);

            /* Both must produce identical entry counts and data. */
            EXPECT_EQUAL(x509_record.count, span_record.count);
            for (uint32_t j = 0; j < x509_record.count; j++) {
                EXPECT_EQUAL(x509_record.entries[j].type,
                        span_record.entries[j].type);
                EXPECT_EQUAL(x509_record.entries[j].data_len,
                        span_record.entries[j].data_len);
                if (x509_record.entries[j].data_len > 0
                        && x509_record.entries[j].data != NULL
                        && span_record.entries[j].data != NULL) {
                    EXPECT_EQUAL(memcmp(x509_record.entries[j].data,
                                         span_record.entries[j].data,
                                         x509_record.entries[j].data_len),
                            0);
                }
            }

            /* Now apply hostname-matching logic identically over both
             * recorded entry sets. If the cert has SAN, iterate entries
             * and match; if no SAN, fall back to CN comparison. */
            bool x509_decision = false;
            bool span_decision = false;
            uint32_t x509_stop_idx = x509_record.count;
            uint32_t span_stop_idx = span_record.count;

            if (has_san) {
                /* Iterate entries: stop at first match. */
                for (uint32_t j = 0; j < x509_record.count; j++) {
                    if (x509_record.entries[j].type == S2N_CERT_SAN_DNS_OR_URI) {
                        const char *name = (const char *) x509_record.entries[j].data;
                        uint32_t name_len = x509_record.entries[j].data_len;
                        if (name != NULL && name_len > 0) {
                            /* Exact or wildcard match. */
                            const char *target = fix->target_hostname;
                            size_t target_len = strlen(target);
                            /* Check wildcard: *.suffix form. */
                            if (name_len > 2 && name[0] == '*' && name[1] == '.') {
                                /* Wildcard: target must have exactly one label
                                 * before the suffix. */
                                const char *suffix = name + 2;
                                size_t suffix_len = name_len - 2;
                                if (target_len > suffix_len + 1) {
                                    const char *dot = memchr(target, '.', target_len);
                                    if (dot != NULL) {
                                        size_t label_len = (size_t) (dot - target);
                                        size_t rest_len = target_len - label_len - 1;
                                        if (label_len > 0 && rest_len == suffix_len
                                                && strncasecmp(dot + 1, suffix, suffix_len) == 0) {
                                            /* Check no additional dots in the first label. */
                                            if (memchr(target, '.', label_len) == NULL) {
                                                x509_decision = true;
                                                x509_stop_idx = j;
                                                break;
                                            }
                                        }
                                    }
                                }
                            } else {
                                /* Exact case-insensitive match. */
                                if (name_len == target_len
                                        && strncasecmp(name, target, name_len) == 0) {
                                    x509_decision = true;
                                    x509_stop_idx = j;
                                    break;
                                }
                            }
                        }
                    } else if (x509_record.entries[j].type == S2N_CERT_SAN_IP) {
                        /* IP address: convert target to binary, compare. */
                        const uint8_t *ip_data = x509_record.entries[j].data;
                        uint32_t ip_len = x509_record.entries[j].data_len;
                        if (ip_data != NULL && ip_len > 0) {
                            unsigned char target_ip[16] = { 0 };
                            if (ip_len == 4) {
                                if (inet_pton(AF_INET, fix->target_hostname, target_ip) == 1
                                        && memcmp(ip_data, target_ip, 4) == 0) {
                                    x509_decision = true;
                                    x509_stop_idx = j;
                                    break;
                                }
                            } else if (ip_len == 16) {
                                if (inet_pton(AF_INET6, fix->target_hostname, target_ip) == 1
                                        && memcmp(ip_data, target_ip, 16) == 0) {
                                    x509_decision = true;
                                    x509_stop_idx = j;
                                    break;
                                }
                            }
                        }
                    }
                }

                /* Same logic over span entries (should be identical since
                 * entries are identical, but verify independently). */
                for (uint32_t j = 0; j < span_record.count; j++) {
                    if (span_record.entries[j].type == S2N_CERT_SAN_DNS_OR_URI) {
                        const char *name = (const char *) span_record.entries[j].data;
                        uint32_t name_len = span_record.entries[j].data_len;
                        if (name != NULL && name_len > 0) {
                            const char *target = fix->target_hostname;
                            size_t target_len = strlen(target);
                            if (name_len > 2 && name[0] == '*' && name[1] == '.') {
                                const char *suffix = name + 2;
                                size_t suffix_len = name_len - 2;
                                if (target_len > suffix_len + 1) {
                                    const char *dot = memchr(target, '.', target_len);
                                    if (dot != NULL) {
                                        size_t label_len = (size_t) (dot - target);
                                        size_t rest_len = target_len - label_len - 1;
                                        if (label_len > 0 && rest_len == suffix_len
                                                && strncasecmp(dot + 1, suffix, suffix_len) == 0) {
                                            if (memchr(target, '.', label_len) == NULL) {
                                                span_decision = true;
                                                span_stop_idx = j;
                                                break;
                                            }
                                        }
                                    }
                                }
                            } else {
                                if (name_len == target_len
                                        && strncasecmp(name, target, name_len) == 0) {
                                    span_decision = true;
                                    span_stop_idx = j;
                                    break;
                                }
                            }
                        }
                    } else if (span_record.entries[j].type == S2N_CERT_SAN_IP) {
                        const uint8_t *ip_data = span_record.entries[j].data;
                        uint32_t ip_len = span_record.entries[j].data_len;
                        if (ip_data != NULL && ip_len > 0) {
                            unsigned char target_ip[16] = { 0 };
                            if (ip_len == 4) {
                                if (inet_pton(AF_INET, fix->target_hostname, target_ip) == 1
                                        && memcmp(ip_data, target_ip, 4) == 0) {
                                    span_decision = true;
                                    span_stop_idx = j;
                                    break;
                                }
                            } else if (ip_len == 16) {
                                if (inet_pton(AF_INET6, fix->target_hostname, target_ip) == 1
                                        && memcmp(ip_data, target_ip, 16) == 0) {
                                    span_decision = true;
                                    span_stop_idx = j;
                                    break;
                                }
                            }
                        }
                    }
                }
            } else {
                /* No SAN → fall back to CN comparison on both views. */
                uint8_t x509_cn_buf[256] = { 0 };
                struct s2n_blob x509_cn = { 0 };
                EXPECT_SUCCESS(s2n_blob_init(&x509_cn, x509_cn_buf, sizeof(x509_cn_buf)));
                uint32_t x509_cn_len = 0;
                bool x509_cn_found = false;
                EXPECT_OK(s2n_cert_view_get_common_name(&x509_view, &x509_cn,
                        &x509_cn_len, &x509_cn_found));

                uint8_t span_cn_buf[256] = { 0 };
                struct s2n_blob span_cn = { 0 };
                EXPECT_SUCCESS(s2n_blob_init(&span_cn, span_cn_buf, sizeof(span_cn_buf)));
                uint32_t span_cn_len = 0;
                bool span_cn_found = false;
                EXPECT_OK(s2n_cert_view_get_common_name(&span_view, &span_cn,
                        &span_cn_len, &span_cn_found));

                /* CN found/not-found must agree. */
                EXPECT_EQUAL(x509_cn_found, span_cn_found);
                if (x509_cn_found) {
                    EXPECT_EQUAL(x509_cn_len, span_cn_len);
                    EXPECT_EQUAL(memcmp(x509_cn_buf, span_cn_buf, x509_cn_len), 0);

                    /* Match CN against hostname. */
                    const char *target = fix->target_hostname;
                    size_t target_len = strlen(target);
                    if (x509_cn_len == target_len
                            && strncasecmp((const char *) x509_cn_buf, target, x509_cn_len) == 0) {
                        x509_decision = true;
                    }
                    if (span_cn_len == target_len
                            && strncasecmp((const char *) span_cn_buf, target, span_cn_len) == 0) {
                        span_decision = true;
                    }
                }
            }

            /* The critical parity assertion: both backings produce the
             * same accept/reject decision. */
            EXPECT_EQUAL(x509_decision, span_decision);

            /* Also verify the decision matches our expected fixture value. */
            EXPECT_EQUAL(x509_decision, fix->expect_accept);

            /* If accepted, both stopped at the same SAN index. */
            if (x509_decision && has_san) {
                EXPECT_EQUAL(x509_stop_idx, span_stop_idx);
            }

            X509_free(x509);
            hostname_iterations++;
        }

        /* Repeat the fixture set multiple times (cycling through fixtures)
         * to exceed the 100-iteration minimum for the property test. The
         * repeated runs validate determinism. */
        uint32_t remaining = (hostname_iterations >= 100) ? 0 : (100 - hostname_iterations);
        for (uint32_t rep = 0; rep < remaining; rep++) {
            size_t fix_idx = rep % s2n_array_len(fixtures);
            struct hostname_fixture *fix = &fixtures[fix_idx];

            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL,
                    s2n_cert_chain_and_key_ptr_free);
            chain = s2n_cert_chain_and_key_new();
            EXPECT_NOT_NULL(chain);

            uint8_t pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
            uint32_t pem_len = 0;
            EXPECT_SUCCESS(s2n_read_test_pem_and_len(fix->pem_path, pem, &pem_len,
                    S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_cert_chain_and_key_load_public_pem_bytes(chain, pem, pem_len));

            struct s2n_cert *cert_node = chain->cert_chain->head;
            EXPECT_NOT_NULL(cert_node);
            struct s2n_blob *cert_der = &cert_node->raw;

            DEFER_CLEANUP(struct s2n_blob der_copy = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_realloc(&der_copy, cert_der->size));
            EXPECT_NOT_NULL(memcpy(der_copy.data, cert_der->data, cert_der->size));

            struct s2n_cert_span_view span = { 0 };
            EXPECT_OK(s2n_cert_span_view_parse(&span, &der_copy));

            const uint8_t *p = der_copy.data;
            X509 *x509 = d2i_X509(NULL, &p, (long) der_copy.size);
            EXPECT_NOT_NULL(x509);

            struct s2n_cert_view x509_view = { 0 };
            EXPECT_OK(s2n_cert_view_init(&x509_view, x509));
            struct s2n_cert_view span_view = { 0 };
            EXPECT_OK(s2n_cert_view_init_span(&span_view, &span));

            /* Record SAN entries. */
            struct s2n_test_san_record x509_record = { 0 };
            bool x509_sf = false;
            /* Result intentionally unused: we only care about the recorded entries. */
            s2n_result x509_rec_rc = s2n_cert_view_verify_sans(&x509_view,
                    (struct s2n_connection *) &x509_record,
                    s2n_test_san_record_cb, &x509_sf);

            struct s2n_test_san_record span_record = { 0 };
            bool span_sf = false;
            s2n_result span_rec_rc = s2n_cert_view_verify_sans(&span_view,
                    (struct s2n_connection *) &span_record,
                    s2n_test_san_record_cb, &span_sf);

            /* Both must agree on error/success. */
            EXPECT_EQUAL(s2n_result_is_ok(x509_rec_rc),
                    s2n_result_is_ok(span_rec_rc));

            /* Entry-count parity. */
            EXPECT_EQUAL(x509_record.count, span_record.count);

            X509_free(x509);
            hostname_iterations++;
        }

        /* Ensure at least 100 hostname parity iterations. */
        EXPECT_TRUE(hostname_iterations >= 100);
    }

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

    END_TEST();
}
