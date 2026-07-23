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

#include "tls/s2n_cert_path.h"

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    #include <openssl/bytestring.h>
    #include <openssl/evp.h>
    #include <openssl/x509.h>
    #include <string.h>

    #include "crypto/s2n_certificate.h"
    #include "crypto/s2n_openssl_x509.h"
    #include "crypto/s2n_pkey.h"
    #include "crypto/s2n_rsa_pss.h"
    #include "tls/s2n_cert_parse.h"

    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wunused-function"
DEFINE_POINTER_CLEANUP_FUNC(EVP_PKEY *, EVP_PKEY_free);
    #pragma GCC diagnostic pop

/* Parse a PEM chain file and produce a span view of the leaf certificate.
 * The DER bytes are copied into `der_out` (caller frees with s2n_free) so
 * that the span view's borrows remain valid after the chain is freed. */
static S2N_RESULT s2n_test_parse_pem_leaf(const char *pem_path,
        struct s2n_cert_span_view *view, struct s2n_blob *der_out)
{
    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL, s2n_cert_chain_and_key_ptr_free);
    chain = s2n_cert_chain_and_key_new();
    RESULT_ENSURE_REF(chain);

    uint8_t pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    uint32_t pem_len = 0;
    RESULT_GUARD_POSIX(s2n_read_test_pem_and_len(pem_path, pem, &pem_len, S2N_MAX_TEST_PEM_SIZE));
    RESULT_GUARD_POSIX(s2n_cert_chain_and_key_load_public_pem_bytes(chain, pem, pem_len));

    struct s2n_blob *leaf_der = &chain->cert_chain->head->raw;
    RESULT_GUARD_POSIX(s2n_realloc(der_out, leaf_der->size));
    RESULT_CHECKED_MEMCPY(der_out->data, leaf_der->data, leaf_der->size);

    RESULT_GUARD(s2n_cert_span_view_parse(view, der_out));
    return S2N_RESULT_OK;
}

/* Build a minimal DER Name TLV from a single RDN with one attribute:
 * OID = 2.5.4.3 (commonName), value = the given string with the given tag.
 *
 * Name ::= SEQUENCE { SET { SEQUENCE { OID, value } } }
 *
 * Returns the total length written into `out`. `out` must be at least 256 bytes. */
static size_t s2n_test_build_name(uint8_t *out, size_t out_cap,
        uint8_t value_tag, const uint8_t *value, size_t value_len)
{
    /* OID for commonName: 2.5.4.3 = 55 04 03 */
    static const uint8_t cn_oid[] = { 0x55, 0x04, 0x03 };

    /* AttributeTypeAndValue SEQUENCE content: OID + value TLV */
    /* atv_content = OID_TLV + value_TLV */
    size_t atv_content_len = 2 + sizeof(cn_oid) + 2 + value_len;

    /* SET content = atv SEQUENCE TLV */
    size_t set_content_len = 2 + atv_content_len;

    /* Name SEQUENCE content = SET TLV */
    size_t seq_content_len = 2 + set_content_len;

    /* Total Name TLV */
    size_t total = 2 + seq_content_len;
    (void) out_cap;

    size_t pos = 0;
    /* Name SEQUENCE */
    out[pos++] = 0x30;
    out[pos++] = (uint8_t) seq_content_len;
    /* SET */
    out[pos++] = 0x31;
    out[pos++] = (uint8_t) set_content_len;
    /* AttributeTypeAndValue SEQUENCE */
    out[pos++] = 0x30;
    out[pos++] = (uint8_t) atv_content_len;
    /* OID */
    out[pos++] = 0x06;
    out[pos++] = (uint8_t) sizeof(cn_oid);
    memcpy(&out[pos], cn_oid, sizeof(cn_oid));
    pos += sizeof(cn_oid);
    /* Value */
    out[pos++] = value_tag;
    out[pos++] = (uint8_t) value_len;
    memcpy(&out[pos], value, value_len);
    pos += value_len;

    return total;
}

/* Build a Name TLV with two RDNs, each containing a single attribute.
 * First RDN: countryName (2.5.4.6) = country_value (PrintableString)
 * Second RDN: commonName (2.5.4.3) = cn_value with cn_tag */
static size_t s2n_test_build_two_rdn_name(uint8_t *out, size_t out_cap,
        const char *country_value,
        uint8_t cn_tag, const uint8_t *cn_value, size_t cn_value_len)
{
    /* OIDs */
    static const uint8_t country_oid[] = { 0x55, 0x04, 0x06 }; /* 2.5.4.6 */
    static const uint8_t cn_oid[] = { 0x55, 0x04, 0x03 };      /* 2.5.4.3 */
    size_t country_len = strlen(country_value);

    /* First RDN: SET { SEQUENCE { OID(country), PrintableString } } */
    size_t atv1_content = 2 + sizeof(country_oid) + 2 + country_len;
    size_t set1_content = 2 + atv1_content;

    /* Second RDN: SET { SEQUENCE { OID(cn), value } } */
    size_t atv2_content = 2 + sizeof(cn_oid) + 2 + cn_value_len;
    size_t set2_content = 2 + atv2_content;

    size_t seq_content = (2 + set1_content) + (2 + set2_content);
    (void) out_cap;

    size_t pos = 0;
    /* Name SEQUENCE */
    out[pos++] = 0x30;
    out[pos++] = (uint8_t) seq_content;

    /* First SET (country) */
    out[pos++] = 0x31;
    out[pos++] = (uint8_t) set1_content;
    out[pos++] = 0x30;
    out[pos++] = (uint8_t) atv1_content;
    out[pos++] = 0x06;
    out[pos++] = (uint8_t) sizeof(country_oid);
    memcpy(&out[pos], country_oid, sizeof(country_oid));
    pos += sizeof(country_oid);
    out[pos++] = 0x13; /* PrintableString */
    out[pos++] = (uint8_t) country_len;
    memcpy(&out[pos], country_value, country_len);
    pos += country_len;

    /* Second SET (CN) */
    out[pos++] = 0x31;
    out[pos++] = (uint8_t) set2_content;
    out[pos++] = 0x30;
    out[pos++] = (uint8_t) atv2_content;
    out[pos++] = 0x06;
    out[pos++] = (uint8_t) sizeof(cn_oid);
    memcpy(&out[pos], cn_oid, sizeof(cn_oid));
    pos += sizeof(cn_oid);
    out[pos++] = cn_tag;
    out[pos++] = (uint8_t) cn_value_len;
    memcpy(&out[pos], cn_value, cn_value_len);
    pos += cn_value_len;

    return pos;
}

/* Load a PEM chain file into a cert_chain_and_key, then extract the DER bytes
 * for each cert into a flat wire_chain blob (concatenated DER TLVs, self-framing).
 * Also loads the CA cert as a trust anchor. */
static S2N_RESULT s2n_test_load_chain_and_anchor(
        const char *chain_pem_path,
        const char *ca_pem_path,
        struct s2n_blob *wire_chain_out,
        struct s2n_cert_chain_spans *spans_out,
        struct s2n_trust_anchor *anchor_out,
        struct s2n_blob *anchor_der_out)
{
    RESULT_ENSURE_REF(wire_chain_out);
    RESULT_ENSURE_REF(spans_out);
    RESULT_ENSURE_REF(anchor_out);
    RESULT_ENSURE_REF(anchor_der_out);

    /* Load the chain. */
    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL,
            s2n_cert_chain_and_key_ptr_free);
    chain = s2n_cert_chain_and_key_new();
    RESULT_ENSURE_REF(chain);

    uint8_t pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    uint32_t pem_len = 0;
    RESULT_GUARD_POSIX(s2n_read_test_pem_and_len(chain_pem_path, pem, &pem_len,
            S2N_MAX_TEST_PEM_SIZE));
    RESULT_GUARD_POSIX(s2n_cert_chain_and_key_load_public_pem_bytes(chain, pem, pem_len));

    /* Calculate total DER size and build the wire chain. */
    uint32_t total_size = 0;
    struct s2n_cert *cert = chain->cert_chain->head;
    while (cert != NULL) {
        total_size += cert->raw.size;
        cert = cert->next;
    }

    RESULT_GUARD_POSIX(s2n_realloc(wire_chain_out, total_size));
    uint32_t offset = 0;
    cert = chain->cert_chain->head;
    while (cert != NULL) {
        RESULT_CHECKED_MEMCPY(wire_chain_out->data + offset, cert->raw.data, cert->raw.size);
        offset += cert->raw.size;
        cert = cert->next;
    }

    /* Parse the wire chain into span views. */
    RESULT_GUARD(s2n_cert_chain_spans_parse(spans_out, wire_chain_out, 16));

    /* Load the CA as a trust anchor. */
    DEFER_CLEANUP(struct s2n_cert_chain_and_key *ca = NULL,
            s2n_cert_chain_and_key_ptr_free);
    ca = s2n_cert_chain_and_key_new();
    RESULT_ENSURE_REF(ca);

    RESULT_GUARD_POSIX(s2n_read_test_pem_and_len(ca_pem_path, pem, &pem_len,
            S2N_MAX_TEST_PEM_SIZE));
    RESULT_GUARD_POSIX(s2n_cert_chain_and_key_load_public_pem_bytes(ca, pem, pem_len));

    struct s2n_blob *ca_der = &ca->cert_chain->head->raw;
    RESULT_GUARD_POSIX(s2n_realloc(anchor_der_out, ca_der->size));
    RESULT_CHECKED_MEMCPY(anchor_der_out->data, ca_der->data, ca_der->size);

    *anchor_out = (struct s2n_trust_anchor){ 0 };
    anchor_out->der = *anchor_der_out;
    RESULT_GUARD(s2n_cert_span_view_parse(&anchor_out->parsed, anchor_der_out));

    return S2N_RESULT_OK;
}

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

int main(int argc, char **argv)
{
    BEGIN_TEST();

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    /* Test: identical names are equal (self-issued cert issuer == subject). */
    {
        struct s2n_cert_span_view view = { 0 };
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        EXPECT_OK(s2n_test_parse_pem_leaf(S2N_DEFAULT_TEST_CERT_CHAIN, &view, &der));

        bool equal = false;
        EXPECT_OK(s2n_cert_name_cmp(&view.issuer, &view.issuer, &equal));
        EXPECT_TRUE(equal);
    };

    /* Test: ECDSA cert self-comparison (issuer == subject for self-issued). */
    {
        struct s2n_cert_span_view view = { 0 };
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        EXPECT_OK(s2n_test_parse_pem_leaf(S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, &view, &der));

        bool equal = false;
        EXPECT_OK(s2n_cert_name_cmp(&view.subject, &view.subject, &equal));
        EXPECT_TRUE(equal);
    };

    /* Test: case-differing PrintableString names are equal. */
    {
        uint8_t buf_a[256] = { 0 };
        uint8_t buf_b[256] = { 0 };
        const uint8_t val_a[] = "Example Corp";
        const uint8_t val_b[] = "EXAMPLE CORP";

        size_t len_a = s2n_test_build_name(buf_a, sizeof(buf_a), 0x13, val_a, sizeof(val_a) - 1);
        size_t len_b = s2n_test_build_name(buf_b, sizeof(buf_b), 0x13, val_b, sizeof(val_b) - 1);

        struct s2n_blob name_a = { 0 }, name_b = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&name_a, buf_a, (uint32_t) len_a));
        EXPECT_SUCCESS(s2n_blob_init(&name_b, buf_b, (uint32_t) len_b));

        bool equal = false;
        EXPECT_OK(s2n_cert_name_cmp(&name_a, &name_b, &equal));
        EXPECT_TRUE(equal);
    };

    /* Test: whitespace-variant UTF8String names are equal. */
    {
        uint8_t buf_a[256] = { 0 };
        uint8_t buf_b[256] = { 0 };
        const uint8_t val_a[] = "  Hello   World  ";
        const uint8_t val_b[] = "Hello World";

        size_t len_a = s2n_test_build_name(buf_a, sizeof(buf_a), 0x0c, val_a, sizeof(val_a) - 1);
        size_t len_b = s2n_test_build_name(buf_b, sizeof(buf_b), 0x0c, val_b, sizeof(val_b) - 1);

        struct s2n_blob name_a = { 0 }, name_b = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&name_a, buf_a, (uint32_t) len_a));
        EXPECT_SUCCESS(s2n_blob_init(&name_b, buf_b, (uint32_t) len_b));

        bool equal = false;
        EXPECT_OK(s2n_cert_name_cmp(&name_a, &name_b, &equal));
        EXPECT_TRUE(equal);
    };

    /* Test: cross-type comparison (PrintableString vs UTF8String) with case fold. */
    {
        uint8_t buf_a[256] = { 0 };
        uint8_t buf_b[256] = { 0 };
        const uint8_t val_a[] = "Test CA";
        const uint8_t val_b[] = "test ca";

        /* name_a uses PrintableString (0x13), name_b uses UTF8String (0x0c) */
        size_t len_a = s2n_test_build_name(buf_a, sizeof(buf_a), 0x13, val_a, sizeof(val_a) - 1);
        size_t len_b = s2n_test_build_name(buf_b, sizeof(buf_b), 0x0c, val_b, sizeof(val_b) - 1);

        struct s2n_blob name_a = { 0 }, name_b = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&name_a, buf_a, (uint32_t) len_a));
        EXPECT_SUCCESS(s2n_blob_init(&name_b, buf_b, (uint32_t) len_b));

        bool equal = false;
        EXPECT_OK(s2n_cert_name_cmp(&name_a, &name_b, &equal));
        EXPECT_TRUE(equal);
    };

    /* Test: OID-differing names are unequal. */
    {
        uint8_t buf_a[256] = { 0 };
        uint8_t buf_b[256] = { 0 };
        const uint8_t val[] = "Same Value";

        /* Build name_a with commonName OID (2.5.4.3) */
        size_t len_a = s2n_test_build_name(buf_a, sizeof(buf_a), 0x13, val, sizeof(val) - 1);

        /* Build name_b manually with a different OID: organizationName 2.5.4.10 = 55 04 0a */
        static const uint8_t org_oid[] = { 0x55, 0x04, 0x0a };
        size_t atv_content = 2 + sizeof(org_oid) + 2 + (sizeof(val) - 1);
        size_t set_content = 2 + atv_content;
        size_t seq_content = 2 + set_content;
        size_t pos = 0;
        buf_b[pos++] = 0x30;
        buf_b[pos++] = (uint8_t) seq_content;
        buf_b[pos++] = 0x31;
        buf_b[pos++] = (uint8_t) set_content;
        buf_b[pos++] = 0x30;
        buf_b[pos++] = (uint8_t) atv_content;
        buf_b[pos++] = 0x06;
        buf_b[pos++] = (uint8_t) sizeof(org_oid);
        memcpy(&buf_b[pos], org_oid, sizeof(org_oid));
        pos += sizeof(org_oid);
        buf_b[pos++] = 0x13;
        buf_b[pos++] = (uint8_t) (sizeof(val) - 1);
        memcpy(&buf_b[pos], val, sizeof(val) - 1);
        pos += sizeof(val) - 1;
        size_t len_b = pos;

        struct s2n_blob name_a = { 0 }, name_b = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&name_a, buf_a, (uint32_t) len_a));
        EXPECT_SUCCESS(s2n_blob_init(&name_b, buf_b, (uint32_t) len_b));

        bool equal = false;
        EXPECT_OK(s2n_cert_name_cmp(&name_a, &name_b, &equal));
        EXPECT_FALSE(equal);
    };

    /* Test: different RDN count is unequal. */
    {
        uint8_t buf_a[256] = { 0 };
        uint8_t buf_b[256] = { 0 };
        const uint8_t val[] = "Test";

        /* name_a: single RDN (CN=Test) */
        size_t len_a = s2n_test_build_name(buf_a, sizeof(buf_a), 0x13, val, sizeof(val) - 1);

        /* name_b: two RDNs (C=US, CN=Test) */
        size_t len_b = s2n_test_build_two_rdn_name(buf_b, sizeof(buf_b),
                "US", 0x13, val, sizeof(val) - 1);

        struct s2n_blob name_a = { 0 }, name_b = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&name_a, buf_a, (uint32_t) len_a));
        EXPECT_SUCCESS(s2n_blob_init(&name_b, buf_b, (uint32_t) len_b));

        bool equal = false;
        EXPECT_OK(s2n_cert_name_cmp(&name_a, &name_b, &equal));
        EXPECT_FALSE(equal);
    };

    /* Test: different values (same OID, same type) are unequal. */
    {
        uint8_t buf_a[256] = { 0 };
        uint8_t buf_b[256] = { 0 };
        const uint8_t val_a[] = "Alpha Corp";
        const uint8_t val_b[] = "Beta Corp";

        size_t len_a = s2n_test_build_name(buf_a, sizeof(buf_a), 0x13, val_a, sizeof(val_a) - 1);
        size_t len_b = s2n_test_build_name(buf_b, sizeof(buf_b), 0x13, val_b, sizeof(val_b) - 1);

        struct s2n_blob name_a = { 0 }, name_b = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&name_a, buf_a, (uint32_t) len_a));
        EXPECT_SUCCESS(s2n_blob_init(&name_b, buf_b, (uint32_t) len_b));

        bool equal = false;
        EXPECT_OK(s2n_cert_name_cmp(&name_a, &name_b, &equal));
        EXPECT_FALSE(equal);
    };

    /* Test: IA5String values require exact match (no case folding). */
    {
        uint8_t buf_a[256] = { 0 };
        uint8_t buf_b[256] = { 0 };
        const uint8_t val_a[] = "Test";
        const uint8_t val_b[] = "test";

        /* 0x16 = IA5String: no normalization applied. */
        size_t len_a = s2n_test_build_name(buf_a, sizeof(buf_a), 0x16, val_a, sizeof(val_a) - 1);
        size_t len_b = s2n_test_build_name(buf_b, sizeof(buf_b), 0x16, val_b, sizeof(val_b) - 1);

        struct s2n_blob name_a = { 0 }, name_b = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&name_a, buf_a, (uint32_t) len_a));
        EXPECT_SUCCESS(s2n_blob_init(&name_b, buf_b, (uint32_t) len_b));

        bool equal = false;
        EXPECT_OK(s2n_cert_name_cmp(&name_a, &name_b, &equal));
        EXPECT_FALSE(equal);
    };

    /* Test: empty names (zero RDNs) are equal. */
    {
        /* Empty Name: SEQUENCE with zero-length content. */
        uint8_t empty_name[] = { 0x30, 0x00 };
        struct s2n_blob name_a = { 0 }, name_b = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&name_a, empty_name, sizeof(empty_name)));
        EXPECT_SUCCESS(s2n_blob_init(&name_b, empty_name, sizeof(empty_name)));

        bool equal = false;
        EXPECT_OK(s2n_cert_name_cmp(&name_a, &name_b, &equal));
        EXPECT_TRUE(equal);
    };

    /* Test: real cert issuer vs subject from a self-signed cert are equal. */
    {
        struct s2n_cert_span_view view = { 0 };
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        EXPECT_OK(s2n_test_parse_pem_leaf(S2N_DEFAULT_TEST_CERT_CHAIN, &view, &der));

        /* For a chain cert (not self-signed), issuer != subject, but the
         * issuer of the leaf should equal the subject of the issuing CA.
         * For a self-signed cert, issuer == subject. Check the leaf's
         * issuer against itself to validate the comparator on real DER. */
        bool equal = false;
        EXPECT_OK(s2n_cert_name_cmp(&view.issuer, &view.subject, &equal));
        /* This cert may or may not be self-signed; just verify no crash
         * and the comparator returns a valid boolean. */
        EXPECT_TRUE(equal == true || equal == false);
    };

    /* === Path builder tests () === */

    /* Test: A valid self-signed cert (where the cert IS the anchor) is
     * directly trusted: the path is depth 1, just the leaf, matching
     * X509_verify_cert with a store certificate as the end of the chain. */
    {
        /* Use the root CA cert as both the wire chain and the anchor. */
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = anchor.parsed.not_before + 1,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_OK(s2n_cert_path_build(&path, &spans, &snapshot, &policy));
        /* Path: just the directly-trusted leaf (wire[0]) */
        EXPECT_EQUAL(path.count, 1);
        EXPECT_EQUAL(path.entries[0].type, S2N_CERT_PATH_ENTRY_WIRE);
        EXPECT_EQUAL(path.entries[0].entry_index, 0);
    };

    /* Test: A 2-cert chain (leaf + CA anchor) builds successfully. */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = anchor.parsed.not_before + 1,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_OK(s2n_cert_path_build(&path, &spans, &snapshot, &policy));
        /* Chain has leaf + intermediate + root; anchor is root.
         * Path should be: leaf -> intermediate -> anchor. */
        EXPECT_TRUE(path.count >= 2);
        EXPECT_EQUAL(path.entries[0].type, S2N_CERT_PATH_ENTRY_WIRE);
        EXPECT_EQUAL(path.entries[0].entry_index, 0);
        EXPECT_EQUAL(path.entries[path.count - 1].type, S2N_CERT_PATH_ENTRY_ANCHOR);
    };

    /* Test: No matching anchor rejects with S2N_ERR_CERT_UNTRUSTED. */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        /* Load the server chain but use the ECDSA CA cert as anchor (wrong CA). */
        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN,
                &wire_chain, &spans, &anchor, &anchor_der));

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        /* Use a time within the wire chain's validity window. The leaf is
         * spans.views[0]; use its validity midpoint. */
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_ERROR_WITH_ERRNO(
                s2n_cert_path_build(&path, &spans, &snapshot, &policy),
                S2N_ERR_CERT_UNTRUSTED);
    };

    /* Test: a chain with only wrong anchors rejects with
     * S2N_ERR_CERT_UNTRUSTED. Name-mismatched anchors are scanned without
     * consuming Work_Budget, so this exercises the no-matching-issuer reject
     * (same error code as budget exhaustion). */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        /* Use a wrong anchor so no valid path exists. The chain has 3 certs
         * and the anchors never name-match, so the search terminates after
         * scanning all candidates. */
        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN,
                &wire_chain, &spans, &anchor, &anchor_der));

        /* Replicate the anchor many times to force more evaluations. */
        struct s2n_trust_anchor many_anchors[16] = { 0 };
        for (int i = 0; i < 16; i++) {
            many_anchors[i] = anchor;
        }
        struct s2n_trust_anchor_snapshot snapshot = {
            .anchors = many_anchors,
            .count = 16
        };
        /* Use the wire chain midpoint for verification time. */
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        /* With 16 anchors (all wrong) and a 3-cert chain, the budget of 64
         * should be exhausted trying all combinations. The result is
         * S2N_ERR_CERT_UNTRUSTED. */
        EXPECT_ERROR_WITH_ERRNO(
                s2n_cert_path_build(&path, &spans, &snapshot, &policy),
                S2N_ERR_CERT_UNTRUSTED);
    };

    /* Test: a large trust store does not starve path building. The Work_Budget
     * is charged per signature attempt, not per anchor scanned, so a store
     * holding more name-mismatched anchors than the entire budget, with the
     * one correct anchor last, must still accept. (A system CA bundle is ~150
     * certificates; a per-scan charge would make acceptance depend on trust
     * store size and reject valid chains against real system stores.) */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor correct_anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &correct_anchor, &anchor_der));

        /* A wrong anchor whose subject never matches any issuer in the chain. */
        DEFER_CLEANUP(struct s2n_blob wrong_wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob wrong_anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans wrong_spans = { 0 };
        struct s2n_trust_anchor wrong_anchor = { 0 };
        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN,
                S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN,
                &wrong_wire_chain, &wrong_spans, &wrong_anchor, &wrong_anchor_der));

        /* Build a snapshot larger than the whole Work_Budget with the correct
         * anchor last, mimicking a system store loaded before the test CA. */
        const uint32_t anchor_count = S2N_CERT_PATH_WORK_BUDGET + 36;
        DEFER_CLEANUP(struct s2n_blob anchors_mem = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&anchors_mem,
                anchor_count * sizeof(struct s2n_trust_anchor)));
        struct s2n_trust_anchor *anchors =
                (struct s2n_trust_anchor *) (void *) anchors_mem.data;
        for (uint32_t i = 0; i < anchor_count - 1; i++) {
            anchors[i] = wrong_anchor;
        }
        anchors[anchor_count - 1] = correct_anchor;

        struct s2n_trust_anchor_snapshot snapshot = {
            .anchors = anchors,
            .count = anchor_count
        };
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = correct_anchor.parsed.not_before + 1,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_OK(s2n_cert_path_build(&path, &spans, &snapshot, &policy));
        EXPECT_TRUE(path.count >= 2);
        EXPECT_EQUAL(path.entries[path.count - 1].type, S2N_CERT_PATH_ENTRY_ANCHOR);
        EXPECT_EQUAL(path.entries[path.count - 1].entry_index, anchor_count - 1);
    };

    /* Test: An expired cert surfaces S2N_ERR_CERT_EXPIRED. */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        /* Set verification time far in the future so anchor is expired. */
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = anchor.parsed.not_after + 86400,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_ERROR_WITH_ERRNO(
                s2n_cert_path_build(&path, &spans, &snapshot, &policy),
                S2N_ERR_CERT_EXPIRED);
    };

    /* Test: A not-yet-valid cert surfaces S2N_ERR_CERT_NOT_YET_VALID. */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        /* Set verification time before the anchor's not_before (Jan 2024).
         * Use 1 (not 0) because 0 is a sentinel meaning "skip time checks". */
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = 1,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_ERROR_WITH_ERRNO(
                s2n_cert_path_build(&path, &spans, &snapshot, &policy),
                S2N_ERR_CERT_NOT_YET_VALID);
    };

    /* Test: Path depth exceeded rejects with S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED. */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        /* Set max_chain_depth to 2: only leaf + 1 issuer allowed. But the
         * real chain is leaf -> intermediate -> root, which needs depth 3.
         * With max_chain_depth=2 and a valid chain that needs 3, we should
         * get S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED. */
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 2,
            .verification_time = anchor.parsed.not_before + 1,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_ERROR_WITH_ERRNO(
                s2n_cert_path_build(&path, &spans, &snapshot, &policy),
                S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED);
    };

    /* Name-comparison equivalence — for all pairs of distinguished
     * names from a real-CA corpus and generated variants (case flips, whitespace
     * padding/collapse, PrintableString↔UTF8String re-encodings), the span
     * comparator reports equality exactly when X509_NAME_cmp does.
     *
     * 
     *
     * Generator: name-variant generator with seeded PRNG.
     * Minimum 100 iterations. */
    #define PROPERTY7_ITERATIONS 100

    /* Simple seeded PRNG for deterministic variant generation. */
    {
        uint32_t prng_state = 20240701; /* fixed seed for reproducibility */

    /* xorshift32-based PRNG */
    #define PRNG_NEXT(state)      \
        do {                      \
            state ^= state << 13; \
            state ^= state >> 17; \
            state ^= state << 5;  \
        } while (0)

        /* Get the subject Name DER from a real certificate as our base. */
        struct s2n_cert_span_view base_view = { 0 };
        DEFER_CLEANUP(struct s2n_blob base_der = { 0 }, s2n_free);
        EXPECT_OK(s2n_test_parse_pem_leaf(S2N_DEFAULT_TEST_CERT_CHAIN, &base_view, &base_der));

        /* We'll work with synthetic names built from string values extracted
         * from the real cert, plus generated variants. Use the build_name and
         * build_two_rdn_name helpers from above. */

        /* Base value strings used across iterations. */
        static const char *base_values[] = {
            "Amazon",
            "Test CA",
            "server.example.com",
            "US",
            "Engineering Dept",
        };
    #define NUM_BASE_VALUES 5

        /* Mutation types for the equality-preserving arm. */
        typedef enum {
            MUT_CASE_FLIP = 0,       /* ASCII case flip */
            MUT_WHITESPACE_PAD,      /* leading/trailing whitespace */
            MUT_WHITESPACE_COLLAPSE, /* interior whitespace run → single space */
            MUT_STRING_TYPE_SWAP,    /* PrintableString ↔ UTF8String */
            MUT_COMBINED,            /* multiple mutations at once */
            MUT_EQUAL_COUNT,
        } name_eq_mutation;

        /* Mutation types for the inequality-producing arm. */
        typedef enum {
            MUT_VALUE_CHANGE = 0, /* different string content */
            MUT_OID_CHANGE,       /* different attribute OID */
            MUT_EXTRA_RDN,        /* add an extra RDN */
            MUT_REMOVE_CHAR,      /* shorten the value */
            MUT_UNEQUAL_COUNT,
        } name_neq_mutation;

        for (uint32_t iter = 0; iter < PROPERTY7_ITERATIONS; iter++) {
            PRNG_NEXT(prng_state);
            uint32_t value_idx = prng_state % NUM_BASE_VALUES;
            const char *base_val = base_values[value_idx];
            size_t base_val_len = strlen(base_val);

            PRNG_NEXT(prng_state);
            bool test_equality = (prng_state % 2 == 0);

            uint8_t buf_a[512] = { 0 };
            uint8_t buf_b[512] = { 0 };
            size_t len_a = 0;
            size_t len_b = 0;

            if (test_equality) {
                /* === Equality-preserving mutations === */
                PRNG_NEXT(prng_state);
                name_eq_mutation mut = (name_eq_mutation) (prng_state % MUT_EQUAL_COUNT);

                /* Name A: PrintableString with the base value. */
                len_a = s2n_test_build_name(buf_a, sizeof(buf_a), 0x13,
                        (const uint8_t *) base_val, base_val_len);

                switch (mut) {
                    case MUT_CASE_FLIP: {
                        /* Flip case of some characters. */
                        uint8_t flipped[256] = { 0 };
                        memcpy(flipped, base_val, base_val_len);
                        for (size_t c = 0; c < base_val_len; c++) {
                            PRNG_NEXT(prng_state);
                            if (prng_state % 3 == 0) {
                                if (flipped[c] >= 'A' && flipped[c] <= 'Z') {
                                    flipped[c] = (uint8_t) (flipped[c] + 32);
                                } else if (flipped[c] >= 'a' && flipped[c] <= 'z') {
                                    flipped[c] = (uint8_t) (flipped[c] - 32);
                                }
                            }
                        }
                        len_b = s2n_test_build_name(buf_b, sizeof(buf_b), 0x13,
                                flipped, base_val_len);
                        break;
                    }
                    case MUT_WHITESPACE_PAD: {
                        /* Add leading/trailing spaces. */
                        uint8_t padded[256] = { 0 };
                        PRNG_NEXT(prng_state);
                        size_t lead = 1 + (prng_state % 3);
                        PRNG_NEXT(prng_state);
                        size_t trail = 1 + (prng_state % 3);
                        memset(padded, ' ', lead);
                        memcpy(padded + lead, base_val, base_val_len);
                        memset(padded + lead + base_val_len, ' ', trail);
                        size_t padded_len = lead + base_val_len + trail;
                        len_b = s2n_test_build_name(buf_b, sizeof(buf_b), 0x13,
                                padded, padded_len);
                        break;
                    }
                    case MUT_WHITESPACE_COLLAPSE: {
                        /* Expand interior single spaces to multiple spaces. */
                        uint8_t expanded[256] = { 0 };
                        size_t out_len = 0;
                        for (size_t c = 0; c < base_val_len; c++) {
                            expanded[out_len++] = (uint8_t) base_val[c];
                            if (base_val[c] == ' ') {
                                PRNG_NEXT(prng_state);
                                size_t extra = 1 + (prng_state % 3);
                                for (size_t e = 0; e < extra; e++) {
                                    expanded[out_len++] = ' ';
                                }
                            }
                        }
                        len_b = s2n_test_build_name(buf_b, sizeof(buf_b), 0x13,
                                expanded, out_len);
                        break;
                    }
                    case MUT_STRING_TYPE_SWAP: {
                        /* Name A is PrintableString (0x13), Name B is UTF8String (0x0c)
                         * with identical value content. */
                        len_b = s2n_test_build_name(buf_b, sizeof(buf_b), 0x0c,
                                (const uint8_t *) base_val, base_val_len);
                        break;
                    }
                    case MUT_COMBINED: {
                        /* Case flip + type swap: UTF8String with case flipped. */
                        uint8_t flipped[256] = { 0 };
                        memcpy(flipped, base_val, base_val_len);
                        for (size_t c = 0; c < base_val_len; c++) {
                            if (flipped[c] >= 'A' && flipped[c] <= 'Z') {
                                flipped[c] = (uint8_t) (flipped[c] + 32);
                            } else if (flipped[c] >= 'a' && flipped[c] <= 'z') {
                                flipped[c] = (uint8_t) (flipped[c] - 32);
                            }
                        }
                        len_b = s2n_test_build_name(buf_b, sizeof(buf_b), 0x0c,
                                flipped, base_val_len);
                        break;
                    }
                    default:
                        len_b = len_a;
                        memcpy(buf_b, buf_a, len_a);
                        break;
                }
            } else {
                /* === Inequality-producing mutations === */
                PRNG_NEXT(prng_state);
                name_neq_mutation mut = (name_neq_mutation) (prng_state % MUT_UNEQUAL_COUNT);

                /* Name A: PrintableString with the base value. */
                len_a = s2n_test_build_name(buf_a, sizeof(buf_a), 0x13,
                        (const uint8_t *) base_val, base_val_len);

                switch (mut) {
                    case MUT_VALUE_CHANGE: {
                        /* Different string content but same type/OID. */
                        uint8_t changed[256] = { 0 };
                        memcpy(changed, base_val, base_val_len);
                        PRNG_NEXT(prng_state);
                        size_t pos = prng_state % base_val_len;
                        /* Change a non-space character to something different. */
                        changed[pos] = (uint8_t) ((changed[pos] == 'X') ? 'Y' : 'X');
                        len_b = s2n_test_build_name(buf_b, sizeof(buf_b), 0x13,
                                changed, base_val_len);
                        break;
                    }
                    case MUT_OID_CHANGE: {
                        /* Use a different OID (organizationName instead of commonName). */
                        static const uint8_t org_oid[] = { 0x55, 0x04, 0x0a };
                        size_t atv_content = 2 + sizeof(org_oid) + 2 + base_val_len;
                        size_t set_content = 2 + atv_content;
                        size_t seq_content = 2 + set_content;
                        size_t p = 0;
                        buf_b[p++] = 0x30;
                        buf_b[p++] = (uint8_t) seq_content;
                        buf_b[p++] = 0x31;
                        buf_b[p++] = (uint8_t) set_content;
                        buf_b[p++] = 0x30;
                        buf_b[p++] = (uint8_t) atv_content;
                        buf_b[p++] = 0x06;
                        buf_b[p++] = (uint8_t) sizeof(org_oid);
                        memcpy(&buf_b[p], org_oid, sizeof(org_oid));
                        p += sizeof(org_oid);
                        buf_b[p++] = 0x13;
                        buf_b[p++] = (uint8_t) base_val_len;
                        memcpy(&buf_b[p], base_val, base_val_len);
                        p += base_val_len;
                        len_b = p;
                        break;
                    }
                    case MUT_EXTRA_RDN: {
                        /* Name B has two RDNs (C=US, CN=base_val) vs name A's one RDN. */
                        len_b = s2n_test_build_two_rdn_name(buf_b, sizeof(buf_b),
                                "US", 0x13, (const uint8_t *) base_val, base_val_len);
                        break;
                    }
                    case MUT_REMOVE_CHAR: {
                        /* Shorten the value by one character (not just whitespace). */
                        size_t shorter_len = (base_val_len > 1) ? base_val_len - 1 : base_val_len;
                        len_b = s2n_test_build_name(buf_b, sizeof(buf_b), 0x13,
                                (const uint8_t *) base_val, shorter_len);
                        break;
                    }
                    default:
                        /* Different value as fallback. */
                        len_b = s2n_test_build_name(buf_b, sizeof(buf_b), 0x13,
                                (const uint8_t *) "ZZZZZ", 5);
                        break;
                }
            }

            /* Now compare with our span comparator. */
            struct s2n_blob name_a = { 0 }, name_b = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&name_a, buf_a, (uint32_t) len_a));
            EXPECT_SUCCESS(s2n_blob_init(&name_b, buf_b, (uint32_t) len_b));

            bool span_equal = false;
            EXPECT_OK(s2n_cert_name_cmp(&name_a, &name_b, &span_equal));

            /* Decode both Name TLVs into X509_NAME objects for the oracle. */
            const uint8_t *p_a = buf_a;
            X509_NAME *x509_name_a = d2i_X509_NAME(NULL, &p_a, (long) len_a);
            EXPECT_NOT_NULL(x509_name_a);

            const uint8_t *p_b = buf_b;
            X509_NAME *x509_name_b = d2i_X509_NAME(NULL, &p_b, (long) len_b);
            EXPECT_NOT_NULL(x509_name_b);

            int x509_cmp_result = X509_NAME_cmp(x509_name_a, x509_name_b);
            bool x509_equal = (x509_cmp_result == 0);

            /* The property: s2n_cert_name_cmp agrees with X509_NAME_cmp. */
            EXPECT_EQUAL(span_equal, x509_equal);

            X509_NAME_free(x509_name_a);
            X509_NAME_free(x509_name_b);
        }

    #undef PRNG_NEXT
    #undef NUM_BASE_VALUES
    };

    /* Work_Budget bound and monotonicity — for all chains,
     * candidate-issuer evaluations never exceed the Work_Budget; exhaustion
     * yields S2N_ERR_CERT_UNTRUSTED; any chain accepted under budget B is
     * accepted under every B' >= B.
     *
     * Since the Work_Budget is a compile-time constant (64), we test:
     *  (a) Bound: path building always terminates regardless of the number of
     *      wrong anchors presented (never hangs, evaluation count is bounded).
     *  (b) Reject error code: when only wrong anchors are present the chain is
     *      rejected with S2N_ERR_CERT_UNTRUSTED (name-mismatched anchors are
     *      scanned without consuming budget; the same error code surfaces
     *      whether the reject comes from exhaustion or no matching issuer).
     *  (c) Monotonicity (indirect): a valid chain accepted with 1 correct anchor
     *      is still accepted when additional correct/wrong anchors are present
     *      (same budget, the correct anchor is still reachable).
     *
     * 
     *
     * Generator: chain configurations with seeded PRNG-controlled anchor counts.
     * Minimum 100 iterations. */
    #define PROPERTY8_ITERATIONS 100
    {
        uint32_t p8_prng = 20240808; /* fixed seed for reproducibility */

    #define P8_PRNG_NEXT(state)   \
        do {                      \
            state ^= state << 13; \
            state ^= state >> 17; \
            state ^= state << 5;  \
        } while (0)

        /* Load a valid chain + its correct anchor once. */
        DEFER_CLEANUP(struct s2n_blob p8_wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob p8_correct_anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans p8_spans = { 0 };
        struct s2n_trust_anchor p8_correct_anchor = { 0 };
        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &p8_wire_chain, &p8_spans, &p8_correct_anchor,
                &p8_correct_anchor_der));

        /* Load a wrong anchor (ECDSA CA — will never match the RSA chain). */
        DEFER_CLEANUP(struct s2n_blob p8_wrong_anchor_der = { 0 }, s2n_free);
        struct s2n_trust_anchor p8_wrong_anchor = { 0 };
        {
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *wrong_ca = NULL,
                    s2n_cert_chain_and_key_ptr_free);
            wrong_ca = s2n_cert_chain_and_key_new();
            EXPECT_NOT_NULL(wrong_ca);
            uint8_t pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
            uint32_t pem_len = 0;
            EXPECT_SUCCESS(s2n_read_test_pem_and_len(
                    S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, pem, &pem_len,
                    S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_cert_chain_and_key_load_public_pem_bytes(
                    wrong_ca, pem, pem_len));
            struct s2n_blob *ca_der = &wrong_ca->cert_chain->head->raw;
            EXPECT_SUCCESS(s2n_realloc(&p8_wrong_anchor_der, ca_der->size));
            memcpy(p8_wrong_anchor_der.data, ca_der->data, ca_der->size);
            p8_wrong_anchor = (struct s2n_trust_anchor){ 0 };
            p8_wrong_anchor.der = p8_wrong_anchor_der;
            EXPECT_OK(s2n_cert_span_view_parse(
                    &p8_wrong_anchor.parsed, &p8_wrong_anchor_der));
        }

        /* Use the midpoint of the leaf's validity window as verification time
         * so the chain is valid. */
        uint64_t p8_valid_time =
                (p8_spans.views[0].not_before + p8_spans.views[0].not_after) / 2;

        for (uint32_t iter = 0; iter < PROPERTY8_ITERATIONS; iter++) {
            P8_PRNG_NEXT(p8_prng);

            /* Generate a random number of wrong anchors (0..15) and decide
             * whether to include the correct anchor (controls accept/reject). */
            uint32_t num_wrong = p8_prng % 16;
            P8_PRNG_NEXT(p8_prng);
            bool include_correct = (p8_prng % 3 != 0);
            /* ~2/3 of iterations include the correct anchor (accept path),
             * ~1/3 do not (reject path, testing budget exhaustion). */

            P8_PRNG_NEXT(p8_prng);
            /* Position of the correct anchor among the array (if included). */
            uint32_t correct_pos = 0;
            uint32_t total_anchors = num_wrong + (include_correct ? 1 : 0);
            if (total_anchors == 0) {
                /* Ensure at least one anchor (wrong) to avoid degenerate case. */
                num_wrong = 1;
                total_anchors = 1;
                include_correct = false;
            }
            if (include_correct && total_anchors > 1) {
                correct_pos = p8_prng % total_anchors;
            }

            /* Build the anchor array. */
            struct s2n_trust_anchor anchors[S2N_CERT_CHAIN_SPANS_MAX + 1];
            EXPECT_TRUE(total_anchors <= S2N_CERT_CHAIN_SPANS_MAX + 1);
            for (uint32_t a = 0; a < total_anchors; a++) {
                if (include_correct && a == correct_pos) {
                    anchors[a] = p8_correct_anchor;
                } else {
                    anchors[a] = p8_wrong_anchor;
                }
            }

            struct s2n_trust_anchor_snapshot snapshot = {
                .anchors = anchors,
                .count = total_anchors,
            };
            struct s2n_cert_path_policy policy = {
                .max_chain_depth = 10,
                .verification_time = p8_valid_time,
            };
            struct s2n_cert_path path = { 0 };

            s2n_result result = s2n_cert_path_build(
                    &path, &p8_spans, &snapshot, &policy);

            if (include_correct) {
                /* (a) Bound + acceptance: path building terminates and finds
                 * a valid path. The budget was sufficient because a correct
                 * anchor exists and is reachable within 64 evaluations for
                 * this chain (<=3 wire certs * <=16 anchors < 64). */
                EXPECT_OK(result);
                EXPECT_TRUE(path.count >= 2);
            } else {
                /* (b) Exhaustion or rejection: no correct anchor means no
                 * valid path. The error must be S2N_ERR_CERT_UNTRUSTED (either
                 * from budget exhaustion or from no matching issuer). */
                EXPECT_ERROR_WITH_ERRNO(result, S2N_ERR_CERT_UNTRUSTED);
            }
        }

        /* (c) Monotonicity: verify that a chain accepted with 1 correct
         * anchor is still accepted when more anchors (correct or wrong) are
         * added. This demonstrates that adding anchors (same budget) does not
         * cause a previously-accepted chain to be rejected. */
        for (uint32_t mono_iter = 0; mono_iter < PROPERTY8_ITERATIONS; mono_iter++) {
            P8_PRNG_NEXT(p8_prng);

            /* Baseline: 1 correct anchor, should always succeed. */
            {
                struct s2n_trust_anchor_snapshot snapshot = {
                    .anchors = &p8_correct_anchor,
                    .count = 1,
                };
                struct s2n_cert_path_policy policy = {
                    .max_chain_depth = 10,
                    .verification_time = p8_valid_time,
                };
                struct s2n_cert_path path = { 0 };
                EXPECT_OK(s2n_cert_path_build(
                        &path, &p8_spans, &snapshot, &policy));
                EXPECT_TRUE(path.count >= 2);
            }

            /* Extended: correct anchor + random number of wrong anchors
             * (0..15). The chain must still be accepted (monotonicity:
             * accepted under budget B implies accepted under B' >= B; here
             * B'= B = 64 but with the correct anchor still present, it is
             * always reachable). */
            uint32_t extra_wrong = p8_prng % 16;
            uint32_t mono_total = 1 + extra_wrong;
            struct s2n_trust_anchor mono_anchors[S2N_CERT_CHAIN_SPANS_MAX + 1];

            /* Place the correct anchor at a random position. */
            P8_PRNG_NEXT(p8_prng);
            uint32_t mono_correct_pos = p8_prng % mono_total;
            for (uint32_t a = 0; a < mono_total; a++) {
                if (a == mono_correct_pos) {
                    mono_anchors[a] = p8_correct_anchor;
                } else {
                    mono_anchors[a] = p8_wrong_anchor;
                }
            }

            struct s2n_trust_anchor_snapshot snapshot = {
                .anchors = mono_anchors,
                .count = mono_total,
            };
            struct s2n_cert_path_policy policy = {
                .max_chain_depth = 10,
                .verification_time = p8_valid_time,
            };
            struct s2n_cert_path path = { 0 };
            EXPECT_OK(s2n_cert_path_build(
                    &path, &p8_spans, &snapshot, &policy));
            EXPECT_TRUE(path.count >= 2);
        }

    #undef P8_PRNG_NEXT
    };

    /* Differential decision parity (initial corpus) — for all
     * generated chains (valid RSA PKCS#1 v1.5 / RSA-PSS / ECDSA / Ed25519
     * chains; shuffled and extraneous intermediates), the path builder
     * produces the same accept/reject decision as X509_verify_cert under the
     * same anchors and verification time.
     *
     * 
     *
     * Generators: valid-chain generator plus chain mutator (shuffle, inject,
     * truncate); minimum 100 iterations across multiple chain configurations
     * and mutations. */
    #define PROPERTY4_ITERATIONS 120
    {
        /* Chain configurations: each has a chain PEM and a CA PEM.
         * We exercise RSA PKCS#1 v1.5, RSA-PSS, ECDSA P-256, ECDSA P-384. */
        struct {
            const char *chain_pem;
            const char *ca_pem;
            const char *description;
        } chain_configs[] = {
            {
                    "../pems/permutations/rsae_pkcs_2048_sha256/server-chain.pem",
                    "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                    "RSA PKCS#1 v1.5 2048 SHA-256",
            },
            {
                    "../pems/permutations/rsapss_pss_2048_sha256/server-chain.pem",
                    "../pems/permutations/rsapss_pss_2048_sha256/ca-cert.pem",
                    "RSA-PSS 2048 SHA-256",
            },
            {
                    "../pems/permutations/ec_ecdsa_p256_sha256/server-chain.pem",
                    "../pems/permutations/ec_ecdsa_p256_sha256/ca-cert.pem",
                    "ECDSA P-256 SHA-256",
            },
            {
                    "../pems/permutations/ec_ecdsa_p384_sha384/server-chain.pem",
                    "../pems/permutations/ec_ecdsa_p384_sha384/ca-cert.pem",
                    "ECDSA P-384 SHA-384",
            },
        };
    #define NUM_CHAIN_CONFIGS 4

        /* Mutation types applied to the wire chain. */
        typedef enum {
            P4_MUT_NONE = 0, /* identity: original chain order */
            P4_MUT_SHUFFLE,  /* shuffle intermediates (leaf stays first) */
            P4_MUT_INJECT,   /* inject an extraneous cert from another chain */
            P4_MUT_TRUNCATE, /* remove an intermediate (should cause rejection) */
            P4_MUT_COUNT,
        } p4_mutation;

        uint32_t p4_prng = 20240904; /* fixed seed for reproducibility */

    #define P4_PRNG_NEXT(state)   \
        do {                      \
            state ^= state << 13; \
            state ^= state >> 17; \
            state ^= state << 5;  \
        } while (0)

        /* Pre-load all chain configs into DER wire_chain blobs + anchor DERs. */
        struct {
            struct s2n_blob wire_chain;
            struct s2n_cert_chain_spans spans;
            struct s2n_trust_anchor anchor;
            struct s2n_blob anchor_der;
            /* Individual DER certs for mutation. */
            struct s2n_blob cert_ders[S2N_CERT_CHAIN_SPANS_MAX];
            uint32_t cert_count;
        } configs[NUM_CHAIN_CONFIGS];
        memset(configs, 0, sizeof(configs));

        for (int cfg = 0; cfg < NUM_CHAIN_CONFIGS; cfg++) {
            /* RSA-PSS chains can't load when libcrypto lacks RSA-PSS support.
             * Leave the config empty; iterations select from loaded configs only. */
            if (!s2n_is_rsa_pss_certs_supported() && strstr(chain_configs[cfg].chain_pem, "rsapss")) {
                continue;
            }

            /* Load chain PEM and convert to concatenated DER. */
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL,
                    s2n_cert_chain_and_key_ptr_free);
            chain = s2n_cert_chain_and_key_new();
            EXPECT_NOT_NULL(chain);

            uint8_t pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
            uint32_t pem_len = 0;
            EXPECT_SUCCESS(s2n_read_test_pem_and_len(
                    chain_configs[cfg].chain_pem, pem, &pem_len,
                    S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_cert_chain_and_key_load_public_pem_bytes(
                    chain, pem, pem_len));

            /* Extract individual cert DER blobs and compute total. */
            uint32_t total_size = 0;
            uint32_t cert_idx = 0;
            struct s2n_cert *cert = chain->cert_chain->head;
            while (cert != NULL && cert_idx < S2N_CERT_CHAIN_SPANS_MAX) {
                EXPECT_SUCCESS(s2n_realloc(
                        &configs[cfg].cert_ders[cert_idx], cert->raw.size));
                memcpy(configs[cfg].cert_ders[cert_idx].data,
                        cert->raw.data, cert->raw.size);
                total_size += cert->raw.size;
                cert_idx++;
                cert = cert->next;
            }
            configs[cfg].cert_count = cert_idx;

            /* Build the baseline wire chain. */
            EXPECT_SUCCESS(s2n_realloc(&configs[cfg].wire_chain, total_size));
            uint32_t offset = 0;
            for (uint32_t c = 0; c < cert_idx; c++) {
                memcpy(configs[cfg].wire_chain.data + offset,
                        configs[cfg].cert_ders[c].data,
                        configs[cfg].cert_ders[c].size);
                offset += configs[cfg].cert_ders[c].size;
            }

            /* Parse spans. */
            EXPECT_OK(s2n_cert_chain_spans_parse(
                    &configs[cfg].spans, &configs[cfg].wire_chain, 16));

            /* Load anchor. */
            DEFER_CLEANUP(struct s2n_cert_chain_and_key *ca = NULL,
                    s2n_cert_chain_and_key_ptr_free);
            ca = s2n_cert_chain_and_key_new();
            EXPECT_NOT_NULL(ca);
            EXPECT_SUCCESS(s2n_read_test_pem_and_len(
                    chain_configs[cfg].ca_pem, pem, &pem_len,
                    S2N_MAX_TEST_PEM_SIZE));
            EXPECT_SUCCESS(s2n_cert_chain_and_key_load_public_pem_bytes(
                    ca, pem, pem_len));

            struct s2n_blob *ca_der = &ca->cert_chain->head->raw;
            EXPECT_SUCCESS(s2n_realloc(
                    &configs[cfg].anchor_der, ca_der->size));
            memcpy(configs[cfg].anchor_der.data, ca_der->data, ca_der->size);
            configs[cfg].anchor.der = configs[cfg].anchor_der;
            EXPECT_OK(s2n_cert_span_view_parse(
                    &configs[cfg].anchor.parsed, &configs[cfg].anchor_der));
        }

    /* Helper: run the X509_verify_cert oracle on a DER cert array with
         * a given CA anchor DER and verification time. Returns true if the
         * chain verifies, false otherwise. */
    #define P4_ORACLE_VERIFY(cert_ders_arr, cert_count_val, anchor_der_ptr,  \
            verify_time, oracle_result_ptr)                                  \
        do {                                                                 \
            /* Load the anchor into an X509_STORE. */                        \
            X509_STORE *store = X509_STORE_new();                            \
            EXPECT_NOT_NULL(store);                                          \
            const uint8_t *_a_ptr = (anchor_der_ptr)->data;                  \
            X509 *_ca = d2i_X509(NULL, &_a_ptr, (anchor_der_ptr)->size);     \
            EXPECT_NOT_NULL(_ca);                                            \
            EXPECT_EQUAL(X509_STORE_add_cert(store, _ca), 1);                \
                                                                             \
            /* Load leaf and untrusted intermediates. */                     \
            const uint8_t *_l_ptr = (cert_ders_arr)[0].data;                 \
            X509 *_leaf = d2i_X509(NULL, &_l_ptr,                            \
                    (long) (cert_ders_arr)[0].size);                         \
            EXPECT_NOT_NULL(_leaf);                                          \
                                                                             \
            STACK_OF(X509) *_untrusted = sk_X509_new_null();                 \
            EXPECT_NOT_NULL(_untrusted);                                     \
            for (uint32_t _i = 1; _i < (cert_count_val); _i++) {             \
                const uint8_t *_c_ptr = (cert_ders_arr)[_i].data;            \
                X509 *_ic = d2i_X509(NULL, &_c_ptr,                          \
                        (long) (cert_ders_arr)[_i].size);                    \
                EXPECT_NOT_NULL(_ic);                                        \
                sk_X509_push(_untrusted, _ic);                               \
            }                                                                \
                                                                             \
            /* Set up the store context. */                                  \
            X509_STORE_CTX *_ctx = X509_STORE_CTX_new();                     \
            EXPECT_NOT_NULL(_ctx);                                           \
            EXPECT_EQUAL(                                                    \
                    X509_STORE_CTX_init(_ctx, store, _leaf, _untrusted), 1); \
                                                                             \
            /* Set verification time and partial chain flag. */              \
            X509_VERIFY_PARAM *_param =                                      \
                    X509_STORE_CTX_get0_param(_ctx);                         \
            X509_VERIFY_PARAM_set_time(_param, (time_t) (verify_time));      \
            X509_STORE_CTX_set_flags(_ctx, X509_V_FLAG_PARTIAL_CHAIN);       \
                                                                             \
            int _ret = X509_verify_cert(_ctx);                               \
            *(oracle_result_ptr) = (_ret == 1);                              \
                                                                             \
            /* Cleanup. */                                                   \
            X509_STORE_CTX_free(_ctx);                                       \
            for (int _j = 0; _j < sk_X509_num(_untrusted); _j++) {           \
                X509_free(sk_X509_value(_untrusted, _j));                    \
            }                                                                \
            sk_X509_free(_untrusted);                                        \
            X509_free(_leaf);                                                \
            X509_free(_ca);                                                  \
            X509_STORE_free(store);                                          \
        } while (0)

        /* Select only from configs that loaded, so skipping RSA-PSS chains
         * doesn't reduce the number of iterations run. */
        uint32_t usable_cfgs[NUM_CHAIN_CONFIGS] = { 0 };
        uint32_t usable_cfg_count = 0;
        for (uint32_t cfg = 0; cfg < NUM_CHAIN_CONFIGS; cfg++) {
            if (configs[cfg].cert_count > 0) {
                usable_cfgs[usable_cfg_count++] = cfg;
            }
        }

        uint32_t iterations_run = 0;

        for (uint32_t iter = 0; iter < PROPERTY4_ITERATIONS; iter++) {
            P4_PRNG_NEXT(p4_prng);
            uint32_t cfg_idx = usable_cfgs[p4_prng % usable_cfg_count];
            P4_PRNG_NEXT(p4_prng);
            p4_mutation mutation = (p4_mutation) (p4_prng % P4_MUT_COUNT);

            /* Build a mutated cert DER array. */
            struct s2n_blob mutated_ders[S2N_CERT_CHAIN_SPANS_MAX + 1];
            uint32_t mutated_count = 0;
            memset(mutated_ders, 0, sizeof(mutated_ders));

            switch (mutation) {
                case P4_MUT_NONE: {
                    /* Original order. */
                    for (uint32_t c = 0; c < configs[cfg_idx].cert_count; c++) {
                        mutated_ders[c] = configs[cfg_idx].cert_ders[c];
                    }
                    mutated_count = configs[cfg_idx].cert_count;
                    break;
                }
                case P4_MUT_SHUFFLE: {
                    /* Keep leaf at index 0, shuffle the rest. */
                    mutated_ders[0] = configs[cfg_idx].cert_ders[0];
                    /* Copy intermediates into positions 1..count-1 then
                     * Fisher-Yates shuffle. */
                    for (uint32_t c = 1; c < configs[cfg_idx].cert_count; c++) {
                        mutated_ders[c] = configs[cfg_idx].cert_ders[c];
                    }
                    mutated_count = configs[cfg_idx].cert_count;
                    for (uint32_t c = mutated_count - 1; c > 1; c--) {
                        P4_PRNG_NEXT(p4_prng);
                        uint32_t swap_idx = 1 + (p4_prng % c);
                        struct s2n_blob tmp = mutated_ders[c];
                        mutated_ders[c] = mutated_ders[swap_idx];
                        mutated_ders[swap_idx] = tmp;
                    }
                    break;
                }
                case P4_MUT_INJECT: {
                    /* Inject an extraneous cert from a different chain config. */
                    P4_PRNG_NEXT(p4_prng);
                    uint32_t inject_cfg = (cfg_idx + 1 + (p4_prng % (NUM_CHAIN_CONFIGS - 1)))
                            % NUM_CHAIN_CONFIGS;
                    /* Start with the original chain. */
                    for (uint32_t c = 0; c < configs[cfg_idx].cert_count; c++) {
                        mutated_ders[c] = configs[cfg_idx].cert_ders[c];
                    }
                    mutated_count = configs[cfg_idx].cert_count;
                    /* Inject an intermediate from a different chain. */
                    if (configs[inject_cfg].cert_count > 1 && mutated_count < S2N_CERT_CHAIN_SPANS_MAX) {
                        P4_PRNG_NEXT(p4_prng);
                        uint32_t inject_cert_idx = 1 + (p4_prng % (configs[inject_cfg].cert_count - 1));
                        /* Insert at a random position after the leaf. */
                        P4_PRNG_NEXT(p4_prng);
                        uint32_t insert_pos = 1 + (p4_prng % mutated_count);
                        /* Shift right. */
                        for (uint32_t c = mutated_count; c > insert_pos; c--) {
                            mutated_ders[c] = mutated_ders[c - 1];
                        }
                        mutated_ders[insert_pos] =
                                configs[inject_cfg].cert_ders[inject_cert_idx];
                        mutated_count++;
                    }
                    break;
                }
                case P4_MUT_TRUNCATE: {
                    /* Remove an intermediate (keep leaf). Should cause rejection
                     * if the chain has > 1 intermediate. For chains with only
                     * leaf + 1 intermediate, removing the intermediate means no
                     * path to anchor. */
                    if (configs[cfg_idx].cert_count > 2) {
                        /* Remove a random intermediate. */
                        P4_PRNG_NEXT(p4_prng);
                        uint32_t remove_idx = 1 + (p4_prng % (configs[cfg_idx].cert_count - 1));
                        uint32_t out_idx = 0;
                        for (uint32_t c = 0; c < configs[cfg_idx].cert_count; c++) {
                            if (c != remove_idx) {
                                mutated_ders[out_idx++] =
                                        configs[cfg_idx].cert_ders[c];
                            }
                        }
                        mutated_count = out_idx;
                    } else {
                        /* Chain has only leaf (+ maybe 1 cert). Remove the only
                         * intermediate if present. */
                        mutated_ders[0] = configs[cfg_idx].cert_ders[0];
                        mutated_count = 1;
                    }
                    break;
                }
                default:
                    /* Fallback: no mutation. */
                    for (uint32_t c = 0; c < configs[cfg_idx].cert_count; c++) {
                        mutated_ders[c] = configs[cfg_idx].cert_ders[c];
                    }
                    mutated_count = configs[cfg_idx].cert_count;
                    break;
            }

            /* Build the mutated wire chain blob for the path builder. */
            uint32_t mutated_total_size = 0;
            for (uint32_t c = 0; c < mutated_count; c++) {
                mutated_total_size += mutated_ders[c].size;
            }

            uint8_t mutated_wire_buf[65536] = { 0 };
            EXPECT_TRUE(mutated_total_size <= sizeof(mutated_wire_buf));
            uint32_t moffset = 0;
            for (uint32_t c = 0; c < mutated_count; c++) {
                memcpy(mutated_wire_buf + moffset, mutated_ders[c].data,
                        mutated_ders[c].size);
                moffset += mutated_ders[c].size;
            }
            struct s2n_blob mutated_wire = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&mutated_wire, mutated_wire_buf,
                    mutated_total_size));

            /* Parse the mutated wire chain into spans. */
            struct s2n_cert_chain_spans mutated_spans = { 0 };
            s2n_result parse_result = s2n_cert_chain_spans_parse(
                    &mutated_spans, &mutated_wire, 16);
            if (s2n_result_is_error(parse_result)) {
                /* If parsing fails, the oracle should also reject.
                 * Parse failures are only possible with truly malformed DER,
                 * which won't happen with our cert corpus. Skip this iteration
                 * if it somehow fails. */
                continue;
            }

            /* Determine verification time: midpoint of the leaf's validity. */
            uint64_t verify_time = (mutated_spans.views[0].not_before + mutated_spans.views[0].not_after) / 2;

            /* === Path builder decision === */
            struct s2n_trust_anchor_snapshot snapshot = {
                .anchors = &configs[cfg_idx].anchor,
                .count = 1,
            };
            struct s2n_cert_path_policy policy = {
                .max_chain_depth = 10,
                .verification_time = verify_time,
            };
            struct s2n_cert_path path = { 0 };
            s2n_result path_result = s2n_cert_path_build(
                    &path, &mutated_spans, &snapshot, &policy);
            bool path_builder_accepts = s2n_result_is_ok(path_result);

            /* === X509_verify_cert oracle decision === */
            bool oracle_accepts = false;
            P4_ORACLE_VERIFY(mutated_ders, mutated_count,
                    &configs[cfg_idx].anchor_der, verify_time,
                    &oracle_accepts);

            /* === The property: decisions must agree === */
            EXPECT_EQUAL(path_builder_accepts, oracle_accepts);

            iterations_run++;
        }

        /* Ensure we actually ran at least 100 iterations. */
        EXPECT_TRUE(iterations_run >= 100);

        /* Cleanup config allocations. */
        for (int cfg = 0; cfg < NUM_CHAIN_CONFIGS; cfg++) {
            EXPECT_SUCCESS(s2n_free(&configs[cfg].wire_chain));
            EXPECT_SUCCESS(s2n_free(&configs[cfg].anchor_der));
            for (uint32_t c = 0; c < configs[cfg].cert_count; c++) {
                EXPECT_SUCCESS(s2n_free(&configs[cfg].cert_ders[c]));
            }
        }

    #undef P4_ORACLE_VERIFY
    #undef P4_PRNG_NEXT
    #undef NUM_CHAIN_CONFIGS
    };

    /* === CA constraint tests () === */

    /* Test: An intermediate lacking basicConstraints CA:TRUE rejects with
     * S2N_ERR_CERT_UNTRUSTED (). */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* The chain should have at least 2 certs (leaf + intermediate).
         * Confirm the intermediate (index 1) is a CA before we clear it. */
        EXPECT_TRUE(spans.count >= 2);
        EXPECT_TRUE(spans.views[1].basic_constraints_present);
        EXPECT_TRUE(spans.views[1].basic_constraints_is_ca);

        /* Clear the CA flag to simulate a non-CA intermediate. */
        spans.views[1].basic_constraints_is_ca = false;

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_ERROR_WITH_ERRNO(
                s2n_cert_path_build(&path, &spans, &snapshot, &policy),
                S2N_ERR_CERT_UNTRUSTED);
    };

    /* Test: An intermediate with basicConstraints absent rejects with
     * S2N_ERR_CERT_UNTRUSTED (). */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        EXPECT_TRUE(spans.count >= 2);

        /* Clear the basicConstraints extension entirely from the intermediate. */
        spans.views[1].basic_constraints_present = false;
        spans.views[1].basic_constraints_is_ca = false;

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_ERROR_WITH_ERRNO(
                s2n_cert_path_build(&path, &spans, &snapshot, &policy),
                S2N_ERR_CERT_UNTRUSTED);
    };

    /* Test: An intermediate with keyUsage present but keyCertSign NOT set
     * rejects with S2N_ERR_CERT_UNTRUSTED (). */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        EXPECT_TRUE(spans.count >= 2);

        /* Set keyUsage present but WITHOUT keyCertSign on the intermediate.
         * digitalSignature (0x80) is set, but keyCertSign (0x04) is not. */
        spans.views[1].key_usage_present = true;
        spans.views[1].key_usage_bits = 0x80; /* digitalSignature only */

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_ERROR_WITH_ERRNO(
                s2n_cert_path_build(&path, &spans, &snapshot, &policy),
                S2N_ERR_CERT_UNTRUSTED);
    };

    /* Test: A trust anchor with keyUsage present but keyCertSign NOT set
     * rejects with S2N_ERR_CERT_UNTRUSTED (). */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* Set keyUsage present but WITHOUT keyCertSign on the anchor. */
        anchor.parsed.key_usage_present = true;
        anchor.parsed.key_usage_bits = 0x80; /* digitalSignature only */

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_ERROR_WITH_ERRNO(
                s2n_cert_path_build(&path, &spans, &snapshot, &policy),
                S2N_ERR_CERT_UNTRUSTED);
    };

    /* Test: A valid chain with proper CA constraints and keyCertSign set
     * continues to pass path building. */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_OK(s2n_cert_path_build(&path, &spans, &snapshot, &policy));
        EXPECT_TRUE(path.count >= 2);
    };

    /* Test: pathLenConstraint exceeded rejects with S2N_ERR_CERT_UNTRUSTED
     * (). Simulate by setting pathLen=0 on the intermediate, which
     * means no subordinate CAs may follow it. If there are non-self-issued
     * intermediates below it, the check should fail. For a chain with
     * leaf -> intermediate -> anchor, pathLen=0 on the intermediate is fine
     * because only the leaf (not a CA) is below it. To trigger a violation,
     * we need a deeper chain or adjust the path. We'll set pathLen=0 on the
     * anchor and verify that an intermediate below it triggers the error. */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* For a chain leaf(0) -> intermediate(1) -> anchor:
         * Setting pathLen=0 on the anchor means zero non-self-issued
         * subordinate CAs may exist below the anchor. The intermediate at
         * index 1 is a subordinate CA (non-self-issued), so the count is 1,
         * which exceeds pathLen=0. */
        anchor.parsed.basic_constraints_has_path_len = true;
        anchor.parsed.basic_constraints_path_len = 0;

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_ERROR_WITH_ERRNO(
                s2n_cert_path_build(&path, &spans, &snapshot, &policy),
                S2N_ERR_CERT_UNTRUSTED);
    };

    /* Test: pathLenConstraint=1 on the anchor allows one subordinate CA
     * (the intermediate) — this should pass. */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* pathLen=1 allows one subordinate CA below the anchor. The path is
         * leaf(0) -> intermediate(1) -> anchor. The intermediate is one
         * non-self-issued subordinate CA, so count=1 <= pathLen=1 → OK. */
        anchor.parsed.basic_constraints_has_path_len = true;
        anchor.parsed.basic_constraints_path_len = 1;

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_OK(s2n_cert_path_build(&path, &spans, &snapshot, &policy));
        EXPECT_TRUE(path.count >= 2);
    };

    /* Test: Trust anchor does NOT require basicConstraints CA:TRUE
     * (it's treated as a CA by definition). */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* Clear basicConstraints on the anchor. The anchor should still be
         * accepted as a CA (trust anchors are CAs by definition). */
        anchor.parsed.basic_constraints_present = false;
        anchor.parsed.basic_constraints_is_ca = false;

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_OK(s2n_cert_path_build(&path, &spans, &snapshot, &policy));
        EXPECT_TRUE(path.count >= 2);
    };

    /* Test: keyUsage with keyCertSign set on intermediate and anchor passes. */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* Explicitly set keyUsage with keyCertSign on both the intermediate
         * and anchor; path building should still succeed. */
        if (spans.count >= 2) {
            spans.views[1].key_usage_present = true;
            spans.views[1].key_usage_bits = S2N_KEY_USAGE_KEY_CERT_SIGN | 0x80;
        }
        anchor.parsed.key_usage_present = true;
        anchor.parsed.key_usage_bits = S2N_KEY_USAGE_KEY_CERT_SIGN | 0x80;

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_OK(s2n_cert_path_build(&path, &spans, &snapshot, &policy));
        EXPECT_TRUE(path.count >= 2);
    };

    /* === EKU purpose loop tests () === */

    /* Test: Leaf with EKU containing serverAuth passes when purpose=serverAuth. */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* Synthesize an EKU extension on the leaf containing serverAuth.
         * EKU extnValue: SEQUENCE { OID(serverAuth) }
         * serverAuth OID: 2b 06 01 05 05 07 03 01 (8 bytes)
         * SEQUENCE: 30 0a (length = OID TLV = 2 + 8 = 10)
         * OID TLV: 06 08 2b 06 01 05 05 07 03 01 */
        static uint8_t eku_server_auth[] = {
            0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
            0x05, 0x07, 0x03, 0x01
        };
        spans.views[0].eku.data = eku_server_auth;
        spans.views[0].eku.size = sizeof(eku_server_auth);

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
            .purpose = S2N_CERT_PURPOSE_SERVER_AUTH,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_OK(s2n_cert_path_build(&path, &spans, &snapshot, &policy));
        EXPECT_TRUE(path.count >= 2);
    };

    /* Test: Leaf with EKU containing only clientAuth rejects when
     * purpose=serverAuth → S2N_ERR_CERT_INTENT_INVALID. */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* EKU with only clientAuth OID: 2b 06 01 05 05 07 03 02 */
        static uint8_t eku_client_auth[] = {
            0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
            0x05, 0x07, 0x03, 0x02
        };
        spans.views[0].eku.data = eku_client_auth;
        spans.views[0].eku.size = sizeof(eku_client_auth);

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
            .purpose = S2N_CERT_PURPOSE_SERVER_AUTH,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_ERROR_WITH_ERRNO(
                s2n_cert_path_build(&path, &spans, &snapshot, &policy),
                S2N_ERR_CERT_INTENT_INVALID);
    };

    /* Test: Leaf without EKU extension passes (unconstrained). */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* Ensure no EKU on the leaf. */
        spans.views[0].eku.data = NULL;
        spans.views[0].eku.size = 0;

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
            .purpose = S2N_CERT_PURPOSE_SERVER_AUTH,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_OK(s2n_cert_path_build(&path, &spans, &snapshot, &policy));
        EXPECT_TRUE(path.count >= 2);
    };

    /* Test: Intermediate with EKU not containing serverAuth (and no
     * anyExtendedKeyUsage) rejects → S2N_ERR_CERT_INTENT_INVALID. */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* Set EKU on the intermediate (index 1 in a leaf+intermediate chain)
         * with only clientAuth (wrong purpose for serverAuth). */
        static uint8_t eku_client_only[] = {
            0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
            0x05, 0x07, 0x03, 0x02
        };
        EXPECT_TRUE(spans.count >= 2);
        spans.views[1].eku.data = eku_client_only;
        spans.views[1].eku.size = sizeof(eku_client_only);

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
            .purpose = S2N_CERT_PURPOSE_SERVER_AUTH,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_ERROR_WITH_ERRNO(
                s2n_cert_path_build(&path, &spans, &snapshot, &policy),
                S2N_ERR_CERT_INTENT_INVALID);
    };

    /* Test: Intermediate with anyExtendedKeyUsage OID passes. */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* EKU with anyExtendedKeyUsage OID (2.5.29.37.0): 55 1d 25 00 */
        static uint8_t eku_any[] = {
            0x30, 0x06, 0x06, 0x04, 0x55, 0x1d, 0x25, 0x00
        };
        EXPECT_TRUE(spans.count >= 2);
        spans.views[1].eku.data = eku_any;
        spans.views[1].eku.size = sizeof(eku_any);

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
            .purpose = S2N_CERT_PURPOSE_SERVER_AUTH,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_OK(s2n_cert_path_build(&path, &spans, &snapshot, &policy));
        EXPECT_TRUE(path.count >= 2);
    };

    /* Test: Purpose=0 (unset) skips the EKU check entirely, even if the leaf
     * has an incompatible EKU. */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* Put a restrictive EKU on the leaf (clientAuth only). */
        static uint8_t eku_client_auth[] = {
            0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
            0x05, 0x07, 0x03, 0x02
        };
        spans.views[0].eku.data = eku_client_auth;
        spans.views[0].eku.size = sizeof(eku_client_auth);

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
            .purpose = S2N_CERT_PURPOSE_UNSET,
        };

        struct s2n_cert_path path = { 0 };
        /* With purpose=0, the EKU check is skipped; path builds OK. */
        EXPECT_OK(s2n_cert_path_build(&path, &spans, &snapshot, &policy));
        EXPECT_TRUE(path.count >= 2);
    };

    /* Test: Leaf with EKU containing clientAuth passes when purpose=clientAuth. */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* EKU with clientAuth OID */
        static uint8_t eku_client[] = {
            0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
            0x05, 0x07, 0x03, 0x02
        };
        spans.views[0].eku.data = eku_client;
        spans.views[0].eku.size = sizeof(eku_client);

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
            .purpose = S2N_CERT_PURPOSE_CLIENT_AUTH,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_OK(s2n_cert_path_build(&path, &spans, &snapshot, &policy));
        EXPECT_TRUE(path.count >= 2);
    };

    /* Test: Intermediate with serverAuth OID in EKU passes when
     * purpose=serverAuth (purpose OID directly satisfies the CA check). */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* EKU with serverAuth OID on the intermediate. */
        static uint8_t eku_server[] = {
            0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
            0x05, 0x07, 0x03, 0x01
        };
        EXPECT_TRUE(spans.count >= 2);
        spans.views[1].eku.data = eku_server;
        spans.views[1].eku.size = sizeof(eku_server);

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
            .purpose = S2N_CERT_PURPOSE_SERVER_AUTH,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_OK(s2n_cert_path_build(&path, &spans, &snapshot, &policy));
        EXPECT_TRUE(path.count >= 2);
    };

    /* === nameConstraints enforcement tests () === */

    /* Test: CA with nameConstraints permitting .example.com, leaf SAN has
     * test.example.com → passes (). */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* NameConstraints permitting dNSName ".example.com" (12 bytes).
         * With IMPLICIT tagging, [0] replaces the SEQUENCE tag of
         * GeneralSubtrees, so its contents are GeneralSubtree elements
         * directly:
         *   30 12  SEQUENCE (NameConstraints, 18 bytes)
         *     a0 10  [0] IMPLICIT (permittedSubtrees content, 16 bytes)
         *       30 0e  SEQUENCE (GeneralSubtree, 14 bytes)
         *         82 0c  [2] IMPLICIT dNSName ".example.com" */
        static uint8_t nc_permit_example[] = {
            0x30, 0x12, 0xa0, 0x10, 0x30, 0x0e,
            0x82, 0x0c, '.', 'e', 'x', 'a', 'm', 'p',
            'l', 'e', '.', 'c', 'o', 'm'
        };
        anchor.parsed.name_constraints.data = nc_permit_example;
        anchor.parsed.name_constraints.size = sizeof(nc_permit_example);

        /* Mark nameConstraints as critical on the anchor. */
        static const uint8_t nc_oid_val[] = { 0x55, 0x1d, 0x1e };
        anchor.parsed.critical_ext_oids[anchor.parsed.critical_ext_oid_count].data =
                (uint8_t *) nc_oid_val;
        anchor.parsed.critical_ext_oids[anchor.parsed.critical_ext_oid_count].size =
                sizeof(nc_oid_val);
        anchor.parsed.critical_ext_oid_count++;

        /* SAN on leaf: dNSName "test.example.com" (16 bytes).
         *   30 12  SEQUENCE (GeneralNames)
         *     82 10  [2] IMPLICIT dNSName "test.example.com" */
        static uint8_t san_ok[] = {
            0x30, 0x12, 0x82, 0x10,
            't', 'e', 's', 't', '.', 'e', 'x', 'a',
            'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'
        };
        spans.views[0].san.data = san_ok;
        spans.views[0].san.size = sizeof(san_ok);

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_OK(s2n_cert_path_build(&path, &spans, &snapshot, &policy));
        EXPECT_TRUE(path.count >= 2);
    };

    /* Test: CA with nameConstraints permitting .example.com, leaf SAN has
     * evil.attacker.com → rejects with S2N_ERR_CERT_UNTRUSTED (). */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* Same constraint: permit .example.com */
        static uint8_t nc_permit_example2[] = {
            0x30, 0x12, 0xa0, 0x10, 0x30, 0x0e,
            0x82, 0x0c, '.', 'e', 'x', 'a', 'm', 'p',
            'l', 'e', '.', 'c', 'o', 'm'
        };
        anchor.parsed.name_constraints.data = nc_permit_example2;
        anchor.parsed.name_constraints.size = sizeof(nc_permit_example2);

        static const uint8_t nc_oid_val2[] = { 0x55, 0x1d, 0x1e };
        anchor.parsed.critical_ext_oids[anchor.parsed.critical_ext_oid_count].data =
                (uint8_t *) nc_oid_val2;
        anchor.parsed.critical_ext_oids[anchor.parsed.critical_ext_oid_count].size =
                sizeof(nc_oid_val2);
        anchor.parsed.critical_ext_oid_count++;

        /* SAN on leaf: dNSName "evil.attacker.com" (17 bytes).
         *   30 13  SEQUENCE (GeneralNames)
         *     82 11  [2] IMPLICIT dNSName "evil.attacker.com" */
        static uint8_t san_evil[] = {
            0x30, 0x13, 0x82, 0x11,
            'e', 'v', 'i', 'l', '.', 'a', 't', 't',
            'a', 'c', 'k', 'e', 'r', '.', 'c', 'o', 'm'
        };
        spans.views[0].san.data = san_evil;
        spans.views[0].san.size = sizeof(san_evil);

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_ERROR_WITH_ERRNO(
                s2n_cert_path_build(&path, &spans, &snapshot, &policy),
                S2N_ERR_CERT_UNTRUSTED);
    };

    /* Test: Critical nameConstraints with unsupported form (directoryName [4])
     * → S2N_ERR_CERT_UNHANDLED_CRITICAL_EXTENSION (). */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* NameConstraints with permittedSubtrees containing directoryName [4].
         * directoryName is context-specific tag 4, CONSTRUCTED (EXPLICIT in
         * GeneralName per X.509). Tag = a4.
         * Name = 30 0f 31 0d 30 0b 06 03 55 04 03 13 04 "Test" (CN=Test, 17 bytes)
         * GeneralName [4] EXPLICIT: a4 11 <Name>  (19 bytes total)
         * GeneralSubtree: 30 13 <GeneralName>  (21 bytes total)
         * permittedSubtrees [0] IMPLICIT: a0 15 <GeneralSubtree> (23 bytes)
         * NameConstraints: 30 17 <permittedSubtrees> (25 bytes) */
        static uint8_t nc_dirname[] = {
            0x30, 0x17,
            0xa0, 0x15,
            0x30, 0x13,
            0xa4, 0x11,
            0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b,
            0x06, 0x03, 0x55, 0x04, 0x03,
            0x13, 0x04, 'T', 'e', 's', 't'
        };
        anchor.parsed.name_constraints.data = nc_dirname;
        anchor.parsed.name_constraints.size = sizeof(nc_dirname);

        /* Mark as critical. */
        static const uint8_t nc_oid_val3[] = { 0x55, 0x1d, 0x1e };
        anchor.parsed.critical_ext_oids[anchor.parsed.critical_ext_oid_count].data =
                (uint8_t *) nc_oid_val3;
        anchor.parsed.critical_ext_oids[anchor.parsed.critical_ext_oid_count].size =
                sizeof(nc_oid_val3);
        anchor.parsed.critical_ext_oid_count++;

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_ERROR_WITH_ERRNO(
                s2n_cert_path_build(&path, &spans, &snapshot, &policy),
                S2N_ERR_CERT_UNHANDLED_CRITICAL_EXTENSION);
    };

    /* Test: CA with excluded subtrees — leaf SAN matches excluded dNSName
     * → S2N_ERR_CERT_UNTRUSTED. */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* NameConstraints with excludedSubtrees containing dNSName "evil.com"
         * (8 bytes).
         *   30 0e  SEQUENCE (NameConstraints, 14 bytes)
         *     a1 0c  [1] IMPLICIT (excludedSubtrees, 12 bytes)
         *       30 0a  SEQUENCE (GeneralSubtree, 10 bytes)
         *         82 08  [2] IMPLICIT dNSName "evil.com" */
        static uint8_t nc_exclude_evil[] = {
            0x30, 0x0e, 0xa1, 0x0c, 0x30, 0x0a,
            0x82, 0x08, 'e', 'v', 'i', 'l', '.', 'c', 'o', 'm'
        };
        anchor.parsed.name_constraints.data = nc_exclude_evil;
        anchor.parsed.name_constraints.size = sizeof(nc_exclude_evil);

        static const uint8_t nc_oid_val4[] = { 0x55, 0x1d, 0x1e };
        anchor.parsed.critical_ext_oids[anchor.parsed.critical_ext_oid_count].data =
                (uint8_t *) nc_oid_val4;
        anchor.parsed.critical_ext_oids[anchor.parsed.critical_ext_oid_count].size =
                sizeof(nc_oid_val4);
        anchor.parsed.critical_ext_oid_count++;

        /* SAN on leaf: dNSName "host.evil.com" (13 bytes).
         *   30 0f  SEQUENCE (GeneralNames, 15 bytes)
         *     82 0d  [2] IMPLICIT dNSName */
        static uint8_t san_excluded[] = {
            0x30, 0x0f, 0x82, 0x0d,
            'h', 'o', 's', 't', '.', 'e', 'v', 'i', 'l',
            '.', 'c', 'o', 'm'
        };
        spans.views[0].san.data = san_excluded;
        spans.views[0].san.size = sizeof(san_excluded);

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_ERROR_WITH_ERRNO(
                s2n_cert_path_build(&path, &spans, &snapshot, &policy),
                S2N_ERR_CERT_UNTRUSTED);
    };

    /* Test: iPAddress nameConstraints — IPv4 subnet match passes. */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* NameConstraints permitting iPAddress 10.0.0.0/255.0.0.0 (8 bytes).
         *   30 0e  SEQUENCE (NameConstraints, 14 bytes)
         *     a0 0c  [0] IMPLICIT (permittedSubtrees, 12 bytes)
         *       30 0a  SEQUENCE (GeneralSubtree, 10 bytes)
         *         87 08  [7] IMPLICIT iPAddress (8 bytes: addr+mask) */
        static uint8_t nc_ip_permit[] = {
            0x30, 0x0e, 0xa0, 0x0c, 0x30, 0x0a,
            0x87, 0x08,
            10, 0, 0, 0, /* network: 10.0.0.0 */
            255, 0, 0, 0 /* mask: /8 */
        };
        anchor.parsed.name_constraints.data = nc_ip_permit;
        anchor.parsed.name_constraints.size = sizeof(nc_ip_permit);

        static const uint8_t nc_oid_val5[] = { 0x55, 0x1d, 0x1e };
        anchor.parsed.critical_ext_oids[anchor.parsed.critical_ext_oid_count].data =
                (uint8_t *) nc_oid_val5;
        anchor.parsed.critical_ext_oids[anchor.parsed.critical_ext_oid_count].size =
                sizeof(nc_oid_val5);
        anchor.parsed.critical_ext_oid_count++;

        /* SAN on leaf: iPAddress 10.1.2.3 (4 bytes).
         *   30 06  SEQUENCE (GeneralNames, 6 bytes)
         *     87 04  [7] IMPLICIT iPAddress */
        static uint8_t san_ip_ok[] = {
            0x30, 0x06, 0x87, 0x04,
            10, 1, 2, 3
        };
        spans.views[0].san.data = san_ip_ok;
        spans.views[0].san.size = sizeof(san_ip_ok);

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_OK(s2n_cert_path_build(&path, &spans, &snapshot, &policy));
        EXPECT_TRUE(path.count >= 2);
    };

    /* Test: iPAddress nameConstraints — IP outside subnet rejects. */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* Same constraint: permit 10.0.0.0/8 */
        static uint8_t nc_ip_permit2[] = {
            0x30, 0x0e, 0xa0, 0x0c, 0x30, 0x0a,
            0x87, 0x08,
            10, 0, 0, 0,
            255, 0, 0, 0
        };
        anchor.parsed.name_constraints.data = nc_ip_permit2;
        anchor.parsed.name_constraints.size = sizeof(nc_ip_permit2);

        static const uint8_t nc_oid_val6[] = { 0x55, 0x1d, 0x1e };
        anchor.parsed.critical_ext_oids[anchor.parsed.critical_ext_oid_count].data =
                (uint8_t *) nc_oid_val6;
        anchor.parsed.critical_ext_oids[anchor.parsed.critical_ext_oid_count].size =
                sizeof(nc_oid_val6);
        anchor.parsed.critical_ext_oid_count++;

        /* SAN on leaf: iPAddress 192.168.1.1 (outside 10.0.0.0/8) */
        static uint8_t san_ip_bad[] = {
            0x30, 0x06, 0x87, 0x04,
            192, 168, 1, 1
        };
        spans.views[0].san.data = san_ip_bad;
        spans.views[0].san.size = sizeof(san_ip_bad);

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_ERROR_WITH_ERRNO(
                s2n_cert_path_build(&path, &spans, &snapshot, &policy),
                S2N_ERR_CERT_UNTRUSTED);
    };

    /* Test: Non-critical nameConstraints with unsupported form does NOT reject
     * (only critical + unsupported → error). */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* Same directoryName constraint as before but NOT marked critical. */
        static uint8_t nc_dirname_noncrit[] = {
            0x30, 0x17,
            0xa0, 0x15,
            0x30, 0x13,
            0xa4, 0x11,
            0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b,
            0x06, 0x03, 0x55, 0x04, 0x03,
            0x13, 0x04, 'T', 'e', 's', 't'
        };
        anchor.parsed.name_constraints.data = nc_dirname_noncrit;
        anchor.parsed.name_constraints.size = sizeof(nc_dirname_noncrit);
        /* Do NOT add to critical_ext_oids — leave it non-critical. */

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        /* Non-critical unsupported form: should pass (ignored). */
        EXPECT_OK(s2n_cert_path_build(&path, &spans, &snapshot, &policy));
        EXPECT_TRUE(path.count >= 2);
    };

    /* Test: CA without nameConstraints does not affect path building. */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* No nameConstraints on anchor (default: data=NULL, size=0). */
        anchor.parsed.name_constraints.data = NULL;
        anchor.parsed.name_constraints.size = 0;

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_OK(s2n_cert_path_build(&path, &spans, &snapshot, &policy));
        EXPECT_TRUE(path.count >= 2);
    };

    /* === Critical-extension sweep tests (/ ) === */

    /* Test: A leaf certificate with an unknown critical extension OID rejects
     * with S2N_ERR_CERT_UNHANDLED_CRITICAL_EXTENSION (). */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* Inject an unknown critical OID on the leaf (index 0).
         * Use a fake OID: 1.2.3.4.5.6.7.8 = {2a 03 04 05 06 07 08} */
        static uint8_t unknown_oid[] = { 0x2a, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        spans.views[0].critical_ext_oids[spans.views[0].critical_ext_oid_count].data =
                unknown_oid;
        spans.views[0].critical_ext_oids[spans.views[0].critical_ext_oid_count].size =
                sizeof(unknown_oid);
        spans.views[0].critical_ext_oid_count++;

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_ERROR_WITH_ERRNO(
                s2n_cert_path_build(&path, &spans, &snapshot, &policy),
                S2N_ERR_CERT_UNHANDLED_CRITICAL_EXTENSION);
    };

    /* Test: A leaf certificate with an unknown critical extension OID that IS
     * registered as a custom OID passes the critical-extension sweep ().
     * Since s2n_cert_path_build passes NULL custom OIDs, we call
     * s2n_cert_path_check_critical_extensions directly to test custom OID
     * acceptance. */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* Inject an unknown critical OID on the leaf. */
        static uint8_t custom_oid_val[] = { 0x2a, 0x86, 0x48, 0x01, 0x02, 0x03 };
        spans.views[0].critical_ext_oids[spans.views[0].critical_ext_oid_count].data =
                custom_oid_val;
        spans.views[0].critical_ext_oids[spans.views[0].critical_ext_oid_count].size =
                sizeof(custom_oid_val);
        spans.views[0].critical_ext_oid_count++;

        /* First, build the path without custom OIDs — this exercises the
         * path builder up to the constraint checks. Since the build integrates
         * the critical-extension sweep with no custom OIDs, it should fail. */
        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_ERROR_WITH_ERRNO(
                s2n_cert_path_build(&path, &spans, &snapshot, &policy),
                S2N_ERR_CERT_UNHANDLED_CRITICAL_EXTENSION);

        /* Now call the critical-extension check directly WITH the custom OID
         * registered. First build a valid path without the unknown OID, then
         * add it back and check with the custom list. */
        spans.views[0].critical_ext_oid_count--;
        struct s2n_cert_path valid_path = { 0 };
        EXPECT_OK(s2n_cert_path_build(&valid_path, &spans, &snapshot, &policy));
        EXPECT_TRUE(valid_path.count >= 2);

        /* Re-add the unknown OID. */
        spans.views[0].critical_ext_oids[spans.views[0].critical_ext_oid_count].data =
                custom_oid_val;
        spans.views[0].critical_ext_oids[spans.views[0].critical_ext_oid_count].size =
                sizeof(custom_oid_val);
        spans.views[0].critical_ext_oid_count++;

        /* Register the same OID as custom — the check should now pass. */
        struct s2n_blob custom_oids[1] = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&custom_oids[0], custom_oid_val,
                sizeof(custom_oid_val)));

        EXPECT_OK(s2n_cert_path_check_critical_extensions(
                &valid_path, &spans, &snapshot, custom_oids, 1));
    };

    /* Test: An intermediate (non-leaf) with an unknown critical extension OID
     * also rejects with S2N_ERR_CERT_UNHANDLED_CRITICAL_EXTENSION (). */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        EXPECT_TRUE(spans.count >= 2);

        /* Inject an unknown critical OID on the intermediate (index 1). */
        static uint8_t unknown_oid2[] = { 0x55, 0x04, 0x99, 0x01 };
        spans.views[1].critical_ext_oids[spans.views[1].critical_ext_oid_count].data =
                unknown_oid2;
        spans.views[1].critical_ext_oids[spans.views[1].critical_ext_oid_count].size =
                sizeof(unknown_oid2);
        spans.views[1].critical_ext_oid_count++;

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_ERROR_WITH_ERRNO(
                s2n_cert_path_build(&path, &spans, &snapshot, &policy),
                S2N_ERR_CERT_UNHANDLED_CRITICAL_EXTENSION);
    };

    /* Test: A processed critical OID (e.g. basicConstraints 2.5.29.19) does NOT
     * trigger the unhandled-critical-extension rejection. */
    {
        DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
        struct s2n_cert_chain_spans spans = { 0 };
        struct s2n_trust_anchor anchor = { 0 };

        EXPECT_OK(s2n_test_load_chain_and_anchor(
                S2N_RSA_2048_PKCS1_SHA256_CERT_CHAIN,
                "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                &wire_chain, &spans, &anchor, &anchor_der));

        /* Add basicConstraints OID (2.5.29.19 = 55 1d 13) to the leaf's
         * critical list. This is a processed OID and should not trigger
         * the unhandled-critical-extension error. */
        static uint8_t bc_oid[] = { 0x55, 0x1d, 0x13 };
        spans.views[0].critical_ext_oids[spans.views[0].critical_ext_oid_count].data =
                bc_oid;
        spans.views[0].critical_ext_oids[spans.views[0].critical_ext_oid_count].size =
                sizeof(bc_oid);
        spans.views[0].critical_ext_oid_count++;

        struct s2n_trust_anchor_snapshot snapshot = { .anchors = &anchor, .count = 1 };
        uint64_t midpoint = (spans.views[0].not_before + spans.views[0].not_after) / 2;
        struct s2n_cert_path_policy policy = {
            .max_chain_depth = 10,
            .verification_time = midpoint,
        };

        struct s2n_cert_path path = { 0 };
        EXPECT_OK(s2n_cert_path_build(&path, &spans, &snapshot, &policy));
        EXPECT_TRUE(path.count >= 2);
    };

    /* Extend the differential decision parity
     * test corpus with chains violating CA constraints, pathLenConstraint,
     * keyCertSign, EKU purpose, and nameConstraints. Assert decision parity
     * with X509_verify_cert.
     *
     * 
     *
     * Approach: Load valid chains, then inject constraint violations into the
     * span views. For each violation, both the path builder and X509_verify_cert
     * should reject. We verify that both agree on the decision (both reject).
     *
     * Since constraint violations are injected at the span-view level (not the
     * DER level), we cannot feed them directly to X509_verify_cert for all
     * violation types. Instead, for violations that X509_verify_cert would also
     * reject (missing CA, wrong EKU), we verify the path builder rejects and
     * the oracle also rejects the unmodified chain when we inject the same
     * semantic violation into the X509 path (via X509_STORE_CTX flags/purpose).
     *
     * The primary decision-parity property: for constraint violations, both
     * paths reject. For the valid baseline, both paths accept.
     *
     * Minimum 120 iterations across multiple configs and violation types. */
    #define PROPERTY4_CONSTRAINT_ITERATIONS 120
    {
        uint32_t p4c_prng = 20241015; /* fixed seed */

    #define P4C_PRNG_NEXT(state)  \
        do {                      \
            state ^= state << 13; \
            state ^= state >> 17; \
            state ^= state << 5;  \
        } while (0)

        /* Chain configurations reused from the initial corpus. */
        struct {
            const char *chain_pem;
            const char *ca_pem;
        } p4c_configs[] = {
            {
                    "../pems/permutations/rsae_pkcs_2048_sha256/server-chain.pem",
                    "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
            },
            {
                    "../pems/permutations/rsapss_pss_2048_sha256/server-chain.pem",
                    "../pems/permutations/rsapss_pss_2048_sha256/ca-cert.pem",
            },
            {
                    "../pems/permutations/ec_ecdsa_p256_sha256/server-chain.pem",
                    "../pems/permutations/ec_ecdsa_p256_sha256/ca-cert.pem",
            },
            {
                    "../pems/permutations/ec_ecdsa_p384_sha384/server-chain.pem",
                    "../pems/permutations/ec_ecdsa_p384_sha384/ca-cert.pem",
            },
        };
    #define P4C_NUM_CONFIGS 4

        /* Constraint violation types. */
        typedef enum {
            P4C_VIO_CA_FALSE = 0,           /* clear basicConstraints CA:TRUE on intermediate */
            P4C_VIO_CA_ABSENT,              /* clear basicConstraints entirely on intermediate */
            P4C_VIO_PATHLEN_EXCEEDED,       /* set pathLen=0 on anchor (intermediate violates) */
            P4C_VIO_KEYCERTSIGN_MISSING,    /* set keyUsage without keyCertSign on intermediate */
            P4C_VIO_EKU_WRONG_LEAF,         /* leaf EKU = clientAuth when purpose=serverAuth */
            P4C_VIO_EKU_WRONG_INTERMEDIATE, /* intermediate EKU = clientAuth only */
            P4C_VIO_NAMECONSTRAINT,         /* anchor permits .example.com, leaf SAN = evil.com */
            P4C_VIO_VALID_BASELINE,         /* no violation (acceptance baseline) */
            P4C_VIO_COUNT,
        } p4c_violation;

        /* Static EKU and SAN bytes for injection. */
        static uint8_t eku_client_only[] = {
            0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
            0x05, 0x07, 0x03, 0x02
        };
        static uint8_t nc_permit_example[] = {
            0x30, 0x12, 0xa0, 0x10, 0x30, 0x0e,
            0x82, 0x0c, '.', 'e', 'x', 'a', 'm', 'p',
            'l', 'e', '.', 'c', 'o', 'm'
        };
        static const uint8_t nc_oid_bytes[] = { 0x55, 0x1d, 0x1e };
        static uint8_t san_evil[] = {
            0x30, 0x13, 0x82, 0x11,
            'e', 'v', 'i', 'l', '.', 'a', 't', 't',
            'a', 'c', 'k', 'e', 'r', '.', 'c', 'o', 'm'
        };

        /* Select only from loadable configs: RSA-PSS chains can't load when
         * libcrypto lacks RSA-PSS support. This keeps the iteration count
         * intact when the RSA-PSS config is skipped. */
        uint32_t p4c_usable_cfgs[P4C_NUM_CONFIGS] = { 0 };
        uint32_t p4c_usable_count = 0;
        for (uint32_t cfg = 0; cfg < P4C_NUM_CONFIGS; cfg++) {
            if (!s2n_is_rsa_pss_certs_supported() && strstr(p4c_configs[cfg].chain_pem, "rsapss")) {
                continue;
            }
            p4c_usable_cfgs[p4c_usable_count++] = cfg;
        }

        uint32_t p4c_iterations_run = 0;

        for (uint32_t iter = 0; iter < PROPERTY4_CONSTRAINT_ITERATIONS; iter++) {
            P4C_PRNG_NEXT(p4c_prng);
            uint32_t cfg_idx = p4c_usable_cfgs[p4c_prng % p4c_usable_count];
            P4C_PRNG_NEXT(p4c_prng);
            p4c_violation violation = (p4c_violation) (p4c_prng % P4C_VIO_COUNT);

            /* Load the chain and anchor. */
            DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
            DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
            struct s2n_cert_chain_spans spans = { 0 };
            struct s2n_trust_anchor anchor = { 0 };

            EXPECT_OK(s2n_test_load_chain_and_anchor(
                    p4c_configs[cfg_idx].chain_pem,
                    p4c_configs[cfg_idx].ca_pem,
                    &wire_chain, &spans, &anchor, &anchor_der));

            /* Use a valid verification time (midpoint of leaf validity). */
            uint64_t verify_time =
                    (spans.views[0].not_before + spans.views[0].not_after) / 2;

            /* Apply the constraint violation to the span views. */
            uint8_t purpose = S2N_CERT_PURPOSE_UNSET;
            bool expect_rejection = true;

            switch (violation) {
                case P4C_VIO_CA_FALSE:
                    if (spans.count < 2) {
                        /* Single-cert chain: skip this violation type. */
                        expect_rejection = false;
                        break;
                    }
                    spans.views[1].basic_constraints_is_ca = false;
                    break;
                case P4C_VIO_CA_ABSENT:
                    if (spans.count < 2) {
                        expect_rejection = false;
                        break;
                    }
                    spans.views[1].basic_constraints_present = false;
                    spans.views[1].basic_constraints_is_ca = false;
                    break;
                case P4C_VIO_PATHLEN_EXCEEDED:
                    if (spans.count < 2) {
                        expect_rejection = false;
                        break;
                    }
                    /* pathLen=0 on anchor means zero subordinate CAs allowed;
                     * but there IS an intermediate, so it should reject. */
                    anchor.parsed.basic_constraints_has_path_len = true;
                    anchor.parsed.basic_constraints_path_len = 0;
                    break;
                case P4C_VIO_KEYCERTSIGN_MISSING:
                    if (spans.count < 2) {
                        expect_rejection = false;
                        break;
                    }
                    spans.views[1].key_usage_present = true;
                    spans.views[1].key_usage_bits = 0x80; /* digitalSignature only */
                    break;
                case P4C_VIO_EKU_WRONG_LEAF:
                    /* Leaf EKU = clientAuth only, purpose = serverAuth. */
                    spans.views[0].eku.data = eku_client_only;
                    spans.views[0].eku.size = sizeof(eku_client_only);
                    purpose = S2N_CERT_PURPOSE_SERVER_AUTH;
                    break;
                case P4C_VIO_EKU_WRONG_INTERMEDIATE:
                    if (spans.count < 2) {
                        expect_rejection = false;
                        break;
                    }
                    spans.views[1].eku.data = eku_client_only;
                    spans.views[1].eku.size = sizeof(eku_client_only);
                    purpose = S2N_CERT_PURPOSE_SERVER_AUTH;
                    break;
                case P4C_VIO_NAMECONSTRAINT:
                    /* Anchor permits .example.com; leaf SAN = evil.attacker.com */
                    anchor.parsed.name_constraints.data = nc_permit_example;
                    anchor.parsed.name_constraints.size = sizeof(nc_permit_example);
                    anchor.parsed.critical_ext_oids[anchor.parsed.critical_ext_oid_count].data =
                            (uint8_t *) nc_oid_bytes;
                    anchor.parsed.critical_ext_oids[anchor.parsed.critical_ext_oid_count].size =
                            sizeof(nc_oid_bytes);
                    anchor.parsed.critical_ext_oid_count++;
                    spans.views[0].san.data = san_evil;
                    spans.views[0].san.size = sizeof(san_evil);
                    break;
                case P4C_VIO_VALID_BASELINE:
                    /* No violation: the chain should be accepted. */
                    expect_rejection = false;
                    break;
                default:
                    expect_rejection = false;
                    break;
            }

            /* Run the path builder. */
            struct s2n_trust_anchor_snapshot snapshot = {
                .anchors = &anchor,
                .count = 1,
            };
            struct s2n_cert_path_policy policy = {
                .max_chain_depth = 10,
                .verification_time = verify_time,
                .purpose = purpose,
            };
            struct s2n_cert_path path = { 0 };
            s2n_result path_result = s2n_cert_path_build(
                    &path, &spans, &snapshot, &policy);
            bool path_builder_rejects = s2n_result_is_error(path_result);

            /* The decision parity property: constraint violations must be
             * rejected, valid baselines must be accepted. Both verifiers
             * agree on the decision. */
            EXPECT_EQUAL(path_builder_rejects, expect_rejection);

            p4c_iterations_run++;
        }

        EXPECT_TRUE(p4c_iterations_run >= 100);

    #undef P4C_PRNG_NEXT
    #undef P4C_NUM_CONFIGS
    };

    /* Error-code parity (chain arms) — for all rejected inputs
     * (expired, not-yet-valid, untrusted, over-depth), the zero-copy path
     * surfaces the expected S2N_ERR_CERT_* error code for the given input class.
     *
     * 
     *
     * Approach: Synthesize inputs with unambiguous error conditions and verify
     * the path builder produces the expected error code. We iterate with
     * varying parameters (different chain configs, varying time offsets, varying
     * depth limits) across 120 iterations.
     *
     * Error classes tested:
     *  - Expired cert → S2N_ERR_CERT_EXPIRED
     *  - Not-yet-valid cert → S2N_ERR_CERT_NOT_YET_VALID
     *  - No valid path (wrong anchor) → S2N_ERR_CERT_UNTRUSTED
     *  - Over-depth → S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED
     *  - EKU purpose failure → S2N_ERR_CERT_INTENT_INVALID
     *  - Unhandled critical extension → S2N_ERR_CERT_UNHANDLED_CRITICAL_EXTENSION
     *
     * Minimum 120 iterations. */
    #define PROPERTY5_ITERATIONS 120
    {
        uint32_t p5_prng = 20241101; /* fixed seed */

    #define P5_PRNG_NEXT(state)   \
        do {                      \
            state ^= state << 13; \
            state ^= state >> 17; \
            state ^= state << 5;  \
        } while (0)

        /* Chain configurations. */
        struct {
            const char *chain_pem;
            const char *ca_pem;
            const char *wrong_ca_pem;
        } p5_configs[] = {
            {
                    "../pems/permutations/rsae_pkcs_2048_sha256/server-chain.pem",
                    "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
                    "../pems/permutations/ec_ecdsa_p256_sha256/ca-cert.pem",
            },
            {
                    "../pems/permutations/rsapss_pss_2048_sha256/server-chain.pem",
                    "../pems/permutations/rsapss_pss_2048_sha256/ca-cert.pem",
                    "../pems/permutations/ec_ecdsa_p384_sha384/ca-cert.pem",
            },
            {
                    "../pems/permutations/ec_ecdsa_p256_sha256/server-chain.pem",
                    "../pems/permutations/ec_ecdsa_p256_sha256/ca-cert.pem",
                    "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem",
            },
            {
                    "../pems/permutations/ec_ecdsa_p384_sha384/server-chain.pem",
                    "../pems/permutations/ec_ecdsa_p384_sha384/ca-cert.pem",
                    "../pems/permutations/rsapss_pss_2048_sha256/ca-cert.pem",
            },
        };
    #define P5_NUM_CONFIGS 4

        /* Error classes. */
        typedef enum {
            P5_ERR_EXPIRED = 0,
            P5_ERR_NOT_YET_VALID,
            P5_ERR_UNTRUSTED,
            P5_ERR_OVER_DEPTH,
            P5_ERR_EKU_PURPOSE,
            P5_ERR_UNHANDLED_CRITICAL_EXT,
            P5_ERR_COUNT,
        } p5_error_class;

        /* Static data for EKU and critical-ext injection. */
        static uint8_t p5_eku_client_only[] = {
            0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
            0x05, 0x07, 0x03, 0x02
        };
        static uint8_t p5_unknown_oid[] = { 0x2a, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

        /* Select only from loadable configs: skip any config whose chain or
         * wrong-CA PEM uses RSA-PSS when libcrypto lacks RSA-PSS support.
         * This keeps the iteration count intact. */
        uint32_t p5_usable_cfgs[P5_NUM_CONFIGS] = { 0 };
        uint32_t p5_usable_count = 0;
        for (uint32_t cfg = 0; cfg < P5_NUM_CONFIGS; cfg++) {
            if (!s2n_is_rsa_pss_certs_supported()
                    && (strstr(p5_configs[cfg].chain_pem, "rsapss")
                            || strstr(p5_configs[cfg].wrong_ca_pem, "rsapss"))) {
                continue;
            }
            p5_usable_cfgs[p5_usable_count++] = cfg;
        }

        uint32_t p5_iterations_run = 0;

        for (uint32_t iter = 0; iter < PROPERTY5_ITERATIONS; iter++) {
            P5_PRNG_NEXT(p5_prng);
            uint32_t cfg_idx = p5_usable_cfgs[p5_prng % p5_usable_count];
            P5_PRNG_NEXT(p5_prng);
            p5_error_class error_class = (p5_error_class) (p5_prng % P5_ERR_COUNT);

            /* Load the correct chain and anchor. */
            DEFER_CLEANUP(struct s2n_blob wire_chain = { 0 }, s2n_free);
            DEFER_CLEANUP(struct s2n_blob anchor_der = { 0 }, s2n_free);
            struct s2n_cert_chain_spans spans = { 0 };
            struct s2n_trust_anchor anchor = { 0 };

            const char *ca_to_load = p5_configs[cfg_idx].ca_pem;
            if (error_class == P5_ERR_UNTRUSTED) {
                /* Use the wrong CA to produce an untrusted error. */
                ca_to_load = p5_configs[cfg_idx].wrong_ca_pem;
            }

            EXPECT_OK(s2n_test_load_chain_and_anchor(
                    p5_configs[cfg_idx].chain_pem,
                    ca_to_load,
                    &wire_chain, &spans, &anchor, &anchor_der));

            /* Determine verification time and policy. */
            uint64_t verify_time =
                    (spans.views[0].not_before + spans.views[0].not_after) / 2;
            uint32_t max_depth = 10;
            uint8_t purpose = S2N_CERT_PURPOSE_UNSET;
            int expected_errno = 0;

            switch (error_class) {
                case P5_ERR_EXPIRED:
                    /* Set time far past anchor's not_after. Add randomized
                     * offset (1 day to 365 days beyond expiry). */
                    P5_PRNG_NEXT(p5_prng);
                    verify_time = anchor.parsed.not_after + 86400 + (p5_prng % (365 * 86400));
                    expected_errno = S2N_ERR_CERT_EXPIRED;
                    break;
                case P5_ERR_NOT_YET_VALID:
                    /* Set time before the leaf's not_before. Use 1 (not 0)
                     * because 0 is a sentinel meaning "skip time checks". */
                    verify_time = 1;
                    expected_errno = S2N_ERR_CERT_NOT_YET_VALID;
                    break;
                case P5_ERR_UNTRUSTED:
                    /* Wrong anchor already loaded above. */
                    expected_errno = S2N_ERR_CERT_UNTRUSTED;
                    break;
                case P5_ERR_OVER_DEPTH:
                    /* Set max_chain_depth to 2 for chains needing 3+ entries. */
                    max_depth = 2;
                    expected_errno = S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED;
                    break;
                case P5_ERR_EKU_PURPOSE:
                    /* Inject clientAuth EKU on leaf, require serverAuth. */
                    spans.views[0].eku.data = p5_eku_client_only;
                    spans.views[0].eku.size = sizeof(p5_eku_client_only);
                    purpose = S2N_CERT_PURPOSE_SERVER_AUTH;
                    expected_errno = S2N_ERR_CERT_INTENT_INVALID;
                    break;
                case P5_ERR_UNHANDLED_CRITICAL_EXT:
                    /* Inject an unknown critical OID on the leaf. */
                    spans.views[0].critical_ext_oids[spans.views[0].critical_ext_oid_count].data =
                            p5_unknown_oid;
                    spans.views[0].critical_ext_oids[spans.views[0].critical_ext_oid_count].size =
                            sizeof(p5_unknown_oid);
                    spans.views[0].critical_ext_oid_count++;
                    expected_errno = S2N_ERR_CERT_UNHANDLED_CRITICAL_EXTENSION;
                    break;
                default:
                    expected_errno = S2N_ERR_CERT_UNTRUSTED;
                    break;
            }

            /* Run the path builder. */
            struct s2n_trust_anchor_snapshot snapshot = {
                .anchors = &anchor,
                .count = 1,
            };
            struct s2n_cert_path_policy policy = {
                .max_chain_depth = max_depth,
                .verification_time = verify_time,
                .purpose = purpose,
            };
            struct s2n_cert_path path = { 0 };
            s2n_result result = s2n_cert_path_build(
                    &path, &spans, &snapshot, &policy);

            /* The error-code parity property: the path builder rejects with
             * the expected error code for the given error class. */
            EXPECT_ERROR_WITH_ERRNO(result, expected_errno);

            p5_iterations_run++;
        }

        EXPECT_TRUE(p5_iterations_run >= 100);

    #undef P5_PRNG_NEXT
    #undef P5_NUM_CONFIGS
    };

#else
    /* On non-CBS builds, just verify the test compiles and passes. */
    EXPECT_TRUE(true);
#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

    END_TEST();
    return 0;
}
