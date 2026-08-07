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

#include "tls/s2n_cert_parse.h"

#include "crypto/s2n_certificate.h"
#include "crypto/s2n_openssl_x509.h"
#include "crypto/s2n_rsa_pss.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    #include <openssl/bytestring.h>
    #include <openssl/obj.h>
    #include <stdint.h>
    #include <string.h>
    #include <time.h>

    /* Mirror the validator's default max chain depth (DEFAULT_MAX_CHAIN_DEPTH in
     * s2n_x509_validator.c, not exported) for chain-parse tests. */
    #define S2N_TEST_MAX_CHAIN_DEPTH 7

/* Assert that `span` is an exact in-bounds sub-range of `base` (provenance). */
static S2N_RESULT s2n_test_assert_span_within(const struct s2n_blob *span, const struct s2n_blob *base)
{
    RESULT_ENSURE_REF(span->data);
    RESULT_ENSURE_GTE(span->data, base->data);
    RESULT_ENSURE_LTE(span->data + span->size, base->data + base->size);
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_parse_pem_leaf(const char *pem_path, struct s2n_cert_span_view *view,
        struct s2n_blob *der_out)
{
    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL, s2n_cert_chain_and_key_ptr_free);
    chain = s2n_cert_chain_and_key_new();
    RESULT_ENSURE_REF(chain);

    uint8_t pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    uint32_t pem_len = 0;
    RESULT_GUARD_POSIX(s2n_read_test_pem_and_len(pem_path, pem, &pem_len, S2N_MAX_TEST_PEM_SIZE));
    RESULT_GUARD_POSIX(s2n_cert_chain_and_key_load_public_pem_bytes(chain, pem, pem_len));

    /* Copy the leaf DER so the view outlives the chain in the caller. */
    struct s2n_blob *leaf_der = &chain->cert_chain->head->raw;
    RESULT_GUARD_POSIX(s2n_realloc(der_out, leaf_der->size));
    RESULT_CHECKED_MEMCPY(der_out->data, leaf_der->data, leaf_der->size);

    RESULT_GUARD(s2n_cert_span_view_parse(view, der_out));
    return S2N_RESULT_OK;
}

/* Concatenate the DER bytes of every certificate in a loaded PEM chain into a
 * single wire blob (raw back-to-back Certificate TLVs, the chain input
 * contract). `count_out` receives the number of certificates concatenated. */
static S2N_RESULT s2n_test_load_wire_chain(const char *pem_path, struct s2n_blob *wire_out,
        uint32_t *count_out)
{
    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL, s2n_cert_chain_and_key_ptr_free);
    chain = s2n_cert_chain_and_key_new();
    RESULT_ENSURE_REF(chain);

    uint8_t pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    uint32_t pem_len = 0;
    RESULT_GUARD_POSIX(s2n_read_test_pem_and_len(pem_path, pem, &pem_len, S2N_MAX_TEST_PEM_SIZE));
    RESULT_GUARD_POSIX(s2n_cert_chain_and_key_load_public_pem_bytes(chain, pem, pem_len));

    uint32_t count = 0;
    for (struct s2n_cert *cert = chain->cert_chain->head; cert != NULL; cert = cert->next) {
        struct s2n_blob *der = &cert->raw;
        uint32_t old_size = wire_out->size;
        RESULT_GUARD_POSIX(s2n_realloc(wire_out, old_size + der->size));
        RESULT_CHECKED_MEMCPY(wire_out->data + old_size, der->data, der->size);
        count++;
    }
    *count_out = count;
    return S2N_RESULT_OK;
}

/* Materialize an s2n_pkey from a certificate's DER bytes via d2i_X509. The
 * verify helper takes an s2n_pkey and never touches X509 itself; span-backed
 * SPKI materialization arrives in so tests bootstrap the issuer key
 * through libcrypto. */
static S2N_RESULT s2n_test_pkey_from_der(const struct s2n_blob *der, struct s2n_pkey *key,
        s2n_pkey_type *type)
{
    const uint8_t *der_ptr = der->data;
    DEFER_CLEANUP(X509 *cert = d2i_X509(NULL, &der_ptr, der->size), X509_free_pointer);
    RESULT_ENSURE_REF(cert);
    RESULT_GUARD(s2n_pkey_from_x509(cert, key, type));
    return S2N_RESULT_OK;
}

/* Wrap an ASCII time string in a DER TLV (tag 0x17 UTCTime / 0x18
 * GeneralizedTime) and parse it. Time strings are always < 128 bytes, so a
 * single short-form length octet is exact DER. */
static S2N_RESULT s2n_test_parse_time(uint8_t tag, const char *str, uint64_t *out)
{
    size_t len = strlen(str);
    RESULT_ENSURE_LT(len, 128);
    uint8_t tlv[130] = { 0 };
    tlv[0] = tag;
    tlv[1] = (uint8_t) len;
    RESULT_CHECKED_MEMCPY(&tlv[2], str, len);

    struct s2n_blob blob = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&blob, tlv, (uint32_t) (len + 2)));
    RESULT_GUARD(s2n_cert_parse_time(&blob, out));
    return S2N_RESULT_OK;
}

/* Build a minimal synthetic DER certificate with `ext_count` extensions, where
 * `critical_count` of them are marked critical. If `duplicate_oid` is true, all
 * extensions share the same OID (triggering duplicate detection). Otherwise each
 * extension gets a unique synthetic OID.
 *
 * The certificate is structurally valid DER: a SEQUENCE of (TBS SEQUENCE,
 * AlgorithmIdentifier, BIT STRING signature). The TBS contains: version [0] v3,
 * serial, inner AlgorithmIdentifier, empty issuer, validity, empty subject,
 * minimal SPKI, and the extensions [3] EXPLICIT SEQUENCE OF Extension. The
 * signature is a dummy; this only exercises the parser's DER and extension-count
 * logic, not cryptographic verification.
 *
 * Returns an allocated blob that the caller frees with s2n_free. */
static S2N_RESULT s2n_test_build_cert_with_extensions(uint32_t ext_count,
        uint32_t critical_count, bool duplicate_oid, struct s2n_blob *out)
{
    /* We'll accumulate into a stack buffer; the synthetic cert is small because
     * each extension is just a few bytes. Max cert size estimate:
     * header (~50 bytes) + ext_count * ~20 bytes + trailer (~30 bytes).
     * For 33 extensions: ~50 + 33*20 + 30 = ~740 bytes.
     * For 17 critical: same. Use a 2048-byte buffer for safety. */
    uint8_t buf[2048] = { 0 };
    size_t pos = 0;

    /* Helper macros for building DER in the buffer */
    #define PUT_BYTE(b)                         \
        do {                                    \
            RESULT_ENSURE_LT(pos, sizeof(buf)); \
            buf[pos++] = (b);                   \
        } while (0)
    #define PUT_BYTES(data, len)                         \
        do {                                             \
            RESULT_ENSURE_LTE(pos + (len), sizeof(buf)); \
            memcpy(&buf[pos], (data), (len));            \
            pos += (len);                                \
        } while (0)

    /* We build from innermost out. First, build the extensions SEQUENCE content. */
    uint8_t ext_buf[1600] = { 0 };
    size_t ext_pos = 0;

    for (uint32_t i = 0; i < ext_count; i++) {
        /* Extension ::= SEQUENCE { extnID OID, critical BOOLEAN, extnValue OCTET STRING } */
        uint8_t ext_body[32] = { 0 };
        size_t ebody_pos = 0;

        /* OID: 2.5.29.{100+i} or 2.5.29.100 for duplicate test.
         * Encoded: 55 1d XX (where XX = 0x64 + i, or 0x64 always) */
        uint8_t oid_byte = duplicate_oid ? 0x64 : (uint8_t) (0x64 + (i & 0x3F));
        ext_body[ebody_pos++] = 0x06; /* OID tag */
        ext_body[ebody_pos++] = 0x03; /* OID length: 3 bytes */
        ext_body[ebody_pos++] = 0x55;
        ext_body[ebody_pos++] = 0x1d;
        ext_body[ebody_pos++] = oid_byte;

        /* critical BOOLEAN (only for the first critical_count extensions) */
        bool is_critical = (i < critical_count);
        if (is_critical) {
            ext_body[ebody_pos++] = 0x01; /* BOOLEAN tag */
            ext_body[ebody_pos++] = 0x01; /* length 1 */
            ext_body[ebody_pos++] = 0xFF; /* TRUE */
        }

        /* extnValue: OCTET STRING containing a NULL (05 00) */
        ext_body[ebody_pos++] = 0x04; /* OCTET STRING tag */
        ext_body[ebody_pos++] = 0x02; /* length 2 */
        ext_body[ebody_pos++] = 0x05; /* NULL */
        ext_body[ebody_pos++] = 0x00;

        /* Wrap in a SEQUENCE */
        RESULT_ENSURE_LTE(ext_pos + 2 + ebody_pos, sizeof(ext_buf));
        ext_buf[ext_pos++] = 0x30; /* SEQUENCE tag */
        ext_buf[ext_pos++] = (uint8_t) ebody_pos;
        memcpy(&ext_buf[ext_pos], ext_body, ebody_pos);
        ext_pos += ebody_pos;
    }

    /* Now build the TBS content */
    uint8_t tbs_buf[1800] = { 0 };
    size_t tbs_pos = 0;

    /* version [0] EXPLICIT INTEGER 2 (v3) */
    uint8_t version[] = { 0xa0, 0x03, 0x02, 0x01, 0x02 };
    memcpy(&tbs_buf[tbs_pos], version, sizeof(version));
    tbs_pos += sizeof(version);

    /* serial: INTEGER 1 */
    uint8_t serial[] = { 0x02, 0x01, 0x01 };
    memcpy(&tbs_buf[tbs_pos], serial, sizeof(serial));
    tbs_pos += sizeof(serial);

    /* inner AlgorithmIdentifier: sha256WithRSAEncryption (dummy) */
    uint8_t alg_id[] = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00 };
    memcpy(&tbs_buf[tbs_pos], alg_id, sizeof(alg_id));
    tbs_pos += sizeof(alg_id);

    /* issuer: SEQUENCE {} (empty Name) */
    uint8_t empty_name[] = { 0x30, 0x00 };
    memcpy(&tbs_buf[tbs_pos], empty_name, sizeof(empty_name));
    tbs_pos += sizeof(empty_name);

    /* validity: SEQUENCE { UTCTime "250101000000Z", UTCTime "350101000000Z" } */
    uint8_t validity[] = { 0x30, 0x1e,
        0x17, 0x0d, '2', '5', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
        0x17, 0x0d, '3', '5', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z' };
    memcpy(&tbs_buf[tbs_pos], validity, sizeof(validity));
    tbs_pos += sizeof(validity);

    /* subject: SEQUENCE {} (empty Name) */
    memcpy(&tbs_buf[tbs_pos], empty_name, sizeof(empty_name));
    tbs_pos += sizeof(empty_name);

    /* SPKI: SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }
     * We need: SEQUENCE { AlgorithmIdentifier SEQUENCE { OID, NULL }, BIT STRING } */
    uint8_t spki2[] = {
        0x30, 0x1a,                                                       /* SEQUENCE, 26 bytes */
        0x30, 0x0d,                                                       /* AlgorithmIdentifier SEQUENCE, 13 bytes */
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, /* rsaEncryption OID */
        0x05, 0x00,                                                       /* NULL */
        0x03, 0x09,                                                       /* BIT STRING, 9 bytes */
        0x00,                                                             /* unused bits = 0 */
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01                    /* dummy: SEQUENCE { INT 1, INT 1 } */
    };
    memcpy(&tbs_buf[tbs_pos], spki2, sizeof(spki2));
    tbs_pos += sizeof(spki2);

    /* extensions [3] EXPLICIT SEQUENCE OF Extension */
    /* Build the extensions wrapper: [3] { SEQUENCE { ext_buf } } */
    /* The extensions SEQUENCE wraps ext_buf */
    size_t ext_seq_len = ext_pos;
    uint8_t ext_seq_hdr[4] = { 0 };
    size_t ext_seq_hdr_len = 0;
    ext_seq_hdr[0] = 0x30; /* SEQUENCE tag */
    if (ext_seq_len < 128) {
        ext_seq_hdr[1] = (uint8_t) ext_seq_len;
        ext_seq_hdr_len = 2;
    } else if (ext_seq_len < 256) {
        ext_seq_hdr[1] = 0x81;
        ext_seq_hdr[2] = (uint8_t) ext_seq_len;
        ext_seq_hdr_len = 3;
    } else {
        ext_seq_hdr[1] = 0x82;
        ext_seq_hdr[2] = (uint8_t) (ext_seq_len >> 8);
        ext_seq_hdr[3] = (uint8_t) (ext_seq_len & 0xFF);
        ext_seq_hdr_len = 4;
    }

    /* [3] CONSTRUCTED EXPLICIT wrapper */
    size_t ctx3_content_len = ext_seq_hdr_len + ext_seq_len;
    uint8_t ctx3_hdr[4] = { 0 };
    size_t ctx3_hdr_len = 0;
    ctx3_hdr[0] = 0xa3; /* context [3] constructed */
    if (ctx3_content_len < 128) {
        ctx3_hdr[1] = (uint8_t) ctx3_content_len;
        ctx3_hdr_len = 2;
    } else if (ctx3_content_len < 256) {
        ctx3_hdr[1] = 0x81;
        ctx3_hdr[2] = (uint8_t) ctx3_content_len;
        ctx3_hdr_len = 3;
    } else {
        ctx3_hdr[1] = 0x82;
        ctx3_hdr[2] = (uint8_t) (ctx3_content_len >> 8);
        ctx3_hdr[3] = (uint8_t) (ctx3_content_len & 0xFF);
        ctx3_hdr_len = 4;
    }

    /* Append the [3] wrapper + extensions to TBS */
    memcpy(&tbs_buf[tbs_pos], ctx3_hdr, ctx3_hdr_len);
    tbs_pos += ctx3_hdr_len;
    memcpy(&tbs_buf[tbs_pos], ext_seq_hdr, ext_seq_hdr_len);
    tbs_pos += ext_seq_hdr_len;
    memcpy(&tbs_buf[tbs_pos], ext_buf, ext_pos);
    tbs_pos += ext_pos;

    /* Now build the full certificate: SEQUENCE { TBS_SEQUENCE, sigAlg, sigValue } */
    /* TBS SEQUENCE header */
    uint8_t tbs_hdr[4] = { 0 };
    size_t tbs_hdr_len = 0;
    tbs_hdr[0] = 0x30;
    if (tbs_pos < 128) {
        tbs_hdr[1] = (uint8_t) tbs_pos;
        tbs_hdr_len = 2;
    } else if (tbs_pos < 256) {
        tbs_hdr[1] = 0x81;
        tbs_hdr[2] = (uint8_t) tbs_pos;
        tbs_hdr_len = 3;
    } else {
        tbs_hdr[1] = 0x82;
        tbs_hdr[2] = (uint8_t) (tbs_pos >> 8);
        tbs_hdr[3] = (uint8_t) (tbs_pos & 0xFF);
        tbs_hdr_len = 4;
    }

    /* Outer AlgorithmIdentifier (same as inner) */
    /* Signature BIT STRING: 00 + 1 dummy byte */
    uint8_t sig_bs[] = { 0x03, 0x02, 0x00, 0x01 };

    /* Total content of outer SEQUENCE: tbs_hdr + tbs_pos + alg_id + sig_bs */
    size_t outer_content = tbs_hdr_len + tbs_pos + sizeof(alg_id) + sizeof(sig_bs);

    /* Outer SEQUENCE header */
    PUT_BYTE(0x30);
    if (outer_content < 128) {
        PUT_BYTE((uint8_t) outer_content);
    } else if (outer_content < 256) {
        PUT_BYTE(0x81);
        PUT_BYTE((uint8_t) outer_content);
    } else {
        PUT_BYTE(0x82);
        PUT_BYTE((uint8_t) (outer_content >> 8));
        PUT_BYTE((uint8_t) (outer_content & 0xFF));
    }

    /* TBS */
    PUT_BYTES(tbs_hdr, tbs_hdr_len);
    PUT_BYTES(tbs_buf, tbs_pos);
    /* Outer AlgorithmIdentifier */
    PUT_BYTES(alg_id, sizeof(alg_id));
    /* Signature BIT STRING */
    PUT_BYTES(sig_bs, sizeof(sig_bs));

    #undef PUT_BYTE
    #undef PUT_BYTES

    RESULT_GUARD_POSIX(s2n_alloc(out, (uint32_t) pos));
    RESULT_CHECKED_MEMCPY(out->data, buf, pos);
    return S2N_RESULT_OK;
}

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

int main(int argc, char **argv)
{
    BEGIN_TEST();

#if S2N_LIBCRYPTO_SUPPORTS_CBS
    const char *test_pems[] = {
        S2N_DEFAULT_TEST_CERT_CHAIN,
        S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN,
    };

    /* Well-formed certificates parse; every span is an exact in-bounds
     * sub-range of the input DER (round-trip provenance, ) */
    for (size_t i = 0; i < s2n_array_len(test_pems); i++) {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        struct s2n_cert_span_view view = { 0 };
        EXPECT_OK(s2n_test_parse_pem_leaf(test_pems[i], &view, &der));

        /* raw covers the entire input */
        EXPECT_EQUAL(view.raw.data, der.data);
        EXPECT_EQUAL(view.raw.size, der.size);

        const struct s2n_blob *spans[] = {
            &view.tbs, &view.outer_sig_alg, &view.inner_sig_alg, &view.sig,
            &view.serial, &view.issuer, &view.validity, &view.subject, &view.spki
        };
        for (size_t j = 0; j < s2n_array_len(spans); j++) {
            EXPECT_TRUE(spans[j]->size > 0);
            EXPECT_OK(s2n_test_assert_span_within(spans[j], &view.raw));
        }

        /* The TBS span keeps its TLV header (SEQUENCE tag). */
        EXPECT_EQUAL(view.tbs.data[0], 0x30);
        /* Outer and inner AlgorithmIdentifier TLVs must carry identical bytes
         * in a well-formed cert. */
        EXPECT_EQUAL(view.outer_sig_alg.size, view.inner_sig_alg.size);
        EXPECT_BYTEARRAY_EQUAL(view.outer_sig_alg.data, view.inner_sig_alg.data,
                view.outer_sig_alg.size);

        /* Our test certs are v3 with extensions and a SAN. */
        EXPECT_EQUAL(view.version, 2);
        EXPECT_NOT_NULL(view.extensions.data);
        EXPECT_OK(s2n_test_assert_span_within(&view.extensions, &view.raw));
        EXPECT_NOT_NULL(view.san.data);
        EXPECT_OK(s2n_test_assert_span_within(&view.san, &view.raw));
    }

    /* Cached extension facts: the self-signed ECDSA test cert carries a
     * critical basicConstraints CA:TRUE plus SKID/AKID. */
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        struct s2n_cert_span_view view = { 0 };
        EXPECT_OK(s2n_test_parse_pem_leaf(S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, &view, &der));

        EXPECT_TRUE(view.basic_constraints_present);
        EXPECT_TRUE(view.basic_constraints_is_ca);
        EXPECT_FALSE(view.basic_constraints_has_path_len);
        EXPECT_NOT_NULL(view.skid.data);
        EXPECT_NOT_NULL(view.akid.data);
        /* basicConstraints is the only critical extension on this cert */
        EXPECT_EQUAL(view.critical_ext_oid_count, 1);
        uint8_t oid_basic_constraints[] = { 0x55, 0x1d, 0x13 };
        EXPECT_EQUAL(view.critical_ext_oids[0].size, sizeof(oid_basic_constraints));
        EXPECT_BYTEARRAY_EQUAL(view.critical_ext_oids[0].data, oid_basic_constraints,
                sizeof(oid_basic_constraints));
    }

    /* Malformed input rejects with S2N_ERR_CERT_INVALID ().
     * (Exhaustive per-class fixtures are covered by the parser fixture suite;
     * these are integration sanity checks for the parse entry point.) */
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        struct s2n_cert_span_view view = { 0 };
        EXPECT_OK(s2n_test_parse_pem_leaf(S2N_DEFAULT_TEST_CERT_CHAIN, &view, &der));

        /* Truncated certificate */
        {
            struct s2n_blob truncated = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&truncated, der.data, der.size - 1));
            struct s2n_cert_span_view bad_view = { 0 };
            EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&bad_view, &truncated),
                    S2N_ERR_CERT_INVALID);
        }

        /* Trailing garbage after the certificate TLV */
        {
            DEFER_CLEANUP(struct s2n_blob padded = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&padded, der.size + 1));
            EXPECT_MEMCPY_SUCCESS(padded.data, der.data, der.size);
            padded.data[der.size] = 0x00;
            struct s2n_cert_span_view bad_view = { 0 };
            EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&bad_view, &padded),
                    S2N_ERR_CERT_INVALID);
        }

        /* Indefinite-form outer length (0x80) is not DER */
        {
            DEFER_CLEANUP(struct s2n_blob indefinite = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&indefinite, der.size));
            EXPECT_MEMCPY_SUCCESS(indefinite.data, der.data, der.size);
            indefinite.data[1] = 0x80;
            struct s2n_cert_span_view bad_view = { 0 };
            EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&bad_view, &indefinite),
                    S2N_ERR_CERT_INVALID);
        }

        /* Nonzero unused-bits octet in the signature BIT STRING (signature-
         * bypass class): flip the octet in place and expect rejection. */
        {
            DEFER_CLEANUP(struct s2n_blob mutated = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&mutated, der.size));
            EXPECT_MEMCPY_SUCCESS(mutated.data, der.data, der.size);
            /* The unused-bits octet is the first content byte of the sig span:
             * one byte before view.sig within the original layout. */
            size_t unused_bits_offset = (size_t) (view.sig.data - der.data) - 1;
            EXPECT_EQUAL(mutated.data[unused_bits_offset], 0x00);
            mutated.data[unused_bits_offset] = 0x01;
            struct s2n_cert_span_view bad_view = { 0 };
            EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&bad_view, &mutated),
                    S2N_ERR_CERT_INVALID);
        }
    }

    /* Hardened validity-time parser () */
    {
        const uint8_t UTC = 0x17;
        const uint8_t GEN = 0x18;
        uint64_t seconds = 0;

        /* UTCTime on both sides of the RFC 5280 century pivot:
         * YY=49 is 2049, YY=50 is 1950 (pre-epoch, saturates to 0). */
        EXPECT_OK(s2n_test_parse_time(UTC, "490101000000Z", &seconds));
        EXPECT_EQUAL(seconds, 2493072000);
        EXPECT_OK(s2n_test_parse_time(UTC, "500101000000Z", &seconds));
        EXPECT_EQUAL(seconds, 0);
        /* Epoch itself and a late-1999 boundary */
        EXPECT_OK(s2n_test_parse_time(UTC, "700101000000Z", &seconds));
        EXPECT_EQUAL(seconds, 0);
        EXPECT_OK(s2n_test_parse_time(UTC, "991231235959Z", &seconds));
        EXPECT_EQUAL(seconds, 946684799);

        /* GeneralizedTime, including a post-2050 date UTCTime cannot express */
        EXPECT_OK(s2n_test_parse_time(GEN, "20240229123045Z", &seconds));
        EXPECT_EQUAL(seconds, 1709209845);
        EXPECT_OK(s2n_test_parse_time(GEN, "20500615010203Z", &seconds));
        EXPECT_EQUAL(seconds, 2538867723);

        /* Fractional seconds reject */
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(GEN, "20240101000000.5Z", &seconds),
                S2N_ERR_CERT_INVALID);
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(UTC, "240101000000.5Z", &seconds),
                S2N_ERR_CERT_INVALID);
        /* UTC offset suffixes reject */
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(GEN, "20240101000000+0000", &seconds),
                S2N_ERR_CERT_INVALID);
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(UTC, "240101000000-0500", &seconds),
                S2N_ERR_CERT_INVALID);
        /* Missing Z rejects */
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(UTC, "240101000000", &seconds),
                S2N_ERR_CERT_INVALID);
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(GEN, "20240101000000", &seconds),
                S2N_ERR_CERT_INVALID);
        /* Non-digit characters reject */
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(UTC, "24010100000AZ", &seconds),
                S2N_ERR_CERT_INVALID);
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(GEN, "2024010100000xZ", &seconds),
                S2N_ERR_CERT_INVALID);

        /* Out-of-range components reject */
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(GEN, "20241301000000Z", &seconds),
                S2N_ERR_CERT_INVALID); /* month 13 */
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(GEN, "20240001000000Z", &seconds),
                S2N_ERR_CERT_INVALID); /* month 00 */
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(GEN, "20240100000000Z", &seconds),
                S2N_ERR_CERT_INVALID); /* day 00 */
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(GEN, "20240132000000Z", &seconds),
                S2N_ERR_CERT_INVALID); /* Jan 32 */
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(GEN, "20240431000000Z", &seconds),
                S2N_ERR_CERT_INVALID); /* Apr 31 */
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(GEN, "20240101240000Z", &seconds),
                S2N_ERR_CERT_INVALID); /* hour 24 */
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(GEN, "20240101006000Z", &seconds),
                S2N_ERR_CERT_INVALID); /* minute 60 */
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(GEN, "20240101000060Z", &seconds),
                S2N_ERR_CERT_INVALID); /* second 60 (no leap-second allowance) */

        /* Leap-day handling: 2024 and 2000 are leap years; 2023 and 1900
         * (divisible by 100, not 400) are not. */
        EXPECT_OK(s2n_test_parse_time(GEN, "20240229000000Z", &seconds));
        EXPECT_OK(s2n_test_parse_time(GEN, "20000229000000Z", &seconds));
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(GEN, "20230229000000Z", &seconds),
                S2N_ERR_CERT_INVALID);
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(GEN, "19000229000000Z", &seconds),
                S2N_ERR_CERT_INVALID);

        /* Wrong tag (e.g. IA5String) rejects */
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(0x16, "20240101000000Z", &seconds),
                S2N_ERR_CERT_INVALID);
        /* Truncated and over-long strings reject */
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(UTC, "2401010000Z", &seconds),
                S2N_ERR_CERT_INVALID);
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(GEN, "202401010000000Z", &seconds),
                S2N_ERR_CERT_INVALID);
        /* GeneralizedTime in UTCTime shape and vice versa reject */
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(UTC, "20240101000000Z", &seconds),
                S2N_ERR_CERT_INVALID);
        EXPECT_ERROR_WITH_ERRNO(s2n_test_parse_time(GEN, "240101000000Z", &seconds),
                S2N_ERR_CERT_INVALID);
    }

    /* Parsing a certificate populates not_before/not_after from the Validity
     * field, agreeing with libcrypto's ASN1_TIME interpretation. */
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        struct s2n_cert_span_view view = { 0 };
        EXPECT_OK(s2n_test_parse_pem_leaf(S2N_DEFAULT_TEST_CERT_CHAIN, &view, &der));

        EXPECT_TRUE(view.not_before > 0);
        EXPECT_TRUE(view.not_after > view.not_before);

        const uint8_t *der_ptr = der.data;
        DEFER_CLEANUP(X509 *cert = d2i_X509(NULL, &der_ptr, der.size), X509_free_pointer);
        EXPECT_NOT_NULL(cert);
        /* ASN1_TIME_to_time_t is used instead of ASN1_TIME_to_tm +
         * OPENSSL_tm_to_posix because it exists on every aws-lc branch the
         * CBS builds support (awslc-fips-2022 predates the other two). */
        time_t libcrypto_not_before = 0;
        time_t libcrypto_not_after = 0;
        EXPECT_EQUAL(ASN1_TIME_to_time_t(X509_get0_notBefore(cert), &libcrypto_not_before), 1);
        EXPECT_EQUAL(ASN1_TIME_to_time_t(X509_get0_notAfter(cert), &libcrypto_not_after), 1);
        EXPECT_EQUAL(view.not_before, (uint64_t) libcrypto_not_before);
        EXPECT_EQUAL(view.not_after, (uint64_t) libcrypto_not_after);
    }

    /* A certificate whose Validity holds a malformed time rejects. */
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        struct s2n_cert_span_view view = { 0 };
        EXPECT_OK(s2n_test_parse_pem_leaf(S2N_DEFAULT_TEST_CERT_CHAIN, &view, &der));

        DEFER_CLEANUP(struct s2n_blob mutated = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&mutated, der.size));
        EXPECT_MEMCPY_SUCCESS(mutated.data, der.data, der.size);
        /* Corrupt the first digit of notBefore (first time TLV inside the
         * Validity SEQUENCE: skip SEQUENCE header + time tag + length). */
        size_t not_before_offset = (size_t) (view.validity.data - der.data) + 2 + 2;
        EXPECT_TRUE(mutated.data[not_before_offset] >= '0'
                && mutated.data[not_before_offset] <= '9');
        mutated.data[not_before_offset] = 'X';
        struct s2n_cert_span_view bad_view = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&bad_view, &mutated),
                S2N_ERR_CERT_INVALID);
    }

    /* Chain-level parse: a multi-cert wire chain parses into N views, each with
     * valid provenance into the wire blob (). The RSA test chain ships
     * with a leaf plus intermediate(s). */
    {
        DEFER_CLEANUP(struct s2n_blob wire = { 0 }, s2n_free);
        uint32_t cert_count = 0;
        EXPECT_OK(s2n_test_load_wire_chain(S2N_DEFAULT_TEST_CERT_CHAIN, &wire, &cert_count));
        EXPECT_TRUE(cert_count >= 2);

        struct s2n_cert_chain_spans chain = { 0 };
        EXPECT_OK(s2n_cert_chain_spans_parse(&chain, &wire, S2N_TEST_MAX_CHAIN_DEPTH));
        EXPECT_EQUAL(chain.count, cert_count);

        /* Every span of every view borrows from the wire blob, and the
         * concatenated raw TLVs tile the wire blob exactly (no gaps). */
        uint8_t *cursor = wire.data;
        for (uint32_t i = 0; i < chain.count; i++) {
            struct s2n_cert_span_view *view = &chain.views[i];
            EXPECT_EQUAL(view->raw.data, cursor);
            EXPECT_TRUE(view->raw.size > 0);
            EXPECT_OK(s2n_test_assert_span_within(&view->raw, &wire));

            const struct s2n_blob *spans[] = {
                &view->tbs, &view->outer_sig_alg, &view->inner_sig_alg,
                &view->sig, &view->serial, &view->issuer, &view->validity,
                &view->subject, &view->spki
            };
            for (size_t j = 0; j < s2n_array_len(spans); j++) {
                EXPECT_TRUE(spans[j]->size > 0);
                EXPECT_OK(s2n_test_assert_span_within(spans[j], &view->raw));
            }
            cursor += view->raw.size;
        }
        /* The chain consumed the wire blob exactly. */
        EXPECT_EQUAL(cursor, wire.data + wire.size);
    }

    /* Chain-level parse agrees cert-for-cert with the single-cert parser: the
     * leaf view from the chain matches the standalone leaf parse. */
    {
        DEFER_CLEANUP(struct s2n_blob wire = { 0 }, s2n_free);
        uint32_t cert_count = 0;
        EXPECT_OK(s2n_test_load_wire_chain(S2N_DEFAULT_TEST_CERT_CHAIN, &wire, &cert_count));

        struct s2n_cert_chain_spans chain = { 0 };
        EXPECT_OK(s2n_cert_chain_spans_parse(&chain, &wire, S2N_TEST_MAX_CHAIN_DEPTH));

        DEFER_CLEANUP(struct s2n_blob leaf_der = { 0 }, s2n_free);
        struct s2n_cert_span_view leaf_view = { 0 };
        EXPECT_OK(s2n_test_parse_pem_leaf(S2N_DEFAULT_TEST_CERT_CHAIN, &leaf_view, &leaf_der));

        EXPECT_EQUAL(chain.views[0].raw.size, leaf_view.raw.size);
        EXPECT_BYTEARRAY_EQUAL(chain.views[0].raw.data, leaf_view.raw.data, leaf_view.raw.size);
    }

    /* An empty wire chain is well-formed input with zero certificates. */
    {
        struct s2n_blob empty = { 0 };
        struct s2n_cert_chain_spans chain = { 0 };
        EXPECT_OK(s2n_cert_chain_spans_parse(&chain, &empty, S2N_TEST_MAX_CHAIN_DEPTH));
        EXPECT_EQUAL(chain.count, 0);
    }

    /* A chain whose certificate count exceeds max_chain_depth rejects with
     * S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED (). The RSA chain has >= 2
     * certificates, so a depth of 1 must reject it. */
    {
        DEFER_CLEANUP(struct s2n_blob wire = { 0 }, s2n_free);
        uint32_t cert_count = 0;
        EXPECT_OK(s2n_test_load_wire_chain(S2N_DEFAULT_TEST_CERT_CHAIN, &wire, &cert_count));
        EXPECT_TRUE(cert_count >= 2);

        struct s2n_cert_chain_spans chain = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_chain_spans_parse(&chain, &wire, 1),
                S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED);

        /* The exact-fit depth accepts the same chain. */
        struct s2n_cert_chain_spans exact = { 0 };
        EXPECT_OK(s2n_cert_chain_spans_parse(&exact, &wire, (uint16_t) cert_count));
        EXPECT_EQUAL(exact.count, cert_count);
    }

    /* A malformed certificate inside an otherwise valid chain rejects the whole
     * chain with S2N_ERR_CERT_INVALID: corrupt the signature BIT STRING
     * unused-bits octet of the leaf. */
    {
        DEFER_CLEANUP(struct s2n_blob wire = { 0 }, s2n_free);
        uint32_t cert_count = 0;
        EXPECT_OK(s2n_test_load_wire_chain(S2N_DEFAULT_TEST_CERT_CHAIN, &wire, &cert_count));

        /* Parse cleanly first to locate the leaf signature span. */
        struct s2n_cert_chain_spans chain = { 0 };
        EXPECT_OK(s2n_cert_chain_spans_parse(&chain, &wire, S2N_TEST_MAX_CHAIN_DEPTH));
        size_t unused_bits_offset = (size_t) (chain.views[0].sig.data - wire.data) - 1;
        EXPECT_EQUAL(wire.data[unused_bits_offset], 0x00);
        wire.data[unused_bits_offset] = 0x01;

        struct s2n_cert_chain_spans bad_chain = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_chain_spans_parse(&bad_chain, &wire, S2N_TEST_MAX_CHAIN_DEPTH),
                S2N_ERR_CERT_INVALID);
    }

    /* Trailing garbage after the last certificate TLV rejects: the split is
     * self-framing and must consume the wire blob exactly. */
    {
        DEFER_CLEANUP(struct s2n_blob wire = { 0 }, s2n_free);
        uint32_t cert_count = 0;
        EXPECT_OK(s2n_test_load_wire_chain(S2N_DEFAULT_TEST_CERT_CHAIN, &wire, &cert_count));

        DEFER_CLEANUP(struct s2n_blob padded = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&padded, wire.size + 1));
        EXPECT_MEMCPY_SUCCESS(padded.data, wire.data, wire.size);
        padded.data[wire.size] = 0x00;

        struct s2n_cert_chain_spans chain = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_chain_spans_parse(&chain, &padded, S2N_TEST_MAX_CHAIN_DEPTH),
                S2N_ERR_CERT_INVALID);
    }

    /* Algorithm identification populates sig_nid / sig_digest_nid / sig_pkey_nid
     * with the same NIDs the libcrypto path derives via s2n_cert_info, for both
     * an RSA PKCS#1 SHA-256 cert and an ECDSA-with-SHA-256 cert (). */
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        struct s2n_cert_span_view view = { 0 };
        EXPECT_OK(s2n_test_parse_pem_leaf(S2N_DEFAULT_TEST_CERT_CHAIN, &view, &der));

        EXPECT_EQUAL(view.sig_nid, NID_sha256WithRSAEncryption);
        EXPECT_EQUAL(view.sig_digest_nid, NID_sha256);
        EXPECT_EQUAL(view.sig_pkey_nid, NID_rsaEncryption);

        /* The span-view NIDs match s2n_cert_info populated from the same DER. */
        const uint8_t *der_ptr = der.data;
        DEFER_CLEANUP(X509 *cert = d2i_X509(NULL, &der_ptr, der.size), X509_free_pointer);
        EXPECT_NOT_NULL(cert);
        struct s2n_cert_info info = { 0 };
        EXPECT_OK(s2n_openssl_x509_get_cert_info(cert, &info));
        EXPECT_EQUAL(view.sig_nid, info.signature_nid);
        EXPECT_EQUAL(view.sig_digest_nid, info.signature_digest_nid);
    }
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        struct s2n_cert_span_view view = { 0 };
        EXPECT_OK(s2n_test_parse_pem_leaf(S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, &view, &der));

        EXPECT_EQUAL(view.sig_nid, NID_ecdsa_with_SHA256);
        EXPECT_EQUAL(view.sig_digest_nid, NID_sha256);
        EXPECT_EQUAL(view.sig_pkey_nid, NID_X9_62_id_ecPublicKey);
    }

    /* Outer vs inner AlgorithmIdentifier mismatch rejects with
     * S2N_ERR_CERT_UNTRUSTED (algorithm anti-substitution, ). Corrupt a
     * single OID byte inside the outer signatureAlgorithm so it no longer
     * matches the inner tbsCertificate.signature. */
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        struct s2n_cert_span_view view = { 0 };
        EXPECT_OK(s2n_test_parse_pem_leaf(S2N_DEFAULT_TEST_CERT_CHAIN, &view, &der));

        DEFER_CLEANUP(struct s2n_blob mutated = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&mutated, der.size));
        EXPECT_MEMCPY_SUCCESS(mutated.data, der.data, der.size);

        /* Flip the final OID content byte of the outer AlgorithmIdentifier. The
         * OID is the first element inside the outer_sig_alg SEQUENCE; its last
         * content byte is safely within the span. */
        /* Walk back to the last byte of the SEQUENCE contents (the algorithm
         * parameters end the TLV; the OID sits at the front). Simplest robust
         * mutation: corrupt the OID's third content byte, which every sig OID
         * we test has. Locate the OID via a fresh CBS walk over the outer TLV. */
        CBS outer = { 0 };
        CBS_init(&outer, mutated.data + (view.outer_sig_alg.data - der.data),
                view.outer_sig_alg.size);
        CBS seq = { 0 };
        EXPECT_TRUE(CBS_get_asn1(&outer, &seq, CBS_ASN1_SEQUENCE));
        CBS oid = { 0 };
        EXPECT_TRUE(CBS_get_asn1(&seq, &oid, CBS_ASN1_OBJECT));
        EXPECT_TRUE(CBS_len(&oid) >= 1);
        /* CBS_data points into `mutated`; flip the OID's last content byte. */
        uint8_t *oid_last = (uint8_t *) (uintptr_t) (CBS_data(&oid) + CBS_len(&oid) - 1);
        *oid_last ^= 0x01;

        struct s2n_cert_span_view bad_view = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&bad_view, &mutated),
                S2N_ERR_CERT_UNTRUSTED);
    }

    /* A genuine self-signed certificate verifies via s2n_cert_verify_signed
     * against its own public key, and a tampered TBS fails to verify ().
     * Exercises RSA-PSS, ECDSA, and RSA PKCS#1 v1.5 self-signed roots. */
    {
        const char *self_signed_pems[] = {
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN,                        /* ECDSA-with-SHA256 */
            S2N_RSA_PSS_2048_SHA256_CA_CERT,                          /* RSASSA-PSS */
            "../pems/permutations/rsae_pkcs_2048_sha256/ca-cert.pem", /* RSA PKCS#1 */
        };
        for (size_t i = 0; i < s2n_array_len(self_signed_pems); i++) {
            /* Skip the RSA-PSS root when libcrypto can't parse RSA-PSS public keys. */
            if (!s2n_is_rsa_pss_certs_supported() && strstr(self_signed_pems[i], "rsa_pss")) {
                continue;
            }

            DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
            struct s2n_cert_span_view view = { 0 };
            EXPECT_OK(s2n_test_parse_pem_leaf(self_signed_pems[i], &view, &der));

            DEFER_CLEANUP(struct s2n_pkey key = { 0 }, s2n_pkey_free);
            s2n_pkey_type type = S2N_PKEY_TYPE_UNKNOWN;
            EXPECT_OK(s2n_test_pkey_from_der(&der, &key, &type));

            /* The self-signed cert's signature verifies against its own key. */
            EXPECT_OK(s2n_cert_verify_signed(&view.tbs, &view.outer_sig_alg,
                    &view.sig, &key));

            /* Tampering with the TBS bytes makes verification fail. Copy the TBS
             * out so we can flip a byte without disturbing other spans. */
            DEFER_CLEANUP(struct s2n_blob tbs_copy = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&tbs_copy, view.tbs.size));
            EXPECT_MEMCPY_SUCCESS(tbs_copy.data, view.tbs.data, view.tbs.size);
            /* Flip a byte deep in the TBS (avoid the leading SEQUENCE header). */
            tbs_copy.data[tbs_copy.size / 2] ^= 0x01;
            EXPECT_ERROR_WITH_ERRNO(s2n_cert_verify_signed(&tbs_copy, &view.outer_sig_alg,
                                            &view.sig, &key),
                    S2N_ERR_CERT_UNTRUSTED);

            /* A truncated signature also fails to verify. */
            struct s2n_blob short_sig = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&short_sig, view.sig.data, view.sig.size - 1));
            EXPECT_ERROR_WITH_ERRNO(s2n_cert_verify_signed(&view.tbs, &view.outer_sig_alg,
                                            &short_sig, &key),
                    S2N_ERR_CERT_UNTRUSTED);
        }
    }

    /* Verifying a leaf against the wrong issuer key fails: the RSA leaf's
     * signature does not verify against the ECDSA self-signed cert's key. */
    {
        DEFER_CLEANUP(struct s2n_blob leaf_der = { 0 }, s2n_free);
        struct s2n_cert_span_view leaf_view = { 0 };
        EXPECT_OK(s2n_test_parse_pem_leaf(S2N_DEFAULT_TEST_CERT_CHAIN, &leaf_view, &leaf_der));

        DEFER_CLEANUP(struct s2n_blob wrong_der = { 0 }, s2n_free);
        struct s2n_cert_span_view wrong_view = { 0 };
        EXPECT_OK(s2n_test_parse_pem_leaf(S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, &wrong_view, &wrong_der));

        DEFER_CLEANUP(struct s2n_pkey wrong_key = { 0 }, s2n_pkey_free);
        s2n_pkey_type type = S2N_PKEY_TYPE_UNKNOWN;
        EXPECT_OK(s2n_test_pkey_from_der(&wrong_der, &wrong_key, &type));

        /* RSA signature algorithm against an ECDSA key: key-type mismatch. */
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_verify_signed(&leaf_view.tbs, &leaf_view.outer_sig_alg,
                                        &leaf_view.sig, &wrong_key),
                S2N_ERR_CERT_UNTRUSTED);
    }

    /* === Exhaustive malformed-DER fixture suite () === */

    /* Non-minimal long-form length: encode a short content length (< 128) using
     * the long form (0x81 LL). CBS rejects this as non-minimal DER (). */
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        struct s2n_cert_span_view view = { 0 };
        EXPECT_OK(s2n_test_parse_pem_leaf(S2N_DEFAULT_TEST_CERT_CHAIN, &view, &der));

        /* Build a tiny SEQUENCE with a non-minimal length: 30 81 02 05 00.
         * The content is 2 bytes, but encoded with long form 0x81 0x02. */
        uint8_t non_minimal[] = { 0x30, 0x81, 0x02, 0x05, 0x00 };
        struct s2n_blob nm_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&nm_blob, non_minimal, sizeof(non_minimal)));
        struct s2n_cert_span_view bad_view = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&bad_view, &nm_blob),
                S2N_ERR_CERT_INVALID);
    }

    /* Non-minimal long-form length inside the certificate: mutate the TBS
     * SEQUENCE length to long form when it could be short form. The outer
     * SEQUENCE remains valid so CBS reaches the inner violation. */
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        struct s2n_cert_span_view view = { 0 };
        EXPECT_OK(s2n_test_parse_pem_leaf(S2N_DEFAULT_TEST_CERT_CHAIN, &view, &der));

        /* The cert's outer SEQUENCE uses long-form legitimately (> 127 bytes).
         * We craft a minimal cert-like TLV whose inner SEQUENCE uses non-minimal
         * long-form length. A SEQUENCE { SEQUENCE(non-minimal-len) {} } */
        uint8_t inner_nm[] = {
            0x30, 0x04,       /* outer SEQUENCE, 4 content bytes */
            0x30, 0x81, 0x01, /* inner SEQUENCE, length 1 encoded as 0x81 0x01 */
            0x05              /* a NULL as 1 byte of content */
        };
        struct s2n_blob nm_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&nm_blob, inner_nm, sizeof(inner_nm)));
        struct s2n_cert_span_view bad_view = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&bad_view, &nm_blob),
                S2N_ERR_CERT_INVALID);
    }

    /* Oversized declared length: the outer SEQUENCE declares more content bytes
     * than actually exist in the buffer. CBS cannot read past the end (). */
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        struct s2n_cert_span_view view = { 0 };
        EXPECT_OK(s2n_test_parse_pem_leaf(S2N_DEFAULT_TEST_CERT_CHAIN, &view, &der));

        /* Inflate the outer SEQUENCE's declared length by 1 beyond what remains.
         * The cert uses multi-byte length (0x82 HH LL); increment LL. */
        DEFER_CLEANUP(struct s2n_blob mutated = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&mutated, der.size));
        EXPECT_MEMCPY_SUCCESS(mutated.data, der.data, der.size);
        /* The outer SEQUENCE tag is at offset 0. For a real cert > 127 bytes
         * the length is long-form; byte[1] is 0x82, bytes[2..3] are the
         * big-endian length. Increment the length by 1. */
        EXPECT_EQUAL(mutated.data[0], 0x30);
        EXPECT_EQUAL(mutated.data[1], 0x82);
        uint16_t declared = ((uint16_t) mutated.data[2] << 8) | mutated.data[3];
        declared += 1;
        mutated.data[2] = (uint8_t) (declared >> 8);
        mutated.data[3] = (uint8_t) (declared & 0xFF);
        struct s2n_cert_span_view bad_view = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&bad_view, &mutated),
                S2N_ERR_CERT_INVALID);
    }

    /* Oversized declared length (inner): inflate the TBS SEQUENCE length so it
     * claims more bytes than the outer certificate provides. */
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        struct s2n_cert_span_view view = { 0 };
        EXPECT_OK(s2n_test_parse_pem_leaf(S2N_DEFAULT_TEST_CERT_CHAIN, &view, &der));

        DEFER_CLEANUP(struct s2n_blob mutated = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&mutated, der.size));
        EXPECT_MEMCPY_SUCCESS(mutated.data, der.data, der.size);
        /* Locate the TBS SEQUENCE header within the cert. tbs.data points at
         * the TBS SEQUENCE tag (0x30) in the original buffer. */
        size_t tbs_offset = (size_t) (view.tbs.data - der.data);
        EXPECT_EQUAL(mutated.data[tbs_offset], 0x30);
        /* The TBS also uses 0x82 length form for typical test certs. */
        EXPECT_EQUAL(mutated.data[tbs_offset + 1], 0x82);
        uint16_t tbs_len = ((uint16_t) mutated.data[tbs_offset + 2] << 8)
                | mutated.data[tbs_offset + 3];
        tbs_len += 100; /* grossly overshoot */
        mutated.data[tbs_offset + 2] = (uint8_t) (tbs_len >> 8);
        mutated.data[tbs_offset + 3] = (uint8_t) (tbs_len & 0xFF);
        struct s2n_cert_span_view bad_view = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&bad_view, &mutated),
                S2N_ERR_CERT_INVALID);
    }

    /* Nesting beyond depth bound: the parser walks a fixed grammar and never
     * recurses (depth bounded by construction per S2N_CERT_PARSE_MAX_DEPTH).
     * Deeply nested ASN.1 structures cannot arise from the fixed tag sequence
     * the parser expects; any input requiring deeper traversal fails the
     * fixed-shape tag checks. This is documented here rather than tested with
     * a synthetic input because there is no way to present a well-framed cert
     * whose internal structure exceeds the parser's fixed grammar — the parser
     * does not recurse generically. The nesting cap is implicit. */

    /* Extension count beyond S2N_CERT_PARSE_MAX_EXTENSIONS (32): a synthetic
     * certificate with 33 extensions must reject (). */
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        EXPECT_OK(s2n_test_build_cert_with_extensions(
                S2N_CERT_PARSE_MAX_EXTENSIONS + 1, 0, false, &der));
        struct s2n_cert_span_view bad_view = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&bad_view, &der),
                S2N_ERR_CERT_INVALID);
    }

    /* Extension count at exactly the cap (32) should succeed. */
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        EXPECT_OK(s2n_test_build_cert_with_extensions(
                S2N_CERT_PARSE_MAX_EXTENSIONS, 0, false, &der));
        struct s2n_cert_span_view view = { 0 };
        EXPECT_OK(s2n_cert_span_view_parse(&view, &der));
    }

    /* Critical extension count beyond S2N_CERT_PARSE_MAX_CRITICAL_EXTENSIONS
     * (16): a synthetic cert with 17 critical extensions must reject. */
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        EXPECT_OK(s2n_test_build_cert_with_extensions(
                S2N_CERT_PARSE_MAX_CRITICAL_EXTENSIONS + 1,
                S2N_CERT_PARSE_MAX_CRITICAL_EXTENSIONS + 1, false, &der));
        struct s2n_cert_span_view bad_view = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&bad_view, &der),
                S2N_ERR_CERT_INVALID);
    }

    /* Critical extension count at exactly the cap (16) should succeed. */
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        EXPECT_OK(s2n_test_build_cert_with_extensions(
                S2N_CERT_PARSE_MAX_CRITICAL_EXTENSIONS,
                S2N_CERT_PARSE_MAX_CRITICAL_EXTENSIONS, false, &der));
        struct s2n_cert_span_view view = { 0 };
        EXPECT_OK(s2n_cert_span_view_parse(&view, &der));
        EXPECT_EQUAL(view.critical_ext_oid_count,
                S2N_CERT_PARSE_MAX_CRITICAL_EXTENSIONS);
    }

    /* Duplicate extension rejection: RFC 5280 §4.2 prohibits a certificate from
     * including more than one instance of a particular extension. The parser's
     * s2n_cert_parse_cache_span helper rejects the duplicate by checking that the
     * target span is still NULL. Tested below with two SAN extensions. */

    /* Duplicate SAN extension (known cached OID): craft a minimal cert with two
     * subjectAltName (2.5.29.17) extensions to exercise the cache_span guard. */
    {
        /* Build a cert by hand with two SAN extensions. */
        uint8_t ext_buf[64] = { 0 };
        size_t ext_pos = 0;

        /* SAN extension #1: OID 55 1d 11, extnValue = OCTET STRING { SEQUENCE {} } */
        uint8_t san_ext[] = {
            0x30, 0x0b,                   /* Extension SEQUENCE, 11 bytes */
            0x06, 0x03, 0x55, 0x1d, 0x11, /* OID: 2.5.29.17 (SAN) */
            0x04, 0x04,                   /* OCTET STRING, 4 bytes */
            0x30, 0x02, 0x82, 0x00        /* GeneralNames: SEQUENCE { dNSName "" } */
        };
        memcpy(&ext_buf[ext_pos], san_ext, sizeof(san_ext));
        ext_pos += sizeof(san_ext);

        /* SAN extension #2: identical (duplicate) */
        memcpy(&ext_buf[ext_pos], san_ext, sizeof(san_ext));
        ext_pos += sizeof(san_ext);

        /* Build TBS with these two extensions */
        uint8_t tbs_buf[256] = { 0 };
        size_t tbs_pos = 0;

        /* version [0] v3 */
        uint8_t version[] = { 0xa0, 0x03, 0x02, 0x01, 0x02 };
        memcpy(&tbs_buf[tbs_pos], version, sizeof(version));
        tbs_pos += sizeof(version);
        /* serial */
        uint8_t serial[] = { 0x02, 0x01, 0x01 };
        memcpy(&tbs_buf[tbs_pos], serial, sizeof(serial));
        tbs_pos += sizeof(serial);
        /* inner AlgorithmIdentifier */
        uint8_t alg_id[] = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00 };
        memcpy(&tbs_buf[tbs_pos], alg_id, sizeof(alg_id));
        tbs_pos += sizeof(alg_id);
        /* issuer (empty) */
        uint8_t empty_seq[] = { 0x30, 0x00 };
        memcpy(&tbs_buf[tbs_pos], empty_seq, sizeof(empty_seq));
        tbs_pos += sizeof(empty_seq);
        /* validity */
        uint8_t val[] = { 0x30, 0x1e,
            0x17, 0x0d, '2', '5', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
            0x17, 0x0d, '3', '5', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z' };
        memcpy(&tbs_buf[tbs_pos], val, sizeof(val));
        tbs_pos += sizeof(val);
        /* subject (empty) */
        memcpy(&tbs_buf[tbs_pos], empty_seq, sizeof(empty_seq));
        tbs_pos += sizeof(empty_seq);
        /* SPKI */
        uint8_t spki[] = {
            0x30, 0x1a,
            0x30, 0x0d,
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
            0x05, 0x00,
            0x03, 0x09, 0x00,
            0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01
        };
        memcpy(&tbs_buf[tbs_pos], spki, sizeof(spki));
        tbs_pos += sizeof(spki);
        /* extensions [3] { SEQUENCE { ext_buf } } */
        tbs_buf[tbs_pos++] = 0xa3;
        tbs_buf[tbs_pos++] = (uint8_t) (ext_pos + 2);
        tbs_buf[tbs_pos++] = 0x30;
        tbs_buf[tbs_pos++] = (uint8_t) ext_pos;
        memcpy(&tbs_buf[tbs_pos], ext_buf, ext_pos);
        tbs_pos += ext_pos;

        /* Full cert: SEQUENCE { TBS_SEQ, sigAlg, sigBitString } */
        uint8_t sig_bs[] = { 0x03, 0x02, 0x00, 0x01 };
        size_t outer_content = 2 + tbs_pos + sizeof(alg_id) + sizeof(sig_bs);
        /* +2 for TBS SEQUENCE header (short form, tbs_pos < 128) */

        uint8_t cert[512] = { 0 };
        size_t cpos = 0;
        cert[cpos++] = 0x30;
        if (outer_content < 128) {
            cert[cpos++] = (uint8_t) outer_content;
        } else {
            cert[cpos++] = 0x81;
            cert[cpos++] = (uint8_t) outer_content;
        }
        /* TBS SEQUENCE */
        cert[cpos++] = 0x30;
        cert[cpos++] = (uint8_t) tbs_pos;
        memcpy(&cert[cpos], tbs_buf, tbs_pos);
        cpos += tbs_pos;
        /* outer AlgorithmIdentifier */
        memcpy(&cert[cpos], alg_id, sizeof(alg_id));
        cpos += sizeof(alg_id);
        /* signature */
        memcpy(&cert[cpos], sig_bs, sizeof(sig_bs));
        cpos += sizeof(sig_bs);

        struct s2n_blob dup_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&dup_blob, cert, (uint32_t) cpos));
        struct s2n_cert_span_view bad_view = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&bad_view, &dup_blob),
                S2N_ERR_CERT_INVALID);
    }

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

    END_TEST();
}
