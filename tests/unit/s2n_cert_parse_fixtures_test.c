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

/* Malformed-DER fixture suite for the zero-copy certificate parser.
 * Each test constructs a targeted byte-level mutation of a valid DER
 * certificate (or a synthetic DER fragment) to exercise one malformed-input
 * class and asserts the expected error code from the error taxonomy.
 *
 * 
 */

#include "crypto/s2n_certificate.h"
#include "crypto/s2n_openssl_x509.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cert_parse.h"

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    #include <openssl/bytestring.h>
    #include <stdint.h>
    #include <string.h>

    #define S2N_TEST_MAX_CHAIN_DEPTH 7

/* Load the leaf certificate DER from a PEM chain into a caller-owned blob. */
static S2N_RESULT s2n_fixture_load_leaf_der(const char *pem_path,
        struct s2n_blob *der_out)
{
    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain = NULL,
            s2n_cert_chain_and_key_ptr_free);
    chain = s2n_cert_chain_and_key_new();
    RESULT_ENSURE_REF(chain);

    uint8_t pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    uint32_t pem_len = 0;
    RESULT_GUARD_POSIX(s2n_read_test_pem_and_len(pem_path, pem, &pem_len,
            S2N_MAX_TEST_PEM_SIZE));
    RESULT_GUARD_POSIX(s2n_cert_chain_and_key_load_public_pem_bytes(chain,
            pem, pem_len));

    struct s2n_blob *leaf_der = &chain->cert_chain->head->raw;
    RESULT_GUARD_POSIX(s2n_realloc(der_out, leaf_der->size));
    RESULT_CHECKED_MEMCPY(der_out->data, leaf_der->data, leaf_der->size);
    return S2N_RESULT_OK;
}

/* Parse the leaf cert and return both DER and populated span view. */
static S2N_RESULT s2n_fixture_parse_leaf(struct s2n_blob *der_out,
        struct s2n_cert_span_view *view_out)
{
    RESULT_GUARD(s2n_fixture_load_leaf_der(S2N_DEFAULT_TEST_CERT_CHAIN,
            der_out));
    RESULT_GUARD(s2n_cert_span_view_parse(view_out, der_out));
    return S2N_RESULT_OK;
}

/* Wrap an ASCII time string in a DER TLV and parse it. */
static S2N_RESULT s2n_fixture_parse_time(uint8_t tag, const char *str,
        uint64_t *out)
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

/* Write a DER length in the minimum number of bytes at `out` and return the
 * number of bytes written. */
static size_t s2n_fixture_write_der_length(uint8_t *out, size_t len)
{
    if (len < 128) {
        out[0] = (uint8_t) len;
        return 1;
    } else if (len < 256) {
        out[0] = 0x81;
        out[1] = (uint8_t) len;
        return 2;
    } else {
        out[0] = 0x82;
        out[1] = (uint8_t) (len >> 8);
        out[2] = (uint8_t) (len & 0xFF);
        return 3;
    }
}

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

int main(int argc, char **argv)
{
    BEGIN_TEST();

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    /* =======================================================================
     * Fixture 1: Non-minimal long-form length ().
     *
     * DER requires the shortest length encoding. A length of 5 encoded as
     * 0x81 0x05 instead of just 0x05 is non-minimal. CBS rejects this at
     * the first CBS_get_asn1_element call on the outer SEQUENCE.
     * ======================================================================= */
    {
        /* Outer SEQUENCE with non-minimal long-form length (0x81 for len < 128). */
        uint8_t non_minimal[] = {
            0x30, 0x81, 0x05, /* SEQUENCE, length 5, non-minimal (should be 0x05) */
            0x30, 0x03,       /* inner SEQUENCE, 3 bytes */
            0x02, 0x01, 0x01, /* INTEGER 1 */
        };
        struct s2n_blob blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&blob, non_minimal, sizeof(non_minimal)));
        struct s2n_cert_span_view view = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&view, &blob),
                S2N_ERR_CERT_INVALID);
    }

    /* =======================================================================
     * Fixture 2: Indefinite length encoding ().
     *
     * DER forbids indefinite-length encoding (0x80). We set the outer
     * SEQUENCE's length byte to 0x80 in a real cert.
     * ======================================================================= */
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        struct s2n_cert_span_view good_view = { 0 };
        EXPECT_OK(s2n_fixture_parse_leaf(&der, &good_view));

        /* Corrupt outer SEQUENCE length to 0x80 (indefinite). */
        der.data[1] = 0x80;
        struct s2n_cert_span_view view = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&view, &der),
                S2N_ERR_CERT_INVALID);
    }

    /* =======================================================================
     * Fixture 3: Truncated structure — input ends mid-TLV ().
     * ======================================================================= */
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        struct s2n_cert_span_view good_view = { 0 };
        EXPECT_OK(s2n_fixture_parse_leaf(&der, &good_view));

        /* Truncate by 50 bytes from the end. */
        struct s2n_blob trunc = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&trunc, der.data, der.size - 50));
        struct s2n_cert_span_view view = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&view, &trunc),
                S2N_ERR_CERT_INVALID);

        /* Truncate at half the cert. */
        struct s2n_blob half = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&half, der.data, der.size / 2));
        struct s2n_cert_span_view view2 = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&view2, &half),
                S2N_ERR_CERT_INVALID);
    }

    /* =======================================================================
     * Fixture 4: Oversized declared length ().
     *
     * The outer SEQUENCE's declared length exceeds the buffer. Increment
     * the encoded length by 1.
     * ======================================================================= */
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        struct s2n_cert_span_view good_view = { 0 };
        EXPECT_OK(s2n_fixture_parse_leaf(&der, &good_view));

        /* Cert uses 0x30 0x82 HH LL. Increment the 16-bit length by 1. */
        EXPECT_EQUAL(der.data[0], 0x30);
        EXPECT_EQUAL(der.data[1], 0x82);
        uint16_t orig_len = (uint16_t) ((der.data[2] << 8) | der.data[3]);
        uint16_t new_len = orig_len + 1;
        der.data[2] = (uint8_t) (new_len >> 8);
        der.data[3] = (uint8_t) (new_len & 0xFF);

        struct s2n_cert_span_view view = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&view, &der),
                S2N_ERR_CERT_INVALID);
    }

    /* =======================================================================
     * Fixture 5: Nesting beyond depth bound ().
     *
     * The parser walks a fixed grammar. A structure the grammar cannot follow
     * triggers rejection. We corrupt the Extensions inner SEQUENCE tag to a
     * different constructed type (SET 0x31) so the parser cannot descend into
     * the expected structure.
     * ======================================================================= */
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        struct s2n_cert_span_view good_view = { 0 };
        EXPECT_OK(s2n_fixture_parse_leaf(&der, &good_view));

        /* The Extensions SEQUENCE contents start at good_view.extensions.data.
         * The inner SEQUENCE tag (0x30) is 2 bytes before (tag + short-form
         * length) or more if long-form. Locate the SEQUENCE by scanning
         * backward from the extensions content for 0x30 tag. We know the
         * SEQUENCE wrapping extensions is right before extensions.data minus
         * its header. The [3] EXPLICIT wrapper is before that.
         *
         * Simplest corruption: change the tag of the first Extension SEQUENCE
         * within the extensions content to something unexpected (e.g., 0xA0).
         * The extension loop expects CBS_ASN1_SEQUENCE (0x30) elements. */
        size_t first_ext_offset =
                (size_t) (good_view.extensions.data - der.data);
        EXPECT_EQUAL(der.data[first_ext_offset], 0x30);
        der.data[first_ext_offset] = 0xA0; /* context-specific constructed */

        struct s2n_cert_span_view view = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&view, &der),
                S2N_ERR_CERT_INVALID);
    }

    /* =======================================================================
     * Fixture 6: Nonzero BIT STRING unused-bits octet ().
     *
     * The certificate signature BIT STRING's unused-bits octet must be 0x00.
     * A nonzero value is a known signature-bypass class.
     * ======================================================================= */
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        struct s2n_cert_span_view good_view = { 0 };
        EXPECT_OK(s2n_fixture_parse_leaf(&der, &good_view));

        /* The unused-bits octet is one byte before the sig span start. */
        size_t unused_bits_offset =
                (size_t) (good_view.sig.data - der.data) - 1;
        EXPECT_EQUAL(der.data[unused_bits_offset], 0x00);

        /* unused_bits = 1 */
        der.data[unused_bits_offset] = 0x01;
        struct s2n_cert_span_view view = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&view, &der),
                S2N_ERR_CERT_INVALID);

        /* unused_bits = 7 (max for BIT STRING in general, still invalid here) */
        der.data[unused_bits_offset] = 0x07;
        struct s2n_cert_span_view view2 = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&view2, &der),
                S2N_ERR_CERT_INVALID);

        /* unused_bits = 0xFF (obviously invalid) */
        der.data[unused_bits_offset] = 0xFF;
        struct s2n_cert_span_view view3 = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&view3, &der),
                S2N_ERR_CERT_INVALID);
    }

    /* =======================================================================
     * Fixture 7: Extension count beyond S2N_CERT_PARSE_MAX_EXTENSIONS ().
     *
     * We build a certificate with 33 extensions by constructing a buffer that
     * splices 33 minimal extensions into the real cert's extension area.
     * Approach: take everything before and after the extensions content, insert
     * 33 extensions, and rewrite the enclosing DER lengths.
     * ======================================================================= */
    {
        DEFER_CLEANUP(struct s2n_blob orig = { 0 }, s2n_free);
        struct s2n_cert_span_view orig_view = { 0 };
        EXPECT_OK(s2n_fixture_parse_leaf(&orig, &orig_view));

        /* Each extension: 30 09 06 03 55 1d XX 04 02 05 00 = 11 bytes */
        const uint32_t target_ext_count = S2N_CERT_PARSE_MAX_EXTENSIONS + 1;
        const size_t ext_size = 11;
        const size_t new_exts_len = ext_size * target_ext_count; /* 363 */

        uint8_t new_exts[11 * 33];
        for (uint32_t i = 0; i < target_ext_count; i++) {
            uint8_t *e = &new_exts[i * ext_size];
            e[0] = 0x30;
            e[1] = 0x09;
            e[2] = 0x06;
            e[3] = 0x03;
            e[4] = 0x55;
            e[5] = 0x1d;
            e[6] = (uint8_t) (0x80 + i);
            e[7] = 0x04;
            e[8] = 0x02;
            e[9] = 0x05;
            e[10] = 0x00;
        }

        /* Locate the extensions content within the original cert DER.
         * Structure: ... [3] EXPLICIT { SEQUENCE { <extensions_content> } } ...
         * extensions.data -> start of SEQUENCE content (past SEQUENCE header)
         * extensions.size -> length of that content */
        size_t exts_content_off =
                (size_t) (orig_view.extensions.data - orig.data);
        size_t old_exts_len = orig_view.extensions.size;
        size_t exts_end = exts_content_off + old_exts_len;

        /* Bytes before the SEQUENCE tag that wraps extensions. We know the
         * SEQUENCE header occupies: tag(1) + length-field. Then the [3]
         * EXPLICIT occupies: tag(1) + length-field before that SEQUENCE.
         * Both headers sit between some prefix offset and exts_content_off. */

        /* Find the [3] tag by scanning backward from the SEQUENCE header.
         * SEQUENCE header starts at exts_content_off - seq_header_len. */
        size_t seq_hdr_len = (old_exts_len < 128) ? 2 : (old_exts_len < 256) ? 3 :
                                                                               4;
        size_t seq_tag_off = exts_content_off - seq_hdr_len;
        EXPECT_EQUAL(orig.data[seq_tag_off], 0x30);

        /* The [3] header is before the SEQUENCE tag. Its content length =
         * seq_hdr_len + old_exts_len. */
        size_t a3_content_len = seq_hdr_len + old_exts_len;
        size_t a3_len_field_size = (a3_content_len < 128) ? 1 : (a3_content_len < 256) ? 2 :
                                                                                         3;
        size_t a3_tag_off = seq_tag_off - 1 - a3_len_field_size;
        EXPECT_EQUAL(orig.data[a3_tag_off], 0xA3);

        /* Now: prefix = orig[0 .. a3_tag_off)
         *      suffix = orig[exts_end .. orig.size)
         * We rebuild:
         *   prefix | [3] { SEQUENCE { new_exts } } | suffix
         * wrapped in outer SEQUENCE { TBS_SEQUENCE { ... } | outer_sig_alg | sig } */

        /* New [3] wrapper and SEQUENCE for the extensions */
        size_t new_seq_hdr_len = 1 + ((new_exts_len < 128) ? 1 : (new_exts_len < 256) ? 2 :
                                                                                        3);
        size_t new_a3_content = new_seq_hdr_len + new_exts_len;
        size_t new_a3_hdr_len = 1 + ((new_a3_content < 128) ? 1 : (new_a3_content < 256) ? 2 :
                                                                                           3);
        size_t new_a3_total = new_a3_hdr_len + new_a3_content;

        /* Build the new cert: prefix + new [3] block + suffix.
         * Then fixup outer SEQUENCE and TBS SEQUENCE lengths. */
        size_t prefix_len = a3_tag_off;
        size_t suffix_len = orig.size - exts_end;
        size_t raw_inner_len = prefix_len + new_a3_total + suffix_len;

        /* The prefix includes the outer SEQUENCE header (4 bytes: 30 82 XX XX)
         * and the TBS SEQUENCE header (4 bytes: 30 82 XX XX), plus TBS fields.
         * We need to fix those headers. For simplicity, rebuild from scratch
         * by setting the lengths directly in the prefix copy. */
        DEFER_CLEANUP(struct s2n_blob built = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&built, raw_inner_len));
        /* Copy prefix */
        EXPECT_MEMCPY_SUCCESS(built.data, orig.data, prefix_len);
        /* Write [3] EXPLICIT header */
        uint8_t *p = built.data + prefix_len;
        *p++ = 0xA3;
        p += s2n_fixture_write_der_length(p, new_a3_content);
        /* Write SEQUENCE header */
        *p++ = 0x30;
        p += s2n_fixture_write_der_length(p, new_exts_len);
        /* Write extensions content */
        EXPECT_MEMCPY_SUCCESS(p, new_exts, new_exts_len);
        p += new_exts_len;
        /* Write suffix */
        EXPECT_MEMCPY_SUCCESS(p, orig.data + exts_end, suffix_len);
        size_t actual_size = (size_t) (p + suffix_len - built.data);
        built.size = (uint32_t) actual_size;

        /* Fix outer SEQUENCE length (first 4 bytes: 30 82 XX XX). */
        size_t outer_content_len = actual_size - 4;
        EXPECT_TRUE(outer_content_len < 65536);
        built.data[0] = 0x30;
        built.data[1] = 0x82;
        built.data[2] = (uint8_t) (outer_content_len >> 8);
        built.data[3] = (uint8_t) (outer_content_len & 0xFF);

        /* Fix TBS SEQUENCE length (bytes 4..7: 30 82 XX XX).
         * TBS content = everything from byte 8 to end-of-TBS.
         * end-of-TBS = actual_size - suffix after TBS (outer_sig_alg + sig).
         * suffix after TBS = orig.size - (TBS end in original).
         * TBS end in original = offset of outer_sig_alg.data. */
        size_t orig_tbs_end = (size_t) (orig_view.outer_sig_alg.data - orig.data);
        size_t post_tbs_len = orig.size - orig_tbs_end;
        size_t new_tbs_end = actual_size - post_tbs_len;
        size_t new_tbs_content_len = new_tbs_end - 8; /* 8 = outer hdr(4) + TBS hdr(4) */
        EXPECT_TRUE(new_tbs_content_len < 65536);
        built.data[4] = 0x30;
        built.data[5] = 0x82;
        built.data[6] = (uint8_t) (new_tbs_content_len >> 8);
        built.data[7] = (uint8_t) (new_tbs_content_len & 0xFF);

        struct s2n_cert_span_view view = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&view, &built),
                S2N_ERR_CERT_INVALID);
    }

    /* =======================================================================
     * Fixture 8: Bad time encodings ().
     *
     * The hardened time parser rejects various malformed time strings.
     * These complement the tests in s2n_cert_parse_test.c with additional
     * malformed classes: wrong-length strings, embedded NULs, and boundary
     * values.
     * ======================================================================= */
    {
        const uint8_t UTC = 0x17;
        const uint8_t GEN = 0x18;
        uint64_t seconds = 0;

        /* Embedded NUL byte in the time string */
        {
            uint8_t nul_time[] = {
                0x17, 0x0D, /* UTCTime, length 13 */
                '2', '4', '0', '1', '0', '1', 0x00, '0', '0', '0', '0', '0', 'Z'
            };
            struct s2n_blob blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&blob, nul_time, sizeof(nul_time)));
            EXPECT_ERROR_WITH_ERRNO(s2n_cert_parse_time(&blob, &seconds),
                    S2N_ERR_CERT_INVALID);
        }

        /* Feb 29 on a non-leap year (century rule: 1900 not leap) */
        EXPECT_ERROR_WITH_ERRNO(
                s2n_fixture_parse_time(GEN, "19000229000000Z", &seconds),
                S2N_ERR_CERT_INVALID);

        /* Feb 30 (never valid) */
        EXPECT_ERROR_WITH_ERRNO(
                s2n_fixture_parse_time(GEN, "20240230000000Z", &seconds),
                S2N_ERR_CERT_INVALID);

        /* Month 00 */
        EXPECT_ERROR_WITH_ERRNO(
                s2n_fixture_parse_time(UTC, "240001000000Z", &seconds),
                S2N_ERR_CERT_INVALID);

        /* Day 00 */
        EXPECT_ERROR_WITH_ERRNO(
                s2n_fixture_parse_time(UTC, "240100000000Z", &seconds),
                S2N_ERR_CERT_INVALID);

        /* Second 60 (no leap second support) */
        EXPECT_ERROR_WITH_ERRNO(
                s2n_fixture_parse_time(GEN, "20240101235960Z", &seconds),
                S2N_ERR_CERT_INVALID);

        /* Non-Z suffix ('+' offset) */
        EXPECT_ERROR_WITH_ERRNO(
                s2n_fixture_parse_time(GEN, "20240101000000+0100", &seconds),
                S2N_ERR_CERT_INVALID);

        /* Trailing characters after Z */
        EXPECT_ERROR_WITH_ERRNO(
                s2n_fixture_parse_time(UTC, "240101000000ZX", &seconds),
                S2N_ERR_CERT_INVALID);

        /* Empty content (just tag + length 0) */
        {
            uint8_t empty_time[] = { 0x17, 0x00 };
            struct s2n_blob blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&blob, empty_time, sizeof(empty_time)));
            EXPECT_ERROR_WITH_ERRNO(s2n_cert_parse_time(&blob, &seconds),
                    S2N_ERR_CERT_INVALID);
        }
    }

    /* =======================================================================
     * Fixture 9: Outer/inner signature algorithm mismatch ().
     *
     * The outer AlgorithmIdentifier (Certificate.signatureAlgorithm) and the
     * inner one (tbsCertificate.signature) must be byte-for-byte identical.
     * A mismatch is the algorithm anti-substitution class and rejects with
     * S2N_ERR_CERT_UNTRUSTED.
     * ======================================================================= */
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        struct s2n_cert_span_view good_view = { 0 };
        EXPECT_OK(s2n_fixture_parse_leaf(&der, &good_view));

        /* Corrupt the last byte of the outer AlgorithmIdentifier OID. Find it
         * via CBS walk over the outer_sig_alg span. */
        CBS outer = { 0 };
        CBS_init(&outer,
                der.data + (good_view.outer_sig_alg.data - der.data),
                good_view.outer_sig_alg.size);
        CBS seq = { 0 };
        EXPECT_TRUE(CBS_get_asn1(&outer, &seq, CBS_ASN1_SEQUENCE));
        CBS oid = { 0 };
        EXPECT_TRUE(CBS_get_asn1(&seq, &oid, CBS_ASN1_OBJECT));
        EXPECT_TRUE(CBS_len(&oid) >= 1);

        /* Flip the last OID byte — CBS_data points into `der`. */
        size_t oid_last_off = (size_t) (CBS_data(&oid) + CBS_len(&oid) - 1
                - der.data);
        der.data[oid_last_off] ^= 0x01;

        struct s2n_cert_span_view view = { 0 };
        EXPECT_ERROR_WITH_ERRNO(s2n_cert_span_view_parse(&view, &der),
                S2N_ERR_CERT_UNTRUSTED);
    }

    /* =======================================================================
     * Fixture 10: Non-minimal INTEGER — serial with unnecessary leading zero
     * ().
     *
     * DER requires INTEGER encoding to be minimal: a leading 0x00 byte is only
     * permitted when the next byte has its high bit set (to keep the integer
     * positive). Adding 0x00 before a byte < 0x80 is non-minimal and must be
     * rejected by s2n_cert_parse_validate_integer.
     * ======================================================================= */
    {
        DEFER_CLEANUP(struct s2n_blob der = { 0 }, s2n_free);
        struct s2n_cert_span_view good_view = { 0 };
        EXPECT_OK(s2n_fixture_parse_leaf(&der, &good_view));

        /* The serial INTEGER is at good_view.serial. Its contents are the raw
         * integer bytes. To create a non-minimal serial, we need to prepend a
         * 0x00 byte before a byte that doesn't have its high bit set.
         *
         * Approach: take the original cert, find the serial INTEGER TLV
         * (tag 0x02, then length, then contents). Insert a 0x00 at the start
         * of the contents and increment the length. This requires expanding
         * the buffer and fixing enclosing lengths.
         *
         * Simpler: just corrupt the serial contents in place to be non-minimal.
         * If serial[0] is 0x00 and serial[1] < 0x80, it's already non-minimal
         * (but our cert is valid, so it shouldn't be). If serial[0] != 0x00,
         * we can set serial[0] to 0x00 and shift the check — but that changes
         * the length. Instead: if the serial has > 1 byte and serial[0] < 0x80,
         * prefix a 0x00 byte in an expanded buffer.
         *
         * Cleanest: build a synthetic buffer that has a non-minimal serial. */

        /* Find the serial INTEGER tag offset. serial.data points to INTEGER
         * contents. The tag (0x02) is before that, at serial.data - 2 (short
         * form) or serial.data - 3 (if length >= 128, but serial is short). */
        size_t serial_content_off =
                (size_t) (good_view.serial.data - der.data);
        size_t serial_len = good_view.serial.size;
        /* For short serials (< 128): tag at -2, length at -1. */
        EXPECT_TRUE(serial_len < 128);
        EXPECT_EQUAL(der.data[serial_content_off - 2], 0x02);
        EXPECT_EQUAL(der.data[serial_content_off - 1], (uint8_t) serial_len);

        /* Create expanded cert: insert 0x00 at start of serial contents.
         * This increases serial by 1 byte. We also increment the INTEGER
         * length byte and all enclosing SEQUENCE lengths. */
        DEFER_CLEANUP(struct s2n_blob expanded = { 0 }, s2n_free);
        EXPECT_SUCCESS(s2n_alloc(&expanded, der.size + 1));
        /* Copy up to serial contents */
        EXPECT_MEMCPY_SUCCESS(expanded.data, der.data, serial_content_off);
        /* Insert leading 0x00 */
        expanded.data[serial_content_off] = 0x00;
        /* Copy rest of original serial + remainder */
        EXPECT_MEMCPY_SUCCESS(expanded.data + serial_content_off + 1,
                der.data + serial_content_off,
                der.size - serial_content_off);

        /* Fix INTEGER length: was serial_len, now serial_len + 1. */
        expanded.data[serial_content_off - 1] = (uint8_t) (serial_len + 1);

        /* Fix outer SEQUENCE length (+1). */
        EXPECT_EQUAL(expanded.data[1], 0x82);
        uint16_t outer_len =
                (uint16_t) ((expanded.data[2] << 8) | expanded.data[3]);
        outer_len += 1;
        expanded.data[2] = (uint8_t) (outer_len >> 8);
        expanded.data[3] = (uint8_t) (outer_len & 0xFF);

        /* Fix TBS SEQUENCE length (+1): starts at byte 4. */
        EXPECT_EQUAL(expanded.data[4], 0x30);
        EXPECT_EQUAL(expanded.data[5], 0x82);
        uint16_t tbs_len =
                (uint16_t) ((expanded.data[6] << 8) | expanded.data[7]);
        tbs_len += 1;
        expanded.data[6] = (uint8_t) (tbs_len >> 8);
        expanded.data[7] = (uint8_t) (tbs_len & 0xFF);

        /* The serial now starts with 0x00 followed by the original first byte.
         * If the original first byte has bit 7 clear, this is non-minimal. Our
         * test serials are typically positive random numbers. Verify the setup
         * creates a non-minimal case: serial[0] == 0x00, serial[1] < 0x80. */
        uint8_t first_orig_byte = der.data[serial_content_off];
        if ((first_orig_byte & 0x80) == 0) {
            /* Non-minimal case: 0x00 prefix before a positive byte. */
            struct s2n_cert_span_view view = { 0 };
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_cert_span_view_parse(&view, &expanded),
                    S2N_ERR_CERT_INVALID);
        } else {
            /* The original serial started with a high byte, so 0x00 prefix is
             * actually valid (makes the integer positive). In this case, build
             * a different non-minimal case: set bytes to 0x00 0x01 (non-minimal
             * because 0x01 < 0x80, so the leading zero is unnecessary). */
            expanded.data[serial_content_off] = 0x00;
            expanded.data[serial_content_off + 1] = 0x01;
            struct s2n_cert_span_view view = { 0 };
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_cert_span_view_parse(&view, &expanded),
                    S2N_ERR_CERT_INVALID);
        }
    }

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

    END_TEST();
}
