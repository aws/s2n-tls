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

#include "utils/s2n_safety.h"

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    #include <openssl/bytestring.h>
    #include <openssl/digest.h>
    #include <openssl/evp.h>
    #include <openssl/obj.h>
    #include <openssl/rsa.h>
    #include <openssl/x509.h>
    #include <string.h>

DEFINE_POINTER_CLEANUP_FUNC(EVP_MD_CTX *, EVP_MD_CTX_free);
DEFINE_POINTER_CLEANUP_FUNC(X509_ALGOR *, X509_ALGOR_free);
DEFINE_POINTER_CLEANUP_FUNC(RSA_PSS_PARAMS *, RSA_PSS_PARAMS_free);

/* Strict DER comes from two layers:
 * - The CBS DER functions (CBS_get_asn1, CBS_get_asn1_element) reject
 *   non-minimal long-form lengths and indefinite lengths, and can never read
 *   past the enclosing buffer, so declared lengths always fit their parent.
 * - The parser walks a fixed, non-recursive grammar (depth bounded by
 *   construction, see S2N_CERT_PARSE_MAX_DEPTH) and requires every enclosing
 *   element to be fully consumed, so trailing garbage at any level rejects.
 *
 * All rejections map to S2N_ERR_CERT_INVALID. The view owns nothing: no
 * allocation happens on any path, so failure needs no cleanup. */

/* DER-encoded OID contents for the extensions whose facts we cache. */
static const uint8_t s2n_oid_basic_constraints[] = { 0x55, 0x1d, 0x13 }; /* 2.5.29.19 */
static const uint8_t s2n_oid_key_usage[] = { 0x55, 0x1d, 0x0f };         /* 2.5.29.15 */
static const uint8_t s2n_oid_ext_key_usage[] = { 0x55, 0x1d, 0x25 };     /* 2.5.29.37 */
static const uint8_t s2n_oid_subject_alt_name[] = { 0x55, 0x1d, 0x11 };  /* 2.5.29.17 */
static const uint8_t s2n_oid_name_constraints[] = { 0x55, 0x1d, 0x1e };  /* 2.5.29.30 */
static const uint8_t s2n_oid_skid[] = { 0x55, 0x1d, 0x0e };              /* 2.5.29.14 */
static const uint8_t s2n_oid_akid[] = { 0x55, 0x1d, 0x23 };              /* 2.5.29.35 */

static bool s2n_cert_parse_oid_eq(const CBS *oid, const uint8_t *ref, size_t ref_len)
{
    return CBS_len(oid) == ref_len && memcmp(CBS_data(oid), ref, ref_len) == 0;
}

/* Read exactly `count` ASCII digits as a decimal number. Any non-digit
 * (including '+', '-', '.', and 'Z' arriving early) rejects. */
static S2N_RESULT s2n_cert_parse_read_digits(CBS *cbs, size_t count, uint64_t *out)
{
    uint64_t value = 0;
    for (size_t i = 0; i < count; i++) {
        uint8_t c = 0;
        RESULT_ENSURE(CBS_get_u8(cbs, &c), S2N_ERR_CERT_INVALID);
        RESULT_ENSURE(c >= '0' && c <= '9', S2N_ERR_CERT_INVALID);
        value = value * 10 + (c - '0');
    }
    *out = value;
    return S2N_RESULT_OK;
}

static bool s2n_cert_parse_is_leap_year(uint64_t year)
{
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

/* Days from the Unix epoch to `year`-`month`-`day` in the proleptic Gregorian
 * calendar (Howard Hinnant's days_from_civil; no timegm/libc dependency).
 * Negative for pre-epoch dates. Inputs are already range-validated. */
static int64_t s2n_cert_parse_days_from_epoch(uint64_t year, uint64_t month, uint64_t day)
{
    int64_t y = (int64_t) year;
    if (month <= 2) {
        y -= 1;
    }
    /* Floor division: GeneralizedTime admits year 0000, making y negative. */
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    uint64_t yoe = (uint64_t) (y - era * 400);
    uint64_t doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
    uint64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t) doe - 719468;
}

/* Parse the contents of one UTCTime or GeneralizedTime TLV into seconds since
 * the Unix epoch. Accepts exactly `YYMMDDHHMMSSZ` (UTCTime, RFC 5280 century
 * pivot: YY < 50 is 20YY, else 19YY) or `YYYYMMDDHHMMSSZ` (GeneralizedTime).
 * The fixed-length digit reads plus the single mandatory trailing 'Z' reject
 * fractional seconds, UTC offsets, and every other suffix by construction. */
static S2N_RESULT s2n_cert_parse_time_contents(CBS *contents, CBS_ASN1_TAG tag,
        uint64_t *seconds_since_epoch)
{
    uint64_t year = 0;
    if (tag == CBS_ASN1_UTCTIME) {
        RESULT_ENSURE(CBS_len(contents) == 13, S2N_ERR_CERT_INVALID);
        uint64_t yy = 0;
        RESULT_GUARD(s2n_cert_parse_read_digits(contents, 2, &yy));
        year = (yy < 50) ? 2000 + yy : 1900 + yy;
    } else if (tag == CBS_ASN1_GENERALIZEDTIME) {
        RESULT_ENSURE(CBS_len(contents) == 15, S2N_ERR_CERT_INVALID);
        RESULT_GUARD(s2n_cert_parse_read_digits(contents, 4, &year));
    } else {
        RESULT_BAIL(S2N_ERR_CERT_INVALID);
    }

    uint64_t month = 0, day = 0, hour = 0, minute = 0, second = 0;
    RESULT_GUARD(s2n_cert_parse_read_digits(contents, 2, &month));
    RESULT_GUARD(s2n_cert_parse_read_digits(contents, 2, &day));
    RESULT_GUARD(s2n_cert_parse_read_digits(contents, 2, &hour));
    RESULT_GUARD(s2n_cert_parse_read_digits(contents, 2, &minute));
    RESULT_GUARD(s2n_cert_parse_read_digits(contents, 2, &second));

    uint8_t suffix = 0;
    RESULT_ENSURE(CBS_get_u8(contents, &suffix), S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(suffix == 'Z', S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_len(contents) == 0, S2N_ERR_CERT_INVALID);

    RESULT_ENSURE(month >= 1 && month <= 12, S2N_ERR_CERT_INVALID);
    static const uint8_t days_in_month[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    uint64_t max_day = days_in_month[month - 1];
    if (month == 2 && s2n_cert_parse_is_leap_year(year)) {
        max_day = 29;
    }
    RESULT_ENSURE(day >= 1 && day <= max_day, S2N_ERR_CERT_INVALID);
    /* No leap-second allowance: sec == 60 rejects, matching CBS_parse_utc_time
     * and CBS_parse_generalized_time (equivalence target). */
    RESULT_ENSURE(hour <= 23 && minute <= 59 && second <= 59, S2N_ERR_CERT_INVALID);

    int64_t days = s2n_cert_parse_days_from_epoch(year, month, day);
    int64_t seconds = days * 86400 + (int64_t) (hour * 3600 + minute * 60 + second);
    /* UTCTime reaches back to 1950; pre-epoch instants saturate to 0. */
    *seconds_since_epoch = (seconds < 0) ? 0 : (uint64_t) seconds;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_cert_parse_time(const struct s2n_blob *time_tlv, uint64_t *seconds_since_epoch)
{
    RESULT_ENSURE_REF(time_tlv);
    RESULT_ENSURE_REF(time_tlv->data);
    RESULT_ENSURE_REF(seconds_since_epoch);

    CBS tlv = { 0 };
    CBS_init(&tlv, time_tlv->data, time_tlv->size);
    CBS contents = { 0 };
    CBS_ASN1_TAG tag = 0;
    RESULT_ENSURE(CBS_get_any_asn1(&tlv, &contents, &tag), S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_len(&tlv) == 0, S2N_ERR_CERT_INVALID);
    RESULT_GUARD(s2n_cert_parse_time_contents(&contents, tag, seconds_since_epoch));
    return S2N_RESULT_OK;
}

/* Capture a CBS as a borrowed s2n_blob span, proving it is an exact in-bounds
 * sub-range of `base` (the round-trip/provenance invariant). */
static S2N_RESULT s2n_cert_parse_capture(const struct s2n_blob *base, const CBS *cbs,
        struct s2n_blob *span)
{
    RESULT_ENSURE_REF(base);
    RESULT_ENSURE_REF(cbs);
    RESULT_ENSURE_REF(span);

    const uint8_t *data = CBS_data(cbs);
    size_t len = CBS_len(cbs);
    RESULT_ENSURE(data != NULL, S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(data >= base->data, S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(len <= base->size, S2N_ERR_CERT_INVALID);
    size_t offset = (size_t) (data - base->data);
    RESULT_ENSURE(offset <= base->size - len, S2N_ERR_CERT_INVALID);

    RESULT_GUARD_POSIX(s2n_blob_init(span, base->data + offset, (uint32_t) len));
    return S2N_RESULT_OK;
}

/* DER INTEGER contents must be non-empty and minimally encoded: a leading 0x00
 * (or 0xFF) octet is only permitted when needed to fix the sign of the next. */
static S2N_RESULT s2n_cert_parse_validate_integer(const CBS *contents)
{
    RESULT_ENSURE_REF(contents);
    size_t len = CBS_len(contents);
    RESULT_ENSURE(len > 0, S2N_ERR_CERT_INVALID);
    if (len > 1) {
        const uint8_t *d = CBS_data(contents);
        RESULT_ENSURE(!(d[0] == 0x00 && (d[1] & 0x80) == 0), S2N_ERR_CERT_INVALID);
        RESULT_ENSURE(!(d[0] == 0xFF && (d[1] & 0x80) != 0), S2N_ERR_CERT_INVALID);
    }
    return S2N_RESULT_OK;
}

/* BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE,
 *                                 pathLenConstraint INTEGER (0..MAX) OPTIONAL } */
static S2N_RESULT s2n_cert_parse_basic_constraints(struct s2n_cert_span_view *view, CBS *value)
{
    RESULT_ENSURE(!view->basic_constraints_present, S2N_ERR_CERT_INVALID);

    CBS bc = { 0 };
    RESULT_ENSURE(CBS_get_asn1(value, &bc, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_len(value) == 0, S2N_ERR_CERT_INVALID);

    view->basic_constraints_present = true;
    if (CBS_peek_asn1_tag(&bc, CBS_ASN1_BOOLEAN)) {
        int is_ca = 0;
        RESULT_ENSURE(CBS_get_asn1_bool(&bc, &is_ca), S2N_ERR_CERT_INVALID);
        view->basic_constraints_is_ca = (is_ca != 0);
    }
    if (CBS_len(&bc) > 0) {
        uint64_t path_len = 0;
        RESULT_ENSURE(CBS_get_asn1_uint64(&bc, &path_len), S2N_ERR_CERT_INVALID);
        view->basic_constraints_has_path_len = true;
        view->basic_constraints_path_len = path_len;
    }
    RESULT_ENSURE(CBS_len(&bc) == 0, S2N_ERR_CERT_INVALID);
    return S2N_RESULT_OK;
}

/* KeyUsage ::= BIT STRING. Named-bit-list contents: byte 0 lands in the low 8
 * bits of key_usage_bits, byte 1 (decipherOnly) in the high 8 bits. keyUsage
 * defines bits 0..8, so a valid DER encoding has at most 2 content bytes. */
static S2N_RESULT s2n_cert_parse_key_usage(struct s2n_cert_span_view *view, CBS *value)
{
    RESULT_ENSURE(!view->key_usage_present, S2N_ERR_CERT_INVALID);

    CBS bits = { 0 };
    RESULT_ENSURE(CBS_get_asn1(value, &bits, CBS_ASN1_BITSTRING), S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_len(value) == 0, S2N_ERR_CERT_INVALID);

    uint8_t unused = 0;
    RESULT_ENSURE(CBS_get_u8(&bits, &unused), S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(unused <= 7, S2N_ERR_CERT_INVALID);

    size_t byte_count = CBS_len(&bits);
    RESULT_ENSURE(byte_count <= 2, S2N_ERR_CERT_INVALID);
    if (byte_count == 0) {
        /* An empty BIT STRING must declare zero unused bits (DER). */
        RESULT_ENSURE(unused == 0, S2N_ERR_CERT_INVALID);
    } else {
        const uint8_t *d = CBS_data(&bits);
        /* DER: the declared unused bits in the final byte must be zero. */
        RESULT_ENSURE((d[byte_count - 1] & ((1 << unused) - 1)) == 0, S2N_ERR_CERT_INVALID);
        view->key_usage_bits = d[0];
        if (byte_count == 2) {
            view->key_usage_bits |= (uint16_t) (d[1] << 8);
        }
    }
    view->key_usage_present = true;
    return S2N_RESULT_OK;
}

/* Cache a bare extnValue span, rejecting duplicate extensions (RFC 5280 §4.2:
 * a certificate MUST NOT include more than one instance of an extension). */
static S2N_RESULT s2n_cert_parse_cache_span(const struct s2n_blob *base, const CBS *value,
        struct s2n_blob *span)
{
    RESULT_ENSURE(span->data == NULL, S2N_ERR_CERT_INVALID);
    RESULT_GUARD(s2n_cert_parse_capture(base, value, span));
    return S2N_RESULT_OK;
}

/* Walk the Extensions SEQUENCE contents once, caching the facts the verifier
 * needs later. Bounded by S2N_CERT_PARSE_MAX_EXTENSIONS. */
static S2N_RESULT s2n_cert_parse_extensions(struct s2n_cert_span_view *view,
        const struct s2n_blob *base, CBS *extensions)
{
    uint32_t count = 0;
    while (CBS_len(extensions) > 0) {
        count++;
        RESULT_ENSURE(count <= S2N_CERT_PARSE_MAX_EXTENSIONS, S2N_ERR_CERT_INVALID);

        /* Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER,
         *                          critical BOOLEAN DEFAULT FALSE,
         *                          extnValue OCTET STRING } */
        CBS ext = { 0 };
        RESULT_ENSURE(CBS_get_asn1(extensions, &ext, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);
        CBS oid = { 0 };
        RESULT_ENSURE(CBS_get_asn1(&ext, &oid, CBS_ASN1_OBJECT), S2N_ERR_CERT_INVALID);
        RESULT_ENSURE(CBS_len(&oid) > 0, S2N_ERR_CERT_INVALID);

        int critical = 0;
        if (CBS_peek_asn1_tag(&ext, CBS_ASN1_BOOLEAN)) {
            RESULT_ENSURE(CBS_get_asn1_bool(&ext, &critical), S2N_ERR_CERT_INVALID);
        }

        CBS value = { 0 };
        RESULT_ENSURE(CBS_get_asn1(&ext, &value, CBS_ASN1_OCTETSTRING), S2N_ERR_CERT_INVALID);
        RESULT_ENSURE(CBS_len(&ext) == 0, S2N_ERR_CERT_INVALID);

        if (critical) {
            /* Every critical OID is cached for the post-path critical-extension
             * sweep. The list is bounded; overflow must reject, because an
             * untracked critical extension could never be swept. */
            RESULT_ENSURE(view->critical_ext_oid_count < S2N_CERT_PARSE_MAX_CRITICAL_EXTENSIONS,
                    S2N_ERR_CERT_INVALID);
            RESULT_GUARD(s2n_cert_parse_capture(base, &oid,
                    &view->critical_ext_oids[view->critical_ext_oid_count]));
            view->critical_ext_oid_count++;
        }

        if (s2n_cert_parse_oid_eq(&oid, s2n_oid_basic_constraints, sizeof(s2n_oid_basic_constraints))) {
            RESULT_GUARD(s2n_cert_parse_basic_constraints(view, &value));
        } else if (s2n_cert_parse_oid_eq(&oid, s2n_oid_key_usage, sizeof(s2n_oid_key_usage))) {
            RESULT_GUARD(s2n_cert_parse_key_usage(view, &value));
        } else if (s2n_cert_parse_oid_eq(&oid, s2n_oid_ext_key_usage, sizeof(s2n_oid_ext_key_usage))) {
            RESULT_GUARD(s2n_cert_parse_cache_span(base, &value, &view->eku));
        } else if (s2n_cert_parse_oid_eq(&oid, s2n_oid_subject_alt_name, sizeof(s2n_oid_subject_alt_name))) {
            RESULT_GUARD(s2n_cert_parse_cache_span(base, &value, &view->san));
        } else if (s2n_cert_parse_oid_eq(&oid, s2n_oid_name_constraints, sizeof(s2n_oid_name_constraints))) {
            RESULT_GUARD(s2n_cert_parse_cache_span(base, &value, &view->name_constraints));
        } else if (s2n_cert_parse_oid_eq(&oid, s2n_oid_skid, sizeof(s2n_oid_skid))) {
            RESULT_GUARD(s2n_cert_parse_cache_span(base, &value, &view->skid));
        } else if (s2n_cert_parse_oid_eq(&oid, s2n_oid_akid, sizeof(s2n_oid_akid))) {
            RESULT_GUARD(s2n_cert_parse_cache_span(base, &value, &view->akid));
        }
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_cert_span_view_parse(struct s2n_cert_span_view *view, struct s2n_blob *cert_der)
{
    RESULT_ENSURE_REF(view);
    RESULT_ENSURE_REF(cert_der);
    RESULT_ENSURE_REF(cert_der->data);

    *view = (struct s2n_cert_span_view){ 0 };

    CBS cert = { 0 };
    CBS_init(&cert, cert_der->data, cert_der->size);

    /* Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
     * The buffer must contain exactly one certificate TLV, nothing more. */
    CBS raw = { 0 };
    RESULT_ENSURE(CBS_get_asn1_element(&cert, &raw, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_len(&cert) == 0, S2N_ERR_CERT_INVALID);
    RESULT_GUARD(s2n_cert_parse_capture(cert_der, &raw, &view->raw));

    CBS top = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&raw, &top, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);

    /* The TBS span keeps its tag+length header: the signature is computed over
     * the full TLV, so verification must feed exactly these bytes. */
    CBS tbs = { 0 };
    RESULT_ENSURE(CBS_get_asn1_element(&top, &tbs, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);
    RESULT_GUARD(s2n_cert_parse_capture(cert_der, &tbs, &view->tbs));

    CBS outer_sig_alg = { 0 };
    RESULT_ENSURE(CBS_get_asn1_element(&top, &outer_sig_alg, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);
    RESULT_GUARD(s2n_cert_parse_capture(cert_der, &outer_sig_alg, &view->outer_sig_alg));

    /* signature BIT STRING: the unused-bits octet MUST be 0x00. Accepting a
     * nonzero value here is a known signature-bypass class (trailing signature
     * bits become attacker-malleable while still verifying). */
    CBS sig_bits = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&top, &sig_bits, CBS_ASN1_BITSTRING), S2N_ERR_CERT_INVALID);
    uint8_t unused_bits = 0xff;
    RESULT_ENSURE(CBS_get_u8(&sig_bits, &unused_bits), S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(unused_bits == 0x00, S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_len(&sig_bits) > 0, S2N_ERR_CERT_INVALID);
    RESULT_GUARD(s2n_cert_parse_capture(cert_der, &sig_bits, &view->sig));

    RESULT_ENSURE(CBS_len(&top) == 0, S2N_ERR_CERT_INVALID);

    /* Walk into the TBS for the field spans (contents-only traversal). */
    CBS tbs_copy = tbs;
    CBS tbs_inner = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&tbs_copy, &tbs_inner, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);

    /* version [0] EXPLICIT INTEGER DEFAULT v1 */
    CBS version_wrapper = { 0 };
    int version_present = 0;
    RESULT_ENSURE(CBS_get_optional_asn1(&tbs_inner, &version_wrapper, &version_present,
                          CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0),
            S2N_ERR_CERT_INVALID);
    if (version_present) {
        uint64_t version = 0;
        RESULT_ENSURE(CBS_get_asn1_uint64(&version_wrapper, &version), S2N_ERR_CERT_INVALID);
        RESULT_ENSURE(CBS_len(&version_wrapper) == 0, S2N_ERR_CERT_INVALID);
        /* v1 = 0, v2 = 1, v3 = 2; anything else is not an X.509 certificate. */
        RESULT_ENSURE(version <= 2, S2N_ERR_CERT_INVALID);
        view->version = (uint8_t) version;
    }

    CBS serial = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&tbs_inner, &serial, CBS_ASN1_INTEGER), S2N_ERR_CERT_INVALID);
    RESULT_GUARD(s2n_cert_parse_validate_integer(&serial));
    RESULT_GUARD(s2n_cert_parse_capture(cert_der, &serial, &view->serial));

    CBS inner_sig_alg = { 0 };
    RESULT_ENSURE(CBS_get_asn1_element(&tbs_inner, &inner_sig_alg, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);
    RESULT_GUARD(s2n_cert_parse_capture(cert_der, &inner_sig_alg, &view->inner_sig_alg));

    CBS issuer = { 0 };
    RESULT_ENSURE(CBS_get_asn1_element(&tbs_inner, &issuer, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);
    RESULT_GUARD(s2n_cert_parse_capture(cert_der, &issuer, &view->issuer));

    CBS validity = { 0 };
    RESULT_ENSURE(CBS_get_asn1_element(&tbs_inner, &validity, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);
    RESULT_GUARD(s2n_cert_parse_capture(cert_der, &validity, &view->validity));

    /* Validity ::= SEQUENCE { notBefore Time, notAfter Time } where each Time
     * is a UTCTime or GeneralizedTime TLV; decoded by the hardened parser. */
    CBS validity_copy = validity;
    CBS validity_inner = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&validity_copy, &validity_inner, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);
    for (size_t i = 0; i < 2; i++) {
        CBS time_contents = { 0 };
        CBS_ASN1_TAG time_tag = 0;
        RESULT_ENSURE(CBS_get_any_asn1(&validity_inner, &time_contents, &time_tag), S2N_ERR_CERT_INVALID);
        uint64_t *out = (i == 0) ? &view->not_before : &view->not_after;
        RESULT_GUARD(s2n_cert_parse_time_contents(&time_contents, time_tag, out));
    }
    RESULT_ENSURE(CBS_len(&validity_inner) == 0, S2N_ERR_CERT_INVALID);

    CBS subject = { 0 };
    RESULT_ENSURE(CBS_get_asn1_element(&tbs_inner, &subject, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);
    RESULT_GUARD(s2n_cert_parse_capture(cert_der, &subject, &view->subject));

    CBS spki = { 0 };
    RESULT_ENSURE(CBS_get_asn1_element(&tbs_inner, &spki, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);
    RESULT_GUARD(s2n_cert_parse_capture(cert_der, &spki, &view->spki));

    /* issuerUniqueID [1] IMPLICIT BIT STRING OPTIONAL,
     * subjectUniqueID [2] IMPLICIT BIT STRING OPTIONAL: skipped if present.
     * DER fixes the field order, so a single ordered pass is exact. */
    CBS unique_id = { 0 };
    int present = 0;
    RESULT_ENSURE(CBS_get_optional_asn1(&tbs_inner, &unique_id, &present,
                          CBS_ASN1_CONTEXT_SPECIFIC | 1),
            S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_get_optional_asn1(&tbs_inner, &unique_id, &present,
                          CBS_ASN1_CONTEXT_SPECIFIC | 2),
            S2N_ERR_CERT_INVALID);

    /* extensions [3] EXPLICIT SEQUENCE OF Extension OPTIONAL */
    CBS extensions_wrapper = { 0 };
    int extensions_present = 0;
    RESULT_ENSURE(CBS_get_optional_asn1(&tbs_inner, &extensions_wrapper, &extensions_present,
                          CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 3),
            S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_len(&tbs_inner) == 0, S2N_ERR_CERT_INVALID);

    if (extensions_present) {
        CBS extensions = { 0 };
        RESULT_ENSURE(CBS_get_asn1(&extensions_wrapper, &extensions, CBS_ASN1_SEQUENCE),
                S2N_ERR_CERT_INVALID);
        RESULT_ENSURE(CBS_len(&extensions_wrapper) == 0, S2N_ERR_CERT_INVALID);
        RESULT_GUARD(s2n_cert_parse_capture(cert_der, &extensions, &view->extensions));
        RESULT_GUARD(s2n_cert_parse_extensions(view, cert_der, &extensions));
    }

    /* Identify the signature algorithm and enforce outer/inner agreement. This
     * populates sig_nid/sig_digest_nid/sig_pkey_nid and rejects the algorithm
     * anti-substitution class with S2N_ERR_CERT_UNTRUSTED. */
    RESULT_GUARD(s2n_cert_span_view_identify_alg(view));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_cert_chain_spans_parse(struct s2n_cert_chain_spans *chain,
        const struct s2n_blob *wire_chain, uint16_t max_chain_depth)
{
    RESULT_ENSURE_REF(chain);
    RESULT_ENSURE_REF(wire_chain);

    /* Only count is reset here, and views are initialized one at a time as
     * they are parsed (s2n_cert_span_view_parse zero-initializes its output).
     * `chain` may be a trailing-truncated heap block with capacity for fewer
     * than S2N_CERT_CHAIN_SPANS_MAX views, so no write may touch past the
     * capacity implied by max_chain_depth. */
    chain->count = 0;

    /* The configured depth caps the certificate count; the fixed inline array
     * caps it structurally. The tighter of the two bounds applies. */
    uint32_t depth_cap = max_chain_depth;
    if (depth_cap > S2N_CERT_CHAIN_SPANS_MAX) {
        depth_cap = S2N_CERT_CHAIN_SPANS_MAX;
    }

    /* An empty chain is well-formed input with zero certificates. */
    if (wire_chain->size == 0) {
        return S2N_RESULT_OK;
    }
    RESULT_ENSURE_REF(wire_chain->data);

    CBS remaining = { 0 };
    CBS_init(&remaining, wire_chain->data, wire_chain->size);

    while (CBS_len(&remaining) > 0) {
        /* Self-framing split: each certificate is exactly one outer SEQUENCE
         * TLV. CBS_get_asn1_element carves off that TLV (header + contents) in
         * minimal-form DER, so successive certificates need no length prefix. */
        CBS cert_element = { 0 };
        RESULT_ENSURE(CBS_get_asn1_element(&remaining, &cert_element, CBS_ASN1_SEQUENCE),
                S2N_ERR_CERT_INVALID);

        /* Reject the (count + 1)th certificate before parsing it: a chain
         * longer than the allowed depth is rejected, not truncated. */
        RESULT_ENSURE(chain->count < depth_cap, S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED);

        struct s2n_blob cert_der = { 0 };
        RESULT_GUARD(s2n_cert_parse_capture(wire_chain, &cert_element, &cert_der));
        RESULT_GUARD(s2n_cert_span_view_parse(&chain->views[chain->count], &cert_der));
        chain->count++;
    }

    RESULT_ENSURE(chain->count > 0, S2N_ERR_CERT_INVALID);
    return S2N_RESULT_OK;
}

/* Extract the OID contents from an AlgorithmIdentifier TLV span into `oid`.
 * AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER,
 *                                    parameters ANY DEFINED BY algorithm OPTIONAL } */
static S2N_RESULT s2n_cert_alg_id_oid(const struct s2n_blob *sig_alg, CBS *oid)
{
    RESULT_ENSURE_REF(sig_alg);
    RESULT_ENSURE_REF(sig_alg->data);

    CBS tlv = { 0 };
    CBS_init(&tlv, sig_alg->data, sig_alg->size);
    CBS seq = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&tlv, &seq, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_len(&tlv) == 0, S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_get_asn1(&seq, oid, CBS_ASN1_OBJECT), S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_len(oid) > 0, S2N_ERR_CERT_INVALID);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_cert_span_view_identify_alg(struct s2n_cert_span_view *view)
{
    RESULT_ENSURE_REF(view);
    RESULT_ENSURE_REF(view->outer_sig_alg.data);
    RESULT_ENSURE_REF(view->inner_sig_alg.data);

    /* Anti-substitution: the outer signatureAlgorithm and the inner
     * tbsCertificate.signature MUST be byte-for-byte identical. Comparing the
     * full AlgorithmIdentifier TLVs also covers any algorithm parameters (e.g.
     * RSA-PSS), matching libcrypto's X509_ALGOR_cmp check in X509_verify. */
    RESULT_ENSURE(view->outer_sig_alg.size == view->inner_sig_alg.size,
            S2N_ERR_CERT_UNTRUSTED);
    RESULT_ENSURE(memcmp(view->outer_sig_alg.data, view->inner_sig_alg.data,
                          view->outer_sig_alg.size)
                    == 0,
            S2N_ERR_CERT_UNTRUSTED);

    /* Map the AlgorithmIdentifier OID to a signature NID, then split it into
     * digest and public-key NIDs. An unknown OID leaves the NIDs as NID_undef;
     * the security-policy layer decides whether that is acceptable, exactly as
     * it does for the libcrypto path's s2n_cert_info. */
    CBS oid = { 0 };
    RESULT_GUARD(s2n_cert_alg_id_oid(&view->outer_sig_alg, &oid));

    view->sig_nid = OBJ_cbs2nid(&oid);
    view->sig_digest_nid = 0;
    view->sig_pkey_nid = 0;
    if (view->sig_nid != NID_undef) {
        /* OBJ_find_sigid_algs may leave the digest unspecified (NID_undef) for
         * algorithms like RSASSA-PSS and Ed25519. Failure is treated as an
         * undefined digest (0), matching s2n_openssl_x509_get_cert_info. */
        if (OBJ_find_sigid_algs(view->sig_nid, &view->sig_digest_nid, &view->sig_pkey_nid) != 1) {
            view->sig_digest_nid = 0;
            view->sig_pkey_nid = 0;
        }
    }
    return S2N_RESULT_OK;
}

/* Digests forbidden in certificate signatures, matching the libcrypto verify
 * layer (aws-lc x509_digest_nid_ok): MD4 and MD5 reject. SHA-1 is NOT rejected
 * here - the libcrypto verify layer accepts it, and s2n's SHA-1 restriction
 * lives in the security-policy layer (check_cert_preferences), which the
 * zero-copy path feeds through the populated sig_digest_nid. */
static bool s2n_cert_verify_digest_nid_ok(int digest_nid)
{
    switch (digest_nid) {
        case NID_md4:
        case NID_md5:
            return false;
        default:
            return true;
    }
}

/* Configure `ctx` for an RSASSA-PSS verification from the AlgorithmIdentifier
 * parameters (hash, MGF1 hash, salt length), mirroring aws-lc's
 * x509_rsa_pss_to_ctx using only public APIs. */
static S2N_RESULT s2n_cert_verify_pss_init(EVP_MD_CTX *ctx, const X509_ALGOR *sigalg,
        EVP_PKEY *pkey)
{
    RESULT_ENSURE_REF(sigalg);
    RESULT_ENSURE_REF(sigalg->parameter);
    RESULT_ENSURE(sigalg->parameter->type == V_ASN1_SEQUENCE, S2N_ERR_CERT_UNTRUSTED);

    const ASN1_STRING *params = sigalg->parameter->value.sequence;
    RESULT_ENSURE_REF(params);
    const uint8_t *p = ASN1_STRING_get0_data(params);
    int plen = ASN1_STRING_length(params);
    RESULT_ENSURE(p != NULL && plen > 0, S2N_ERR_CERT_UNTRUSTED);

    DEFER_CLEANUP(RSA_PSS_PARAMS *pss = d2i_RSA_PSS_PARAMS(NULL, &p, plen), RSA_PSS_PARAMS_free_pointer);
    RESULT_ENSURE(pss != NULL, S2N_ERR_CERT_UNTRUSTED);

    /* Message digest: defaults to SHA-1 when absent (RFC 4055). */
    const EVP_MD *md = EVP_sha1();
    if (pss->hashAlgorithm != NULL) {
        md = EVP_get_digestbyobj(pss->hashAlgorithm->algorithm);
    }
    RESULT_ENSURE(md != NULL, S2N_ERR_CERT_UNTRUSTED);

    /* MGF1 digest: defaults to SHA-1 when absent; otherwise the mask-gen
     * algorithm must be id-mgf1 with its own hash AlgorithmIdentifier. */
    const EVP_MD *mgf1md = EVP_sha1();
    DEFER_CLEANUP(X509_ALGOR *mask_hash = NULL, X509_ALGOR_free_pointer);
    if (pss->maskGenAlgorithm != NULL) {
        RESULT_ENSURE(OBJ_obj2nid(pss->maskGenAlgorithm->algorithm) == NID_mgf1,
                S2N_ERR_CERT_UNTRUSTED);
        const ASN1_TYPE *mgf_param = pss->maskGenAlgorithm->parameter;
        RESULT_ENSURE(mgf_param != NULL && mgf_param->type == V_ASN1_SEQUENCE,
                S2N_ERR_CERT_UNTRUSTED);
        const ASN1_STRING *mgf_seq = mgf_param->value.sequence;
        RESULT_ENSURE_REF(mgf_seq);
        const uint8_t *mp = ASN1_STRING_get0_data(mgf_seq);
        int mplen = ASN1_STRING_length(mgf_seq);
        RESULT_ENSURE(mp != NULL && mplen > 0, S2N_ERR_CERT_UNTRUSTED);
        mask_hash = d2i_X509_ALGOR(NULL, &mp, mplen);
        RESULT_ENSURE(mask_hash != NULL, S2N_ERR_CERT_UNTRUSTED);
        mgf1md = EVP_get_digestbyobj(mask_hash->algorithm);
        RESULT_ENSURE(mgf1md != NULL, S2N_ERR_CERT_UNTRUSTED);
    }

    /* Both PSS digests are subject to the same weak-digest rejection. */
    RESULT_ENSURE(s2n_cert_verify_digest_nid_ok(EVP_MD_type(md)), S2N_ERR_CERT_UNTRUSTED);
    RESULT_ENSURE(s2n_cert_verify_digest_nid_ok(EVP_MD_type(mgf1md)), S2N_ERR_CERT_UNTRUSTED);

    int saltlen = 20;
    if (pss->saltLength != NULL) {
        saltlen = ASN1_INTEGER_get(pss->saltLength);
        RESULT_ENSURE(saltlen >= 0, S2N_ERR_CERT_UNTRUSTED);
    }
    /* Only trailer field 0xbc (encoded value 1) is valid per PKCS#1. */
    if (pss->trailerField != NULL) {
        RESULT_ENSURE(ASN1_INTEGER_get(pss->trailerField) == 1, S2N_ERR_CERT_UNTRUSTED);
    }

    EVP_PKEY_CTX *pctx = NULL;
    RESULT_GUARD_OSSL(EVP_DigestVerifyInit(ctx, &pctx, md, NULL, pkey), S2N_ERR_CERT_UNTRUSTED);
    RESULT_GUARD_OSSL(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING), S2N_ERR_CERT_UNTRUSTED);
    RESULT_GUARD_OSSL(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, saltlen), S2N_ERR_CERT_UNTRUSTED);
    RESULT_GUARD_OSSL(EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, mgf1md), S2N_ERR_CERT_UNTRUSTED);
    return S2N_RESULT_OK;
}

/* Configure `ctx` for verification from the signature AlgorithmIdentifier,
 * mirroring aws-lc's x509_digest_verify_init: OID -> (digest, pkey) NIDs,
 * key-type agreement, weak-digest rejection, and the RSA-PSS / Ed25519 special
 * cases. Uses only public APIs so it compiles against any CBS libcrypto. */
static S2N_RESULT s2n_cert_verify_ctx_init(EVP_MD_CTX *ctx, const X509_ALGOR *sigalg,
        EVP_PKEY *pkey)
{
    RESULT_ENSURE_REF(sigalg);
    RESULT_ENSURE_REF(sigalg->algorithm);
    RESULT_ENSURE_REF(pkey);

    int sigalg_nid = OBJ_obj2nid(sigalg->algorithm);
    int digest_nid = 0;
    int pkey_nid = 0;
    RESULT_ENSURE(OBJ_find_sigid_algs(sigalg_nid, &digest_nid, &pkey_nid) == 1,
            S2N_ERR_CERT_UNTRUSTED);

    /* The signature algorithm's public-key type must match the issuer key. The
     * one exception is RSASSA-PSS, whose sigid maps to NID_rsaEncryption while
     * the key may be an RSA or RSA-PSS EVP_PKEY. */
    int pkey_id = EVP_PKEY_id(pkey);
    bool key_type_ok = (pkey_nid == pkey_id)
            || (sigalg_nid == NID_rsassaPss && pkey_nid == NID_rsaEncryption
                    && (pkey_id == EVP_PKEY_RSA || pkey_id == EVP_PKEY_RSA_PSS));
    RESULT_ENSURE(key_type_ok, S2N_ERR_CERT_UNTRUSTED);

    /* NID_undef digest means the algorithm carries its own parameters. */
    if (digest_nid == NID_undef) {
        if (sigalg_nid == NID_rsassaPss) {
            RESULT_GUARD(s2n_cert_verify_pss_init(ctx, sigalg, pkey));
            return S2N_RESULT_OK;
        }
        if (sigalg_nid == NID_ED25519) {
            /* Ed25519: single-shot, no pre-hash, and no algorithm parameters. */
            RESULT_ENSURE(sigalg->parameter == NULL, S2N_ERR_CERT_UNTRUSTED);
            RESULT_GUARD_OSSL(EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey),
                    S2N_ERR_CERT_UNTRUSTED);
            return S2N_RESULT_OK;
        }
        RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
    }

    RESULT_ENSURE(s2n_cert_verify_digest_nid_ok(digest_nid), S2N_ERR_CERT_UNTRUSTED);

    /* RSA carries an explicit NULL parameter; ECDSA omits it. For
     * compatibility either form is tolerated for both, matching libcrypto. */
    if (sigalg->parameter != NULL && sigalg->parameter->type != V_ASN1_NULL) {
        RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
    }

    const EVP_MD *digest = EVP_get_digestbynid(digest_nid);
    RESULT_ENSURE(digest != NULL, S2N_ERR_CERT_UNTRUSTED);
    RESULT_GUARD_OSSL(EVP_DigestVerifyInit(ctx, NULL, digest, NULL, pkey),
            S2N_ERR_CERT_UNTRUSTED);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_cert_verify_signed(const struct s2n_blob *tbs,
        const struct s2n_blob *sig_alg, const struct s2n_blob *sig,
        struct s2n_pkey *issuer_key)
{
    RESULT_ENSURE_REF(tbs);
    RESULT_ENSURE_REF(tbs->data);
    RESULT_ENSURE_REF(sig_alg);
    RESULT_ENSURE_REF(sig_alg->data);
    RESULT_ENSURE_REF(sig);
    RESULT_ENSURE_REF(sig->data);
    RESULT_ENSURE_REF(issuer_key);
    RESULT_ENSURE_REF(issuer_key->pkey);

    /* Decode the AlgorithmIdentifier TLV into an X509_ALGOR so the digest and
     * padding parameters can be read exactly as the libcrypto verify layer
     * reads them. This is a small, bounded allocation on a cold path. */
    const uint8_t *alg_ptr = sig_alg->data;
    DEFER_CLEANUP(X509_ALGOR *algor = d2i_X509_ALGOR(NULL, &alg_ptr, sig_alg->size),
            X509_ALGOR_free_pointer);
    RESULT_ENSURE(algor != NULL, S2N_ERR_CERT_UNTRUSTED);
    RESULT_ENSURE(alg_ptr == sig_alg->data + sig_alg->size, S2N_ERR_CERT_UNTRUSTED);

    DEFER_CLEANUP(EVP_MD_CTX *ctx = EVP_MD_CTX_new(), EVP_MD_CTX_free_pointer);
    RESULT_ENSURE(ctx != NULL, S2N_ERR_CERT_UNTRUSTED);

    RESULT_GUARD(s2n_cert_verify_ctx_init(ctx, algor, issuer_key->pkey));

    /* Single-shot verification over the borrowed TBS TLV. EVP_DigestVerify
     * handles both streaming (RSA/ECDSA) and one-shot (Ed25519) algorithms. */
    RESULT_GUARD_OSSL(EVP_DigestVerify(ctx, sig->data, sig->size, tbs->data, tbs->size),
            S2N_ERR_CERT_UNTRUSTED);
    return S2N_RESULT_OK;
}

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */
