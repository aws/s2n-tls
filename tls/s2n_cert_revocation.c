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

#include "tls/s2n_cert_revocation.h"

#include "tls/s2n_cert_path.h"
#include "utils/s2n_safety.h"

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    #include <openssl/bytestring.h>
    #include <openssl/digest.h>
    #include <openssl/evp.h>
    #include <openssl/sha.h>
    #include <string.h>

    #include "crypto/s2n_pkey.h"

DEFINE_POINTER_CLEANUP_FUNC(EVP_PKEY *, EVP_PKEY_free);

/* Materialize an s2n_pkey from a SubjectPublicKeyInfo TLV span. Private copy of
 * the static helper in s2n_cert_path.c (not exported): d2i_PUBKEY on the SPKI
 * bytes, then s2n_pkey type dispatch. The caller owns the result and must free
 * it with s2n_pkey_free. */
static S2N_RESULT s2n_cert_path_pkey_from_spki(const struct s2n_blob *spki,
        struct s2n_pkey *pkey_out)
{
    RESULT_ENSURE_REF(spki);
    RESULT_ENSURE_REF(spki->data);
    RESULT_ENSURE_REF(pkey_out);

    const uint8_t *p = spki->data;
    DEFER_CLEANUP(EVP_PKEY *evp_pkey = d2i_PUBKEY(NULL, &p, (long) spki->size),
            EVP_PKEY_free_pointer);
    RESULT_ENSURE(evp_pkey != NULL, S2N_ERR_CERT_UNTRUSTED);
    /* d2i_PUBKEY must consume the entire SPKI TLV. */
    RESULT_ENSURE(p == spki->data + spki->size, S2N_ERR_CERT_UNTRUSTED);

    s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
    RESULT_GUARD(s2n_pkey_get_type(evp_pkey, &pkey_type));
    RESULT_GUARD(s2n_pkey_setup_for_type(pkey_out, pkey_type));

    pkey_out->pkey = evp_pkey;
    ZERO_TO_DISABLE_DEFER_CLEANUP(evp_pkey);
    return S2N_RESULT_OK;
}

/* Strict DER, identical rules to the parser: the CBS DER functions
 * reject non-minimal long-form lengths and indefinite lengths and can never
 * read past the enclosing buffer, and every enclosing element must be fully
 * consumed. Both validators own nothing; no allocation happens on the parse
 * paths, so failure needs no cleanup. */

/* Default nextUpdate horizon when an OCSP SingleResponse omits nextUpdate,
 * matching s2n_x509_validator's DEFAULT_OCSP_NEXT_UPDATE_PERIOD. */
    #define S2N_OCSP_DEFAULT_NEXT_UPDATE_PERIOD 3600

/* SHA-1 (id-sha1) OID contents: 1.3.14.3.2.26. */
static const uint8_t s2n_oid_sha1[] = { 0x2b, 0x0e, 0x03, 0x02, 0x1a };
/* id-pkix-ocsp-basic OID contents: 1.3.6.1.5.5.7.48.1.1. */
static const uint8_t s2n_oid_ocsp_basic[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01 };
/* id-kp-OCSPSigning OID contents: 1.3.6.1.5.5.7.3.9. */
static const uint8_t s2n_oid_ocsp_signing[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09 };

/* Capture a CBS as a borrowed s2n_blob span, proving it is an exact in-bounds
 * sub-range of `base`. Mirrors the parser's provenance check. */
static S2N_RESULT s2n_revocation_capture(const struct s2n_blob *base, const CBS *cbs,
        struct s2n_blob *span, int S2N_ERR_code)
{
    RESULT_ENSURE_REF(base);
    RESULT_ENSURE_REF(cbs);
    RESULT_ENSURE_REF(span);

    const uint8_t *data = CBS_data(cbs);
    size_t len = CBS_len(cbs);
    RESULT_ENSURE(data != NULL, S2N_ERR_code);
    RESULT_ENSURE(data >= base->data, S2N_ERR_code);
    RESULT_ENSURE(len <= base->size, S2N_ERR_code);
    size_t offset = (size_t) (data - base->data);
    RESULT_ENSURE(offset <= base->size - len, S2N_ERR_code);

    RESULT_GUARD_POSIX(s2n_blob_init(span, base->data + offset, (uint32_t) len));
    return S2N_RESULT_OK;
}

static bool s2n_revocation_oid_eq(const CBS *oid, const uint8_t *ref, size_t ref_len)
{
    return CBS_len(oid) == ref_len && memcmp(CBS_data(oid), ref, ref_len) == 0;
}

/* Read the signature BIT STRING contents, enforcing the unused-bits octet == 0
 * (the same signature-bypass class the parser guards against). */
static S2N_RESULT s2n_revocation_get_sig_bits(CBS *parent, const struct s2n_blob *base,
        struct s2n_blob *sig_out, int S2N_ERR_code)
{
    CBS sig_bits = { 0 };
    RESULT_ENSURE(CBS_get_asn1(parent, &sig_bits, CBS_ASN1_BITSTRING), S2N_ERR_code);
    uint8_t unused_bits = 0xff;
    RESULT_ENSURE(CBS_get_u8(&sig_bits, &unused_bits), S2N_ERR_code);
    RESULT_ENSURE(unused_bits == 0x00, S2N_ERR_code);
    RESULT_ENSURE(CBS_len(&sig_bits) > 0, S2N_ERR_code);
    RESULT_GUARD(s2n_revocation_capture(base, &sig_bits, sig_out, S2N_ERR_code));
    return S2N_RESULT_OK;
}

/* Extract the subjectPublicKey BIT STRING contents (key bits WITHOUT the
 * unused-bits octet) from a SubjectPublicKeyInfo TLV span. This is exactly the
 * byte range OCSP's issuerKeyHash is computed over (X509_get0_pubkey_bitstr →
 * ASN1_BIT_STRING data/length, tag/length and unused-bits octet excluded). */
static S2N_RESULT s2n_revocation_spki_key_bits(const struct s2n_blob *spki, CBS *key_bits)
{
    RESULT_ENSURE_REF(spki);
    RESULT_ENSURE_REF(spki->data);

    CBS tlv = { 0 };
    CBS_init(&tlv, spki->data, spki->size);
    CBS spki_seq = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&tlv, &spki_seq, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_UNTRUSTED);

    CBS alg = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&spki_seq, &alg, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_UNTRUSTED);

    CBS bits = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&spki_seq, &bits, CBS_ASN1_BITSTRING), S2N_ERR_CERT_UNTRUSTED);
    uint8_t unused = 0xff;
    RESULT_ENSURE(CBS_get_u8(&bits, &unused), S2N_ERR_CERT_UNTRUSTED);
    RESULT_ENSURE(unused == 0x00, S2N_ERR_CERT_UNTRUSTED);
    *key_bits = bits;
    return S2N_RESULT_OK;
}

/* SHA-1 digest of a byte range into `md` (20 bytes). */
static S2N_RESULT s2n_revocation_sha1(const uint8_t *data, size_t len, uint8_t *md)
{
    unsigned int md_len = 0;
    RESULT_GUARD_OSSL(EVP_Digest(data, len, md, &md_len, EVP_sha1(), NULL),
            S2N_ERR_CERT_UNTRUSTED);
    RESULT_ENSURE(md_len == SHA_DIGEST_LENGTH, S2N_ERR_CERT_UNTRUSTED);
    return S2N_RESULT_OK;
}

/* --- CRL_Validator -------------------------------------------------------- */

S2N_RESULT s2n_crl_view_parse(struct s2n_crl_view *view, struct s2n_blob *crl_der)
{
    RESULT_ENSURE_REF(view);
    RESULT_ENSURE_REF(crl_der);
    RESULT_ENSURE_REF(crl_der->data);

    *view = (struct s2n_crl_view){ 0 };

    CBS input = { 0 };
    CBS_init(&input, crl_der->data, crl_der->size);

    /* CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }
     * Exactly one CertificateList TLV, nothing trailing. */
    CBS raw = { 0 };
    RESULT_ENSURE(CBS_get_asn1_element(&input, &raw, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_len(&input) == 0, S2N_ERR_CERT_INVALID);
    RESULT_GUARD(s2n_revocation_capture(crl_der, &raw, &view->raw, S2N_ERR_CERT_INVALID));

    CBS top = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&raw, &top, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);

    /* tbsCertList captured WITH header: the signature covers the full TLV. */
    CBS tbs = { 0 };
    RESULT_ENSURE(CBS_get_asn1_element(&top, &tbs, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);
    RESULT_GUARD(s2n_revocation_capture(crl_der, &tbs, &view->tbs, S2N_ERR_CERT_INVALID));

    CBS sig_alg = { 0 };
    RESULT_ENSURE(CBS_get_asn1_element(&top, &sig_alg, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);
    RESULT_GUARD(s2n_revocation_capture(crl_der, &sig_alg, &view->sig_alg, S2N_ERR_CERT_INVALID));

    RESULT_GUARD(s2n_revocation_get_sig_bits(&top, crl_der, &view->sig, S2N_ERR_CERT_INVALID));
    RESULT_ENSURE(CBS_len(&top) == 0, S2N_ERR_CERT_INVALID);

    /* TBSCertList ::= SEQUENCE {
     *   version           Version OPTIONAL,   -- v2
     *   signature         AlgorithmIdentifier,
     *   issuer            Name,
     *   thisUpdate        Time,
     *   nextUpdate        Time OPTIONAL,
     *   revokedCertificates SEQUENCE OF SEQUENCE { ... } OPTIONAL,
     *   crlExtensions [0] EXPLICIT Extensions OPTIONAL } */
    CBS tbs_body = tbs;
    CBS tbs_inner = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&tbs_body, &tbs_inner, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);

    /* Optional version INTEGER (present when v2). */
    if (CBS_peek_asn1_tag(&tbs_inner, CBS_ASN1_INTEGER)) {
        CBS version = { 0 };
        RESULT_ENSURE(CBS_get_asn1(&tbs_inner, &version, CBS_ASN1_INTEGER), S2N_ERR_CERT_INVALID);
    }

    /* inner signature AlgorithmIdentifier (must equal the outer). */
    CBS inner_sig_alg = { 0 };
    RESULT_ENSURE(CBS_get_asn1_element(&tbs_inner, &inner_sig_alg, CBS_ASN1_SEQUENCE),
            S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_len(&inner_sig_alg) == view->sig_alg.size, S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(memcmp(CBS_data(&inner_sig_alg), view->sig_alg.data, view->sig_alg.size) == 0,
            S2N_ERR_CERT_INVALID);

    CBS issuer = { 0 };
    RESULT_ENSURE(CBS_get_asn1_element(&tbs_inner, &issuer, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);
    RESULT_GUARD(s2n_revocation_capture(crl_der, &issuer, &view->issuer, S2N_ERR_CERT_INVALID));

    /* thisUpdate Time (UTCTime or GeneralizedTime). */
    CBS this_update = { 0 };
    CBS_ASN1_TAG this_tag = 0;
    RESULT_ENSURE(CBS_get_any_asn1_element(&tbs_inner, &this_update, &this_tag, NULL),
            S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(this_tag == CBS_ASN1_UTCTIME || this_tag == CBS_ASN1_GENERALIZEDTIME,
            S2N_ERR_CERT_INVALID);
    RESULT_GUARD(s2n_revocation_capture(crl_der, &this_update, &view->this_update, S2N_ERR_CERT_INVALID));

    /* nextUpdate Time OPTIONAL. */
    if (CBS_peek_asn1_tag(&tbs_inner, CBS_ASN1_UTCTIME)
            || CBS_peek_asn1_tag(&tbs_inner, CBS_ASN1_GENERALIZEDTIME)) {
        CBS next_update = { 0 };
        CBS_ASN1_TAG next_tag = 0;
        RESULT_ENSURE(CBS_get_any_asn1_element(&tbs_inner, &next_update, &next_tag, NULL),
                S2N_ERR_CERT_INVALID);
        RESULT_GUARD(s2n_revocation_capture(crl_der, &next_update, &view->next_update,
                S2N_ERR_CERT_INVALID));
        view->has_next_update = true;
    }

    /* revokedCertificates SEQUENCE OF ... OPTIONAL. */
    if (CBS_peek_asn1_tag(&tbs_inner, CBS_ASN1_SEQUENCE)) {
        CBS revoked = { 0 };
        RESULT_ENSURE(CBS_get_asn1(&tbs_inner, &revoked, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);
        RESULT_GUARD(s2n_revocation_capture(crl_der, &revoked, &view->revoked, S2N_ERR_CERT_INVALID));
    }

    /* crlExtensions [0] and any remaining fields are intentionally not walked:
     * delta-CRL / distribution-point / reason-code handling is out of scope
     * (documented in the header), matching today's effective CRL behavior. */
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_crl_verify_signature(const struct s2n_crl_view *view, struct s2n_pkey *issuer_key)
{
    RESULT_ENSURE_REF(view);
    /* Reuse the shared signature-verify helper over the tbsCertList
     * TLV. A verification failure maps to S2N_ERR_CRL_SIGNATURE. */
    RESULT_ENSURE(s2n_result_is_ok(
                          s2n_cert_verify_signed(&view->tbs, &view->sig_alg, &view->sig, issuer_key)),
            S2N_ERR_CRL_SIGNATURE);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_crl_check_times(const struct s2n_crl_view *view, uint64_t verification_time)
{
    RESULT_ENSURE_REF(view);

    /* thisUpdate must be at or before the verification time, matching
     * s2n_crl_validate_active (X509_cmp_time this_update vs now). */
    uint64_t this_update = 0;
    RESULT_ENSURE(s2n_result_is_ok(s2n_cert_parse_time(&view->this_update, &this_update)),
            S2N_ERR_CRL_INVALID_THIS_UPDATE);
    RESULT_ENSURE(this_update <= verification_time, S2N_ERR_CRL_NOT_YET_VALID);

    /* nextUpdate, when present, must be at or after the verification time,
     * matching s2n_crl_validate_not_expired. Absent nextUpdate never expires. */
    if (view->has_next_update) {
        uint64_t next_update = 0;
        RESULT_ENSURE(s2n_result_is_ok(s2n_cert_parse_time(&view->next_update, &next_update)),
                S2N_ERR_CRL_INVALID_NEXT_UPDATE);
        RESULT_ENSURE(next_update >= verification_time, S2N_ERR_CRL_EXPIRED);
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_crl_check_serial(const struct s2n_crl_view *view, const struct s2n_blob *serial)
{
    RESULT_ENSURE_REF(view);
    RESULT_ENSURE_REF(serial);
    RESULT_ENSURE_REF(serial->data);

    /* No revokedCertificates list means nothing is revoked. */
    if (view->revoked.data == NULL || view->revoked.size == 0) {
        return S2N_RESULT_OK;
    }

    CBS revoked = { 0 };
    CBS_init(&revoked, view->revoked.data, view->revoked.size);

    /* revokedCertificates ::= SEQUENCE OF SEQUENCE {
     *   userCertificate CertificateSerialNumber (INTEGER),
     *   revocationDate  Time,
     *   crlEntryExtensions Extensions OPTIONAL } */
    uint64_t entries = 0;
    while (CBS_len(&revoked) > 0) {
        entries++;
        RESULT_ENSURE(entries <= S2N_CRL_MAX_REVOKED_ENTRIES, S2N_ERR_CERT_INVALID);

        CBS entry = { 0 };
        RESULT_ENSURE(CBS_get_asn1(&revoked, &entry, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);

        CBS entry_serial = { 0 };
        RESULT_ENSURE(CBS_get_asn1(&entry, &entry_serial, CBS_ASN1_INTEGER), S2N_ERR_CERT_INVALID);

        /* Serial comparison is byte-for-byte over the INTEGER contents; both
         * come from minimal-form DER so this matches libcrypto's serial match.
         * Reason codes and entry extensions are not interpreted (any listed
         * serial is treated as revoked, matching the current path). */
        if (CBS_len(&entry_serial) == serial->size
                && memcmp(CBS_data(&entry_serial), serial->data, serial->size) == 0) {
            RESULT_BAIL(S2N_ERR_CERT_REVOKED);
        }
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_crl_validate(struct s2n_blob *crl_der, struct s2n_pkey *issuer_key,
        const struct s2n_blob *serial, uint64_t verification_time)
{
    struct s2n_crl_view view = { 0 };
    RESULT_GUARD(s2n_crl_view_parse(&view, crl_der));
    RESULT_GUARD(s2n_crl_verify_signature(&view, issuer_key));
    RESULT_GUARD(s2n_crl_check_times(&view, verification_time));
    RESULT_GUARD(s2n_crl_check_serial(&view, serial));
    return S2N_RESULT_OK;
}

/* --- OCSP_Validator ------------------------------------------------------- */

S2N_RESULT s2n_ocsp_response_parse(struct s2n_ocsp_response_view *view, struct s2n_blob *ocsp_der)
{
    RESULT_ENSURE_REF(view);
    RESULT_ENSURE_REF(ocsp_der);
    RESULT_ENSURE_REF(ocsp_der->data);

    *view = (struct s2n_ocsp_response_view){ 0 };

    CBS input = { 0 };
    CBS_init(&input, ocsp_der->data, ocsp_der->size);

    /* OCSPResponse ::= SEQUENCE { responseStatus OCSPResponseStatus,
     *                             responseBytes [0] EXPLICIT ResponseBytes OPTIONAL } */
    CBS response = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&input, &response, CBS_ASN1_SEQUENCE), S2N_ERR_INVALID_OCSP_RESPONSE);
    RESULT_ENSURE(CBS_len(&input) == 0, S2N_ERR_INVALID_OCSP_RESPONSE);

    /* responseStatus ENUMERATED: only "successful" (0) is accepted. A
     * non-successful status matches the current path's S2N_ERR_CERT_UNTRUSTED. */
    CBS status = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&response, &status, CBS_ASN1_ENUMERATED), S2N_ERR_INVALID_OCSP_RESPONSE);
    uint8_t status_val = 0xff;
    RESULT_ENSURE(CBS_get_u8(&status, &status_val), S2N_ERR_INVALID_OCSP_RESPONSE);
    RESULT_ENSURE(CBS_len(&status) == 0, S2N_ERR_INVALID_OCSP_RESPONSE);
    RESULT_ENSURE(status_val == 0 /* successful */, S2N_ERR_CERT_UNTRUSTED);

    /* responseBytes [0] EXPLICIT SEQUENCE { responseType OID, response OCTET STRING } */
    CBS response_bytes = { 0 };
    int present = 0;
    RESULT_ENSURE(CBS_get_optional_asn1(&response, &response_bytes, &present,
                          CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0),
            S2N_ERR_INVALID_OCSP_RESPONSE);
    RESULT_ENSURE(present, S2N_ERR_INVALID_OCSP_RESPONSE);

    CBS resp_bytes_seq = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&response_bytes, &resp_bytes_seq, CBS_ASN1_SEQUENCE),
            S2N_ERR_INVALID_OCSP_RESPONSE);

    CBS response_type = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&resp_bytes_seq, &response_type, CBS_ASN1_OBJECT),
            S2N_ERR_INVALID_OCSP_RESPONSE);
    RESULT_ENSURE(s2n_revocation_oid_eq(&response_type, s2n_oid_ocsp_basic, sizeof(s2n_oid_ocsp_basic)),
            S2N_ERR_INVALID_OCSP_RESPONSE);

    CBS basic_octets = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&resp_bytes_seq, &basic_octets, CBS_ASN1_OCTETSTRING),
            S2N_ERR_INVALID_OCSP_RESPONSE);

    /* The OCTET STRING contents are the DER BasicOCSPResponse. Spans below
     * borrow from ocsp_der, which contains those bytes. */
    struct s2n_blob basic_blob = { 0 };
    RESULT_GUARD(s2n_revocation_capture(ocsp_der, &basic_octets, &basic_blob, S2N_ERR_INVALID_OCSP_RESPONSE));

    /* BasicOCSPResponse ::= SEQUENCE { tbsResponseData ResponseData,
     *   signatureAlgorithm AlgorithmIdentifier, signature BIT STRING,
     *   certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL } */
    CBS basic = { 0 };
    CBS_init(&basic, basic_blob.data, basic_blob.size);
    CBS basic_seq = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&basic, &basic_seq, CBS_ASN1_SEQUENCE), S2N_ERR_INVALID_OCSP_RESPONSE);
    RESULT_ENSURE(CBS_len(&basic) == 0, S2N_ERR_INVALID_OCSP_RESPONSE);

    /* tbsResponseData captured WITH header (signature input). */
    CBS tbs = { 0 };
    RESULT_ENSURE(CBS_get_asn1_element(&basic_seq, &tbs, CBS_ASN1_SEQUENCE), S2N_ERR_INVALID_OCSP_RESPONSE);
    RESULT_GUARD(s2n_revocation_capture(ocsp_der, &tbs, &view->tbs_response_data, S2N_ERR_INVALID_OCSP_RESPONSE));

    CBS sig_alg = { 0 };
    RESULT_ENSURE(CBS_get_asn1_element(&basic_seq, &sig_alg, CBS_ASN1_SEQUENCE), S2N_ERR_INVALID_OCSP_RESPONSE);
    RESULT_GUARD(s2n_revocation_capture(ocsp_der, &sig_alg, &view->sig_alg, S2N_ERR_INVALID_OCSP_RESPONSE));

    RESULT_GUARD(s2n_revocation_get_sig_bits(&basic_seq, ocsp_der, &view->sig, S2N_ERR_INVALID_OCSP_RESPONSE));

    /* certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL. */
    CBS certs_wrapper = { 0 };
    int certs_present = 0;
    RESULT_ENSURE(CBS_get_optional_asn1(&basic_seq, &certs_wrapper, &certs_present,
                          CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0),
            S2N_ERR_INVALID_OCSP_RESPONSE);
    if (certs_present) {
        CBS certs = { 0 };
        RESULT_ENSURE(CBS_get_asn1(&certs_wrapper, &certs, CBS_ASN1_SEQUENCE), S2N_ERR_INVALID_OCSP_RESPONSE);
        RESULT_GUARD(s2n_revocation_capture(ocsp_der, &certs, &view->certs, S2N_ERR_INVALID_OCSP_RESPONSE));
    }

    /* ResponseData ::= SEQUENCE { version [0] EXPLICIT DEFAULT v1,
     *   responderID ResponderID, producedAt GeneralizedTime,
     *   responses SEQUENCE OF SingleResponse, responseExtensions [1] ... OPTIONAL } */
    CBS rd_body = { 0 };
    CBS_init(&rd_body, view->tbs_response_data.data, view->tbs_response_data.size);
    CBS rd = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&rd_body, &rd, CBS_ASN1_SEQUENCE), S2N_ERR_INVALID_OCSP_RESPONSE);

    /* version [0] EXPLICIT INTEGER DEFAULT v1. */
    CBS version_wrapper = { 0 };
    int version_present = 0;
    RESULT_ENSURE(CBS_get_optional_asn1(&rd, &version_wrapper, &version_present,
                          CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0),
            S2N_ERR_INVALID_OCSP_RESPONSE);

    /* responderID ::= CHOICE { byName [1] EXPLICIT Name, byKey [2] EXPLICIT KeyHash }. */
    if (CBS_peek_asn1_tag(&rd, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 1)) {
        CBS by_name = { 0 };
        RESULT_ENSURE(CBS_get_asn1(&rd, &by_name, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 1),
                S2N_ERR_INVALID_OCSP_RESPONSE);
        CBS name = { 0 };
        RESULT_ENSURE(CBS_get_asn1_element(&by_name, &name, CBS_ASN1_SEQUENCE), S2N_ERR_INVALID_OCSP_RESPONSE);
        RESULT_GUARD(s2n_revocation_capture(ocsp_der, &name, &view->responder_name, S2N_ERR_INVALID_OCSP_RESPONSE));
    } else if (CBS_peek_asn1_tag(&rd, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 2)) {
        CBS by_key = { 0 };
        RESULT_ENSURE(CBS_get_asn1(&rd, &by_key, CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 2),
                S2N_ERR_INVALID_OCSP_RESPONSE);
        CBS key_hash = { 0 };
        RESULT_ENSURE(CBS_get_asn1(&by_key, &key_hash, CBS_ASN1_OCTETSTRING), S2N_ERR_INVALID_OCSP_RESPONSE);
        RESULT_GUARD(s2n_revocation_capture(ocsp_der, &key_hash, &view->responder_key_hash,
                S2N_ERR_INVALID_OCSP_RESPONSE));
    } else {
        RESULT_BAIL(S2N_ERR_INVALID_OCSP_RESPONSE);
    }

    /* producedAt GeneralizedTime (parsed for completeness; freshness is driven
     * by each SingleResponse's thisUpdate/nextUpdate, matching the current path). */
    CBS produced_at = { 0 };
    CBS_ASN1_TAG produced_tag = 0;
    RESULT_ENSURE(CBS_get_any_asn1_element(&rd, &produced_at, &produced_tag, NULL),
            S2N_ERR_INVALID_OCSP_RESPONSE);
    RESULT_ENSURE(produced_tag == CBS_ASN1_GENERALIZEDTIME, S2N_ERR_INVALID_OCSP_RESPONSE);
    RESULT_GUARD(s2n_revocation_capture(ocsp_der, &produced_at, &view->produced_at, S2N_ERR_INVALID_OCSP_RESPONSE));

    /* responses SEQUENCE OF SingleResponse. */
    CBS responses = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&rd, &responses, CBS_ASN1_SEQUENCE), S2N_ERR_INVALID_OCSP_RESPONSE);
    RESULT_GUARD(s2n_revocation_capture(ocsp_der, &responses, &view->responses, S2N_ERR_INVALID_OCSP_RESPONSE));

    return S2N_RESULT_OK;
}

/* Check whether a certificate's EKU span contains the id-kp-OCSPSigning OID. */
static S2N_RESULT s2n_ocsp_eku_has_signing(const struct s2n_blob *eku, bool *found)
{
    RESULT_ENSURE_REF(found);
    *found = false;
    if (eku == NULL || eku->data == NULL || eku->size == 0) {
        return S2N_RESULT_OK;
    }

    CBS cbs = { 0 };
    CBS_init(&cbs, eku->data, eku->size);
    CBS seq = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&cbs, &seq, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_len(&cbs) == 0, S2N_ERR_CERT_INVALID);
    while (CBS_len(&seq) > 0) {
        CBS oid = { 0 };
        RESULT_ENSURE(CBS_get_asn1(&seq, &oid, CBS_ASN1_OBJECT), S2N_ERR_CERT_INVALID);
        if (s2n_revocation_oid_eq(&oid, s2n_oid_ocsp_signing, sizeof(s2n_oid_ocsp_signing))) {
            *found = true;
            return S2N_RESULT_OK;
        }
    }
    return S2N_RESULT_OK;
}

/* Does the responderID identify `candidate`? byName matches candidate.subject
 * via the RFC 5280 name comparator; byKey matches SHA-1 of candidate's key
 * bits, exactly as OCSP_RESPID is derived (RFC 6960 §4.2.1). */
static S2N_RESULT s2n_ocsp_responder_id_matches(const struct s2n_ocsp_response_view *view,
        const struct s2n_cert_span_view *candidate, bool *matches)
{
    RESULT_ENSURE_REF(matches);
    *matches = false;

    if (view->responder_name.data != NULL) {
        RESULT_GUARD(s2n_cert_name_cmp(&view->responder_name, &candidate->subject, matches));
        return S2N_RESULT_OK;
    }

    if (view->responder_key_hash.data != NULL) {
        RESULT_ENSURE(view->responder_key_hash.size == SHA_DIGEST_LENGTH, S2N_ERR_INVALID_OCSP_RESPONSE);
        CBS key_bits = { 0 };
        RESULT_GUARD(s2n_revocation_spki_key_bits(&candidate->spki, &key_bits));
        uint8_t md[SHA_DIGEST_LENGTH] = { 0 };
        RESULT_GUARD(s2n_revocation_sha1(CBS_data(&key_bits), CBS_len(&key_bits), md));
        *matches = (memcmp(md, view->responder_key_hash.data, SHA_DIGEST_LENGTH) == 0);
        return S2N_RESULT_OK;
    }

    return S2N_RESULT_OK;
}

/* Verify the responder signature over tbsResponseData. Mirrors OCSP_basic_verify's
 * signer selection: either the certificate's issuer signs directly (no EKU
 * requirement), or a delegated responder cert carried in certs[] signs, in
 * which case it must be issued by `issuer` and carry id-kp-OCSPSigning. */
static S2N_RESULT s2n_ocsp_verify_responder(const struct s2n_ocsp_response_view *view,
        const struct s2n_cert_span_view *issuer, uint64_t verification_time)
{
    RESULT_ENSURE_REF(view);
    RESULT_ENSURE_REF(issuer);

    /* Case A: the issuer signs the response directly. */
    bool issuer_is_responder = false;
    RESULT_GUARD(s2n_ocsp_responder_id_matches(view, issuer, &issuer_is_responder));
    if (issuer_is_responder) {
        DEFER_CLEANUP(struct s2n_pkey issuer_key = { 0 }, s2n_pkey_free);
        RESULT_GUARD(s2n_cert_path_pkey_from_spki(&issuer->spki, &issuer_key));
        RESULT_ENSURE(s2n_result_is_ok(s2n_cert_verify_signed(&view->tbs_response_data,
                              &view->sig_alg, &view->sig, &issuer_key)),
                S2N_ERR_CERT_UNTRUSTED);
        return S2N_RESULT_OK;
    }

    /* Case B: a delegated responder certificate in certs[]. */
    RESULT_ENSURE(view->certs.data != NULL && view->certs.size > 0, S2N_ERR_CERT_UNTRUSTED);

    CBS certs = { 0 };
    CBS_init(&certs, view->certs.data, view->certs.size);

    uint32_t cert_count = 0;
    while (CBS_len(&certs) > 0) {
        cert_count++;
        RESULT_ENSURE(cert_count <= S2N_OCSP_MAX_CERTS, S2N_ERR_INVALID_OCSP_RESPONSE);

        CBS cert_element = { 0 };
        RESULT_ENSURE(CBS_get_asn1_element(&certs, &cert_element, CBS_ASN1_SEQUENCE),
                S2N_ERR_INVALID_OCSP_RESPONSE);

        struct s2n_blob cert_der = { 0 };
        RESULT_GUARD(s2n_revocation_capture(&view->certs, &cert_element, &cert_der,
                S2N_ERR_INVALID_OCSP_RESPONSE));

        struct s2n_cert_span_view responder = { 0 };
        if (s2n_result_is_error(s2n_cert_span_view_parse(&responder, &cert_der))) {
            continue;
        }

        /* The responderID must identify this candidate. */
        bool id_matches = false;
        RESULT_GUARD(s2n_ocsp_responder_id_matches(view, &responder, &id_matches));
        if (!id_matches) {
            continue;
        }

        /* Delegated responders MUST carry id-kp-OCSPSigning. */
        bool has_ocsp_signing = false;
        RESULT_GUARD(s2n_ocsp_eku_has_signing(&responder.eku, &has_ocsp_signing));
        RESULT_ENSURE(has_ocsp_signing, S2N_ERR_CERT_UNTRUSTED);

        /* The responder cert must be issued directly by the certificate's
         * issuer: name match + signature verify against the issuer key. */
        bool names_match = false;
        RESULT_GUARD(s2n_cert_name_cmp(&responder.issuer, &issuer->subject, &names_match));
        RESULT_ENSURE(names_match, S2N_ERR_CERT_UNTRUSTED);

        DEFER_CLEANUP(struct s2n_pkey issuer_key = { 0 }, s2n_pkey_free);
        RESULT_GUARD(s2n_cert_path_pkey_from_spki(&issuer->spki, &issuer_key));
        RESULT_ENSURE(s2n_result_is_ok(s2n_cert_verify_signed(&responder.tbs,
                              &responder.outer_sig_alg, &responder.sig, &issuer_key)),
                S2N_ERR_CERT_UNTRUSTED);

        /* Responder cert must be within its validity window. */
        RESULT_ENSURE(verification_time >= responder.not_before, S2N_ERR_CERT_UNTRUSTED);
        RESULT_ENSURE(verification_time <= responder.not_after, S2N_ERR_CERT_UNTRUSTED);

        /* Finally verify the response signature with the responder key. */
        DEFER_CLEANUP(struct s2n_pkey responder_key = { 0 }, s2n_pkey_free);
        RESULT_GUARD(s2n_cert_path_pkey_from_spki(&responder.spki, &responder_key));
        RESULT_ENSURE(s2n_result_is_ok(s2n_cert_verify_signed(&view->tbs_response_data,
                              &view->sig_alg, &view->sig, &responder_key)),
                S2N_ERR_CERT_UNTRUSTED);
        return S2N_RESULT_OK;
    }

    RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
}

/* Compute the SHA-1 CertID identifiers for the validated leaf/issuer pair and
 * compare against a SingleResponse's CertID. Mirrors OCSP_cert_to_id +
 * OCSP_id_cmp with EVP_sha1(). */
static S2N_RESULT s2n_ocsp_certid_matches(CBS *cert_id,
        const struct s2n_cert_span_view *leaf, const struct s2n_cert_span_view *issuer,
        bool *matches)
{
    RESULT_ENSURE_REF(matches);
    *matches = false;

    /* CertID ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier,
     *   issuerNameHash OCTET STRING, issuerKeyHash OCTET STRING,
     *   serialNumber CertificateSerialNumber } */
    CBS hash_alg = { 0 };
    RESULT_ENSURE(CBS_get_asn1(cert_id, &hash_alg, CBS_ASN1_SEQUENCE), S2N_ERR_INVALID_OCSP_RESPONSE);
    CBS hash_oid = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&hash_alg, &hash_oid, CBS_ASN1_OBJECT), S2N_ERR_INVALID_OCSP_RESPONSE);
    /* We only build SHA-1 comparison CertIDs, matching the current path; a
     * non-SHA-1 CertID cannot match and is simply skipped. */
    if (!s2n_revocation_oid_eq(&hash_oid, s2n_oid_sha1, sizeof(s2n_oid_sha1))) {
        return S2N_RESULT_OK;
    }

    CBS issuer_name_hash = { 0 };
    RESULT_ENSURE(CBS_get_asn1(cert_id, &issuer_name_hash, CBS_ASN1_OCTETSTRING), S2N_ERR_INVALID_OCSP_RESPONSE);
    CBS issuer_key_hash = { 0 };
    RESULT_ENSURE(CBS_get_asn1(cert_id, &issuer_key_hash, CBS_ASN1_OCTETSTRING), S2N_ERR_INVALID_OCSP_RESPONSE);
    CBS serial = { 0 };
    RESULT_ENSURE(CBS_get_asn1(cert_id, &serial, CBS_ASN1_INTEGER), S2N_ERR_INVALID_OCSP_RESPONSE);

    /* issuerNameHash = SHA1(issuer Name TLV), i.e. SHA1 of the leaf's issuer
     * name (== the issuer's subject name). Use the leaf's issuer span. */
    if (CBS_len(&issuer_name_hash) != SHA_DIGEST_LENGTH) {
        return S2N_RESULT_OK;
    }
    uint8_t name_md[SHA_DIGEST_LENGTH] = { 0 };
    RESULT_GUARD(s2n_revocation_sha1(leaf->issuer.data, leaf->issuer.size, name_md));
    if (memcmp(name_md, CBS_data(&issuer_name_hash), SHA_DIGEST_LENGTH) != 0) {
        return S2N_RESULT_OK;
    }

    /* issuerKeyHash = SHA1(issuer subjectPublicKey bits, no unused-bits octet). */
    if (CBS_len(&issuer_key_hash) != SHA_DIGEST_LENGTH) {
        return S2N_RESULT_OK;
    }
    CBS key_bits = { 0 };
    RESULT_GUARD(s2n_revocation_spki_key_bits(&issuer->spki, &key_bits));
    uint8_t key_md[SHA_DIGEST_LENGTH] = { 0 };
    RESULT_GUARD(s2n_revocation_sha1(CBS_data(&key_bits), CBS_len(&key_bits), key_md));
    if (memcmp(key_md, CBS_data(&issuer_key_hash), SHA_DIGEST_LENGTH) != 0) {
        return S2N_RESULT_OK;
    }

    /* serialNumber: byte-for-byte over the INTEGER contents. */
    if (CBS_len(&serial) != leaf->serial.size
            || memcmp(CBS_data(&serial), leaf->serial.data, leaf->serial.size) != 0) {
        return S2N_RESULT_OK;
    }

    *matches = true;
    return S2N_RESULT_OK;
}

/* Check the freshness window of a matched SingleResponse, mirroring the current
 * OCSP path's thisUpdate/nextUpdate comparisons. */
static S2N_RESULT s2n_ocsp_check_freshness(const struct s2n_blob *this_update_tlv,
        const struct s2n_blob *next_update_tlv, uint64_t verification_time)
{
    uint64_t this_update = 0;
    RESULT_ENSURE(s2n_result_is_ok(s2n_cert_parse_time(this_update_tlv, &this_update)),
            S2N_ERR_CERT_UNTRUSTED);
    /* current time must be at or after thisUpdate. */
    RESULT_ENSURE(verification_time >= this_update, S2N_ERR_CERT_INVALID);

    if (next_update_tlv->data != NULL) {
        uint64_t next_update = 0;
        RESULT_ENSURE(s2n_result_is_ok(s2n_cert_parse_time(next_update_tlv, &next_update)),
                S2N_ERR_CERT_UNTRUSTED);
        RESULT_ENSURE(verification_time <= next_update, S2N_ERR_CERT_EXPIRED);
    } else {
        /* Absent nextUpdate: reject if more than the default horizon past
         * thisUpdate, matching DEFAULT_OCSP_NEXT_UPDATE_PERIOD behavior. */
        RESULT_ENSURE(verification_time - this_update < S2N_OCSP_DEFAULT_NEXT_UPDATE_PERIOD,
                S2N_ERR_CERT_EXPIRED);
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ocsp_validate(struct s2n_blob *ocsp_der,
        const struct s2n_cert_span_view *leaf,
        const struct s2n_cert_span_view *issuer,
        uint64_t verification_time)
{
    RESULT_ENSURE_REF(ocsp_der);
    RESULT_ENSURE_REF(leaf);
    RESULT_ENSURE_REF(issuer);

    struct s2n_ocsp_response_view view = { 0 };
    RESULT_GUARD(s2n_ocsp_response_parse(&view, ocsp_der));

    /* Verify the responder signature (direct issuer or delegated responder). */
    RESULT_GUARD(s2n_ocsp_verify_responder(&view, issuer, verification_time));

    /* Locate the SingleResponse whose CertID matches the validated leaf. */
    CBS responses = { 0 };
    CBS_init(&responses, view.responses.data, view.responses.size);

    uint32_t response_count = 0;
    while (CBS_len(&responses) > 0) {
        response_count++;
        RESULT_ENSURE(response_count <= S2N_OCSP_MAX_RESPONSES, S2N_ERR_INVALID_OCSP_RESPONSE);

        /* SingleResponse ::= SEQUENCE { certID CertID, certStatus CertStatus,
         *   thisUpdate GeneralizedTime, nextUpdate [0] EXPLICIT ... OPTIONAL,
         *   singleExtensions [1] EXPLICIT ... OPTIONAL } */
        CBS single = { 0 };
        RESULT_ENSURE(CBS_get_asn1(&responses, &single, CBS_ASN1_SEQUENCE), S2N_ERR_INVALID_OCSP_RESPONSE);

        CBS cert_id = { 0 };
        RESULT_ENSURE(CBS_get_asn1(&single, &cert_id, CBS_ASN1_SEQUENCE), S2N_ERR_INVALID_OCSP_RESPONSE);

        bool matches = false;
        RESULT_GUARD(s2n_ocsp_certid_matches(&cert_id, leaf, issuer, &matches));
        if (!matches) {
            continue;
        }

        /* certStatus CHOICE: [0] good (primitive), [1] revoked (constructed),
         * [2] unknown (primitive). */
        CBS cert_status = { 0 };
        CBS_ASN1_TAG status_tag = 0;
        RESULT_ENSURE(CBS_get_any_asn1(&single, &cert_status, &status_tag), S2N_ERR_INVALID_OCSP_RESPONSE);
        uint32_t status_num = status_tag & 0x1f;

        /* thisUpdate GeneralizedTime. */
        CBS this_update = { 0 };
        CBS_ASN1_TAG this_tag = 0;
        RESULT_ENSURE(CBS_get_any_asn1_element(&single, &this_update, &this_tag, NULL),
                S2N_ERR_INVALID_OCSP_RESPONSE);
        RESULT_ENSURE(this_tag == CBS_ASN1_GENERALIZEDTIME, S2N_ERR_INVALID_OCSP_RESPONSE);
        struct s2n_blob this_update_blob = { 0 };
        RESULT_GUARD(s2n_revocation_capture(ocsp_der, &this_update, &this_update_blob,
                S2N_ERR_INVALID_OCSP_RESPONSE));

        /* nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL. */
        struct s2n_blob next_update_blob = { 0 };
        CBS next_wrapper = { 0 };
        int next_present = 0;
        RESULT_ENSURE(CBS_get_optional_asn1(&single, &next_wrapper, &next_present,
                              CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0),
                S2N_ERR_INVALID_OCSP_RESPONSE);
        if (next_present) {
            CBS next_update = { 0 };
            CBS_ASN1_TAG next_tag = 0;
            RESULT_ENSURE(CBS_get_any_asn1_element(&next_wrapper, &next_update, &next_tag, NULL),
                    S2N_ERR_INVALID_OCSP_RESPONSE);
            RESULT_ENSURE(next_tag == CBS_ASN1_GENERALIZEDTIME, S2N_ERR_INVALID_OCSP_RESPONSE);
            RESULT_GUARD(s2n_revocation_capture(ocsp_der, &next_update, &next_update_blob,
                    S2N_ERR_INVALID_OCSP_RESPONSE));
        }

        RESULT_GUARD(s2n_ocsp_check_freshness(&this_update_blob, &next_update_blob, verification_time));

        /* status_num: 0 = good, 1 = revoked, 2 = unknown. */
        switch (status_num) {
            case 0:
                return S2N_RESULT_OK; /* caller drives OCSP_VALIDATED */
            case 1:
                RESULT_BAIL(S2N_ERR_CERT_REVOKED);
            default:
                RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
        }
    }

    /* No SingleResponse covered the leaf: treat as unverifiable, matching the
     * current path's OCSP_resp_find_status failure. */
    RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
}

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */
