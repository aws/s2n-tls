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

#include "tls/s2n_cert_view.h"

#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"

#if S2N_LIBCRYPTO_SUPPORTS_CBS
    #include <openssl/bytestring.h>
    #include <openssl/evp.h>
    #include <string.h>

    #include "tls/s2n_cert_parse.h"
    #include "tls/s2n_cert_path.h"

DEFINE_POINTER_CLEANUP_FUNC(EVP_PKEY *, EVP_PKEY_free);

/* OID for id-at-commonName: 2.5.4.3 */
static const uint8_t s2n_oid_common_name[] = { 0x55, 0x04, 0x03 };

/* RFC 5280 Appendix A.1 string-type allow-list for X520CommonName. */
    #define S2N_ASN1_TELETEXSTRING   0x14
    #define S2N_ASN1_PRINTABLESTRING 0x13
    #define S2N_ASN1_UNIVERSALSTRING 0x1c
    #define S2N_ASN1_UTF8STRING      0x0c
    #define S2N_ASN1_BMPSTRING       0x1e

static bool s2n_cert_view_cn_tag_allowed(uint8_t tag)
{
    return tag == S2N_ASN1_TELETEXSTRING
            || tag == S2N_ASN1_PRINTABLESTRING
            || tag == S2N_ASN1_UNIVERSALSTRING
            || tag == S2N_ASN1_UTF8STRING
            || tag == S2N_ASN1_BMPSTRING;
}

/* EKU OIDs for the check_purpose span arm. */
static const uint8_t s2n_view_oid_server_auth[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
static const uint8_t s2n_view_oid_client_auth[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02 };
static const uint8_t s2n_view_oid_any_eku[] = { 0x55, 0x1d, 0x25, 0x00 };

/* Check if the EKU extension contains a specific OID. */
static S2N_RESULT s2n_cert_view_eku_contains(const struct s2n_blob *eku,
        const uint8_t *target_oid, size_t target_oid_len, bool *found)
{
    RESULT_ENSURE_REF(eku);
    RESULT_ENSURE_REF(eku->data);
    RESULT_ENSURE_REF(target_oid);
    RESULT_ENSURE_REF(found);
    *found = false;

    CBS eku_cbs = { 0 };
    CBS_init(&eku_cbs, eku->data, eku->size);

    CBS seq = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&eku_cbs, &seq, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_len(&eku_cbs) == 0, S2N_ERR_CERT_INVALID);

    while (CBS_len(&seq) > 0) {
        CBS oid = { 0 };
        RESULT_ENSURE(CBS_get_asn1(&seq, &oid, CBS_ASN1_OBJECT), S2N_ERR_CERT_INVALID);
        if (CBS_len(&oid) == target_oid_len
                && memcmp(CBS_data(&oid), target_oid, target_oid_len) == 0) {
            *found = true;
            return S2N_RESULT_OK;
        }
    }
    return S2N_RESULT_OK;
}

/* SAN GeneralName context-specific tags. */
    #define S2N_SAN_TAG_DNSNAME 2
    #define S2N_SAN_TAG_URI     6
    #define S2N_SAN_TAG_IPADDR  7

/* keyUsage bit definitions (byte 0 of the BIT STRING contents). */
    #define S2N_KEY_USAGE_DIGITAL_SIGNATURE  0x80
    #define S2N_KEY_USAGE_KEY_CERT_SIGN_VIEW 0x04

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

S2N_RESULT s2n_cert_view_init(struct s2n_cert_view *view, X509 *cert)
{
    RESULT_ENSURE_REF(view);
    RESULT_ENSURE_REF(cert);
    view->backing = S2N_CERT_VIEW_X509;
    view->u.x509 = cert;
    return S2N_RESULT_OK;
}

#if S2N_LIBCRYPTO_SUPPORTS_CBS
S2N_RESULT s2n_cert_view_init_span(struct s2n_cert_view *view,
        const struct s2n_cert_span_view *span)
{
    RESULT_ENSURE_REF(view);
    RESULT_ENSURE_REF(span);
    view->backing = S2N_CERT_VIEW_SPAN;
    view->u.span = span;
    return S2N_RESULT_OK;
}
#endif

S2N_RESULT s2n_cert_view_get_public_key(const struct s2n_cert_view *view,
        struct s2n_pkey *public_key_out, s2n_pkey_type *pkey_type_out)
{
    RESULT_ENSURE_REF(view);

    switch (view->backing) {
        case S2N_CERT_VIEW_X509:
            RESULT_ENSURE_REF(view->u.x509);
            RESULT_GUARD(s2n_pkey_from_x509(view->u.x509, public_key_out, pkey_type_out));
            return S2N_RESULT_OK;
#if S2N_LIBCRYPTO_SUPPORTS_CBS
        case S2N_CERT_VIEW_SPAN: {
            RESULT_ENSURE_REF(view->u.span);
            RESULT_ENSURE_REF(view->u.span->spki.data);
            RESULT_ENSURE_REF(public_key_out);
            RESULT_ENSURE_REF(pkey_type_out);

            const uint8_t *p = view->u.span->spki.data;
            DEFER_CLEANUP(EVP_PKEY *evp_pkey = d2i_PUBKEY(NULL, &p, (long) view->u.span->spki.size),
                    EVP_PKEY_free_pointer);
            RESULT_ENSURE(evp_pkey != NULL, S2N_ERR_CERT_UNTRUSTED);
            RESULT_ENSURE(p == view->u.span->spki.data + view->u.span->spki.size,
                    S2N_ERR_CERT_UNTRUSTED);

            s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
            RESULT_GUARD(s2n_pkey_get_type(evp_pkey, &pkey_type));
            RESULT_GUARD(s2n_pkey_setup_for_type(public_key_out, pkey_type));

            public_key_out->pkey = evp_pkey;
            ZERO_TO_DISABLE_DEFER_CLEANUP(evp_pkey);
            *pkey_type_out = pkey_type;
            return S2N_RESULT_OK;
        }
#endif
    }
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_RESULT s2n_cert_view_get_common_name(const struct s2n_cert_view *view,
        struct s2n_blob *cn_out, uint32_t *cn_len_out, bool *cn_found)
{
    RESULT_ENSURE_REF(view);
    RESULT_ENSURE_REF(cn_out);
    RESULT_ENSURE_REF(cn_len_out);
    RESULT_ENSURE_REF(cn_found);

    *cn_found = false;

    switch (view->backing) {
        case S2N_CERT_VIEW_X509: {
            RESULT_ENSURE_REF(view->u.x509);

            X509_NAME *subject_name = X509_get_subject_name(view->u.x509);
            RESULT_ENSURE(subject_name, S2N_ERR_CERT_UNTRUSTED);

            /* Use the last CN entry if multiple are present. */
            int curr_idx = -1;
            while (true) {
                int next_idx = X509_NAME_get_index_by_NID(subject_name, NID_commonName, curr_idx);
                if (next_idx >= 0) {
                    curr_idx = next_idx;
                } else {
                    break;
                }
            }
            RESULT_ENSURE(curr_idx >= 0, S2N_ERR_CERT_UNTRUSTED);

            ASN1_STRING *common_name = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject_name, curr_idx));
            RESULT_ENSURE(common_name, S2N_ERR_CERT_UNTRUSTED);

            /* X520CommonName allows the following ANSI string types per RFC 5280 Appendix A.1 */
            RESULT_ENSURE(ASN1_STRING_type(common_name) == V_ASN1_TELETEXSTRING
                            || ASN1_STRING_type(common_name) == V_ASN1_PRINTABLESTRING
                            || ASN1_STRING_type(common_name) == V_ASN1_UNIVERSALSTRING
                            || ASN1_STRING_type(common_name) == V_ASN1_UTF8STRING
                            || ASN1_STRING_type(common_name) == V_ASN1_BMPSTRING,
                    S2N_ERR_CERT_UNTRUSTED);

            /* at this point we have a valid CN value */
            *cn_found = true;

            int cn_len = ASN1_STRING_length(common_name);
            RESULT_ENSURE_GT(cn_len, 0);
            uint32_t len = (uint32_t) cn_len;
            RESULT_ENSURE_LTE(len, cn_out->size - 1);
            RESULT_CHECKED_MEMCPY(cn_out->data, ASN1_STRING_data(common_name), len);
            *cn_len_out = len;

            return S2N_RESULT_OK;
        }
#if S2N_LIBCRYPTO_SUPPORTS_CBS
        case S2N_CERT_VIEW_SPAN: {
            RESULT_ENSURE_REF(view->u.span);

            /* The subject field may be absent (NULL) if the cert has no subject. */
            RESULT_ENSURE(view->u.span->subject.data != NULL, S2N_ERR_CERT_UNTRUSTED);

            /* Walk the subject Name TLV with a CBS cursor.
             * Name ::= SEQUENCE OF SET OF SEQUENCE { OID, value }
             * We iterate all attributes looking for OID = commonName (2.5.4.3).
             * Last-CN-wins rule: if multiple CN attributes exist, we take the last. */
            CBS subject_cbs = { 0 };
            CBS_init(&subject_cbs, view->u.span->subject.data, view->u.span->subject.size);

            CBS name_seq = { 0 };
            RESULT_ENSURE(CBS_get_asn1(&subject_cbs, &name_seq, CBS_ASN1_SEQUENCE),
                    S2N_ERR_CERT_UNTRUSTED);

            const uint8_t *last_cn_data = NULL;
            size_t last_cn_len = 0;
            uint8_t last_cn_tag = 0;

            /* Iterate RDN SETs. */
            while (CBS_len(&name_seq) > 0) {
                CBS rdn_set = { 0 };
                RESULT_ENSURE(CBS_get_asn1(&name_seq, &rdn_set, CBS_ASN1_SET),
                        S2N_ERR_CERT_UNTRUSTED);

                /* Iterate attributes within the RDN SET. */
                while (CBS_len(&rdn_set) > 0) {
                    CBS atv = { 0 };
                    RESULT_ENSURE(CBS_get_asn1(&rdn_set, &atv, CBS_ASN1_SEQUENCE),
                            S2N_ERR_CERT_UNTRUSTED);

                    CBS oid = { 0 };
                    RESULT_ENSURE(CBS_get_asn1(&atv, &oid, CBS_ASN1_OBJECT),
                            S2N_ERR_CERT_UNTRUSTED);

                    /* Check if this is the commonName OID. */
                    if (CBS_len(&oid) == sizeof(s2n_oid_common_name)
                            && memcmp(CBS_data(&oid), s2n_oid_common_name,
                                       sizeof(s2n_oid_common_name))
                                    == 0) {
                        /* Read the value with its tag. */
                        CBS value_element = { 0 };
                        unsigned value_tag = 0;
                        RESULT_ENSURE(CBS_get_any_asn1(&atv, &value_element, &value_tag),
                                S2N_ERR_CERT_UNTRUSTED);

                        last_cn_data = CBS_data(&value_element);
                        last_cn_len = CBS_len(&value_element);
                        last_cn_tag = (uint8_t) value_tag;
                    }
                }
            }

            /* No CN found. */
            RESULT_ENSURE(last_cn_data != NULL, S2N_ERR_CERT_UNTRUSTED);

            /* Check string type against the RFC 5280 Appendix A.1 allow-list. */
            RESULT_ENSURE(s2n_cert_view_cn_tag_allowed(last_cn_tag), S2N_ERR_CERT_UNTRUSTED);

            *cn_found = true;
            uint32_t len = (uint32_t) last_cn_len;
            RESULT_ENSURE_GT(len, 0);
            RESULT_ENSURE_LTE(len, cn_out->size - 1);
            RESULT_CHECKED_MEMCPY(cn_out->data, last_cn_data, len);
            *cn_len_out = len;

            return S2N_RESULT_OK;
        }
#endif
    }
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

DEFINE_POINTER_CLEANUP_FUNC(STACK_OF(GENERAL_NAME) *, GENERAL_NAMES_free);

S2N_RESULT s2n_cert_view_verify_sans(const struct s2n_cert_view *view,
        struct s2n_connection *conn, s2n_cert_san_fn cb, bool *san_found)
{
    RESULT_ENSURE_REF(view);
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(cb);
    RESULT_ENSURE_REF(san_found);

    *san_found = false;

    switch (view->backing) {
        case S2N_CERT_VIEW_X509: {
            RESULT_ENSURE_REF(view->u.x509);

            DEFER_CLEANUP(STACK_OF(GENERAL_NAME) *names_list = NULL, GENERAL_NAMES_free_pointer);
            names_list = X509_get_ext_d2i(view->u.x509, NID_subject_alt_name, NULL, NULL);
            RESULT_ENSURE(names_list, S2N_ERR_CERT_UNTRUSTED);

            int n = sk_GENERAL_NAME_num(names_list);
            RESULT_ENSURE(n > 0, S2N_ERR_CERT_UNTRUSTED);

            s2n_result result = S2N_RESULT_OK;
            for (int i = 0; i < n; i++) {
                GENERAL_NAME *current_name = sk_GENERAL_NAME_value(names_list, i);
                RESULT_ENSURE_REF(current_name);

                struct s2n_cert_san_entry entry = { .type = S2N_CERT_SAN_OTHER };
                if (current_name->type == GEN_DNS || current_name->type == GEN_URI) {
                    entry.type = S2N_CERT_SAN_DNS_OR_URI;
                    entry.data = ASN1_STRING_data(current_name->d.ia5);
                    int name_len = ASN1_STRING_length(current_name->d.ia5);
                    entry.data_len = name_len > 0 ? (uint32_t) name_len : 0;
                } else if (current_name->type == GEN_IPADD) {
                    entry.type = S2N_CERT_SAN_IP;
                    entry.data = current_name->d.iPAddress->data;
                    int ip_len = current_name->d.iPAddress->length;
                    entry.data_len = ip_len > 0 ? (uint32_t) ip_len : 0;
                }

                /* return success on the first entry that passes verification */
                result = cb(conn, &entry, san_found);
                if (s2n_result_is_ok(result)) {
                    return S2N_RESULT_OK;
                }
            }

            /* propagate the error from the last SAN entry call */
            RESULT_GUARD(result);

            RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
        }
#if S2N_LIBCRYPTO_SUPPORTS_CBS
        case S2N_CERT_VIEW_SPAN: {
            RESULT_ENSURE_REF(view->u.span);

            /* No SAN extension → fail untrusted (matches X509 arm behavior). */
            RESULT_ENSURE(view->u.span->san.data != NULL, S2N_ERR_CERT_UNTRUSTED);
            RESULT_ENSURE(view->u.span->san.size > 0, S2N_ERR_CERT_UNTRUSTED);

            /* The san blob contains the extnValue contents: a SEQUENCE OF
             * GeneralName. Each GeneralName is IMPLICIT context-specific tagged:
             *   dNSName [2] IA5String, uniformResourceIdentifier [6] IA5String,
             *   iPAddress [7] OCTET STRING. */
            CBS san_cbs = { 0 };
            CBS_init(&san_cbs, view->u.span->san.data, view->u.span->san.size);

            CBS san_seq = { 0 };
            RESULT_ENSURE(CBS_get_asn1(&san_cbs, &san_seq, CBS_ASN1_SEQUENCE),
                    S2N_ERR_CERT_UNTRUSTED);

            RESULT_ENSURE(CBS_len(&san_seq) > 0, S2N_ERR_CERT_UNTRUSTED);

            s2n_result result = S2N_RESULT_OK;
            while (CBS_len(&san_seq) > 0) {
                CBS element = { 0 };
                unsigned tag = 0;
                RESULT_ENSURE(CBS_get_any_asn1(&san_seq, &element, &tag),
                        S2N_ERR_CERT_UNTRUSTED);

                /* Extract the implicit tag number (low 5 bits). */
                unsigned tag_number = tag & 0x1f;

                struct s2n_cert_san_entry entry = { .type = S2N_CERT_SAN_OTHER };

                if (tag_number == S2N_SAN_TAG_DNSNAME || tag_number == S2N_SAN_TAG_URI) {
                    entry.type = S2N_CERT_SAN_DNS_OR_URI;
                    entry.data = CBS_data(&element);
                    entry.data_len = (uint32_t) CBS_len(&element);
                } else if (tag_number == S2N_SAN_TAG_IPADDR) {
                    entry.type = S2N_CERT_SAN_IP;
                    entry.data = CBS_data(&element);
                    entry.data_len = (uint32_t) CBS_len(&element);
                }

                /* Stop-on-first-accept: return success when cb accepts. */
                result = cb(conn, &entry, san_found);
                if (s2n_result_is_ok(result)) {
                    return S2N_RESULT_OK;
                }
            }

            /* Propagate the error from the last SAN entry call. */
            RESULT_GUARD(result);

            RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
        }
#endif
    }
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_RESULT s2n_cert_view_check_purpose(const struct s2n_cert_view *view,
        s2n_cert_purpose purpose, bool require_ca)
{
    RESULT_ENSURE_REF(view);

    switch (view->backing) {
        case S2N_CERT_VIEW_X509: {
            RESULT_ENSURE_REF(view->u.x509);

            int x509_purpose = X509_PURPOSE_SSL_CLIENT;
            if (purpose == S2N_CERT_PURPOSE_SSL_SERVER) {
                x509_purpose = X509_PURPOSE_SSL_SERVER;
            }

            RESULT_GUARD_OSSL(X509_check_purpose(view->u.x509, x509_purpose, require_ca),
                    S2N_ERR_CERT_INTENT_INVALID);

            return S2N_RESULT_OK;
        }
#if S2N_LIBCRYPTO_SUPPORTS_CBS
        case S2N_CERT_VIEW_SPAN: {
            RESULT_ENSURE_REF(view->u.span);

            /* Determine the EKU OID to check based on purpose. */
            const uint8_t *purpose_oid = s2n_view_oid_server_auth;
            size_t purpose_oid_len = sizeof(s2n_view_oid_server_auth);
            if (purpose == S2N_CERT_PURPOSE_SSL_CLIENT) {
                purpose_oid = s2n_view_oid_client_auth;
                purpose_oid_len = sizeof(s2n_view_oid_client_auth);
            }

            if (require_ca) {
                /* CA certificate: basicConstraints CA:TRUE is required.
                 * This mirrors X509_check_purpose which rejects non-CA certs
                 * when require_ca is set. */
                RESULT_ENSURE(view->u.span->basic_constraints_present
                                && view->u.span->basic_constraints_is_ca,
                        S2N_ERR_CERT_INTENT_INVALID);

                /* keyUsage keyCertSign must be set if keyUsage
                 * extension is present. */
                if (view->u.span->key_usage_present) {
                    RESULT_ENSURE(view->u.span->key_usage_bits & S2N_KEY_USAGE_KEY_CERT_SIGN_VIEW,
                            S2N_ERR_CERT_INTENT_INVALID);
                }

                /* EKU check for CA: if present, must contain the purpose OID
                 * or anyExtendedKeyUsage. */
                if (view->u.span->eku.data != NULL && view->u.span->eku.size > 0) {
                    bool has_purpose = false;
                    RESULT_GUARD(s2n_cert_view_eku_contains(&view->u.span->eku,
                            purpose_oid, purpose_oid_len, &has_purpose));
                    if (!has_purpose) {
                        bool has_any = false;
                        RESULT_GUARD(s2n_cert_view_eku_contains(&view->u.span->eku,
                                s2n_view_oid_any_eku, sizeof(s2n_view_oid_any_eku), &has_any));
                        RESULT_ENSURE(has_any, S2N_ERR_CERT_INTENT_INVALID);
                    }
                }
            } else {
                /* Leaf certificate: EKU check. If EKU is present, must contain
                 * the purpose OID or anyExtendedKeyUsage.
                 * Note: X509_check_purpose's keyUsage check for leaves depends
                 * on the key type and purpose (e.g., SSL_SERVER accepts
                 * digitalSignature OR keyEncipherment for RSA). We skip the
                 * keyUsage check here and rely on the path builder's separate
                 * keyUsage enforcement where applicable. */
                if (view->u.span->eku.data != NULL && view->u.span->eku.size > 0) {
                    bool has_purpose = false;
                    RESULT_GUARD(s2n_cert_view_eku_contains(&view->u.span->eku,
                            purpose_oid, purpose_oid_len, &has_purpose));
                    if (!has_purpose) {
                        bool has_any = false;
                        RESULT_GUARD(s2n_cert_view_eku_contains(&view->u.span->eku,
                                s2n_view_oid_any_eku, sizeof(s2n_view_oid_any_eku), &has_any));
                        RESULT_ENSURE(has_any, S2N_ERR_CERT_INTENT_INVALID);
                    }
                }
            }

            return S2N_RESULT_OK;
        }
#endif
    }
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_RESULT s2n_cert_view_check_issued(const struct s2n_cert_view *issuer_view,
        const struct s2n_cert_view *subject_view, bool *issued)
{
    RESULT_ENSURE_REF(issuer_view);
    RESULT_ENSURE_REF(subject_view);
    RESULT_ENSURE_REF(issued);

    switch (issuer_view->backing) {
        case S2N_CERT_VIEW_X509:
            RESULT_ENSURE_REF(issuer_view->u.x509);
            RESULT_ENSURE(subject_view->backing == S2N_CERT_VIEW_X509, S2N_ERR_UNIMPLEMENTED);
            RESULT_ENSURE_REF(subject_view->u.x509);

            *issued = (X509_check_issued(issuer_view->u.x509, subject_view->u.x509) == X509_V_OK);
            return S2N_RESULT_OK;
#if S2N_LIBCRYPTO_SUPPORTS_CBS
        case S2N_CERT_VIEW_SPAN: {
            RESULT_ENSURE_REF(issuer_view->u.span);
            RESULT_ENSURE(subject_view->backing == S2N_CERT_VIEW_SPAN, S2N_ERR_UNIMPLEMENTED);
            RESULT_ENSURE_REF(subject_view->u.span);

            *issued = false;

            /* RFC 5280 name check: issuer's subject == subject's issuer. */
            RESULT_ENSURE(issuer_view->u.span->subject.data != NULL, S2N_ERR_CERT_UNTRUSTED);
            RESULT_ENSURE(subject_view->u.span->issuer.data != NULL, S2N_ERR_CERT_UNTRUSTED);

            bool names_equal = false;
            RESULT_GUARD(s2n_cert_name_cmp(&issuer_view->u.span->subject,
                    &subject_view->u.span->issuer, &names_equal));

            if (!names_equal) {
                return S2N_RESULT_OK;
            }

            /* AKID/SKID matching: if both are present, verify that the
             * subject's AKID keyIdentifier matches the issuer's SKID.
             *
             * AuthorityKeyIdentifier ::= SEQUENCE {
             *   keyIdentifier [0] IMPLICIT OCTET STRING OPTIONAL, ... }
             * SubjectKeyIdentifier ::= OCTET STRING
             *
             * The akid blob contains the extnValue contents of AKID. We need to
             * extract the [0] keyIdentifier from it and compare to the SKID. */
            if (subject_view->u.span->akid.data != NULL
                    && subject_view->u.span->akid.size > 0
                    && issuer_view->u.span->skid.data != NULL
                    && issuer_view->u.span->skid.size > 0) {
                /* Parse the AKID to extract keyIdentifier [0]. */
                CBS akid_cbs = { 0 };
                CBS_init(&akid_cbs, subject_view->u.span->akid.data,
                        subject_view->u.span->akid.size);

                CBS akid_seq = { 0 };
                RESULT_ENSURE(CBS_get_asn1(&akid_cbs, &akid_seq, CBS_ASN1_SEQUENCE),
                        S2N_ERR_CERT_UNTRUSTED);

                /* Look for the [0] IMPLICIT OCTET STRING (context tag 0). */
                bool found_key_id = false;
                CBS key_id = { 0 };
                if (CBS_len(&akid_seq) > 0) {
                    /* Peek at the first tag. AKID keyIdentifier is [0] which is
                     * context-specific class (0x80) | tag 0 = 0x80. */
                    if (CBS_get_asn1(&akid_seq, &key_id,
                                CBS_ASN1_CONTEXT_SPECIFIC | 0)) {
                        found_key_id = true;
                    }
                }

                if (found_key_id) {
                    /* Parse the SKID. SubjectKeyIdentifier ::= OCTET STRING.
                     * The skid blob contains the extnValue contents. */
                    CBS skid_cbs = { 0 };
                    CBS_init(&skid_cbs, issuer_view->u.span->skid.data,
                            issuer_view->u.span->skid.size);

                    CBS skid_value = { 0 };
                    RESULT_ENSURE(CBS_get_asn1(&skid_cbs, &skid_value, CBS_ASN1_OCTETSTRING),
                            S2N_ERR_CERT_UNTRUSTED);

                    /* Compare keyIdentifier bytes. */
                    if (CBS_len(&key_id) != CBS_len(&skid_value)
                            || memcmp(CBS_data(&key_id), CBS_data(&skid_value),
                                       CBS_len(&key_id))
                                    != 0) {
                        /* AKID/SKID mismatch: not issued by this issuer. */
                        return S2N_RESULT_OK;
                    }
                }
            }

            *issued = true;
            return S2N_RESULT_OK;
        }
#endif
    }
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_RESULT s2n_cert_chain_view_init(struct s2n_cert_chain_view *chain, STACK_OF(X509) *stack)
{
    RESULT_ENSURE_REF(chain);
    RESULT_ENSURE_REF(stack);
    chain->backing = S2N_CERT_VIEW_X509;
    chain->u.stack = stack;
    return S2N_RESULT_OK;
}

#if S2N_LIBCRYPTO_SUPPORTS_CBS
S2N_RESULT s2n_cert_chain_view_init_spans(struct s2n_cert_chain_view *chain,
        const struct s2n_cert_span_view *views, uint32_t count)
{
    RESULT_ENSURE_REF(chain);
    RESULT_ENSURE_REF(views);
    chain->backing = S2N_CERT_VIEW_SPAN;
    chain->u.spans.views = views;
    chain->u.spans.count = count;
    return S2N_RESULT_OK;
}
#endif

S2N_RESULT s2n_cert_chain_view_count(const struct s2n_cert_chain_view *chain, int *count_out)
{
    RESULT_ENSURE_REF(chain);
    RESULT_ENSURE_REF(count_out);

    switch (chain->backing) {
        case S2N_CERT_VIEW_X509:
            RESULT_ENSURE_REF(chain->u.stack);
            *count_out = sk_X509_num(chain->u.stack);
            return S2N_RESULT_OK;
#if S2N_LIBCRYPTO_SUPPORTS_CBS
        case S2N_CERT_VIEW_SPAN:
            *count_out = (int) chain->u.spans.count;
            return S2N_RESULT_OK;
#endif
    }
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}

S2N_RESULT s2n_cert_chain_view_get(const struct s2n_cert_chain_view *chain, int cert_index,
        struct s2n_cert_view *cert_out)
{
    RESULT_ENSURE_REF(chain);
    RESULT_ENSURE_REF(cert_out);

    switch (chain->backing) {
        case S2N_CERT_VIEW_X509: {
            RESULT_ENSURE_REF(chain->u.stack);
            X509 *cert = sk_X509_value(chain->u.stack, cert_index);
            RESULT_ENSURE_REF(cert);
            RESULT_GUARD(s2n_cert_view_init(cert_out, cert));
            return S2N_RESULT_OK;
        }
#if S2N_LIBCRYPTO_SUPPORTS_CBS
        case S2N_CERT_VIEW_SPAN: {
            RESULT_ENSURE(cert_index >= 0, S2N_ERR_SAFETY);
            RESULT_ENSURE((uint32_t) cert_index < chain->u.spans.count, S2N_ERR_SAFETY);
            RESULT_GUARD(s2n_cert_view_init_span(cert_out, &chain->u.spans.views[cert_index]));
            return S2N_RESULT_OK;
        }
#endif
    }
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
}
