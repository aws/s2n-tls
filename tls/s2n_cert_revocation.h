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

#pragma once

#include "crypto/s2n_pkey.h"
#include "tls/s2n_cert_parse.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_result.h"

/* Zero-copy revocation validators (CRL + stapled OCSP) for the zero-copy
 * certificate verifier. Both parse their DER inputs into borrowed byte spans
 * with the same strict-DER CBS rules as the parser, and reuse the
 * shared s2n_cert_verify_signed helper for every signature check. Requires the
 * CBS API, so this is only available on aws-lc / BoringSSL builds. */
#if S2N_LIBCRYPTO_SUPPORTS_CBS

/* --- CRL_Validator --------------------------------------------------------
 *
 * Parses an X.509 CertificateList (RFC 5280 §5.1), verifies its signature
 * against the issuing CA's key, checks the thisUpdate/nextUpdate window with
 * the same acceptance behavior as the current libcrypto CRL path, and scans
 * the revokedCertificates list for a target serial number.
 *
 * ENFORCED FEATURES / DELIBERATE NON-ENFORCEMENT (matching today's effective
 * behavior of the libcrypto CRL path):
 *  - Delta CRLs are NOT supported: the deltaCRLIndicator / freshestCRL
 *    extensions are ignored, so a delta CRL is treated as (and scanned as) a
 *    full CRL. This matches the current path, which never requests or applies
 *    delta CRLs.
 *  - CRL distribution-point matching is NOT enforced: the issuingDistributionPoint
 *    extension is not consulted and the certificate's cRLDistributionPoints are
 *    not matched against the CRL. The applicable CRL is selected entirely by the
 *    application's lookup callback (by issuer hash), exactly as today.
 *  - Per-entry CRL reason codes are NOT interpreted: any serial present in the
 *    revokedCertificates list is treated as revoked regardless of reason,
 *    matching the current path.
 *  - CRL-entry and CRL extensions (including critical ones) are not processed;
 *    the scan only reads userCertificate serials.
 *
 * The async lookup-callback flow (crl_lookup_list, AWAITING_CRL_CALLBACK,
 * S2N_ERR_CRL_LOOKUP_FAILED) is shared with the libcrypto path and lives in the
 * validator (deferred); only the parse/check swaps to these
 * functions. */

/* Upper bound on the number of revokedCertificates entries the linear scan
 * will walk. Bounds the algorithmic-complexity DoS surface of a pathological
 * CRL. A CRL declaring more entries than this rejects with
 * S2N_ERR_CERT_INVALID. The cap is generous: legitimate CRLs stay well below
 * it, so it does not perturb decision parity on the differential corpus. */
    #define S2N_CRL_MAX_REVOKED_ENTRIES (1024 * 1024)

/* A zero-copy view over one DER CertificateList. Every s2n_blob is a borrowed
 * span into the caller's CRL buffer: the view owns nothing and needs no
 * cleanup. A span with data == NULL means the corresponding optional field is
 * absent. Spans annotated "TLV" include the ASN.1 tag+length header; the
 * tbs span in particular MUST keep its header because the CRL signature is
 * computed over the full TBSCertList TLV. */
struct s2n_crl_view {
    struct s2n_blob raw;         /* full CertificateList TLV */
    struct s2n_blob tbs;         /* tbsCertList TLV, WITH header (signature input) */
    struct s2n_blob sig_alg;     /* signatureAlgorithm AlgorithmIdentifier TLV (outer) */
    struct s2n_blob sig;         /* signatureValue BIT STRING contents; unused-bits == 0 verified */
    struct s2n_blob issuer;      /* Name TLV */
    struct s2n_blob this_update; /* thisUpdate Time TLV */
    struct s2n_blob next_update; /* nextUpdate Time TLV; data == NULL if absent */
    struct s2n_blob revoked;     /* revokedCertificates SEQUENCE OF contents; data == NULL if absent */
    bool has_next_update;
};

/* Parse one DER CertificateList TLV into a CRL view. `crl_der` must contain
 * exactly one CertificateList (no trailing bytes) and must outlive the view:
 * every span borrows from it. Strict DER only. Malformed input rejects with
 * S2N_ERR_CERT_INVALID. */
S2N_RESULT s2n_crl_view_parse(struct s2n_crl_view *view, struct s2n_blob *crl_der);

/* Verify the CRL signature over its tbsCertList TLV using the issuing CA's
 * public key (materialized by the caller from the CA's SubjectPublicKeyInfo).
 * Reuses the shared s2n_cert_verify_signed helper. A verification failure
 * rejects with S2N_ERR_CRL_SIGNATURE. */
S2N_RESULT s2n_crl_verify_signature(const struct s2n_crl_view *view,
        struct s2n_pkey *issuer_key);

/* Check the CRL thisUpdate / nextUpdate window against `verification_time`
 * (seconds since the Unix epoch), matching the current libcrypto CRL path:
 *  - thisUpdate must be at or before verification_time, else S2N_ERR_CRL_NOT_YET_VALID.
 *  - nextUpdate, when present, must be at or after verification_time, else
 *    S2N_ERR_CRL_EXPIRED. When absent, the CRL is assumed to never expire.
 * A thisUpdate/nextUpdate value that fails RFC 5280 time decoding rejects with
 * S2N_ERR_CRL_INVALID_THIS_UPDATE / S2N_ERR_CRL_INVALID_NEXT_UPDATE. */
S2N_RESULT s2n_crl_check_times(const struct s2n_crl_view *view,
        uint64_t verification_time);

/* Scan revokedCertificates for `serial` (the target certificate's INTEGER
 * serial-number contents). A match rejects with S2N_ERR_CERT_REVOKED. The scan
 * is bounded by S2N_CRL_MAX_REVOKED_ENTRIES. */
S2N_RESULT s2n_crl_check_serial(const struct s2n_crl_view *view,
        const struct s2n_blob *serial);

/* Convenience: parse + verify signature + check times + check serial in one
 * call. Equivalent to calling the four functions above in order. */
S2N_RESULT s2n_crl_validate(struct s2n_blob *crl_der, struct s2n_pkey *issuer_key,
        const struct s2n_blob *serial, uint64_t verification_time);

/* --- OCSP_Validator -------------------------------------------------------
 *
 * Parses a stapled OCSPResponse / BasicOCSPResponse (RFC 6960), verifies the
 * responder signature, matches the response's CertID against the validated
 * leaf via SHA-1 CertID hashing, checks the freshness window, and reports the
 * certificate status. Decisions mirror OCSP_basic_verify + OCSP_resp_find_status
 * as used by the current libcrypto OCSP path.
 *
 * The SHA-1 usage here is identification (RFC 6960 CertID hashing), not trust:
 * the responder key hash and issuer name hash are how a SingleResponse names
 * the certificate it covers, exactly as in the current path (OCSP_cert_to_id
 * with EVP_sha1()).
 *
 * DELEGATED-RESPONDER SUPPORT / LIMITATIONS: a response signed by a delegated
 * responder certificate carried in the BasicOCSPResponse certs[] field is
 * accepted when that certificate (a) carries the id-kp-OCSPSigning EKU and
 * (b) is directly issued by the certificate's issuer (name match + signature
 * verification against the issuer key) — the common RFC 6960 delegated case
 * s2n exercises. Responder certificates that chain to the issuer through
 * additional intermediates are not validated here (the current path validates
 * them through OCSP_basic_verify against the full trust store; that broader
 * case is out of scope for the span validator and pinned by the differential
 * corpus). */

/* Bounds on the OCSP parse to cap input-driven work. */
    #define S2N_OCSP_MAX_CERTS     16
    #define S2N_OCSP_MAX_RESPONSES 64

/* A zero-copy view over a BasicOCSPResponse plus the ResponseData fields the
 * validator needs. Every span borrows from the caller's OCSP buffer. */
struct s2n_ocsp_response_view {
    struct s2n_blob tbs_response_data;  /* ResponseData TLV, WITH header (signature input) */
    struct s2n_blob sig_alg;            /* signatureAlgorithm AlgorithmIdentifier TLV */
    struct s2n_blob sig;                /* signature BIT STRING contents; unused-bits == 0 verified */
    struct s2n_blob certs;              /* certs [0] SEQUENCE OF Certificate contents; NULL if absent */
    struct s2n_blob responder_name;     /* responderID byName Name TLV; NULL unless byName */
    struct s2n_blob responder_key_hash; /* responderID byKey KeyHash contents; NULL unless byKey */
    struct s2n_blob produced_at;        /* producedAt GeneralizedTime TLV */
    struct s2n_blob responses;          /* responses SEQUENCE OF SingleResponse contents */
};

/* Parse a DER OCSPResponse into an OCSP response view. `ocsp_der` must outlive
 * the view: every span borrows from it. The responseStatus must be successful
 * and the responseType must be id-pkix-ocsp-basic, matching the current path.
 * A non-successful status rejects with S2N_ERR_CERT_UNTRUSTED; a structurally
 * malformed response rejects with S2N_ERR_INVALID_OCSP_RESPONSE. */
S2N_RESULT s2n_ocsp_response_parse(struct s2n_ocsp_response_view *view,
        struct s2n_blob *ocsp_der);

/* Validate a stapled OCSP response against the validated leaf.
 *
 * `leaf` and `issuer` are span views of the validated leaf certificate and the
 * certificate that issued it (the caller locates the issuer in the validated
 * path). `verification_time` is seconds since the Unix epoch.
 *
 * Verifies the responder signature (direct issuer or delegated responder),
 * matches the CertID against the leaf, checks the thisUpdate/nextUpdate
 * freshness window with the same acceptance as the current OCSP path, and
 * reports status:
 *  - good    -> S2N_RESULT_OK (caller drives OCSP_VALIDATED)
 *  - revoked -> S2N_ERR_CERT_REVOKED
 *  - unknown / any other failure -> S2N_ERR_CERT_UNTRUSTED
 * A stale/future response rejects with S2N_ERR_CERT_EXPIRED / S2N_ERR_CERT_INVALID
 * matching the current path. */
S2N_RESULT s2n_ocsp_validate(struct s2n_blob *ocsp_der,
        const struct s2n_cert_span_view *leaf,
        const struct s2n_cert_span_view *issuer,
        uint64_t verification_time);

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */
