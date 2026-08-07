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

#include "tls/s2n_cert_parse.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_result.h"

/* Path builder and constraint checker for the zero-copy certificate verifier.
 * Requires the CBS API, available only on aws-lc / BoringSSL builds. */
#if S2N_LIBCRYPTO_SUPPORTS_CBS

/* Candidate-issuer evaluation budget. Charged once per SIGNATURE ATTEMPT: a
 * candidate whose subject matches the child's issuer name costs one unit
 * (public key materialization + signature verify); name-mismatched candidates
 * are scanned for free. Exhaustion rejects with S2N_ERR_CERT_UNTRUSTED. This
 * bounds the algorithmic-complexity DoS surface for pathological chains with
 * many same-name candidate issuers, without making acceptance depend on trust
 * store size (a system CA bundle alone typically exceeds this budget). */
    #define S2N_CERT_PATH_WORK_BUDGET 64

/* Maximum number of certificates in a validated path (leaf + intermediates +
 * anchor). Matches the design's S2N_CERT_CHAIN_SPANS_MAX + 1 for the anchor. */
    #define S2N_CERT_PATH_MAX_DEPTH (S2N_CERT_CHAIN_SPANS_MAX + 1)

/* A trust anchor: an owned DER copy of a CA certificate plus its parsed span
 * view. builds the real lazy-snapshot from X509_STORE; for this
 * is a simple placeholder array populated directly from DER bytes. */
struct s2n_trust_anchor {
    struct s2n_blob der;              /* owned DER copy */
    struct s2n_cert_span_view parsed; /* spans borrow from der */
};

/* An immutable snapshot of trust anchors for path building. builds this
 * lazily from an X509_STORE and reference-counts it so concurrent validations
 * share one immutable copy (see the Trust_Store_Bridge in s2n_x509_validator.c).
 * `anchors`/`count` are read lock-free once built; `refcount` is mutated only
 * under the bridge's build mutex. A caller-owned stack snapshot (as used by the
 * path tests) simply leaves `refcount` at 0. */
struct s2n_trust_anchor_snapshot {
    struct s2n_trust_anchor *anchors;
    uint32_t count;
    /* Number of live references (the trust store holds one while attached, plus
     * one per in-flight validation). Freed when it drops to 0. Only touched
     * under the Trust_Store_Bridge build mutex. */
    uint32_t refcount;
};

/* A single entry in a validated certification path. Each entry identifies
 * either a wire certificate (by index into the chain spans) or a trust anchor
 * (by index into the anchor snapshot). */
typedef enum {
    S2N_CERT_PATH_ENTRY_WIRE,
    S2N_CERT_PATH_ENTRY_ANCHOR,
} s2n_cert_path_entry_type;

struct s2n_cert_path_entry {
    s2n_cert_path_entry_type type;
    uint32_t entry_index;
};

/* The validated certification path: an ordered sequence of path entries from
 * the leaf (index 0) to the trust anchor (index count-1). */
struct s2n_cert_path {
    struct s2n_cert_path_entry entries[S2N_CERT_PATH_MAX_DEPTH];
    uint32_t count;
};

/* EKU purpose constants for the cert path policy. When purpose is 0 (unset),
 * the EKU check is skipped entirely (matching current behavior where
 * X509_check_purpose is only called with a specific purpose). */
    #define S2N_CERT_PURPOSE_UNSET       0
    #define S2N_CERT_PURPOSE_SERVER_AUTH 1
    #define S2N_CERT_PURPOSE_CLIENT_AUTH 2

/* Policy controlling path construction and per-edge verification. */
struct s2n_cert_path_policy {
    /* Maximum allowed path depth (leaf + intermediates + anchor). */
    uint32_t max_chain_depth;
    /* Verification time in seconds since the Unix epoch. Validity windows
     * are checked against this value. */
    uint64_t verification_time;
    /* TLS purpose (serverAuth / clientAuth). Controls the EKU check after
     * path building: leaf must have the matching EKU OID, intermediates
     * must have the matching OID or anyExtendedKeyUsage. If 0 (unset),
     * the entire EKU check is skipped. */
    uint8_t purpose;
    /* Placeholder: signature/key security-policy preferences. Not enforced
     * in beyond what s2n_cert_verify_signed already rejects
     * (MD5/MD4). Full integration deferred to later phases. */
};

/* keyUsage bit definitions (named-bit-list positions, stored in byte 0 of the
 * BIT STRING contents as parsed into key_usage_bits). */
    #define S2N_KEY_USAGE_DIGITAL_SIGNATURE 0x80 /* bit 0 */
    #define S2N_KEY_USAGE_KEY_ENCIPHERMENT  0x20 /* bit 2 */
    #define S2N_KEY_USAGE_KEY_AGREEMENT     0x08 /* bit 4 */
    #define S2N_KEY_USAGE_KEY_CERT_SIGN     0x04 /* bit 5 */

/* RFC 5280 section 7.1 Distinguished Name comparison over borrowed Name TLVs.
 *
 * Two Names are equal when they have the same number of RDNs, each RDN has the
 * same number of AttributeTypeAndValues, and for each corresponding attribute:
 *  - The OIDs are byte-for-byte identical.
 *  - The values are compared according to their string type:
 *      * PrintableString and UTF8String: case-insensitive (ASCII fold) with
 *        leading/trailing whitespace stripped and interior runs of whitespace
 *        collapsed to a single space.
 *      * All other types: exact byte comparison.
 *
 * This is NOT raw-DER memcmp. Real CAs issue cross-signs where the
 * issuer/subject differ only in string type or case; raw memcmp would reject
 * those as non-matching.
 *
 * `name_a` and `name_b` must each contain a single DER Name TLV (SEQUENCE OF
 * SET OF AttributeTypeAndValue). Both must outlive this call. The comparison
 * result is written to `*equal`. Returns S2N_RESULT_OK on success; failure
 * (malformed DER in either name) results in S2N_ERR_CERT_INVALID. */
S2N_RESULT s2n_cert_name_cmp(const struct s2n_blob *name_a,
        const struct s2n_blob *name_b, bool *equal);

/* Build a validated certification path from the leaf certificate to a trust
 * anchor using backtracking search over candidate issuers.
 *
 * The search considers wire intermediates (in any order) and trust anchors as
 * candidate issuers for each certificate. Each candidate evaluation decrements
 * a shared work budget; exhaustion rejects with S2N_ERR_CERT_UNTRUSTED.
 *
 * Per-edge checks:
 *  - RFC 5280 §7.1 name match (issuer name of child == subject name of parent)
 *  - Signature verification (s2n_cert_verify_signed)
 *  - Validity window (not_before <= verification_time <= not_after)
 *  - CA constraints for wire intermediates: basicConstraints CA:TRUE,
 *    pathLenConstraint, keyUsage keyCertSign 
 *
 * Deferred validity errors: an expired or not-yet-valid certificate rejects
 * that candidate path but the search continues. The error is surfaced only if
 * no alternative valid path exists (S2N_ERR_CERT_EXPIRED / S2N_ERR_CERT_NOT_YET_VALID).
 *
 * Path depth exceeding max_chain_depth rejects with
 * S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED.
 *
 * On success, `path_out` contains the validated path from leaf to anchor.
 * The wire chain must outlive the path (entries reference it by index). */
S2N_RESULT s2n_cert_path_build(struct s2n_cert_path *path_out,
        const struct s2n_cert_chain_spans *wire,
        const struct s2n_trust_anchor_snapshot *anchors,
        const struct s2n_cert_path_policy *policy);

/* Check the extendedKeyUsage purpose for the entire validated path.
 *
 * This implements the whole-path EKU check matching today's per-chain
 * X509_check_purpose semantics:
 *  - Leaf: if EKU present, must contain the purpose OID (serverAuth or
 *    clientAuth depending on policy->purpose).
 *  - Intermediates (non-leaf, non-anchor): if EKU present, must contain
 *    either the purpose OID or the anyExtendedKeyUsage OID.
 *  - Anchor: skipped (trust anchors have implicit purpose by presence in
 *    the trust store, matching current validator behavior).
 *  - Certificates without an EKU extension pass unconditionally (they are
 *    unconstrained for any purpose).
 *  - If policy->purpose == S2N_CERT_PURPOSE_UNSET (0), the check is skipped
 *    entirely.
 *
 * Failure rejects with S2N_ERR_CERT_INTENT_INVALID. */
S2N_RESULT s2n_cert_path_check_eku(const struct s2n_cert_path *path,
        const struct s2n_cert_chain_spans *wire,
        const struct s2n_trust_anchor_snapshot *anchors,
        const struct s2n_cert_path_policy *policy);

/* Maximum number of permitted/excluded subtrees that the nameConstraints
 * parser will accept. This bounds the per-CA subtree iteration cost and
 * prevents pathological inputs from consuming unbounded processing time.
 * Exceeding this cap rejects with S2N_ERR_CERT_UNTRUSTED. */
    #define S2N_CERT_NAME_CONSTRAINTS_MAX_SUBTREES 32

/* Check nameConstraints for the entire validated path.
 *
 * For each CA in the path (intermediates and anchor) that carries a
 * nameConstraints extension, every certificate below that CA in the path is
 * checked: its SAN dNSNames, iPAddresses, and rfc822Names are validated against
 * the CA's permitted and excluded subtrees.
 *
 * Supported name forms:
 *  - dNSName [2]: suffix match (constraint is a domain suffix; the name must
 *    equal the suffix or end in '.' + suffix; empty constraint matches all).
 *  - iPAddress [7]: subnet match (constraint = address || mask; name is within
 *    the subtree if (name & mask) == (address & mask)).
 *  - rfc822Name [1]: if constraint starts with '.', domain suffix match on the
 *    domain part; if it contains '@', exact mailbox match; otherwise exact
 *    domain match on the domain part.
 *
 * Unsupported name forms: directoryName [4] and all others. If a CRITICAL
 * nameConstraints extension contains a subtree with an unsupported name form,
 * the path is rejected with S2N_ERR_CERT_UNHANDLED_CRITICAL_EXTENSION.
 *
 * Name constraint violations reject with S2N_ERR_CERT_UNTRUSTED (matching the
 * error the libcrypto path uses for nameConstraints failures).
 *
 * The subtree count is bounded by S2N_CERT_NAME_CONSTRAINTS_MAX_SUBTREES;
 * exceeding it rejects with S2N_ERR_CERT_UNTRUSTED. */
S2N_RESULT s2n_cert_path_check_name_constraints(const struct s2n_cert_path *path,
        const struct s2n_cert_chain_spans *wire,
        const struct s2n_trust_anchor_snapshot *anchors);

/* Check that every critical extension on every certificate in the validated
 * path (leaf + intermediates, excluding the trust anchor) is either in the
 * "processed" set (extensions the zero-copy verifier handles) or registered
 * as a custom critical extension OID by the application.
 *
 * Processed extensions (handled by the path builder or constraint checker):
 *  - basicConstraints     2.5.29.19  {0x55, 0x1d, 0x13}
 *  - keyUsage             2.5.29.15  {0x55, 0x1d, 0x0f}
 *  - extKeyUsage          2.5.29.37  {0x55, 0x1d, 0x25}
 *  - nameConstraints      2.5.29.30  {0x55, 0x1d, 0x1e}
 *  - subjectKeyIdentifier 2.5.29.14  {0x55, 0x1d, 0x0e}
 *  - authorityKeyIdentifier 2.5.29.35 {0x55, 0x1d, 0x23}
 *  - subjectAltName       2.5.29.17  {0x55, 0x1d, 0x11}
 *
 * Custom OIDs are passed as a simple array of s2n_blob + count. In 
 * these will be wired from the s2n_config's custom_x509_extension_oids; for
 * the caller provides them directly.
 *
 * If any critical OID is not in the processed set and not in the custom list,
 * the function rejects with S2N_ERR_CERT_UNHANDLED_CRITICAL_EXTENSION (,
 * 4.8). */
S2N_RESULT s2n_cert_path_check_critical_extensions(const struct s2n_cert_path *path,
        const struct s2n_cert_chain_spans *wire,
        const struct s2n_trust_anchor_snapshot *anchors,
        const struct s2n_blob *custom_oids, uint32_t custom_oid_count);

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */
