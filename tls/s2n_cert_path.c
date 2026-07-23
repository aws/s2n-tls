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

#include "utils/s2n_safety.h"

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    #include <openssl/bytestring.h>
    #include <openssl/evp.h>
    #include <string.h>

    #include "crypto/s2n_pkey.h"

DEFINE_POINTER_CLEANUP_FUNC(EVP_PKEY *, EVP_PKEY_free);

/* RFC 5280 section 7.1 Name comparison.
 *
 * Name ::= SEQUENCE OF RelativeDistinguishedName
 * RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
 * AttributeTypeAndValue ::= SEQUENCE { type OBJECT IDENTIFIER, value ANY }
 *
 * Comparison rules:
 *  - Same number of RDNs, in order.
 *  - Each RDN has the same number of attributes, compared in sequence (DER's
 *    SET ordering guarantees a canonical sequence for DER-encoded Names).
 *  - For each attribute pair: OIDs must match byte-for-byte.
 *  - Value comparison depends on the string type tag:
 *      * PrintableString (0x13) or UTF8String (0x0c): ASCII case-fold plus
 *        whitespace normalization (strip leading/trailing, collapse interior
 *        runs to a single 0x20).
 *      * Any other type: exact byte comparison.
 */

/* ASCII lowercase fold: letters become lowercase for comparison. */
static uint8_t s2n_cert_name_ascii_lower(uint8_t c)
{
    if (c >= 'A' && c <= 'Z') {
        return c + ('a' - 'A');
    }
    return c;
}

static bool s2n_cert_name_is_whitespace(uint8_t c)
{
    return c == ' ';
}

/* Compare two string values with RFC 5280 §7.1 normalization:
 * - Strip leading and trailing whitespace.
 * - Collapse interior whitespace runs to a single space.
 * - Case-fold ASCII letters. */
static bool s2n_cert_name_normalized_eq(const uint8_t *a, size_t a_len,
        const uint8_t *b, size_t b_len)
{
    /* Skip leading whitespace. */
    size_t ai = 0, bi = 0;
    while (ai < a_len && s2n_cert_name_is_whitespace(a[ai])) {
        ai++;
    }
    while (bi < b_len && s2n_cert_name_is_whitespace(b[bi])) {
        bi++;
    }

    /* Determine effective ends (strip trailing whitespace). */
    size_t a_end = a_len;
    while (a_end > ai && s2n_cert_name_is_whitespace(a[a_end - 1])) {
        a_end--;
    }
    size_t b_end = b_len;
    while (b_end > bi && s2n_cert_name_is_whitespace(b[b_end - 1])) {
        b_end--;
    }

    /* Compare character-by-character with whitespace collapsing. */
    while (ai < a_end && bi < b_end) {
        bool a_ws = s2n_cert_name_is_whitespace(a[ai]);
        bool b_ws = s2n_cert_name_is_whitespace(b[bi]);

        if (a_ws && b_ws) {
            /* Both in a whitespace run: skip all whitespace in each. */
            while (ai < a_end && s2n_cert_name_is_whitespace(a[ai])) {
                ai++;
            }
            while (bi < b_end && s2n_cert_name_is_whitespace(b[bi])) {
                bi++;
            }
        } else if (a_ws || b_ws) {
            /* One side has whitespace, the other does not: not equal. */
            return false;
        } else {
            /* Non-whitespace: compare with case fold. */
            if (s2n_cert_name_ascii_lower(a[ai]) != s2n_cert_name_ascii_lower(b[bi])) {
                return false;
            }
            ai++;
            bi++;
        }
    }

    /* Both must be exhausted at the same time. */
    return (ai == a_end) && (bi == b_end);
}

/* Compare one AttributeTypeAndValue pair. Returns true if equal. */
static S2N_RESULT s2n_cert_name_attr_cmp(CBS *attr_a, CBS *attr_b, bool *equal)
{
    RESULT_ENSURE_REF(equal);
    *equal = false;

    /* Each attribute is SEQUENCE { OID, value } */
    CBS a_seq = { 0 }, b_seq = { 0 };
    RESULT_ENSURE(CBS_get_asn1(attr_a, &a_seq, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_get_asn1(attr_b, &b_seq, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);

    /* OID comparison: byte-for-byte. */
    CBS a_oid = { 0 }, b_oid = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&a_seq, &a_oid, CBS_ASN1_OBJECT), S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_get_asn1(&b_seq, &b_oid, CBS_ASN1_OBJECT), S2N_ERR_CERT_INVALID);

    if (CBS_len(&a_oid) != CBS_len(&b_oid)
            || memcmp(CBS_data(&a_oid), CBS_data(&b_oid), CBS_len(&a_oid)) != 0) {
        *equal = false;
        return S2N_RESULT_OK;
    }

    /* Read value: get the tag and contents. */
    CBS a_val = { 0 }, b_val = { 0 };
    CBS_ASN1_TAG a_tag = 0, b_tag = 0;
    RESULT_ENSURE(CBS_get_any_asn1(&a_seq, &a_val, &a_tag), S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_get_any_asn1(&b_seq, &b_val, &b_tag), S2N_ERR_CERT_INVALID);

    /* No trailing bytes in the attribute SEQUENCE. */
    RESULT_ENSURE(CBS_len(&a_seq) == 0, S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_len(&b_seq) == 0, S2N_ERR_CERT_INVALID);

    /* Determine if we should apply case-folding and whitespace normalization.
     * Per RFC 5280 §7.1: if EITHER value is PrintableString or UTF8String we
     * apply the normalized comparison. This handles the cross-sign case where
     * one CA encodes a name as PrintableString and another as UTF8String. */
    bool a_normalize = (a_tag == CBS_ASN1_PRINTABLESTRING || a_tag == CBS_ASN1_UTF8STRING);
    bool b_normalize = (b_tag == CBS_ASN1_PRINTABLESTRING || b_tag == CBS_ASN1_UTF8STRING);

    if (a_normalize && b_normalize) {
        *equal = s2n_cert_name_normalized_eq(CBS_data(&a_val), CBS_len(&a_val),
                CBS_data(&b_val), CBS_len(&b_val));
    } else {
        /* Exact byte comparison: tags must also match. */
        if (a_tag != b_tag) {
            *equal = false;
        } else if (CBS_len(&a_val) != CBS_len(&b_val)) {
            *equal = false;
        } else {
            *equal = (memcmp(CBS_data(&a_val), CBS_data(&b_val), CBS_len(&a_val)) == 0);
        }
    }

    return S2N_RESULT_OK;
}

/* Compare one RDN (SET OF AttributeTypeAndValue). */
static S2N_RESULT s2n_cert_name_rdn_cmp(CBS *rdn_a, CBS *rdn_b, bool *equal)
{
    RESULT_ENSURE_REF(equal);
    *equal = false;

    CBS a_set = { 0 }, b_set = { 0 };
    RESULT_ENSURE(CBS_get_asn1(rdn_a, &a_set, CBS_ASN1_SET), S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_get_asn1(rdn_b, &b_set, CBS_ASN1_SET), S2N_ERR_CERT_INVALID);

    /* Compare attributes in sequence. DER guarantees SET ordering, so
     * comparing in sequence is correct for DER-encoded Names. */
    while (CBS_len(&a_set) > 0 && CBS_len(&b_set) > 0) {
        bool attr_eq = false;
        RESULT_GUARD(s2n_cert_name_attr_cmp(&a_set, &b_set, &attr_eq));
        if (!attr_eq) {
            *equal = false;
            return S2N_RESULT_OK;
        }
    }

    /* Both SETs must be fully consumed (same number of attributes). */
    *equal = (CBS_len(&a_set) == 0 && CBS_len(&b_set) == 0);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_cert_name_cmp(const struct s2n_blob *name_a,
        const struct s2n_blob *name_b, bool *equal)
{
    RESULT_ENSURE_REF(name_a);
    RESULT_ENSURE_REF(name_b);
    RESULT_ENSURE_REF(equal);
    *equal = false;

    /* Fast path: identical bytes means equal. */
    if (name_a->size == name_b->size && name_a->data != NULL && name_b->data != NULL
            && memcmp(name_a->data, name_b->data, name_a->size) == 0) {
        *equal = true;
        return S2N_RESULT_OK;
    }

    /* Parse the outer Name SEQUENCE from each TLV. */
    CBS a_tlv = { 0 }, b_tlv = { 0 };
    CBS_init(&a_tlv, name_a->data, name_a->size);
    CBS_init(&b_tlv, name_b->data, name_b->size);

    CBS a_seq = { 0 }, b_seq = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&a_tlv, &a_seq, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_get_asn1(&b_tlv, &b_seq, CBS_ASN1_SEQUENCE), S2N_ERR_CERT_INVALID);

    /* Name TLV must be consumed exactly. */
    RESULT_ENSURE(CBS_len(&a_tlv) == 0, S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(CBS_len(&b_tlv) == 0, S2N_ERR_CERT_INVALID);

    /* Compare RDN-by-RDN in order. */
    while (CBS_len(&a_seq) > 0 && CBS_len(&b_seq) > 0) {
        bool rdn_eq = false;
        RESULT_GUARD(s2n_cert_name_rdn_cmp(&a_seq, &b_seq, &rdn_eq));
        if (!rdn_eq) {
            *equal = false;
            return S2N_RESULT_OK;
        }
    }

    /* Both sequences must be fully consumed (same number of RDNs). */
    *equal = (CBS_len(&a_seq) == 0 && CBS_len(&b_seq) == 0);
    return S2N_RESULT_OK;
}

/* --- Path builder implementation --- */

/* Deferred validity error: records which validity violation was seen so it can
 * be surfaced if no valid alternative path exists. */
typedef enum {
    S2N_CERT_VALIDITY_OK = 0,
    S2N_CERT_VALIDITY_EXPIRED,      /* not_after < verification_time */
    S2N_CERT_VALIDITY_NOT_YET_VALID /* not_before > verification_time */
} s2n_cert_validity_error;

/* Materialize an s2n_pkey from a SubjectPublicKeyInfo TLV span. Uses
 * d2i_PUBKEY on the SPKI bytes to get an EVP_PKEY, then wraps it in the
 * s2n_pkey structure with type dispatch. The caller owns the result and
 * must free it with s2n_pkey_free. */
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

/* Check the validity window of a candidate issuer cert against the policy's
 * verification time. Returns the type of validity violation (OK if within
 * window). This does NOT fail the function; the caller records the error
 * for deferred surfacing. */
static s2n_cert_validity_error s2n_cert_path_check_validity(
        const struct s2n_cert_span_view *view, uint64_t verification_time)
{
    /* verification_time == 0 is a sentinel meaning "skip time checks" — used
     * when disable_x509_time_validation is set. No real TLS connection runs at
     * time 0 (Unix epoch), so this is safe as a skip signal. */
    if (verification_time == 0) {
        return S2N_CERT_VALIDITY_OK;
    }
    if (verification_time > view->not_after) {
        return S2N_CERT_VALIDITY_EXPIRED;
    }
    if (verification_time < view->not_before) {
        return S2N_CERT_VALIDITY_NOT_YET_VALID;
    }
    return S2N_CERT_VALIDITY_OK;
}

/* Verify one edge of the certification path: child was issued by candidate
 * parent. Checks name match, signature verification, validity window, and
 * CA constraints (for wire intermediates).
 *
 * `parent_is_anchor` indicates whether the parent is a trust anchor. Trust
 * anchors are CAs by definition (matching libcrypto's X509_V_FLAG_PARTIAL_CHAIN
 * behavior) and do not require basicConstraints CA:TRUE. Wire intermediates DO
 * require basicConstraints CA:TRUE to act as issuers.
 *
 * Returns S2N_RESULT_OK on success. On validity failure, writes the error type
 * to *validity_err and returns S2N_RESULT_OK (caller handles deferred logic).
 * On hard failure (name mismatch, bad signature, CA constraint violation),
 * returns error. */
static S2N_RESULT s2n_cert_path_verify_edge(
        const struct s2n_cert_span_view *child,
        const struct s2n_cert_span_view *parent,
        uint64_t verification_time,
        bool parent_is_anchor,
        uint32_t *work_remaining,
        s2n_cert_validity_error *validity_err)
{
    RESULT_ENSURE_REF(child);
    RESULT_ENSURE_REF(parent);
    RESULT_ENSURE_REF(work_remaining);
    RESULT_ENSURE_REF(validity_err);
    *validity_err = S2N_CERT_VALIDITY_OK;

    /* 1. RFC 5280 name match: child's issuer == parent's subject. */
    bool names_match = false;
    RESULT_GUARD(s2n_cert_name_cmp(&child->issuer, &parent->subject, &names_match));
    RESULT_ENSURE(names_match, S2N_ERR_CERT_UNTRUSTED);

    /* The Work_Budget bounds expensive candidate evaluations (public key
     * materialization + signature verification), so it is charged here, only
     * after the issuer name matched. Cheap name scans are NOT charged: a
     * trust store realistically holds more anchors than the entire budget
     * (a system CA bundle is ~150 certificates), and a per-scan charge would
     * exhaust the budget before ever reaching the matching anchor. */
    RESULT_ENSURE(*work_remaining > 0, S2N_ERR_CERT_UNTRUSTED);
    (*work_remaining)--;

    /* 2. CA constraint checks for wire intermediates acting as issuers.
     * Trust anchors are treated as CAs by definition. */
    if (!parent_is_anchor) {
        /* basicConstraints CA:TRUE required for intermediates. */
        RESULT_ENSURE(parent->basic_constraints_present && parent->basic_constraints_is_ca,
                S2N_ERR_CERT_UNTRUSTED);
    }

    /* 3. keyUsage keyCertSign check: when keyUsage is present on any issuer
     * (intermediate OR anchor), keyCertSign must be set. */
    if (parent->key_usage_present) {
        RESULT_ENSURE(parent->key_usage_bits & S2N_KEY_USAGE_KEY_CERT_SIGN,
                S2N_ERR_CERT_UNTRUSTED);
    }

    /* 4. Signature verification: parent signed child. Materialize the
     * parent's public key from its SPKI span. */
    DEFER_CLEANUP(struct s2n_pkey issuer_key = { 0 }, s2n_pkey_free);
    RESULT_GUARD(s2n_cert_path_pkey_from_spki(&parent->spki, &issuer_key));
    RESULT_GUARD(s2n_cert_verify_signed(&child->tbs, &child->outer_sig_alg,
            &child->sig, &issuer_key));

    /* 5. Validity window check on the parent cert. A violation does not
     * hard-fail the edge; it is recorded for deferred surfacing. */
    *validity_err = s2n_cert_path_check_validity(parent, verification_time);

    return S2N_RESULT_OK;
}

/* Internal state for the backtracking path search. */
struct s2n_cert_path_search_state {
    const struct s2n_cert_chain_spans *wire;
    const struct s2n_trust_anchor_snapshot *anchors;
    const struct s2n_cert_path_policy *policy;
    struct s2n_cert_path *path;
    uint32_t work_remaining;
    /* Track which wire certs are already in the current path to avoid cycles. */
    bool wire_used[S2N_CERT_CHAIN_SPANS_MAX];
    /* Deferred validity error: the "worst" validity error seen across all
     * explored candidate paths. */
    s2n_cert_validity_error deferred_validity_err;
};

/* Recursive backtracking search: try to extend the current path from `current`
 * to a trust anchor. Returns true if a valid path was found, false otherwise.
 * On budget exhaustion, sets the path count to 0 and returns false; the caller
 * surfaces S2N_ERR_CERT_UNTRUSTED. */
static bool s2n_cert_path_search(struct s2n_cert_path_search_state *state,
        const struct s2n_cert_span_view *current, uint32_t depth)
{
    /* Depth check: if we've already reached max depth, no room for an issuer. */
    if (depth >= state->policy->max_chain_depth) {
        return false;
    }

    /* Try trust anchors first: if a trust anchor issued this cert, we're done. */
    for (uint32_t i = 0; i < state->anchors->count; i++) {
        if (state->work_remaining == 0) {
            return false;
        }

        const struct s2n_cert_span_view *anchor = &state->anchors->anchors[i].parsed;
        s2n_cert_validity_error validity_err = S2N_CERT_VALIDITY_OK;

        if (s2n_result_is_ok(s2n_cert_path_verify_edge(current, anchor,
                    state->policy->verification_time, true /* parent_is_anchor */,
                    &state->work_remaining, &validity_err))) {
            if (validity_err == S2N_CERT_VALIDITY_OK) {
                /* Valid anchor found. Record it and return success. */
                state->path->entries[depth].type = S2N_CERT_PATH_ENTRY_ANCHOR;
                state->path->entries[depth].entry_index = i;
                state->path->count = depth + 1;
                return true;
            }
            /* Validity failure: record and continue searching. */
            if (state->deferred_validity_err == S2N_CERT_VALIDITY_OK) {
                state->deferred_validity_err = validity_err;
            }
        }
    }

    /* Try wire intermediates as candidate issuers. */
    for (uint32_t i = 0; i < state->wire->count; i++) {
        if (state->wire_used[i]) {
            continue;
        }
        if (state->work_remaining == 0) {
            return false;
        }

        const struct s2n_cert_span_view *candidate = &state->wire->views[i];
        s2n_cert_validity_error validity_err = S2N_CERT_VALIDITY_OK;

        if (s2n_result_is_ok(s2n_cert_path_verify_edge(current, candidate,
                    state->policy->verification_time, false /* parent_is_anchor */,
                    &state->work_remaining, &validity_err))) {
            if (validity_err != S2N_CERT_VALIDITY_OK) {
                /* Validity failure: record and continue. */
                if (state->deferred_validity_err == S2N_CERT_VALIDITY_OK) {
                    state->deferred_validity_err = validity_err;
                }
                continue;
            }

            /* Edge verified. Try to extend the path from this candidate. */
            state->wire_used[i] = true;
            state->path->entries[depth].type = S2N_CERT_PATH_ENTRY_WIRE;
            state->path->entries[depth].entry_index = i;

            if (s2n_cert_path_search(state, candidate, depth + 1)) {
                return true;
            }

            /* Backtrack: this candidate didn't lead to a valid path. */
            state->wire_used[i] = false;
        }
    }

    return false;
}

S2N_RESULT s2n_cert_path_build(struct s2n_cert_path *path_out,
        const struct s2n_cert_chain_spans *wire,
        const struct s2n_trust_anchor_snapshot *anchors,
        const struct s2n_cert_path_policy *policy)
{
    RESULT_ENSURE_REF(path_out);
    RESULT_ENSURE_REF(wire);
    RESULT_ENSURE_REF(anchors);
    RESULT_ENSURE_REF(policy);

    *path_out = (struct s2n_cert_path){ 0 };

    /* A wire chain must have at least one certificate (the leaf). */
    RESULT_ENSURE(wire->count > 0, S2N_ERR_CERT_UNTRUSTED);

    /* Max chain depth must accommodate at least the leaf + one anchor. */
    RESULT_ENSURE(policy->max_chain_depth >= 2, S2N_ERR_CERT_UNTRUSTED);
    RESULT_ENSURE(policy->max_chain_depth <= S2N_CERT_PATH_MAX_DEPTH,
            S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED);

    /* Also check the leaf's validity window. */
    const struct s2n_cert_span_view *leaf = &wire->views[0];

    struct s2n_cert_path_search_state state = { 0 };
    state.wire = wire;
    state.anchors = anchors;
    state.policy = policy;
    state.path = path_out;
    state.work_remaining = S2N_CERT_PATH_WORK_BUDGET;
    state.deferred_validity_err = S2N_CERT_VALIDITY_OK;

    /* Mark the leaf as used so it cannot appear again as an intermediate. */
    state.wire_used[0] = true;

    /* Record the leaf as the first entry in the path. */
    path_out->entries[0].type = S2N_CERT_PATH_ENTRY_WIRE;
    path_out->entries[0].entry_index = 0;

    /* Check leaf validity. */
    s2n_cert_validity_error leaf_validity = s2n_cert_path_check_validity(
            leaf, policy->verification_time);
    if (leaf_validity != S2N_CERT_VALIDITY_OK) {
        state.deferred_validity_err = leaf_validity;
    }

    bool found = false;

    /* Direct trust: the leaf itself is a trust anchor (byte-identical DER).
     * The libcrypto path sets X509_V_FLAG_PARTIAL_CHAIN, under which
     * X509_verify_cert accepts any store certificate as the end of a chain
     * without treating it as an issuer, so no CA / keyCertSign requirements
     * apply here; those checks only constrain certificates that issue others.
     * Matching libcrypto's internal_verify, the signature is only checked when
     * the certificate is self-issued (it is then verified against its own
     * key); a non-self-issued store cert ends a partial chain with no issuer
     * available to check. The resulting path is depth 1: just the leaf. */
    if (leaf_validity == S2N_CERT_VALIDITY_OK) {
        for (uint32_t i = 0; i < anchors->count; i++) {
            const struct s2n_blob *anchor_der = &anchors->anchors[i].der;
            if (anchor_der->size == leaf->raw.size
                    && anchor_der->data != NULL && leaf->raw.data != NULL
                    && memcmp(anchor_der->data, leaf->raw.data, leaf->raw.size) == 0) {
                bool self_issued = false;
                RESULT_GUARD(s2n_cert_name_cmp(&leaf->subject, &leaf->issuer, &self_issued));
                if (self_issued) {
                    DEFER_CLEANUP(struct s2n_pkey leaf_key = { 0 }, s2n_pkey_free);
                    RESULT_GUARD(s2n_cert_path_pkey_from_spki(&leaf->spki, &leaf_key));
                    RESULT_GUARD(s2n_cert_verify_signed(&leaf->tbs, &leaf->outer_sig_alg,
                            &leaf->sig, &leaf_key));
                }
                path_out->count = 1;
                found = true;
                break;
            }
        }
    }

    /* Start the backtracking search from the leaf, looking for its issuer
     * at depth index 1 (leaf is at index 0). */
    if (!found && leaf_validity == S2N_CERT_VALIDITY_OK) {
        found = s2n_cert_path_search(&state, leaf, 1);
    }

    if (found) {
        /* Fix up path: the leaf is entry[0]; search wrote entries[1..count-1].
         * The total path length includes the leaf. */
        path_out->count = state.path->count;
        /* Ensure the leaf is in position 0. */
        path_out->entries[0].type = S2N_CERT_PATH_ENTRY_WIRE;
        path_out->entries[0].entry_index = 0;

        /* pathLenConstraint check: for each CA in the path that has
         * basicConstraints.pathLenConstraint, count the non-self-issued
         * subordinate CA certificates below it. If the count exceeds the
         * constraint, reject with S2N_ERR_CERT_UNTRUSTED.
         *
         * Path layout: entries[0] = leaf, entries[1..count-2] = intermediates,
         * entries[count-1] = trust anchor.
         * "Below" a CA at index i means certificates at indices 0..i-1.
         * Non-self-issued subordinate CAs are wire intermediates (not the leaf,
         * not the anchor, and not self-issued). */
        for (uint32_t i = 1; i < path_out->count; i++) {
            const struct s2n_cert_span_view *ca_view = NULL;
            if (path_out->entries[i].type == S2N_CERT_PATH_ENTRY_WIRE) {
                ca_view = &wire->views[path_out->entries[i].entry_index];
            } else {
                ca_view = &anchors->anchors[path_out->entries[i].entry_index].parsed;
            }

            if (!ca_view->basic_constraints_has_path_len) {
                continue;
            }

            /* Count non-self-issued subordinate CA certs below this CA.
             * Subordinate CAs are at indices 1..i-1 (the leaf at index 0
             * is not a CA). A cert is self-issued when its subject == issuer. */
            uint64_t subordinate_ca_count = 0;
            for (uint32_t j = 1; j < i; j++) {
                const struct s2n_cert_span_view *sub_view = NULL;
                if (path_out->entries[j].type == S2N_CERT_PATH_ENTRY_WIRE) {
                    sub_view = &wire->views[path_out->entries[j].entry_index];
                } else {
                    sub_view = &anchors->anchors[path_out->entries[j].entry_index].parsed;
                }

                /* Check if self-issued (subject == issuer). Self-issued certs
                 * do not count against pathLenConstraint per RFC 5280 §4.2.1.9. */
                bool self_issued = false;
                RESULT_GUARD(s2n_cert_name_cmp(&sub_view->subject, &sub_view->issuer,
                        &self_issued));
                if (!self_issued) {
                    subordinate_ca_count++;
                }
            }

            RESULT_ENSURE(subordinate_ca_count <= ca_view->basic_constraints_path_len,
                    S2N_ERR_CERT_UNTRUSTED);
        }

        /* EKU purpose loop: check the whole path for EKU compliance
         * after the pathLen check passes. */
        RESULT_GUARD(s2n_cert_path_check_eku(path_out, wire, anchors, policy));

        /* nameConstraints enforcement: check all certificates in
         * the path against each CA's nameConstraints. */
        RESULT_GUARD(s2n_cert_path_check_name_constraints(path_out, wire, anchors));

        /* Critical-extension sweep: reject any critical extension
         * not in the processed set and not custom-registered. No custom OIDs
         * are wired from config at this phase; will pass them. */
        RESULT_GUARD(s2n_cert_path_check_critical_extensions(
                path_out, wire, anchors, NULL, 0));

        return S2N_RESULT_OK;
    }

    /* No valid path found. Surface the appropriate error. */
    if (state.work_remaining == 0) {
        RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
    }

    /* Check if path depth was the limiting factor. If the chain is longer
     * than max_chain_depth, surface that specific error. */
    if (wire->count + 1 > policy->max_chain_depth) {
        RESULT_BAIL(S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED);
    }

    /* Surface deferred validity errors. */
    if (state.deferred_validity_err == S2N_CERT_VALIDITY_EXPIRED) {
        RESULT_BAIL(S2N_ERR_CERT_EXPIRED);
    }
    if (state.deferred_validity_err == S2N_CERT_VALIDITY_NOT_YET_VALID) {
        RESULT_BAIL(S2N_ERR_CERT_NOT_YET_VALID);
    }

    /* No matching issuer at all. */
    RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
}

/* --- EKU purpose loop --- */

/* OID bytes for id-kp-serverAuth: 1.3.6.1.5.5.7.3.1 */
static const uint8_t s2n_oid_server_auth[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
/* OID bytes for id-kp-clientAuth: 1.3.6.1.5.5.7.3.2 */
static const uint8_t s2n_oid_client_auth[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02 };
/* OID bytes for anyExtendedKeyUsage: 2.5.29.37.0 */
static const uint8_t s2n_oid_any_eku[] = { 0x55, 0x1d, 0x25, 0x00 };

/* Check if the EKU extension contents contain the target OID.
 *
 * The `eku` blob points to the OCTET STRING inner contents of the EKU
 * extension (the extnValue). Inside that is a SEQUENCE OF OBJECT IDENTIFIER.
 * We parse with CBS: get the outer SEQUENCE, then iterate each OID checking
 * for a match against `target_oid`. */
static S2N_RESULT s2n_cert_eku_contains_oid(const struct s2n_blob *eku,
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
    /* The EKU extnValue must contain exactly the SEQUENCE, no trailing bytes. */
    RESULT_ENSURE(CBS_len(&eku_cbs) == 0, S2N_ERR_CERT_INVALID);

    /* Iterate over OIDs in the sequence. */
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

/* Check a single certificate's EKU against the required purpose.
 *
 * For the leaf: if EKU is present, it must contain the purpose OID.
 * For intermediates: if EKU is present, it must contain either the purpose
 * OID or anyExtendedKeyUsage.
 * If EKU is absent (eku.data == NULL), the certificate is unconstrained. */
static S2N_RESULT s2n_cert_path_check_eku_for_cert(
        const struct s2n_cert_span_view *view,
        const uint8_t *purpose_oid, size_t purpose_oid_len,
        bool is_leaf)
{
    RESULT_ENSURE_REF(view);

    /* No EKU extension → unconstrained, passes for any purpose. */
    if (view->eku.data == NULL || view->eku.size == 0) {
        return S2N_RESULT_OK;
    }

    /* Check for the purpose OID (serverAuth or clientAuth). */
    bool has_purpose = false;
    RESULT_GUARD(s2n_cert_eku_contains_oid(&view->eku, purpose_oid, purpose_oid_len,
            &has_purpose));
    if (has_purpose) {
        return S2N_RESULT_OK;
    }

    /* For intermediates (non-leaf), anyExtendedKeyUsage also satisfies. */
    if (!is_leaf) {
        bool has_any_eku = false;
        RESULT_GUARD(s2n_cert_eku_contains_oid(&view->eku, s2n_oid_any_eku,
                sizeof(s2n_oid_any_eku), &has_any_eku));
        if (has_any_eku) {
            return S2N_RESULT_OK;
        }
    }

    /* EKU is present but does not satisfy the requirement. */
    RESULT_BAIL(S2N_ERR_CERT_INTENT_INVALID);
}

S2N_RESULT s2n_cert_path_check_eku(const struct s2n_cert_path *path,
        const struct s2n_cert_chain_spans *wire,
        const struct s2n_trust_anchor_snapshot *anchors,
        const struct s2n_cert_path_policy *policy)
{
    RESULT_ENSURE_REF(path);
    RESULT_ENSURE_REF(wire);
    RESULT_ENSURE_REF(anchors);
    RESULT_ENSURE_REF(policy);

    /* If purpose is unset, skip the EKU check entirely. */
    if (policy->purpose == S2N_CERT_PURPOSE_UNSET) {
        return S2N_RESULT_OK;
    }

    /* Determine which OID to check based on purpose. */
    const uint8_t *purpose_oid = NULL;
    size_t purpose_oid_len = 0;
    if (policy->purpose == S2N_CERT_PURPOSE_SERVER_AUTH) {
        purpose_oid = s2n_oid_server_auth;
        purpose_oid_len = sizeof(s2n_oid_server_auth);
    } else if (policy->purpose == S2N_CERT_PURPOSE_CLIENT_AUTH) {
        purpose_oid = s2n_oid_client_auth;
        purpose_oid_len = sizeof(s2n_oid_client_auth);
    } else {
        RESULT_BAIL(S2N_ERR_CERT_INTENT_INVALID);
    }

    /* Check each certificate in the path except the trust anchor.
     * Path layout: entries[0] = leaf, entries[1..count-2] = intermediates,
     * entries[count-1] = trust anchor.
     * The trust anchor is skipped (implicit purpose from presence in store),
     * EXCEPT for a depth-1 directly-trusted leaf: X509_check_purpose runs on
     * the leaf regardless of how it is trusted, so we still check it. */
    RESULT_ENSURE(path->count >= 1, S2N_ERR_CERT_UNTRUSTED);

    uint32_t check_count = path->count;
    if (path->count >= 2) {
        check_count = path->count - 1; /* exclude anchor */
    }
    for (uint32_t i = 0; i < check_count; i++) {
        const struct s2n_cert_span_view *view = NULL;
        if (path->entries[i].type == S2N_CERT_PATH_ENTRY_WIRE) {
            RESULT_ENSURE(path->entries[i].entry_index < wire->count, S2N_ERR_CERT_UNTRUSTED);
            view = &wire->views[path->entries[i].entry_index];
        } else {
            RESULT_ENSURE(path->entries[i].entry_index < anchors->count, S2N_ERR_CERT_UNTRUSTED);
            view = &anchors->anchors[path->entries[i].entry_index].parsed;
        }

        bool is_leaf = (i == 0);
        RESULT_GUARD(s2n_cert_path_check_eku_for_cert(view, purpose_oid, purpose_oid_len,
                is_leaf));

        /* KeyUsage intent check on the leaf (matches X509_check_purpose behavior).
         * If KeyUsage is present on the leaf:
         *   - keyCertSign alone on a leaf is invalid (it's a CA-only bit)
         *   - serverAuth requires digitalSignature or keyEncipherment or keyAgreement
         *   - clientAuth requires digitalSignature */
        if (is_leaf && view->key_usage_present) {
            uint16_t ku = view->key_usage_bits;

            /* Reject leaf certs with keyCertSign — that's a CA-only bit. */
            if (ku & S2N_KEY_USAGE_KEY_CERT_SIGN) {
                RESULT_BAIL(S2N_ERR_CERT_INTENT_INVALID);
            }

            if (policy->purpose == S2N_CERT_PURPOSE_SERVER_AUTH) {
                /* Server leaf needs digitalSignature, keyEncipherment, or keyAgreement. */
                bool has_valid_ku = (ku & S2N_KEY_USAGE_DIGITAL_SIGNATURE)
                        || (ku & S2N_KEY_USAGE_KEY_ENCIPHERMENT)
                        || (ku & S2N_KEY_USAGE_KEY_AGREEMENT);
                RESULT_ENSURE(has_valid_ku, S2N_ERR_CERT_INTENT_INVALID);
            } else if (policy->purpose == S2N_CERT_PURPOSE_CLIENT_AUTH) {
                /* Client leaf needs digitalSignature. */
                RESULT_ENSURE(ku & S2N_KEY_USAGE_DIGITAL_SIGNATURE,
                        S2N_ERR_CERT_INTENT_INVALID);
            }
        }
    }

    return S2N_RESULT_OK;
}

/* --- nameConstraints enforcement --- */

/* GeneralName context-specific tags per RFC 5280 §4.2.1.6. */
    #define S2N_GEN_NAME_RFC822   1
    #define S2N_GEN_NAME_DNS      2
    #define S2N_GEN_NAME_DIR_NAME 4
    #define S2N_GEN_NAME_IP       7

/* Parse a single GeneralSubtree from a CBS cursor. Returns the GeneralName tag,
 * and the name value bytes in *name_out. Skips minimum/maximum fields. */
static S2N_RESULT s2n_nc_parse_subtree(CBS *subtrees_cbs, uint8_t *tag_out,
        CBS *name_out)
{
    RESULT_ENSURE_REF(subtrees_cbs);
    RESULT_ENSURE_REF(tag_out);
    RESULT_ENSURE_REF(name_out);

    /* GeneralSubtree ::= SEQUENCE { base GeneralName, ... } */
    CBS subtree_seq = { 0 };
    RESULT_ENSURE(CBS_get_asn1(subtrees_cbs, &subtree_seq, CBS_ASN1_SEQUENCE),
            S2N_ERR_CERT_INVALID);

    /* GeneralName is a CHOICE with context-specific tags. Read the raw tag. */
    CBS element = { 0 };
    unsigned int cbs_tag = 0;
    RESULT_ENSURE(CBS_get_any_asn1(&subtree_seq, &element, &cbs_tag),
            S2N_ERR_CERT_INVALID);

    /* Extract the implicit tag number (low 5 bits of the raw tag). */
    *tag_out = (uint8_t) (cbs_tag & 0x1f);
    *name_out = element;

    /* We ignore minimum [0] DEFAULT 0, maximum [1] OPTIONAL per common practice. */
    return S2N_RESULT_OK;
}

/* dNSName suffix matching: constraint is a domain suffix; name must be that
 * suffix or end in '.' + suffix. Empty constraint matches everything. */
static bool s2n_nc_dns_match(const uint8_t *name, size_t name_len,
        const uint8_t *constraint, size_t constraint_len)
{
    /* Empty constraint matches all names. */
    if (constraint_len == 0) {
        return true;
    }

    /* If constraint starts with '.', the name must end with it OR equal it
     * minus the leading dot (e.g., constraint ".example.com" matches
     * "host.example.com" and "example.com"). We normalize: strip leading dot
     * from constraint for comparison. */
    const uint8_t *c_start = constraint;
    size_t c_len = constraint_len;
    if (c_len > 0 && c_start[0] == '.') {
        c_start++;
        c_len--;
    }

    /* Exact match (name == constraint without leading dot), case-insensitive. */
    if (name_len == c_len) {
        for (size_t i = 0; i < name_len; i++) {
            uint8_t a = name[i];
            uint8_t b = c_start[i];
            if (a >= 'A' && a <= 'Z') {
                a += 'a' - 'A';
            }
            if (b >= 'A' && b <= 'Z') {
                b += 'a' - 'A';
            }
            if (a != b) {
                return false;
            }
        }
        return true;
    }

    /* Suffix match: name must end in '.' + constraint. */
    if (name_len > c_len + 1) {
        size_t offset = name_len - c_len;
        if (name[offset - 1] == '.') {
            /* Case-insensitive compare for DNS names. */
            for (size_t i = 0; i < c_len; i++) {
                uint8_t a = name[offset + i];
                uint8_t b = c_start[i];
                /* ASCII case fold */
                if (a >= 'A' && a <= 'Z') {
                    a += 'a' - 'A';
                }
                if (b >= 'A' && b <= 'Z') {
                    b += 'a' - 'A';
                }
                if (a != b) {
                    return false;
                }
            }
            return true;
        }
    }

    return false;
}

/* iPAddress subnet matching: constraint contains address + mask (8 bytes for
 * IPv4, 32 bytes for IPv6). The name is within the subtree if
 * (name & mask) == (constraint_address & mask). */
static bool s2n_nc_ip_match(const uint8_t *name, size_t name_len,
        const uint8_t *constraint, size_t constraint_len)
{
    /* IPv4: name is 4 bytes, constraint is 8 (4 addr + 4 mask). */
    /* IPv6: name is 16 bytes, constraint is 32 (16 addr + 16 mask). */
    size_t addr_len = constraint_len / 2;
    if (name_len != addr_len) {
        /* IP address family mismatch: constraint doesn't apply. */
        return false;
    }
    if (constraint_len != 8 && constraint_len != 32) {
        /* Invalid constraint format. Treat as non-matching. */
        return false;
    }

    const uint8_t *addr = constraint;
    const uint8_t *mask = constraint + addr_len;

    for (size_t i = 0; i < addr_len; i++) {
        if ((name[i] & mask[i]) != (addr[i] & mask[i])) {
            return false;
        }
    }
    return true;
}

/* rfc822Name matching:
 * - If constraint starts with '.': domain suffix match on the domain part of
 *   the name (after '@').
 * - If constraint contains '@': exact mailbox match.
 * - Otherwise: exact domain match on the domain part. */
static bool s2n_nc_rfc822_match(const uint8_t *name, size_t name_len,
        const uint8_t *constraint, size_t constraint_len)
{
    /* Find '@' in the name to split local-part and domain. */
    const uint8_t *name_at = NULL;
    for (size_t i = 0; i < name_len; i++) {
        if (name[i] == '@') {
            name_at = &name[i];
            break;
        }
    }

    /* Find '@' in the constraint. */
    const uint8_t *constraint_at = NULL;
    for (size_t i = 0; i < constraint_len; i++) {
        if (constraint[i] == '@') {
            constraint_at = &constraint[i];
            break;
        }
    }

    if (constraint_at != NULL) {
        /* Exact mailbox match: entire name must match entire constraint. */
        if (name_len != constraint_len) {
            return false;
        }
        /* Case-insensitive on domain, case-sensitive on local-part.
         * For simplicity, do full case-insensitive compare (common practice). */
        for (size_t i = 0; i < name_len; i++) {
            uint8_t a = name[i];
            uint8_t b = constraint[i];
            if (a >= 'A' && a <= 'Z') {
                a += 'a' - 'A';
            }
            if (b >= 'A' && b <= 'Z') {
                b += 'a' - 'A';
            }
            if (a != b) {
                return false;
            }
        }
        return true;
    }

    /* No '@' in constraint: it's a domain or domain-suffix constraint. */
    if (name_at == NULL) {
        /* Name has no '@': treat entire name as domain. */
        return s2n_nc_dns_match(name, name_len, constraint, constraint_len);
    }

    /* Domain part of the name: everything after '@'. */
    const uint8_t *domain = name_at + 1;
    size_t domain_len = name_len - (size_t) (domain - name);

    if (constraint_len > 0 && constraint[0] == '.') {
        /* Domain suffix match. */
        return s2n_nc_dns_match(domain, domain_len, constraint, constraint_len);
    }

    /* Exact domain match. */
    if (domain_len != constraint_len) {
        return false;
    }
    for (size_t i = 0; i < domain_len; i++) {
        uint8_t a = domain[i];
        uint8_t b = constraint[i];
        if (a >= 'A' && a <= 'Z') {
            a += 'a' - 'A';
        }
        if (b >= 'A' && b <= 'Z') {
            b += 'a' - 'A';
        }
        if (a != b) {
            return false;
        }
    }
    return true;
}

/* Parsed name constraint subtrees for a single CA. */
struct s2n_nc_subtree {
    uint8_t tag; /* GeneralName tag */
    const uint8_t *data;
    size_t len;
};

struct s2n_nc_parsed {
    struct s2n_nc_subtree permitted[S2N_CERT_NAME_CONSTRAINTS_MAX_SUBTREES];
    uint32_t permitted_count;
    struct s2n_nc_subtree excluded[S2N_CERT_NAME_CONSTRAINTS_MAX_SUBTREES];
    uint32_t excluded_count;
    bool has_unsupported_form;
};

/* Parse NameConstraints extension value into permitted and excluded subtrees. */
static S2N_RESULT s2n_nc_parse(const struct s2n_blob *nc_blob,
        struct s2n_nc_parsed *out, bool is_critical)
{
    RESULT_ENSURE_REF(nc_blob);
    RESULT_ENSURE_REF(nc_blob->data);
    RESULT_ENSURE_REF(out);

    *out = (struct s2n_nc_parsed){ 0 };

    CBS nc_cbs = { 0 };
    CBS_init(&nc_cbs, nc_blob->data, nc_blob->size);

    /* NameConstraints ::= SEQUENCE { permittedSubtrees [0], excludedSubtrees [1] } */
    CBS nc_seq = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&nc_cbs, &nc_seq, CBS_ASN1_SEQUENCE),
            S2N_ERR_CERT_INVALID);

    /* Parse permittedSubtrees [0] OPTIONAL */
    CBS permitted_cbs = { 0 };
    int permitted_present = 0;
    RESULT_ENSURE(CBS_get_optional_asn1(&nc_seq, &permitted_cbs, &permitted_present,
                          CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0),
            S2N_ERR_CERT_INVALID);

    if (permitted_present) {
        while (CBS_len(&permitted_cbs) > 0) {
            RESULT_ENSURE(out->permitted_count < S2N_CERT_NAME_CONSTRAINTS_MAX_SUBTREES,
                    S2N_ERR_CERT_UNTRUSTED);

            uint8_t tag = 0;
            CBS name = { 0 };
            RESULT_GUARD(s2n_nc_parse_subtree(&permitted_cbs, &tag, &name));

            /* Check for unsupported forms. */
            if (tag != S2N_GEN_NAME_DNS && tag != S2N_GEN_NAME_IP
                    && tag != S2N_GEN_NAME_RFC822) {
                out->has_unsupported_form = true;
                /* If critical and unsupported, we'll bail after parsing all subtrees. */
            }

            out->permitted[out->permitted_count].tag = tag;
            out->permitted[out->permitted_count].data = CBS_data(&name);
            out->permitted[out->permitted_count].len = CBS_len(&name);
            out->permitted_count++;
        }
    }

    /* Parse excludedSubtrees [1] OPTIONAL */
    CBS excluded_cbs = { 0 };
    int excluded_present = 0;
    RESULT_ENSURE(CBS_get_optional_asn1(&nc_seq, &excluded_cbs, &excluded_present,
                          CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 1),
            S2N_ERR_CERT_INVALID);

    if (excluded_present) {
        while (CBS_len(&excluded_cbs) > 0) {
            RESULT_ENSURE(out->excluded_count < S2N_CERT_NAME_CONSTRAINTS_MAX_SUBTREES,
                    S2N_ERR_CERT_UNTRUSTED);

            uint8_t tag = 0;
            CBS name = { 0 };
            RESULT_GUARD(s2n_nc_parse_subtree(&excluded_cbs, &tag, &name));

            if (tag != S2N_GEN_NAME_DNS && tag != S2N_GEN_NAME_IP
                    && tag != S2N_GEN_NAME_RFC822) {
                out->has_unsupported_form = true;
            }

            out->excluded[out->excluded_count].tag = tag;
            out->excluded[out->excluded_count].data = CBS_data(&name);
            out->excluded[out->excluded_count].len = CBS_len(&name);
            out->excluded_count++;
        }
    }

    /* If critical and has unsupported form, reject. */
    if (is_critical && out->has_unsupported_form) {
        RESULT_BAIL(S2N_ERR_CERT_UNHANDLED_CRITICAL_EXTENSION);
    }

    return S2N_RESULT_OK;
}

/* Check a single name against the parsed constraints for its form.
 * Returns S2N_RESULT_OK if the name satisfies the constraints, or errors. */
static S2N_RESULT s2n_nc_check_name(uint8_t name_tag, const uint8_t *name_data,
        size_t name_len, const struct s2n_nc_parsed *nc)
{
    RESULT_ENSURE_REF(nc);

    /* Check if there are any permitted subtrees for this form. If so, the name
     * must match at least one. */
    bool permitted_form_present = false;
    bool permitted_match = false;
    for (uint32_t i = 0; i < nc->permitted_count; i++) {
        if (nc->permitted[i].tag != name_tag) {
            continue;
        }
        permitted_form_present = true;

        bool match = false;
        switch (name_tag) {
            case S2N_GEN_NAME_DNS:
                match = s2n_nc_dns_match(name_data, name_len,
                        nc->permitted[i].data, nc->permitted[i].len);
                break;
            case S2N_GEN_NAME_IP:
                match = s2n_nc_ip_match(name_data, name_len,
                        nc->permitted[i].data, nc->permitted[i].len);
                break;
            case S2N_GEN_NAME_RFC822:
                match = s2n_nc_rfc822_match(name_data, name_len,
                        nc->permitted[i].data, nc->permitted[i].len);
                break;
            default:
                /* Unsupported forms handled at parse time if critical. For
                 * non-critical extensions with unsupported forms, skip. */
                break;
        }
        if (match) {
            permitted_match = true;
            break;
        }
    }

    /* If permitted subtrees exist for this form and none matched, reject. */
    if (permitted_form_present && !permitted_match) {
        RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
    }

    /* Check excluded subtrees: if ANY excluded subtree matches, reject. */
    for (uint32_t i = 0; i < nc->excluded_count; i++) {
        if (nc->excluded[i].tag != name_tag) {
            continue;
        }

        bool match = false;
        switch (name_tag) {
            case S2N_GEN_NAME_DNS:
                match = s2n_nc_dns_match(name_data, name_len,
                        nc->excluded[i].data, nc->excluded[i].len);
                break;
            case S2N_GEN_NAME_IP:
                match = s2n_nc_ip_match(name_data, name_len,
                        nc->excluded[i].data, nc->excluded[i].len);
                break;
            case S2N_GEN_NAME_RFC822:
                match = s2n_nc_rfc822_match(name_data, name_len,
                        nc->excluded[i].data, nc->excluded[i].len);
                break;
            default:
                break;
        }
        if (match) {
            RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
        }
    }

    return S2N_RESULT_OK;
}

/* Check a single certificate's SAN names against the parsed constraints.
 * Iterates dNSName, iPAddress, rfc822Name from the SAN extension. */
static S2N_RESULT s2n_nc_check_cert_san(const struct s2n_cert_span_view *cert,
        const struct s2n_nc_parsed *nc)
{
    RESULT_ENSURE_REF(cert);
    RESULT_ENSURE_REF(nc);

    /* No SAN extension: nothing to check from SAN. */
    if (cert->san.data == NULL || cert->san.size == 0) {
        return S2N_RESULT_OK;
    }

    /* Parse the SAN extension: extnValue contents contain a SEQUENCE OF
     * GeneralName. Each GeneralName is context-specific tagged. */
    CBS san_cbs = { 0 };
    CBS_init(&san_cbs, cert->san.data, cert->san.size);

    CBS san_seq = { 0 };
    RESULT_ENSURE(CBS_get_asn1(&san_cbs, &san_seq, CBS_ASN1_SEQUENCE),
            S2N_ERR_CERT_INVALID);

    while (CBS_len(&san_seq) > 0) {
        CBS element = { 0 };
        unsigned int cbs_tag = 0;
        RESULT_ENSURE(CBS_get_any_asn1(&san_seq, &element, &cbs_tag),
                S2N_ERR_CERT_INVALID);

        uint8_t tag = (uint8_t) (cbs_tag & 0x1f);

        /* Only check forms we support. */
        if (tag == S2N_GEN_NAME_DNS || tag == S2N_GEN_NAME_IP
                || tag == S2N_GEN_NAME_RFC822) {
            RESULT_GUARD(s2n_nc_check_name(tag, CBS_data(&element),
                    CBS_len(&element), nc));
        }
    }

    return S2N_RESULT_OK;
}

/* Determine if a nameConstraints extension is critical by checking whether
 * its OID appears in the certificate's critical_ext_oids list. */
static bool s2n_nc_is_critical(const struct s2n_cert_span_view *ca_view)
{
    /* OID for nameConstraints: 2.5.29.30 = 55 1d 1e */
    static const uint8_t nc_oid[] = { 0x55, 0x1d, 0x1e };
    for (uint32_t i = 0; i < ca_view->critical_ext_oid_count; i++) {
        const struct s2n_blob *oid = &ca_view->critical_ext_oids[i];
        if (oid->size == sizeof(nc_oid)
                && memcmp(oid->data, nc_oid, sizeof(nc_oid)) == 0) {
            return true;
        }
    }
    return false;
}

S2N_RESULT s2n_cert_path_check_name_constraints(const struct s2n_cert_path *path,
        const struct s2n_cert_chain_spans *wire,
        const struct s2n_trust_anchor_snapshot *anchors)
{
    RESULT_ENSURE_REF(path);
    RESULT_ENSURE_REF(wire);
    RESULT_ENSURE_REF(anchors);

    /* For each CA in the path that has nameConstraints, check all certs
     * below it. Path layout: entries[0] = leaf, entries[count-1] = anchor.
     * CAs are at indices 1..count-1 (intermediates + anchor). */
    for (uint32_t ca_idx = 1; ca_idx < path->count; ca_idx++) {
        const struct s2n_cert_span_view *ca_view = NULL;
        if (path->entries[ca_idx].type == S2N_CERT_PATH_ENTRY_WIRE) {
            RESULT_ENSURE(path->entries[ca_idx].entry_index < wire->count,
                    S2N_ERR_CERT_UNTRUSTED);
            ca_view = &wire->views[path->entries[ca_idx].entry_index];
        } else {
            RESULT_ENSURE(path->entries[ca_idx].entry_index < anchors->count,
                    S2N_ERR_CERT_UNTRUSTED);
            ca_view = &anchors->anchors[path->entries[ca_idx].entry_index].parsed;
        }

        /* Skip CAs without nameConstraints. */
        if (ca_view->name_constraints.data == NULL
                || ca_view->name_constraints.size == 0) {
            continue;
        }

        /* Determine if this nameConstraints extension is critical. */
        bool is_critical = s2n_nc_is_critical(ca_view);

        /* Parse the nameConstraints. */
        struct s2n_nc_parsed nc = { 0 };
        RESULT_GUARD(s2n_nc_parse(&ca_view->name_constraints, &nc, is_critical));

        /* If no supported subtrees exist and it's not critical with unsupported
         * forms (which would have already rejected above), nothing to check. */
        if (nc.permitted_count == 0 && nc.excluded_count == 0) {
            continue;
        }

        /* Check all certificates below this CA in the path (indices 0..ca_idx-1). */
        for (uint32_t cert_idx = 0; cert_idx < ca_idx; cert_idx++) {
            const struct s2n_cert_span_view *cert_view = NULL;
            if (path->entries[cert_idx].type == S2N_CERT_PATH_ENTRY_WIRE) {
                RESULT_ENSURE(path->entries[cert_idx].entry_index < wire->count,
                        S2N_ERR_CERT_UNTRUSTED);
                cert_view = &wire->views[path->entries[cert_idx].entry_index];
            } else {
                RESULT_ENSURE(path->entries[cert_idx].entry_index < anchors->count,
                        S2N_ERR_CERT_UNTRUSTED);
                cert_view = &anchors->anchors[path->entries[cert_idx].entry_index].parsed;
            }

            /* Check SAN names against the constraints. */
            RESULT_GUARD(s2n_nc_check_cert_san(cert_view, &nc));
        }
    }

    return S2N_RESULT_OK;
}

/* --- Critical-extension sweep --- */

/* OIDs of extensions that the zero-copy verifier processes. Any critical
 * extension whose OID is in this set is considered handled. */
static const uint8_t s2n_processed_oid_basic_constraints[] = { 0x55, 0x1d, 0x13 };
static const uint8_t s2n_processed_oid_key_usage[] = { 0x55, 0x1d, 0x0f };
static const uint8_t s2n_processed_oid_ext_key_usage[] = { 0x55, 0x1d, 0x25 };
static const uint8_t s2n_processed_oid_name_constraints[] = { 0x55, 0x1d, 0x1e };
static const uint8_t s2n_processed_oid_subject_key_id[] = { 0x55, 0x1d, 0x0e };
static const uint8_t s2n_processed_oid_authority_key_id[] = { 0x55, 0x1d, 0x23 };
static const uint8_t s2n_processed_oid_subject_alt_name[] = { 0x55, 0x1d, 0x11 };

struct s2n_processed_oid_entry {
    const uint8_t *data;
    size_t size;
};

static const struct s2n_processed_oid_entry s2n_processed_oids[] = {
    { s2n_processed_oid_basic_constraints, sizeof(s2n_processed_oid_basic_constraints) },
    { s2n_processed_oid_key_usage, sizeof(s2n_processed_oid_key_usage) },
    { s2n_processed_oid_ext_key_usage, sizeof(s2n_processed_oid_ext_key_usage) },
    { s2n_processed_oid_name_constraints, sizeof(s2n_processed_oid_name_constraints) },
    { s2n_processed_oid_subject_key_id, sizeof(s2n_processed_oid_subject_key_id) },
    { s2n_processed_oid_authority_key_id, sizeof(s2n_processed_oid_authority_key_id) },
    { s2n_processed_oid_subject_alt_name, sizeof(s2n_processed_oid_subject_alt_name) },
};

    #define S2N_PROCESSED_OID_COUNT s2n_array_len(s2n_processed_oids)

/* Check if an OID matches any entry in the processed set. */
static bool s2n_cert_oid_is_processed(const struct s2n_blob *oid)
{
    for (size_t i = 0; i < S2N_PROCESSED_OID_COUNT; i++) {
        if (oid->size == s2n_processed_oids[i].size
                && memcmp(oid->data, s2n_processed_oids[i].data,
                           s2n_processed_oids[i].size)
                        == 0) {
            return true;
        }
    }
    return false;
}

/* Check if an OID matches any entry in the custom-registered set. */
static bool s2n_cert_oid_is_custom(const struct s2n_blob *oid,
        const struct s2n_blob *custom_oids, uint32_t custom_oid_count)
{
    if (custom_oids == NULL || custom_oid_count == 0) {
        return false;
    }
    for (uint32_t i = 0; i < custom_oid_count; i++) {
        if (oid->size == custom_oids[i].size
                && custom_oids[i].data != NULL
                && memcmp(oid->data, custom_oids[i].data, oid->size) == 0) {
            return true;
        }
    }
    return false;
}

S2N_RESULT s2n_cert_path_check_critical_extensions(const struct s2n_cert_path *path,
        const struct s2n_cert_chain_spans *wire,
        const struct s2n_trust_anchor_snapshot *anchors,
        const struct s2n_blob *custom_oids, uint32_t custom_oid_count)
{
    RESULT_ENSURE_REF(path);
    RESULT_ENSURE_REF(wire);
    RESULT_ENSURE_REF(anchors);

    /* Check every certificate in the path except the trust anchor.
     * Path layout: entries[0] = leaf, entries[count-1] = anchor.
     * We check indices 0..count-2, EXCEPT for a depth-1 directly-trusted
     * leaf, which is still checked (libcrypto rejects unhandled critical
     * extensions on every chain certificate). */
    uint32_t sweep_count = path->count;
    if (path->count >= 2) {
        sweep_count = path->count - 1;
    }
    for (uint32_t i = 0; i < sweep_count; i++) {
        const struct s2n_cert_span_view *cert_view = NULL;
        if (path->entries[i].type == S2N_CERT_PATH_ENTRY_WIRE) {
            RESULT_ENSURE(path->entries[i].entry_index < wire->count,
                    S2N_ERR_CERT_UNTRUSTED);
            cert_view = &wire->views[path->entries[i].entry_index];
        } else {
            RESULT_ENSURE(path->entries[i].entry_index < anchors->count,
                    S2N_ERR_CERT_UNTRUSTED);
            cert_view = &anchors->anchors[path->entries[i].entry_index].parsed;
        }

        for (uint32_t j = 0; j < cert_view->critical_ext_oid_count; j++) {
            const struct s2n_blob *oid = &cert_view->critical_ext_oids[j];
            RESULT_ENSURE_REF(oid->data);

            if (s2n_cert_oid_is_processed(oid)) {
                continue;
            }
            if (s2n_cert_oid_is_custom(oid, custom_oids, custom_oid_count)) {
                continue;
            }

            RESULT_BAIL(S2N_ERR_CERT_UNHANDLED_CRITICAL_EXTENSION);
        }
    }

    return S2N_RESULT_OK;
}

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */
