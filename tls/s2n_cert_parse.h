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
#include "utils/s2n_blob.h"
#include "utils/s2n_result.h"

/* Zero-copy certificate parser: decodes a DER Certificate into borrowed byte
 * spans (the CBS cursor model) without building a libcrypto X509 object graph.
 * Requires the CBS API, so it is only available on aws-lc / BoringSSL builds. */
#if S2N_LIBCRYPTO_SUPPORTS_CBS

    /* The parser walks a fixed grammar and never recurses, so its nesting depth is
 * bounded by construction. This constant documents that bound: the deepest
 * descent is Certificate > TBS > extensions [3] > SEQUENCE OF > Extension >
 * extnValue > cached-extension contents (e.g. basicConstraints SEQUENCE). Any
 * input requiring deeper traversal fails the fixed-shape tag checks. */
    #define S2N_CERT_PARSE_MAX_DEPTH 8

    /* Per-certificate cap on the number of extensions the parser will walk. */
    #define S2N_CERT_PARSE_MAX_EXTENSIONS 32

    /* Cap on the critical-extension OIDs cached for the post-path critical sweep. */
    #define S2N_CERT_PARSE_MAX_CRITICAL_EXTENSIONS 16

    /* Structural upper bound on the number of certificates a single wire chain
 * may hold. The validator's default max chain depth is 7 (DEFAULT_MAX_CHAIN_DEPTH);
 * this leaves headroom for larger configured limits while keeping the span-view
 * array a fixed, no-allocation inline buffer. A wire chain whose certificate
 * count exceeds min(max_chain_depth, this cap) rejects with
 * S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED. */
    #define S2N_CERT_CHAIN_SPANS_MAX 16

/* A zero-copy view over one DER certificate. Every s2n_blob is a borrowed span
 * into the caller's certificate buffer: the view owns nothing, allocates
 * nothing, and requires no cleanup. A span with data == NULL means the
 * corresponding optional field is absent.
 *
 * Spans annotated "TLV" include the ASN.1 tag and length header; the rest hold
 * element contents only. The TBS span in particular MUST keep its header,
 * because the certificate signature is computed over the full TLV. */
struct s2n_cert_span_view {
    struct s2n_blob raw;           /* full Certificate TLV */
    struct s2n_blob tbs;           /* tbsCertificate TLV, WITH header (signature input) */
    struct s2n_blob outer_sig_alg; /* AlgorithmIdentifier TLV (outer) */
    struct s2n_blob inner_sig_alg; /* AlgorithmIdentifier TLV (inside TBS) */
    struct s2n_blob sig;           /* BIT STRING contents; unused-bits octet verified == 0 */
    struct s2n_blob serial;        /* INTEGER contents */
    struct s2n_blob issuer;        /* Name TLV */
    struct s2n_blob validity;      /* Validity TLV */
    struct s2n_blob subject;       /* Name TLV */
    struct s2n_blob spki;          /* SubjectPublicKeyInfo TLV */
    struct s2n_blob extensions;    /* Extensions SEQUENCE contents; absent if data == NULL */

    /* Scalars decoded during parse (no allocation). */
    uint8_t version; /* raw X.509 version field: 0 = v1, 1 = v2, 2 = v3 */
    /* Validity times in seconds since the Unix epoch, decoded by the hardened
     * time parser. UTCTime reaches back to 1950 but pre-epoch instants cannot
     * be represented in uint64_t, so they saturate to 0; every validity-window
     * comparison at a verification time >= the epoch is unaffected. */
    uint64_t not_before;
    uint64_t not_after;
    /* Populated by algorithm identification (OBJ_cbs2nid / OBJ_find_sigid_algs);
     * 0 (NID_undef) until then. */
    int sig_nid;
    int sig_digest_nid;
    int sig_pkey_nid;

    /* Cached extension facts, filled during the single extension walk. */
    bool basic_constraints_present;
    bool basic_constraints_is_ca;
    bool basic_constraints_has_path_len;
    uint64_t basic_constraints_path_len;
    bool key_usage_present;
    /* keyUsage BIT STRING contents: byte 0 in the low 8 bits (digitalSignature
     * = 0x80, keyCertSign = 0x04, cRLSign = 0x02), byte 1 (decipherOnly) in the
     * high 8 bits. Raw bits; unused-bit masking is the consumer's concern. */
    uint16_t key_usage_bits;
    struct s2n_blob eku;              /* extKeyUsage extnValue contents */
    struct s2n_blob san;              /* subjectAltName extnValue contents */
    struct s2n_blob name_constraints; /* nameConstraints extnValue contents */
    struct s2n_blob skid;             /* subjectKeyIdentifier extnValue contents */
    struct s2n_blob akid;             /* authorityKeyIdentifier extnValue contents */
    /* OID contents of every critical extension, for the critical-extension
     * sweep after path verification. Bounded; overflow rejects the parse. */
    struct s2n_blob critical_ext_oids[S2N_CERT_PARSE_MAX_CRITICAL_EXTENSIONS];
    uint32_t critical_ext_oid_count;
};

/* Parse one DER Certificate TLV into a span view. `cert_der` must contain
 * exactly one certificate (no trailing bytes) and must outlive the view: every
 * span borrows from it. Strict DER only: minimal-form lengths, no indefinite
 * lengths, declared lengths must fit the enclosing buffer. All malformed input
 * is rejected with S2N_ERR_CERT_INVALID. */
S2N_RESULT s2n_cert_span_view_parse(struct s2n_cert_span_view *view,
        struct s2n_blob *cert_der);

/* A parsed view of a wire certificate chain: one span view per certificate,
 * every span borrowing from the wire_chain blob. The chain owns nothing and
 * requires no cleanup; the wire_chain buffer must outlive it. Leaf is at
 * index 0, matching the chain-view / handshake ordering.
 *
 * `count` precedes `views` so that heap users may allocate a trailing-
 * truncated block holding only the views they need:
 *   offsetof(struct s2n_cert_chain_spans, views) + n * sizeof(views[0])
 * A truncated block MUST only ever be passed to s2n_cert_chain_spans_parse
 * with max_chain_depth <= n, and only views[0..count) may be accessed. */
struct s2n_cert_chain_spans {
    uint32_t count;
    struct s2n_cert_span_view views[S2N_CERT_CHAIN_SPANS_MAX];
};

/* Parse a wire certificate chain into one span view per certificate.
 *
 * INPUT CONTRACT : `wire_chain` is the raw concatenation of DER
 * Certificate TLVs, back to back, with no framing between them. The parser is
 * self-framing: it splits certificates by walking successive outer ASN.1
 * SEQUENCE elements (each certificate is exactly one outer SEQUENCE TLV) and
 * requires the buffer to be consumed exactly, with no trailing bytes.
 *
 * This deliberately does NOT handle the TLS Certificate handshake message's
 * 3-byte per-certificate length prefixes (and TLS 1.3 per-certificate
 * extensions). That wire framing is stripped at validator-integration time
 *  before this parser sees the bytes; keeping the split self-framing
 * here means the parser has a single, format-independent input contract.
 *
 * Every span in every produced view borrows from `wire_chain`, which must
 * outlive the result. An empty `wire_chain` (size 0) yields count == 0. A
 * certificate count exceeding min(max_chain_depth, S2N_CERT_CHAIN_SPANS_MAX)
 * rejects with S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED. Any malformed certificate
 * rejects with S2N_ERR_CERT_INVALID. */
S2N_RESULT s2n_cert_chain_spans_parse(struct s2n_cert_chain_spans *chain,
        const struct s2n_blob *wire_chain, uint16_t max_chain_depth);

/* Parse one DER Time TLV into seconds since the Unix epoch. Accepts exactly
 * the RFC 5280 encodings: UTCTime `YYMMDDHHMMSSZ` (century pivot at 50:
 * YY < 50 is 20YY, else 19YY) and GeneralizedTime `YYYYMMDDHHMMSSZ`.
 * Fractional seconds, UTC offsets, non-`Z` suffixes, non-digit characters,
 * and out-of-range date components (including Feb 29 outside leap years)
 * reject with S2N_ERR_CERT_INVALID. Pre-epoch times saturate to 0. */
S2N_RESULT s2n_cert_parse_time(const struct s2n_blob *time_tlv,
        uint64_t *seconds_since_epoch);

/* Identify the certificate's signature algorithm from its AlgorithmIdentifier
 * spans and populate view->sig_nid / sig_digest_nid / sig_pkey_nid.
 *
 * The OID inside outer_sig_alg is mapped with OBJ_cbs2nid, then split into its
 * digest and public-key NIDs with OBJ_find_sigid_algs (EVP_get_digestbynid is
 * used later, at verify time, to resolve the message digest). These are exactly
 * the inputs the existing security-policy certificate_signature_preferences /
 * certificate_key_preferences checks consume, so the zero-copy path feeds them
 * identical values to the libcrypto path.
 *
 * The outer AlgorithmIdentifier (Certificate.signatureAlgorithm) and the inner
 * one (tbsCertificate.signature) MUST be byte-for-byte identical; a mismatch is
 * the algorithm anti-substitution class and rejects with S2N_ERR_CERT_UNTRUSTED
 * . An unrecognized signature OID leaves the NIDs as NID_undef (the
 * security-policy layer decides whether that is acceptable), but the two
 * AlgorithmIdentifier TLVs must still agree. */
S2N_RESULT s2n_cert_span_view_identify_alg(struct s2n_cert_span_view *view);

/* Verify a certificate/CRL/OCSP signature over a borrowed TBS TLV.
 *
 * `tbs` is the full signed TLV (with its ASN.1 header - the signature is
 * computed over those exact bytes). `sig_alg` is the AlgorithmIdentifier TLV
 * describing the signature, and `sig` is the raw signature octets (BIT STRING
 * contents with the unused-bits octet already stripped by the parser).
 * `issuer_key` is the issuer's public key, materialized from its
 * SubjectPublicKeyInfo.
 *
 * The AlgorithmIdentifier drives digest/padding selection so RSA PKCS#1 v1.5,
 * RSA-PSS, ECDSA, and Ed25519 are all handled. PSS parameters (hash,
 * MGF1 hash, salt length) are read from the AlgorithmIdentifier; Ed25519 uses a
 * NULL digest. MD4/MD5-based signatures reject, matching the libcrypto verify
 * layer's x509_digest_nid_ok restriction. A verification failure - bad
 * signature, unknown/weak algorithm, or key/algorithm mismatch - rejects with
 * S2N_ERR_CERT_UNTRUSTED. FIPS restrictions flow from the shared EVP layer. */
S2N_RESULT s2n_cert_verify_signed(const struct s2n_blob *tbs,
        const struct s2n_blob *sig_alg, const struct s2n_blob *sig,
        struct s2n_pkey *issuer_key);

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */
