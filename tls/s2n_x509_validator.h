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

#include <openssl/x509v3.h>

#include "api/s2n.h"
#include "crypto/s2n_pkey.h"
#include "tls/s2n_signature_scheme.h"

#if S2N_LIBCRYPTO_SUPPORTS_CBS
    #include "tls/s2n_cert_parse.h"
    #include "tls/s2n_cert_path.h"
#endif

/* one day, BoringSSL may add ocsp stapling support. Let's future proof this a bit by grabbing a definition
 * that would have to be there when they add support */
#if defined(OPENSSL_IS_BORINGSSL) && !defined(OCSP_RESPONSE_STATUS_SUCCESSFUL)
    #define S2N_OCSP_STAPLING_SUPPORTED 0
#else
    #define S2N_OCSP_STAPLING_SUPPORTED 1
#endif /* defined(OPENSSL_IS_BORINGSSL) && !defined(OCSP_RESPONSE_STATUS_SUCCESSFUL) */

/* Backend_Selector (, 10.2, 10.6).
 *
 * Selection mechanism for the certificate verification backend. On non-CBS
 * builds the enum collapses to a single value (libcrypto unconditionally).
 * On CBS builds (aws-lc), the default is S2N_CERT_BACKEND_ZERO_COPY (value 0,
 * matching C zero-initialization). Internal only — no public API. */
typedef enum {
#if S2N_LIBCRYPTO_SUPPORTS_CBS
    S2N_CERT_BACKEND_ZERO_COPY = 0, /* CBS builds default (zero-init) */
    S2N_CERT_BACKEND_LIBCRYPTO,     /* legacy path */
    S2N_CERT_BACKEND_DIFFERENTIAL,  /* both run; libcrypto authoritative */
#else
    S2N_CERT_BACKEND_LIBCRYPTO = 0, /* non-CBS default (zero-init) */
#endif
} s2n_cert_verify_backend;

typedef enum {
    UNINIT,
    INIT,
    READY_TO_VERIFY,
    AWAITING_CRL_CALLBACK,
    VALIDATED,
    OCSP_VALIDATED,
} validator_state;

/** Return TRUE for trusted, FALSE for untrusted **/
typedef uint8_t (*verify_host)(const char *host_name, size_t host_name_len, void *data);
struct s2n_connection;

/**
 * Trust store simply contains the trust store each connection should validate certs against.
 * For most use cases, you only need one of these per application.
 */
struct s2n_x509_trust_store {
    X509_STORE *trust_store;

    /* Indicates whether system default certs have been loaded into the trust store */
    unsigned loaded_system_certs : 1;

#if S2N_LIBCRYPTO_SUPPORTS_CBS
    /* Trust_Store_Bridge : an immutable, subject-sorted, refcounted
     * DER-span snapshot of the certs in `trust_store`, built lazily at the
     * first zero-copy validation that touches this store. The X509_STORE stays
     * the source of truth; store mutation clears `anchor_snapshot` under the
     * bridge's build mutex while in-flight validations keep their own
     * reference. NULL until the first build (or after invalidation). Only
     * mutated under the build mutex; read lock-free once published. */
    struct s2n_trust_anchor_snapshot *anchor_snapshot;
#endif
};

struct s2n_cert_validation_info {
    unsigned finished : 1;
    unsigned accepted : 1;
};

struct s2n_validated_cert_chain {
    STACK_OF(X509) *stack;
    /* True when this stack is caller-owned (allocated via materialization or
     * get1_chain) and MUST be freed by the cleanup function. False when it is
     * borrowed from X509_STORE_CTX via get0_chain. */
    bool owned;
};

/**
 * You should have one instance of this per connection.
 */
struct s2n_x509_validator {
    struct s2n_x509_trust_store *trust_store;
    X509_STORE_CTX *store_ctx;
    uint8_t skip_cert_validation;
    uint8_t check_stapled_ocsp;
    uint16_t max_chain_depth;
    STACK_OF(X509) *cert_chain_from_wire;
    int state;
    struct s2n_array *crl_lookup_list;
    struct s2n_cert_validation_info cert_validation_info;
    bool cert_validation_cb_invoked;

#if S2N_LIBCRYPTO_SUPPORTS_CBS
    /* Differential_Validator (, 10.4).
     * Incremented when differential mode detects a divergence between the
     * libcrypto and zero-copy verifiers (accept/reject decision or error code).
     * Internal metric only — no public API. */
    uint32_t differential_divergence_count;

    /* Zero-copy validator state : owned copy of the Certificate
     * message bytes; all span views borrow from this blob for the connection
     * lifetime. Freed in s2n_x509_validator_wipe. */
    struct s2n_blob wire_chain;

    /* Parsed span views over the wire_chain: one per wire certificate.
     * Heap-allocated only when the zero-copy path runs, to avoid bloating
     * s2n_connection with the large inline array when CBS is compiled in
     * but not used. */
    struct s2n_blob chain_spans_mem;
    struct s2n_cert_chain_spans *chain_spans;

    /* The validated certification path: indices into chain_spans and the
     * anchor snapshot. Populated by the path builder after chain validation. */
    struct s2n_cert_path validated_path;

    /* Reference to the trust-anchor snapshot held during validation. Acquired
     * from the trust store at validation start; released in wipe regardless
     * of which stage failed. */
    struct s2n_trust_anchor_snapshot *anchor_snapshot;
#endif
};

/** Some libcrypto implementations do not support OCSP validation. Returns 1 if supported, 0 otherwise. */
uint8_t s2n_x509_ocsp_stapling_supported(void);

/** Initialize the trust store to empty defaults (no allocations happen here) */
void s2n_x509_trust_store_init_empty(struct s2n_x509_trust_store *store);

/** Returns TRUE if the trust store has certificates installed, FALSE otherwise */
uint8_t s2n_x509_trust_store_has_certs(struct s2n_x509_trust_store *store);

/** Initialize trust store from a PEM. This will allocate memory, and load PEM into the Trust Store **/
int s2n_x509_trust_store_add_pem(struct s2n_x509_trust_store *store, const char *pem);

/** Initialize trust store from a CA file. This will allocate memory, and load each cert in the file into the trust store
 *  Returns 0 on success, or S2N error codes on failure. */
int s2n_x509_trust_store_from_ca_file(struct s2n_x509_trust_store *store, const char *ca_pem_filename, const char *ca_dir);

/** Cleans up, and frees any underlying memory in the trust store. */
void s2n_x509_trust_store_wipe(struct s2n_x509_trust_store *store);

#if S2N_LIBCRYPTO_SUPPORTS_CBS
/* Trust_Store_Bridge.
 *
 * Acquire a reference to the store's immutable trust-anchor snapshot for a
 * single zero-copy chain validation, building it lazily (under the store's
 * build mutex, double-checked) on first use from X509_STORE_get0_objects +
 * i2d_X509. The returned snapshot is immutable for the caller's lifetime; the
 * caller MUST release it with s2n_x509_trust_store_snapshot_release when done.
 *
 * An empty store yields S2N_ERR_CERT_UNTRUSTED (matching the current path's
 * empty-trust-store behavior); skip_cert_validation callers must not call this.
 * On any build failure the chain fails closed (no snapshot returned). */
S2N_RESULT s2n_x509_trust_store_snapshot_acquire(struct s2n_x509_trust_store *store,
        struct s2n_trust_anchor_snapshot **snapshot_out);

/* Release a reference acquired via s2n_x509_trust_store_snapshot_acquire. When
 * the last reference drops (and the store no longer holds it), the snapshot and
 * its owned DER are freed. Safe to call with a NULL snapshot. */
S2N_RESULT s2n_x509_trust_store_snapshot_release(struct s2n_x509_trust_store *store,
        struct s2n_trust_anchor_snapshot *snapshot);

/* Invalidate the store's cached snapshot pointer (called on trust-store
 * mutation/wipe). In-flight validations keep their own references; the next
 * validation rebuilds. Safe to call when no snapshot exists. */
void s2n_x509_trust_store_snapshot_invalidate(struct s2n_x509_trust_store *store);

/* CRL_Validator wiring.
 *
 * Zero-copy CRL check for a single certificate. The async lookup-callback flow
 * (crl_lookup_list, AWAITING_CRL_CALLBACK, S2N_ERR_CRL_LOOKUP_FAILED) is shared
 * verbatim with the libcrypto path via s2n_crl_invoke_lookup_callbacks and
 * s2n_crl_handle_lookup_callback_result; only the parse/check swaps here to the
 * zero-copy validator in tls/s2n_cert_revocation.h. `lookup` is the
 * crl_lookup_list entry for the certificate being checked; `issuer_key` and
 * `serial` come from the validated span path (supplied by the caller, so this
 * helper carries no zero-copy chain state of its own). `verification_time` is
 * seconds since the Unix epoch.
 *
 * A CRL the callback intentionally declined to return (lookup->crl == NULL)
 * keeps S2N_ERR_CRL_LOOKUP_FAILED, matching the libcrypto path's missing-CRL
 * result. Otherwise the callback-delivered X509_CRL is bridged to DER (via
 * i2d_X509_CRL, mirroring the Trust_Store_Bridge's i2d_X509) and handed to
 * s2n_crl_validate: bad signature -> S2N_ERR_CRL_SIGNATURE, timestamp
 * violations -> existing S2N_ERR_CRL_* codes, revoked serial ->
 * S2N_ERR_CERT_REVOKED. */
struct s2n_crl_lookup;
struct s2n_pkey;
struct s2n_blob;
S2N_RESULT s2n_x509_validator_check_crl(struct s2n_crl_lookup *lookup,
        struct s2n_pkey *issuer_key, const struct s2n_blob *serial,
        uint64_t verification_time);

/* Zero-copy cert chain reading.
 *
 * Reads the TLS-framed certificate chain body into the validator's owned
 * wire_chain blob, stripping TLS framing (3-byte per-cert length prefixes and
 * TLS 1.3 per-cert extensions). Parses span views over the concatenated DER
 * via s2n_cert_chain_spans_parse and transitions to READY_TO_VERIFY.
 *
 * In skip mode (skip_cert_validation): extracts the leaf public key from the
 * leaf span view and returns without chain verification.
 *
 * This function is NOT called from the main handshake flow yet — it will be
 * wired via the Backend_Selector in. */
S2N_RESULT s2n_x509_validator_read_cert_chain_spans(struct s2n_x509_validator *validator,
        struct s2n_connection *conn, uint8_t *cert_chain_in, uint32_t cert_chain_len,
        s2n_pkey_type *pkey_type_out, struct s2n_pkey *public_key_out);

/* Zero-copy chain-validation flow.
 *
 * Called after s2n_x509_validator_read_cert_chain_spans succeeds in non-skip
 * mode (validator state == READY_TO_VERIFY with chain_spans populated). Drives
 * the full verification pipeline:
 *   1. Trust-anchor snapshot acquisition
 *   2. Path build (backtracking search, Work_Budget)
 *   3. Whole-path constraint checks (EKU, nameConstraints, critical extensions)
 *   4. Hostname verification on the leaf (span-backed cert_view)
 *   5. CRL callback flow (if CRL checking is enabled on config)
 *   6. Cert validation callback (exactly once, unchanged s2n_cert_validation_info semantics)
 *   7. State transition to VALIDATED
 *
 * Fail closed: any internal inconsistency (span out of bounds, unexpected parse
 * state, snapshot build failure) rejects with S2N_ERR_CERT_UNTRUSTED. All
 * failures map to the design's error-taxonomy table (no new error codes).
 *
 * This function is NOT yet called from the main handshake flow — 's
 * Backend_Selector will route to it. */
S2N_RESULT s2n_x509_validator_verify_cert_chain_spans(struct s2n_x509_validator *validator,
        struct s2n_connection *conn);
#endif

/** Initialize the validator in unsafe mode. No validity checks for OCSP, host checks, or X.509 will be performed. */
int s2n_x509_validator_init_no_x509_validation(struct s2n_x509_validator *validator);

/** Initialize the validator in safe mode. Will use trust store to validate x.509 certificates, ocsp responses, and will call
 *  the verify host callback to determine if a subject name or alternative name from the cert should be trusted.
 *  Returns 0 on success, and an S2N_ERR_* on failure.
 */
int s2n_x509_validator_init(struct s2n_x509_validator *validator, struct s2n_x509_trust_store *trust_store, uint8_t check_ocsp);

/**
 * Sets the maximum depth for a cert chain that can be used at validation.
 */
int s2n_x509_validator_set_max_chain_depth(struct s2n_x509_validator *validator, uint16_t max_depth);

/** Cleans up underlying memory and data members. Struct can be reused afterwards. */
int s2n_x509_validator_wipe(struct s2n_x509_validator *validator);

/**
 * Validates a certificate chain against the configured trust store in safe mode. In unsafe mode, it will find the public key
 * and return it but not validate the certificates. Alternative Names and Subject Name will be passed to the host verification callback.
 * The verification callback will be possibly called multiple times depending on how many names are found.
 * If any of those calls return TRUE, that stage of the validation will continue, otherwise once all names are tried and none matched as
 * trusted, the chain will be considered UNTRUSTED.
 *
 * This function can only be called once per instance of an s2n_x509_validator. If must be called prior to calling
 * s2n_x509_validator_validate_cert_stapled_ocsp_response().
 */
S2N_RESULT s2n_x509_validator_validate_cert_chain(struct s2n_x509_validator *validator, struct s2n_connection *conn,
        uint8_t *cert_chain_in, uint32_t cert_chain_len, s2n_pkey_type *pkey_type,
        struct s2n_pkey *public_key_out);

/**
 * Validates an ocsp response against the most recent certificate chain. Also verifies the timestamps on the response. This function can only be
 * called once per instance of an s2n_x509_validator and only after a successful call to s2n_x509_validator_validate_cert_chain().
 */
S2N_RESULT s2n_x509_validator_validate_cert_stapled_ocsp_response(struct s2n_x509_validator *validator, struct s2n_connection *conn,
        const uint8_t *ocsp_response, uint32_t size);

/**
 * Checks whether the peer's certificate chain has been received and validated.
 * Should be verified before any use of the peer's certificate data.
 */
bool s2n_x509_validator_is_cert_chain_validated(const struct s2n_x509_validator *validator);

S2N_RESULT s2n_x509_validator_get_validated_cert_chain(const struct s2n_x509_validator *validator,
        struct s2n_validated_cert_chain *validated_cert_chain);

S2N_CLEANUP_RESULT s2n_x509_validator_validated_cert_chain_free(struct s2n_validated_cert_chain *validated_cert_chain);

/* Backend_Selector: internal setter.
 *
 * Sets the cert verification backend for the given config. NOT in any public
 * header — internal use and testing only. On non-CBS builds, any value other
 * than S2N_CERT_BACKEND_LIBCRYPTO is silently clamped to libcrypto.
 *
 * Selection is fixed at config init time. The backend choice is read at
 * validation start with no silent runtime fallback. */
struct s2n_config;
S2N_RESULT s2n_config_set_cert_verify_backend(struct s2n_config *config,
        s2n_cert_verify_backend backend);
