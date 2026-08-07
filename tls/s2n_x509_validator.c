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

/* <winsock2.h> internally includes core elements from <windows.h>. For historical
 * reasons, <windows.h> defaults to including <winsock.h> (Winsock 1.1), whose
 * declarations conflict with <winsock2.h> (Winsock 2). Defining WIN32_LEAN_AND_MEAN
 * before including <winsock2.h> prevents this transitive <winsock.h> inclusion.
 * https://learn.microsoft.com/en-us/windows/win32/winsock/include-files-2
 */
#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <sys/socket.h>
#endif
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <stddef.h>

#include "crypto/s2n_libcrypto.h"
#include "crypto/s2n_openssl_x509.h"
#include "crypto/s2n_pkey.h"
#include "tls/extensions/s2n_extension_list.h"
#include "tls/s2n_cert_view.h"
#include "tls/s2n_config.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_crl.h"
#include "tls/s2n_security_policies.h"
#include "utils/s2n_result.h"
#include "utils/s2n_rfc5952.h"
#include "utils/s2n_safety.h"

#if S2N_LIBCRYPTO_SUPPORTS_CBS
    #include <openssl/mem.h>
    #include <pthread.h>

    #include "tls/s2n_cert_parse.h"
    #include "tls/s2n_cert_path.h"
    #include "tls/s2n_cert_revocation.h"
#endif

#if S2N_OCSP_STAPLING_SUPPORTED
    #include <openssl/ocsp.h>
DEFINE_POINTER_CLEANUP_FUNC(OCSP_RESPONSE *, OCSP_RESPONSE_free);
DEFINE_POINTER_CLEANUP_FUNC(OCSP_BASICRESP *, OCSP_BASICRESP_free);

#endif

#ifndef X509_V_FLAG_PARTIAL_CHAIN
    #define X509_V_FLAG_PARTIAL_CHAIN 0x80000
#endif

#define DEFAULT_MAX_CHAIN_DEPTH 7
/* Time used by default for nextUpdate if none provided in OCSP: 1 hour since thisUpdate. */
#define DEFAULT_OCSP_NEXT_UPDATE_PERIOD 3600

/* s2n's internal clock measures epoch-nanoseconds stored with a uint64_t. The
 * maximum representable timestamp is Sunday, July 21, 2554. time_t measures
 * epoch-seconds in a int64_t or int32_t (platform dependent). If time_t is an
 * int32_t, the maximum representable timestamp is January 19, 2038.
 *
 * This means that converting from the internal clock to a time_t is not safe,
 * because the internal clock might hold a value that is too large to represent
 * in a time_t. This constant represents the largest internal clock value that
 * can be safely represented as a time_t.
 */
#define MAX_32_TIMESTAMP_NANOS 2147483647 * ONE_SEC_IN_NANOS

#define OSSL_VERIFY_CALLBACK_IGNORE_ERROR 1

DEFINE_POINTER_CLEANUP_FUNC(STACK_OF(X509_CRL) *, sk_X509_CRL_free);

uint8_t s2n_x509_ocsp_stapling_supported(void)
{
    return S2N_OCSP_STAPLING_SUPPORTED;
}

void s2n_x509_trust_store_init_empty(struct s2n_x509_trust_store *store)
{
    /* Zero the whole struct: callers may pass stack-allocated stores, and
     * fields like anchor_snapshot must not hold stack garbage (it is
     * dereferenced by s2n_x509_trust_store_snapshot_invalidate). */
    *store = (struct s2n_x509_trust_store){ 0 };
}

uint8_t s2n_x509_trust_store_has_certs(struct s2n_x509_trust_store *store)
{
    return store->trust_store ? (uint8_t) 1 : (uint8_t) 0;
}

int s2n_x509_trust_store_add_pem(struct s2n_x509_trust_store *store, const char *pem)
{
    POSIX_ENSURE_REF(store);
    POSIX_ENSURE_REF(pem);

    if (!store->trust_store) {
        store->trust_store = X509_STORE_new();
        POSIX_ENSURE_REF(store->trust_store);
    }

#if S2N_LIBCRYPTO_SUPPORTS_CBS
    /* Mutating the store invalidates any cached zero-copy snapshot. */
    s2n_x509_trust_store_snapshot_invalidate(store);
#endif

    DEFER_CLEANUP(struct s2n_stuffer pem_in_stuffer = { 0 }, s2n_stuffer_free);
    DEFER_CLEANUP(struct s2n_stuffer der_out_stuffer = { 0 }, s2n_stuffer_free);

    POSIX_GUARD(s2n_stuffer_alloc_ro_from_string(&pem_in_stuffer, pem));
    POSIX_GUARD(s2n_stuffer_growable_alloc(&der_out_stuffer, 2048));

    do {
        DEFER_CLEANUP(struct s2n_blob next_cert = { 0 }, s2n_free);

        POSIX_GUARD(s2n_stuffer_certificate_from_pem(&pem_in_stuffer, &der_out_stuffer));
        POSIX_GUARD(s2n_alloc(&next_cert, s2n_stuffer_data_available(&der_out_stuffer)));
        POSIX_GUARD(s2n_stuffer_read(&der_out_stuffer, &next_cert));

        const uint8_t *data = next_cert.data;
        DEFER_CLEANUP(X509 *ca_cert = d2i_X509(NULL, &data, next_cert.size), X509_free_pointer);
        S2N_ERROR_IF(ca_cert == NULL, S2N_ERR_DECODE_CERTIFICATE);

        if (!X509_STORE_add_cert(store->trust_store, ca_cert)) {
            unsigned long error = ERR_get_error();
            POSIX_ENSURE(ERR_GET_REASON(error) == X509_R_CERT_ALREADY_IN_HASH_TABLE, S2N_ERR_DECODE_CERTIFICATE);
        }
    } while (s2n_stuffer_data_available(&pem_in_stuffer));

    return 0;
}

int s2n_x509_trust_store_from_ca_file(struct s2n_x509_trust_store *store, const char *ca_pem_filename, const char *ca_dir)
{
    if (!store->trust_store) {
        store->trust_store = X509_STORE_new();
        POSIX_ENSURE_REF(store->trust_store);
    }

#if S2N_LIBCRYPTO_SUPPORTS_CBS
    /* Mutating the store invalidates any cached zero-copy snapshot. */
    s2n_x509_trust_store_snapshot_invalidate(store);
#endif

    int err_code = X509_STORE_load_locations(store->trust_store, ca_pem_filename, ca_dir);
    if (!err_code) {
        s2n_x509_trust_store_wipe(store);
        POSIX_BAIL(S2N_ERR_X509_TRUST_STORE);
    }

    return 0;
}

#if S2N_LIBCRYPTO_SUPPORTS_CBS
/* Trust_Store_Bridge.
 *
 * The X509_STORE remains the source of truth. At the first zero-copy validation
 * that touches a store we lazily extract every certificate as owned DER (via
 * i2d_X509) into an immutable, subject-sorted, reference-counted snapshot of
 * s2n_cert_span_views. Because the snapshot never changes after build, in-flight
 * validations read it lock-free. A store mutation only clears the
 * store's cached pointer under the build mutex; validations already holding a
 * reference keep their consistent view until they release it.
 *
 * All snapshot pointer/refcount mutation happens under this single process-wide
 * build mutex (the build itself is a cold, one-per-store-generation cost). */
static pthread_mutex_t s2n_trust_anchor_build_lock = PTHREAD_MUTEX_INITIALIZER;

static S2N_RESULT s2n_trust_anchor_snapshot_free(struct s2n_trust_anchor_snapshot *snapshot)
{
    if (snapshot == NULL) {
        return S2N_RESULT_OK;
    }
    if (snapshot->anchors != NULL) {
        for (uint32_t i = 0; i < snapshot->count; i++) {
            /* parsed borrows from der; freeing der invalidates it, which is
             * fine since the whole snapshot is going away. */
            RESULT_GUARD_POSIX(s2n_free(&snapshot->anchors[i].der));
        }
        RESULT_GUARD_POSIX(s2n_free_object((uint8_t **) &snapshot->anchors,
                snapshot->count * sizeof(struct s2n_trust_anchor)));
    }
    uint32_t self_size = sizeof(struct s2n_trust_anchor_snapshot);
    uint8_t *self = (uint8_t *) snapshot;
    RESULT_GUARD_POSIX(s2n_free_object(&self, self_size));
    return S2N_RESULT_OK;
}

/* Copy i2d-produced DER bytes into an owned anchor blob */
static S2N_RESULT s2n_trust_anchor_copy_der(struct s2n_blob *dest, const uint8_t *src, uint32_t len)
{
    RESULT_ENSURE_REF(dest);
    RESULT_ENSURE_REF(src);
    RESULT_ENSURE(dest->size >= len, S2N_ERR_SAFETY);
    RESULT_CHECKED_MEMCPY(dest->data, src, len);
    return S2N_RESULT_OK;
}

/* Order anchors by their raw subject-name bytes so the snapshot is
 * subject-sorted. The path builder scans linearly, so ordering is
 * not required for correctness; sorting only makes future binary-search lookups
 * possible and gives a deterministic layout. */
static int s2n_trust_anchor_subject_cmp(const void *a, const void *b)
{
    const struct s2n_trust_anchor *anchor_a = a;
    const struct s2n_trust_anchor *anchor_b = b;
    uint32_t len_a = anchor_a->parsed.subject.size;
    uint32_t len_b = anchor_b->parsed.subject.size;
    uint32_t min_len = (len_a < len_b) ? len_a : len_b;
    int cmp = memcmp(anchor_a->parsed.subject.data, anchor_b->parsed.subject.data, min_len);
    if (cmp != 0) {
        return cmp;
    }
    if (len_a != len_b) {
        return (len_a < len_b) ? -1 : 1;
    }
    return 0;
}

/* Build the immutable snapshot from the X509_STORE. Covers PEM string, CA file,
 * CA directory, and system-default loading uniformly, because all of them land
 * as X509 objects in the store. Caller holds the build mutex. */
static S2N_RESULT s2n_trust_anchor_snapshot_build(struct s2n_x509_trust_store *store,
        struct s2n_trust_anchor_snapshot **snapshot_out)
{
    RESULT_ENSURE_REF(store);
    RESULT_ENSURE_REF(store->trust_store);
    RESULT_ENSURE_REF(snapshot_out);

    STACK_OF(X509_OBJECT) *objects = X509_STORE_get0_objects(store->trust_store);
    RESULT_ENSURE_REF(objects);
    int object_count = sk_X509_OBJECT_num(objects);
    RESULT_ENSURE_GTE(object_count, 0);

    /* Count only the X509 certificate objects (the store may also hold CRLs). */
    uint32_t cert_count = 0;
    for (int i = 0; i < object_count; i++) {
        X509_OBJECT *object = sk_X509_OBJECT_value(objects, i);
        if (object != NULL && X509_OBJECT_get_type(object) == X509_LU_X509) {
            cert_count++;
        }
    }
    /* Empty trust store: fail closed with the current path's error. */
    RESULT_ENSURE(cert_count > 0, S2N_ERR_CERT_UNTRUSTED);

    DEFER_CLEANUP(struct s2n_blob snapshot_mem = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&snapshot_mem, sizeof(struct s2n_trust_anchor_snapshot)));
    RESULT_CHECKED_MEMSET(snapshot_mem.data, 0, snapshot_mem.size);
    struct s2n_trust_anchor_snapshot *snapshot = (struct s2n_trust_anchor_snapshot *) (void *) snapshot_mem.data;

    struct s2n_blob anchors_mem = { 0 };
    RESULT_GUARD_POSIX(s2n_alloc(&anchors_mem, cert_count * sizeof(struct s2n_trust_anchor)));
    RESULT_CHECKED_MEMSET(anchors_mem.data, 0, anchors_mem.size);
    snapshot->anchors = (struct s2n_trust_anchor *) (void *) anchors_mem.data;
    snapshot->count = 0;

    /* On any error past this point, free everything built so far. */
    uint32_t built = 0;
    s2n_result build_result = S2N_RESULT_OK;
    for (int i = 0; i < object_count && s2n_result_is_ok(build_result); i++) {
        X509_OBJECT *object = sk_X509_OBJECT_value(objects, i);
        if (object == NULL || X509_OBJECT_get_type(object) != X509_LU_X509) {
            continue;
        }
        X509 *cert = X509_OBJECT_get0_X509(object);
        if (cert == NULL) {
            build_result = S2N_RESULT_ERROR;
            break;
        }

        struct s2n_trust_anchor *anchor = &snapshot->anchors[built];
        unsigned char *der_buf = NULL;
        int der_len = i2d_X509(cert, &der_buf);
        if (der_len <= 0 || der_buf == NULL) {
            build_result = S2N_RESULT_ERROR;
            break;
        }
        if (s2n_alloc(&anchor->der, (uint32_t) der_len) != S2N_SUCCESS) {
            OPENSSL_free(der_buf);
            build_result = S2N_RESULT_ERROR;
            break;
        }
        s2n_result copy_result = s2n_trust_anchor_copy_der(&anchor->der, der_buf, (uint32_t) der_len);
        OPENSSL_free(der_buf);
        if (s2n_result_is_error(copy_result)) {
            build_result = S2N_RESULT_ERROR;
            break;
        }

        if (s2n_result_is_error(s2n_cert_span_view_parse(&anchor->parsed, &anchor->der))) {
            /* A cert already accepted by the libcrypto store failed the strict
             * zero-copy parse: fail closed rather than silently drop it. */
            build_result = S2N_RESULT_ERROR;
            break;
        }
        built++;
    }

    if (s2n_result_is_error(build_result)) {
        snapshot->count = built;
        RESULT_GUARD(s2n_trust_anchor_snapshot_free(snapshot));
        ZERO_TO_DISABLE_DEFER_CLEANUP(snapshot_mem);
        RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
    }

    snapshot->count = built;
    qsort(snapshot->anchors, snapshot->count, sizeof(struct s2n_trust_anchor),
            s2n_trust_anchor_subject_cmp);

    /* refcount starts at 1: the store's own reference. */
    snapshot->refcount = 1;
    *snapshot_out = snapshot;
    ZERO_TO_DISABLE_DEFER_CLEANUP(snapshot_mem);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_x509_trust_store_snapshot_acquire(struct s2n_x509_trust_store *store,
        struct s2n_trust_anchor_snapshot **snapshot_out)
{
    RESULT_ENSURE_REF(store);
    RESULT_ENSURE_REF(snapshot_out);
    *snapshot_out = NULL;

    /* Empty stores (never allocated) fail closed like the current path. */
    RESULT_ENSURE(store->trust_store != NULL, S2N_ERR_CERT_UNTRUSTED);

    RESULT_ENSURE(pthread_mutex_lock(&s2n_trust_anchor_build_lock) == 0, S2N_ERR_ATOMIC);

    s2n_result result = S2N_RESULT_OK;
    if (store->anchor_snapshot == NULL) {
        struct s2n_trust_anchor_snapshot *built = NULL;
        result = s2n_trust_anchor_snapshot_build(store, &built);
        if (s2n_result_is_ok(result)) {
            store->anchor_snapshot = built;
        }
    }

    if (s2n_result_is_ok(result)) {
        /* Hand out a reference for this validation. */
        store->anchor_snapshot->refcount++;
        *snapshot_out = store->anchor_snapshot;
    }

    RESULT_ENSURE(pthread_mutex_unlock(&s2n_trust_anchor_build_lock) == 0, S2N_ERR_ATOMIC);
    return result;
}

S2N_RESULT s2n_x509_trust_store_snapshot_release(struct s2n_x509_trust_store *store,
        struct s2n_trust_anchor_snapshot *snapshot)
{
    RESULT_ENSURE_REF(store);
    if (snapshot == NULL) {
        return S2N_RESULT_OK;
    }

    RESULT_ENSURE(pthread_mutex_lock(&s2n_trust_anchor_build_lock) == 0, S2N_ERR_ATOMIC);
    RESULT_ENSURE_GT(snapshot->refcount, 0);
    snapshot->refcount--;
    bool free_now = (snapshot->refcount == 0);
    RESULT_ENSURE(pthread_mutex_unlock(&s2n_trust_anchor_build_lock) == 0, S2N_ERR_ATOMIC);

    if (free_now) {
        RESULT_GUARD(s2n_trust_anchor_snapshot_free(snapshot));
    }
    return S2N_RESULT_OK;
}

void s2n_x509_trust_store_snapshot_invalidate(struct s2n_x509_trust_store *store)
{
    if (store == NULL) {
        return;
    }
    if (pthread_mutex_lock(&s2n_trust_anchor_build_lock) != 0) {
        return;
    }

    struct s2n_trust_anchor_snapshot *to_free = NULL;
    if (store->anchor_snapshot != NULL) {
        /* Drop the store's reference. In-flight validations keep theirs. */
        store->anchor_snapshot->refcount--;
        if (store->anchor_snapshot->refcount == 0) {
            to_free = store->anchor_snapshot;
        }
        store->anchor_snapshot = NULL;
    }

    pthread_mutex_unlock(&s2n_trust_anchor_build_lock);

    if (to_free != NULL) {
        /* Best-effort: cleanup path, nothing to surface an error to. */
        s2n_result discard = s2n_trust_anchor_snapshot_free(to_free);
        (void) discard;
    }
}

/* CRL_Validator wiring.
 *
 * Zero-copy CRL check for a single certificate whose CRL lookup callback has
 * completed. The callback-delivered X509_CRL is bridged to DER (via
 * i2d_X509_CRL) and handed to the zero-copy s2n_crl_validate.*/
S2N_RESULT s2n_x509_validator_check_crl(struct s2n_crl_lookup *lookup,
        struct s2n_pkey *issuer_key, const struct s2n_blob *serial,
        uint64_t verification_time)
{
    RESULT_ENSURE_REF(lookup);
    RESULT_ENSURE_REF(issuer_key);
    RESULT_ENSURE_REF(serial);

    /* A NULL crl means the callback intentionally declined to return a CRL for
     * this certificate (s2n_crl_lookup_ignore was called). This matches the
     * libcrypto path's missing-CRL result */
    RESULT_ENSURE(lookup->crl != NULL, S2N_ERR_CRL_LOOKUP_FAILED);
    RESULT_ENSURE(lookup->crl->crl != NULL, S2N_ERR_CRL_LOOKUP_FAILED);

    /* Bridge the X509_CRL to DER so the zero-copy validator can consume it.
     * This mirrors the Trust_Store_Bridge's i2d_X509 pattern. */
    unsigned char *der_buf = NULL;
    int der_len = i2d_X509_CRL(lookup->crl->crl, &der_buf);
    RESULT_ENSURE(der_len > 0 && der_buf != NULL, S2N_ERR_CRL_LOOKUP_FAILED);

    DEFER_CLEANUP(struct s2n_blob crl_der = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&crl_der, (uint32_t) der_len));
    s2n_result crl_copy_result = s2n_trust_anchor_copy_der(&crl_der, der_buf, (uint32_t) der_len);
    OPENSSL_free(der_buf);
    RESULT_GUARD(crl_copy_result);

    /* s2n_crl_validate: parse + verify signature + check times + check serial.
     * Error codes surface through: S2N_ERR_CERT_INVALID (malformed),
     * S2N_ERR_CRL_SIGNATURE, S2N_ERR_CRL_NOT_YET_VALID, S2N_ERR_CRL_EXPIRED,
     * S2N_ERR_CRL_INVALID_THIS_UPDATE, S2N_ERR_CRL_INVALID_NEXT_UPDATE, or
     * S2N_ERR_CERT_REVOKED. All match the existing error taxonomy. */
    RESULT_GUARD(s2n_crl_validate(&crl_der, issuer_key, serial, verification_time));

    return S2N_RESULT_OK;
}

/* Zero-copy cert chain reading
 *
 * Reads the TLS-framed certificate chain body (after the 3-byte total-chain-
 * length has already been consumed by the handshake layer) into the validator's
 * owned wire_chain blob. The TLS framing (3-byte per-cert length prefixes, and
 * TLS 1.3 per-cert extensions) is stripped: wire_chain contains only the
 * concatenated raw DER Certificate TLVs, back to back. This satisfies the input
 * contract of s2n_cert_chain_spans_parse (self-framing over ASN.1 SEQUENCE
 * elements).
 *
 * This is the single copy. All subsequent span views
 * borrow from the wire_chain blob, which lives until s2n_x509_validator_wipe.
 *
 * On success the validator transitions to READY_TO_VERIFY. In skip mode
 * (skip_cert_validation), the leaf public key is extracted via the span-backed
 * cert view and written to the output parameters. No further verification.
 *
 * Parameters:
 *   validator   - must be in INIT state; CBS-gated fields are populated on return
 *   conn        - connection, used only for protocol version (TLS 1.3 extensions)
 *   cert_chain_in - pointer to the cert chain body (sequence of [uint24 len | DER]...)
 *   cert_chain_len - total byte length of that body
 *   pkey_type_out - (skip mode only) receives the leaf public key type
 *   public_key_out - (skip mode only) receives the leaf public key
 *
 * This function is NOT yet called from the main handshake flow — it will be
 * wired via the Backend_Selector. */
S2N_RESULT s2n_x509_validator_read_cert_chain_spans(struct s2n_x509_validator *validator,
        struct s2n_connection *conn, uint8_t *cert_chain_in, uint32_t cert_chain_len,
        s2n_pkey_type *pkey_type_out, struct s2n_pkey *public_key_out)
{
    RESULT_ENSURE_REF(validator);
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(cert_chain_in);
    RESULT_ENSURE(validator->state == INIT, S2N_ERR_INVALID_CERT_STATE);

    /* Trust-store check mirrors s2n_x509_validator_read_cert_chain. */
    RESULT_ENSURE(validator->skip_cert_validation || s2n_x509_trust_store_has_certs(validator->trust_store),
            S2N_ERR_CERT_UNTRUSTED);

    /* First pass: walk the TLS-framed chain to compute the total DER size
     * (stripped of 3-byte length prefixes and TLS 1.3 extensions). We use a
     * stuffer just for bounded reading. */
    struct s2n_blob chain_blob = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&chain_blob, cert_chain_in, cert_chain_len));
    struct s2n_stuffer in = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init(&in, &chain_blob));
    RESULT_GUARD_POSIX(s2n_stuffer_skip_write(&in, cert_chain_len));

    uint32_t total_der_size = 0;
    uint32_t cert_count = 0;
    {
        /* Sizing pass - save the stuffer position and restore after. */
        struct s2n_stuffer sizing = in;
        while (s2n_stuffer_data_available(&sizing) > 0 && cert_count < validator->max_chain_depth) {
            uint32_t cert_size = 0;
            RESULT_GUARD_POSIX(s2n_stuffer_read_uint24(&sizing, &cert_size));
            RESULT_ENSURE(cert_size > 0, S2N_ERR_CERT_INVALID);
            RESULT_ENSURE(cert_size <= s2n_stuffer_data_available(&sizing), S2N_ERR_CERT_INVALID);
            RESULT_GUARD_POSIX(s2n_stuffer_skip_read(&sizing, cert_size));
            total_der_size += cert_size;
            cert_count++;

            /* TLS 1.3: skip per-cert extensions (2-byte length + extension bytes). */
            if (conn->actual_protocol_version >= S2N_TLS13) {
                uint16_t ext_size = 0;
                RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&sizing, &ext_size));
                RESULT_ENSURE(ext_size <= s2n_stuffer_data_available(&sizing), S2N_ERR_CERT_INVALID);
                RESULT_GUARD_POSIX(s2n_stuffer_skip_read(&sizing, ext_size));
            }
        }

        /* If there is still data after reading max_chain_depth certs, the chain
         * exceeds the limit (matching s2n_x509_validator_read_cert_chain). In
         * skip mode the existing code tolerates this; we match that behavior. */
        if (!validator->skip_cert_validation) {
            RESULT_ENSURE(s2n_stuffer_data_available(&sizing) == 0,
                    S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED);
        }
    }

    RESULT_ENSURE(cert_count > 0, S2N_ERR_NO_CERT_FOUND);
    RESULT_ENSURE(total_der_size > 0, S2N_ERR_CERT_INVALID);

    /* Allocate the single owned wire_chain blob. */
    RESULT_GUARD_POSIX(s2n_alloc(&validator->wire_chain, total_der_size));

    /* Second pass: copy just the DER cert bytes (stripping framing). */
    uint32_t offset = 0;
    uint32_t certs_copied = 0;
    while (s2n_stuffer_data_available(&in) > 0 && certs_copied < cert_count) {
        uint32_t cert_size = 0;
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint24(&in, &cert_size));

        uint8_t *src = s2n_stuffer_raw_read(&in, cert_size);
        RESULT_ENSURE_REF(src);

        RESULT_CHECKED_MEMCPY(validator->wire_chain.data + offset, src, cert_size);
        offset += cert_size;
        certs_copied++;

        /* TLS 1.3: skip per-cert extensions. */
        if (conn->actual_protocol_version >= S2N_TLS13) {
            uint16_t ext_size = 0;
            RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&in, &ext_size));
            RESULT_GUARD_POSIX(s2n_stuffer_skip_read(&in, ext_size));
        }
    }

    /* Parse the concatenated DER into span views. The block is right-sized to
     * the certificate count from the sizing pass (a full s2n_cert_chain_spans
     * would reserve S2N_CERT_CHAIN_SPANS_MAX views regardless of chain length).
     * cert_count is passed as the parse depth cap: it both bounds writes to the
     * truncated block and rejects a framing mismatch where the ASN.1 split
     * yields more certificates than the TLS framing declared. */
    uint32_t spans_size = offsetof(struct s2n_cert_chain_spans, views)
            + cert_count * sizeof(struct s2n_cert_span_view);
    RESULT_GUARD_POSIX(s2n_alloc(&validator->chain_spans_mem, spans_size));
    RESULT_GUARD_POSIX(s2n_blob_zero(&validator->chain_spans_mem));
    validator->chain_spans = (struct s2n_cert_chain_spans *) (void *) validator->chain_spans_mem.data;

    RESULT_ENSURE(cert_count <= validator->max_chain_depth, S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED);
    RESULT_GUARD(s2n_cert_chain_spans_parse(validator->chain_spans,
            &validator->wire_chain, (uint16_t) cert_count));

    /* Skip mode: extract the leaf public key and return without chain
     * verification (matching current unsafe-mode behavior). */
    if (validator->skip_cert_validation) {
        RESULT_ENSURE_REF(pkey_type_out);
        RESULT_ENSURE_REF(public_key_out);
        RESULT_ENSURE(validator->chain_spans->count > 0, S2N_ERR_NO_CERT_FOUND);

        struct s2n_cert_view leaf_view = { 0 };
        RESULT_GUARD(s2n_cert_view_init_span(&leaf_view, &validator->chain_spans->views[0]));
        RESULT_GUARD(s2n_cert_view_get_public_key(&leaf_view, public_key_out, pkey_type_out));
        return S2N_RESULT_OK;
    }

    validator->state = READY_TO_VERIFY;
    return S2N_RESULT_OK;
}

/* Forward declaration: s2n_verify_host_information_san_entry is defined later
 * in this file (outside the CBS gate) but called from the span-backed hostname
 * verification helper below. */
static S2N_RESULT s2n_verify_host_information_san_entry(struct s2n_connection *conn,
        const struct s2n_cert_san_entry *entry, bool *san_found);

/* Zero-copy hostname verification: drives verify_host_fn over a span-backed
 * cert view's SAN entries and (if no SAN) the common name, exactly mirroring
 * the libcrypto path's s2n_verify_host_information. */
static S2N_RESULT s2n_verify_host_information_span(struct s2n_connection *conn,
        const struct s2n_cert_span_view *leaf_span)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(leaf_span);

    struct s2n_cert_view leaf_view = { 0 };
    RESULT_GUARD(s2n_cert_view_init_span(&leaf_view, leaf_span));

    bool entry_found = false;

    /* Check SubjectAltNames before CommonName as per RFC 6125 6.4.4 */
    s2n_result result = s2n_cert_view_verify_sans(&leaf_view, conn,
            s2n_verify_host_information_san_entry, &entry_found);

    if (entry_found) {
        return result;
    }

    /* CN fallback: only when no SAN extension is present (RFC 6125 §6.4.4). */
    bool cn_found = false;
    char peer_cn[255] = { 0 };
    struct s2n_blob peer_cn_blob = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&peer_cn_blob, (uint8_t *) peer_cn, sizeof(peer_cn)));

    uint32_t len = 0;
    RESULT_GUARD(s2n_cert_view_get_common_name(&leaf_view, &peer_cn_blob, &len, &cn_found));

    if (cn_found) {
        RESULT_ENSURE_REF(conn->config);
        if (!conn->config->allow_ip_in_cn) {
            unsigned char ip_buf[sizeof(struct in6_addr)] = { 0 };
            if (inet_pton(AF_INET, peer_cn, ip_buf) == 1 || inet_pton(AF_INET6, peer_cn, ip_buf) == 1) {
                RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
            }
        }
        RESULT_ENSURE(conn->verify_host_fn(peer_cn, len, conn->data_for_verify_host),
                S2N_ERR_CERT_INVALID_HOSTNAME);
        return S2N_RESULT_OK;
    }

    /* No SAN and no CN: pass an empty string to the callback (matches the
     * libcrypto path's last-resort behavior). */
    const char *name = "";
    size_t name_len = 0;
    RESULT_ENSURE(conn->verify_host_fn(name, name_len, conn->data_for_verify_host),
            S2N_ERR_CERT_INVALID_HOSTNAME);

    return S2N_RESULT_OK;
}

/* Zero-copy chain-validation flow.
 *
 * Called after s2n_x509_validator_read_cert_chain_spans succeeds in non-skip
 * mode (validator state == READY_TO_VERIFY, chain_spans populated). Performs:
 *   1. Trust-anchor snapshot acquisition
 *   2. Path build (backtracking, Work_Budget)
 *   3. Whole-path constraint checks (EKU, nameConstraints, critical extensions)
 *   4. Hostname verification on the leaf (span-backed cert_view)
 *   5. CRL callback flow (if CRL checking is enabled)
 *   6. Cert validation callback invocation (exactly once)
 *   7. State transition to VALIDATED
 *
 * Fail closed: any internal inconsistency rejects with S2N_ERR_CERT_UNTRUSTED.
 * All failures map to the design's error-taxonomy table; no new error codes.
 *
 * This function is NOT yet called from the main handshake flow — 's
 * Backend_Selector will route to it. */
S2N_RESULT s2n_x509_validator_verify_cert_chain_spans(struct s2n_x509_validator *validator,
        struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(validator);
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(conn->config);
    RESULT_ENSURE(validator->state == READY_TO_VERIFY, S2N_ERR_INVALID_CERT_STATE);
    RESULT_ENSURE_REF(validator->chain_spans);
    RESULT_ENSURE(validator->chain_spans->count > 0, S2N_ERR_CERT_UNTRUSTED);

    /* 1. Acquire the trust-anchor snapshot from the trust store. */
    RESULT_ENSURE_REF(validator->trust_store);
    RESULT_GUARD(s2n_x509_trust_store_snapshot_acquire(validator->trust_store,
            &validator->anchor_snapshot));

    /* 2. Build the path policy: max depth, verification time, purpose. */
    struct s2n_cert_path_policy policy = { 0 };
    policy.max_chain_depth = validator->max_chain_depth;

    /* Verification time: when time validation is disabled on the libcrypto path,
     * it either sets NO_CHECK_TIME or installs a verify callback that ignores
     * time errors. For the zero-copy path, we achieve the same by not
     * performing validity checks at all: set verification_time to 0, and the
     * path builder will interpret 0 as "skip time checks". */
    if (conn->config->disable_x509_time_validation) {
        policy.verification_time = 0;
    } else {
        uint64_t current_sys_time_ns = 0;
        RESULT_GUARD(s2n_config_wall_clock(conn->config, &current_sys_time_ns));
        policy.verification_time = current_sys_time_ns / ONE_SEC_IN_NANOS;
    }

    /* Purpose: serverAuth for client connections, clientAuth for server
     * connections (matching the libcrypto path's intent verification). If
     * intent verification is disabled, skip the EKU check. */
    if (!conn->config->disable_x509_intent_verification) {
        if (conn->mode == S2N_CLIENT) {
            policy.purpose = S2N_CERT_PURPOSE_SERVER_AUTH;
        } else {
            policy.purpose = S2N_CERT_PURPOSE_CLIENT_AUTH;
        }
    } else {
        policy.purpose = S2N_CERT_PURPOSE_UNSET;
    }

    /* 3. Build the path from the leaf to a trust anchor. */
    RESULT_GUARD(s2n_cert_path_build(&validator->validated_path,
            validator->chain_spans, validator->anchor_snapshot, &policy));

    /* 4. Whole-path constraint checks. */
    /* EKU purpose check. */
    if (policy.purpose != S2N_CERT_PURPOSE_UNSET) {
        RESULT_GUARD(s2n_cert_path_check_eku(&validator->validated_path,
                validator->chain_spans, validator->anchor_snapshot, &policy));
    }

    /* nameConstraints. */
    RESULT_GUARD(s2n_cert_path_check_name_constraints(&validator->validated_path,
            validator->chain_spans, validator->anchor_snapshot));

    /* Critical-extension sweep. Wire custom OIDs from the config.
     * The existing custom_x509_extension_oids is a STACK_OF(ASN1_OBJECT); we
     * bridge each OID to an s2n_blob of its DER content bytes for the zero-copy
     * check. A NULL/empty stack means no custom OIDs. */
    struct s2n_blob custom_oids[S2N_CERT_PARSE_MAX_CRITICAL_EXTENSIONS] = { { 0 } };
    uint32_t custom_oid_count = 0;

    if (conn->config->custom_x509_extension_oids != NULL) {
        int num_custom = sk_ASN1_OBJECT_num(conn->config->custom_x509_extension_oids);
        for (int i = 0; i < num_custom && custom_oid_count < S2N_CERT_PARSE_MAX_CRITICAL_EXTENSIONS; i++) {
            ASN1_OBJECT *obj = sk_ASN1_OBJECT_value(conn->config->custom_x509_extension_oids, i);
            if (obj == NULL) {
                continue;
            }
            int oid_len = OBJ_length(obj);
            const unsigned char *oid_data = OBJ_get0_data(obj);
            if (oid_len > 0 && oid_data != NULL) {
                custom_oids[custom_oid_count].data = (uint8_t *) (uintptr_t) oid_data;
                custom_oids[custom_oid_count].size = (uint32_t) oid_len;
                custom_oid_count++;
            }
        }
    }

    RESULT_GUARD(s2n_cert_path_check_critical_extensions(&validator->validated_path,
            validator->chain_spans, validator->anchor_snapshot,
            custom_oids, custom_oid_count));

    /* 5. Hostname verification on the leaf ( – 5.5). */
    if (conn->verify_host_fn) {
        RESULT_GUARD(s2n_verify_host_information_span(conn,
                &validator->chain_spans->views[0]));
    }

    /* 6. CRL callback flow. If CRL checking is enabled, invoke the
     * existing lookup callbacks and then validate each delivered CRL using the
     * zero-copy s2n_x509_validator_check_crl. The CRL lookup callbacks populate
     * validator->crl_lookup_list; the async AWAITING_CRL_CALLBACK flow is the
     * same shared code as the libcrypto path. */
    if (conn->config->crl_lookup_cb) {
        RESULT_GUARD(s2n_crl_invoke_lookup_callbacks(conn, validator));
        RESULT_GUARD(s2n_crl_handle_lookup_callback_result(validator));

        /* After all callbacks complete (state back to READY_TO_VERIFY), validate
         * each delivered CRL against the issuer in the validated path. */
        if (validator->crl_lookup_list != NULL) {
            uint32_t num_lookups = 0;
            RESULT_GUARD(s2n_array_num_elements(validator->crl_lookup_list, &num_lookups));

            for (uint32_t i = 0; i < num_lookups; i++) {
                struct s2n_crl_lookup *lookup = NULL;
                RESULT_GUARD(s2n_array_get(validator->crl_lookup_list, i, (void **) &lookup));
                RESULT_ENSURE_REF(lookup);

                /* A NULL crl means the callback intentionally declined (lookup_ignore). */
                if (lookup->crl == NULL) {
                    continue;
                }

                /* Find the issuer of this cert in the validated path. The cert
                 * at path index i is issued by path index i+1. For the last wire
                 * cert, the issuer is the trust anchor. */
                RESULT_ENSURE(i + 1 < validator->validated_path.count, S2N_ERR_CERT_UNTRUSTED);

                const struct s2n_cert_span_view *issuer_view = NULL;
                struct s2n_cert_path_entry *issuer_entry = &validator->validated_path.entries[i + 1];
                if (issuer_entry->type == S2N_CERT_PATH_ENTRY_WIRE) {
                    RESULT_ENSURE(issuer_entry->entry_index < validator->chain_spans->count,
                            S2N_ERR_CERT_UNTRUSTED);
                    issuer_view = &validator->chain_spans->views[issuer_entry->entry_index];
                } else {
                    RESULT_ENSURE(issuer_entry->entry_index < validator->anchor_snapshot->count,
                            S2N_ERR_CERT_UNTRUSTED);
                    issuer_view = &validator->anchor_snapshot->anchors[issuer_entry->entry_index].parsed;
                }

                /* Materialize the issuer's public key from its SPKI span. */
                struct s2n_cert_view issuer_cert_view = { 0 };
                RESULT_GUARD(s2n_cert_view_init_span(&issuer_cert_view, issuer_view));
                DEFER_CLEANUP(struct s2n_pkey issuer_key = { 0 }, s2n_pkey_free);
                s2n_pkey_type issuer_pkey_type = S2N_PKEY_TYPE_UNKNOWN;
                RESULT_GUARD(s2n_cert_view_get_public_key(&issuer_cert_view,
                        &issuer_key, &issuer_pkey_type));

                /* Get the serial of the cert being checked. */
                RESULT_ENSURE(lookup->cert_idx < validator->chain_spans->count,
                        S2N_ERR_CERT_UNTRUSTED);
                const struct s2n_blob *serial = &validator->chain_spans->views[lookup->cert_idx].serial;

                RESULT_GUARD(s2n_x509_validator_check_crl(lookup, &issuer_key,
                        serial, policy.verification_time));
            }
        }
    }

    /* 7. State transition to VALIDATED. This happens BEFORE the cert
     * validation callback so that public APIs gated on validation state
     * (e.g. s2n_connection_get_peer_cert_chain) work inside the callback,
     * matching the libcrypto path's ordering. */
    validator->state = VALIDATED;

    /* 8. Invoke the cert validation callback exactly once.
     * Unchanged s2n_cert_validation_info semantics: accepted+finished flags. */
    if (conn->config->cert_validation_cb) {
        int cb_result = conn->config->cert_validation_cb(conn,
                &validator->cert_validation_info, conn->config->cert_validation_ctx);
        RESULT_ENSURE(cb_result == S2N_SUCCESS, S2N_ERR_CANCELLED);
        validator->cert_validation_cb_invoked = true;

        if (!validator->cert_validation_info.finished) {
            RESULT_BAIL(S2N_ERR_ASYNC_BLOCKED);
        }
        RESULT_ENSURE(validator->cert_validation_info.accepted, S2N_ERR_CERT_REJECTED);
    }

    return S2N_RESULT_OK;
}
#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

void s2n_x509_trust_store_wipe(struct s2n_x509_trust_store *store)
{
    if (store->trust_store) {
#if S2N_LIBCRYPTO_SUPPORTS_CBS
        s2n_x509_trust_store_snapshot_invalidate(store);
#endif
        X509_STORE_free(store->trust_store);
        store->trust_store = NULL;
        store->loaded_system_certs = false;
    }
}

int s2n_x509_validator_init_no_x509_validation(struct s2n_x509_validator *validator)
{
    POSIX_ENSURE_REF(validator);
    validator->trust_store = NULL;
    validator->store_ctx = NULL;
    validator->skip_cert_validation = 1;
    validator->check_stapled_ocsp = 0;
    validator->max_chain_depth = DEFAULT_MAX_CHAIN_DEPTH;
    validator->state = INIT;
    validator->cert_chain_from_wire = sk_X509_new_null();
    validator->crl_lookup_list = NULL;
    validator->cert_validation_info = (struct s2n_cert_validation_info){ 0 };
    validator->cert_validation_cb_invoked = false;

#if S2N_LIBCRYPTO_SUPPORTS_CBS
    validator->wire_chain = (struct s2n_blob){ 0 };
    validator->chain_spans_mem = (struct s2n_blob){ 0 };
    validator->chain_spans = NULL;
    validator->validated_path = (struct s2n_cert_path){ 0 };
    validator->anchor_snapshot = NULL;
#endif

    return 0;
}

int s2n_x509_validator_init(struct s2n_x509_validator *validator, struct s2n_x509_trust_store *trust_store, uint8_t check_ocsp)
{
    POSIX_ENSURE_REF(trust_store);
    validator->trust_store = trust_store;
    validator->skip_cert_validation = 0;
    validator->check_stapled_ocsp = check_ocsp;
    validator->max_chain_depth = DEFAULT_MAX_CHAIN_DEPTH;
    validator->store_ctx = NULL;
    if (validator->trust_store->trust_store) {
        validator->store_ctx = X509_STORE_CTX_new();
        POSIX_ENSURE_REF(validator->store_ctx);
    }
    validator->cert_chain_from_wire = sk_X509_new_null();
    validator->state = INIT;
    validator->crl_lookup_list = NULL;
    validator->cert_validation_info = (struct s2n_cert_validation_info){ 0 };
    validator->cert_validation_cb_invoked = false;

#if S2N_LIBCRYPTO_SUPPORTS_CBS
    validator->wire_chain = (struct s2n_blob){ 0 };
    validator->chain_spans_mem = (struct s2n_blob){ 0 };
    validator->chain_spans = NULL;
    validator->validated_path = (struct s2n_cert_path){ 0 };
    validator->anchor_snapshot = NULL;
#endif

    return 0;
}

static inline void wipe_cert_chain(STACK_OF(X509) *cert_chain)
{
    if (cert_chain) {
        sk_X509_pop_free(cert_chain, X509_free);
    }
}

int s2n_x509_validator_wipe(struct s2n_x509_validator *validator)
{
#if S2N_LIBCRYPTO_SUPPORTS_CBS
    /* Release the trust-anchor snapshot reference BEFORE trust_store is NULLed.
     * The snapshot is externally owned (refcounted by the trust store);
     * releasing it here drops our per-validation reference. */
    if (validator->anchor_snapshot != NULL) {
        if (validator->trust_store != NULL) {
            POSIX_GUARD_RESULT(s2n_x509_trust_store_snapshot_release(
                    validator->trust_store, validator->anchor_snapshot));
        }
        validator->anchor_snapshot = NULL;
    }

    /* Release the owned wire-chain blob. Safe on a zero-initialized blob
     * (s2n_free is a no-op when data == NULL and size == 0). */
    POSIX_GUARD(s2n_free(&validator->wire_chain));

    /* Free the heap-allocated chain spans and NULL the pointer. Safe on a
     * zero-initialized blob (s2n_free is a no-op when data == NULL). */
    POSIX_GUARD(s2n_free(&validator->chain_spans_mem));
    validator->chain_spans = NULL;

    /* Zero out the validated path. */
    validator->validated_path = (struct s2n_cert_path){ 0 };
#endif

    if (validator->store_ctx) {
        X509_STORE_CTX_free(validator->store_ctx);
        validator->store_ctx = NULL;
    }
    wipe_cert_chain(validator->cert_chain_from_wire);
    validator->cert_chain_from_wire = NULL;
    validator->trust_store = NULL;
    validator->skip_cert_validation = 0;
    validator->state = UNINIT;
    validator->max_chain_depth = 0;
    if (validator->crl_lookup_list) {
        POSIX_GUARD_RESULT(s2n_array_free(validator->crl_lookup_list));
        validator->crl_lookup_list = NULL;
    }

    return S2N_SUCCESS;
}

int s2n_x509_validator_set_max_chain_depth(struct s2n_x509_validator *validator, uint16_t max_depth)
{
    POSIX_ENSURE_REF(validator);
    S2N_ERROR_IF(max_depth == 0, S2N_ERR_INVALID_ARGUMENT);

    validator->max_chain_depth = max_depth;
    return 0;
}

static S2N_RESULT s2n_verify_host_information_san_entry(struct s2n_connection *conn,
        const struct s2n_cert_san_entry *entry, bool *san_found)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(entry);
    RESULT_ENSURE_REF(san_found);

    if (entry->type == S2N_CERT_SAN_DNS_OR_URI) {
        *san_found = true;

        RESULT_ENSURE_REF(entry->data);
        RESULT_ENSURE_GT(entry->data_len, 0);
        /* Reject pathologically long entries. DNS names cap at 253; URIs in
         * practice are well under this limit. */
        RESULT_ENSURE_LTE(entry->data_len, 1024);

        /* Null-terminate for callbacks that may use strcmp (matches libcrypto
         * path which delivers NUL-terminated strings from ASN1_STRING). */
        char name_buf[1025] = { 0 };
        RESULT_CHECKED_MEMCPY(name_buf, entry->data, entry->data_len);
        name_buf[entry->data_len] = '\0';

        RESULT_ENSURE(conn->verify_host_fn(name_buf, entry->data_len, conn->data_for_verify_host), S2N_ERR_CERT_INVALID_HOSTNAME);

        return S2N_RESULT_OK;
    }

    if (entry->type == S2N_CERT_SAN_IP) {
        *san_found = true;

        /* try to validate an IP address if it's in the subject alt name. */
        const unsigned char *ip_addr = entry->data;
        RESULT_ENSURE_REF(ip_addr);
        RESULT_ENSURE_GT(entry->data_len, 0);

        RESULT_STACK_BLOB(address, INET6_ADDRSTRLEN + 1, INET6_ADDRSTRLEN + 1);

        if (entry->data_len == 4) {
            RESULT_GUARD(s2n_inet_ntop(AF_INET, ip_addr, &address));
        } else if (entry->data_len == 16) {
            RESULT_GUARD(s2n_inet_ntop(AF_INET6, ip_addr, &address));
        } else {
            /* we aren't able to parse this value so skip it */
            RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
        }

        /* strlen should be safe here since we made sure we were null terminated AND that inet_ntop succeeded */
        const char *name = (const char *) address.data;
        size_t name_len = strlen(name);

        RESULT_ENSURE(conn->verify_host_fn(name, name_len, conn->data_for_verify_host), S2N_ERR_CERT_INVALID_HOSTNAME);

        return S2N_RESULT_OK;
    }

    /* we don't understand this entry type so skip it */
    RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
}

static S2N_RESULT s2n_verify_host_information_san(struct s2n_connection *conn, X509 *public_cert, bool *san_found)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(public_cert);
    RESULT_ENSURE_REF(san_found);

    struct s2n_cert_view cert_view = { 0 };
    RESULT_GUARD(s2n_cert_view_init(&cert_view, public_cert));

    RESULT_GUARD(s2n_cert_view_verify_sans(&cert_view, conn,
            s2n_verify_host_information_san_entry, san_found));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_verify_host_information_common_name(struct s2n_connection *conn, X509 *public_cert, bool *cn_found)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(conn->config);
    RESULT_ENSURE_REF(public_cert);
    RESULT_ENSURE_REF(cn_found);

    struct s2n_cert_view cert_view = { 0 };
    RESULT_GUARD(s2n_cert_view_init(&cert_view, public_cert));

    char peer_cn[255] = { 0 };
    struct s2n_blob peer_cn_blob = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&peer_cn_blob, (uint8_t *) peer_cn, sizeof(peer_cn)));

    uint32_t len = 0;
    RESULT_GUARD(s2n_cert_view_get_common_name(&cert_view, &peer_cn_blob, &len, cn_found));

    /* According to https://www.rfc-editor.org/rfc/rfc6125#section-6.4.4,
     * the CN fallback only applies to fully qualified DNS domain names.
     *
     * An IP address is not a fully qualified DNS domain name. Per RFC 6125
     * section 6.2.1, IP reference identities must only be matched against
     * iPAddress SAN entries, never against CN values. Reject the CN if it
     * parses as an IPv4 or IPv6 address.
     *
     * This check can be temporarily disabled via s2n_config_allow_ip_in_cn()
     * while re-issuing certs with proper iPAddress SAN entries.
     */
    if (!conn->config->allow_ip_in_cn) {
        unsigned char ip_buf[sizeof(struct in6_addr)] = { 0 };
        if (inet_pton(AF_INET, peer_cn, ip_buf) == 1 || inet_pton(AF_INET6, peer_cn, ip_buf) == 1) {
            RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
        }
    }

    RESULT_ENSURE(conn->verify_host_fn(peer_cn, len, conn->data_for_verify_host), S2N_ERR_CERT_INVALID_HOSTNAME);

    return S2N_RESULT_OK;
}

/*
 * For each name in the cert. Iterate them. Call the callback. If one returns true, then consider it validated,
 * if none of them return true, the cert is considered invalid.
 */
static S2N_RESULT s2n_verify_host_information(struct s2n_connection *conn, X509 *public_cert)
{
    bool entry_found = false;

    /* Check SubjectAltNames before CommonName as per RFC 6125 6.4.4 */
    s2n_result result = s2n_verify_host_information_san(conn, public_cert, &entry_found);

    /*
     *= https://www.rfc-editor.org/rfc/rfc6125#section-6.4.4
     *# As noted, a client MUST NOT seek a match for a reference identifier
     *# of CN-ID if the presented identifiers include a DNS-ID, SRV-ID,
     *# URI-ID, or any application-specific identifier types supported by the
     *# client.
     */
    if (entry_found) {
        return result;
    }

    /*
     *= https://www.rfc-editor.org/rfc/rfc6125#section-6.4.4
     *# Therefore, if and only if the presented identifiers do not include a
     *# DNS-ID, SRV-ID, URI-ID, or any application-specific identifier types
     *# supported by the client, then the client MAY as a last resort check
     *# for a string whose form matches that of a fully qualified DNS domain
     *# name in a Common Name field of the subject field (i.e., a CN-ID).
     */
    result = s2n_verify_host_information_common_name(conn, public_cert, &entry_found);
    if (entry_found) {
        return result;
    }

    /* make a null-terminated string in case the callback tries to use strlen */
    const char *name = "";
    size_t name_len = 0;

    /* at this point, we don't have anything to identify the certificate with so pass an empty string to the callback */
    RESULT_ENSURE(conn->verify_host_fn(name, name_len, conn->data_for_verify_host), S2N_ERR_CERT_INVALID_HOSTNAME);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_x509_validator_read_asn1_cert(struct s2n_stuffer *cert_chain_in_stuffer,
        struct s2n_blob *asn1_cert)
{
    uint32_t certificate_size = 0;

    RESULT_GUARD_POSIX(s2n_stuffer_read_uint24(cert_chain_in_stuffer, &certificate_size));
    RESULT_ENSURE(certificate_size > 0, S2N_ERR_CERT_INVALID);
    RESULT_ENSURE(certificate_size <= s2n_stuffer_data_available(cert_chain_in_stuffer), S2N_ERR_CERT_INVALID);

    asn1_cert->size = certificate_size;
    asn1_cert->data = s2n_stuffer_raw_read(cert_chain_in_stuffer, certificate_size);
    RESULT_ENSURE_REF(asn1_cert->data);

    return S2N_RESULT_OK;
}

/**
* Validates that each certificate in a peer's cert chain contains only signature algorithms in a security policy's
* certificate_signatures_preference list.
*/
S2N_RESULT s2n_x509_validator_check_cert_preferences(struct s2n_connection *conn, X509 *cert)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(cert);

    const struct s2n_security_policy *security_policy = NULL;
    RESULT_GUARD_POSIX(s2n_connection_get_security_policy(conn, &security_policy));

    /**
     * We only restrict the signature algorithm on the certificates in the
     * peer's certificate chain if the certificate_signature_preferences field
     * is set in the security policy. This is contrary to the RFC, which
     * specifies that the signatures in the "signature_algorithms" extension
     * apply to signatures in the certificate chain in certain scenarios, so RFC
     * compliance would imply validating that the certificate chain signature
     * algorithm matches one of the algorithms specified in the
     * "signature_algorithms" extension.
     *
     *= https://www.rfc-editor.org/rfc/rfc5246#section-7.4.2
     *= type=exception
     *= reason=not implemented due to lack of utility
     *# If the client provided a "signature_algorithms" extension, then all
     *# certificates provided by the server MUST be signed by a
     *# hash/signature algorithm pair that appears in that extension.
     *
     *= https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3
     *= type=exception
     *= reason=not implemented due to lack of utility
     *# If no "signature_algorithms_cert" extension is present, then the
     *# "signature_algorithms" extension also applies to signatures appearing in
     *# certificates.
     */
    struct s2n_cert_info info = { 0 };
    RESULT_GUARD(s2n_openssl_x509_get_cert_info(cert, &info));

    bool certificate_preferences_defined = security_policy->certificate_signature_preferences != NULL
            || security_policy->certificate_key_preferences != NULL;
    if (certificate_preferences_defined && !info.self_signed && conn->actual_protocol_version == S2N_TLS13) {
        /* Ensure that the certificate signature does not use SHA-1. While this check
         * would ideally apply to all connections, we only enforce it when certificate
         * preferences exist to stay backwards compatible.
         */
        RESULT_ENSURE(info.signature_digest_nid != NID_sha1, S2N_ERR_CERT_UNTRUSTED);
    }

    if (!info.self_signed) {
        RESULT_GUARD(s2n_security_policy_validate_cert_signature(security_policy, &info, S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT));
    }
    RESULT_GUARD(s2n_security_policy_validate_cert_key(security_policy, &info, S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT));

    return S2N_RESULT_OK;
}

#if S2N_LIBCRYPTO_SUPPORTS_CBS
/* On-demand X509 materialization for public APIs.
 *
 * Materializes a STACK_OF(X509) from the validated certification path's DER
 * spans. Each certificate in the validated path is converted from its retained
 * DER (in wire_chain or anchor DER) to an X509 object via d2i_X509.
 *
 * The returned stack has caller-ownership semantics: the caller MUST free it
 * with sk_X509_pop_free(stack, X509_free), exactly as get1_chain results work
 * today. This is a cold path — it is only invoked when a public
 * API genuinely needs materialized X509 objects.
 *
 * Returns S2N_RESULT_OK with validated_cert_chain->stack populated on success.
 * On failure (malformed DER in the retained path — should not happen after
 * successful validation), returns an error and the stack is NULL. */
static S2N_RESULT s2n_x509_validator_materialize_validated_chain(const struct s2n_x509_validator *validator,
        struct s2n_validated_cert_chain *validated_cert_chain)
{
    RESULT_ENSURE_REF(validator);
    RESULT_ENSURE_REF(validated_cert_chain);
    RESULT_ENSURE(validator->validated_path.count > 0, S2N_ERR_INVALID_CERT_STATE);

    STACK_OF(X509) *stack = sk_X509_new_null();
    RESULT_ENSURE(stack != NULL, S2N_ERR_ALLOC);

    for (uint32_t i = 0; i < validator->validated_path.count; i++) {
        const struct s2n_cert_path_entry *entry = &validator->validated_path.entries[i];
        const struct s2n_blob *der = NULL;

        if (entry->type == S2N_CERT_PATH_ENTRY_WIRE) {
            RESULT_ENSURE(entry->entry_index < validator->chain_spans->count, S2N_ERR_CERT_UNTRUSTED);
            der = &validator->chain_spans->views[entry->entry_index].raw;
        } else {
            RESULT_ENSURE_REF(validator->anchor_snapshot);
            RESULT_ENSURE(entry->entry_index < validator->anchor_snapshot->count, S2N_ERR_CERT_UNTRUSTED);
            der = &validator->anchor_snapshot->anchors[entry->entry_index].der;
        }

        RESULT_ENSURE_REF(der);
        RESULT_ENSURE_REF(der->data);
        RESULT_ENSURE(der->size > 0, S2N_ERR_CERT_UNTRUSTED);

        const uint8_t *data_ptr = der->data;
        X509 *cert = d2i_X509(NULL, &data_ptr, der->size);
        if (cert == NULL) {
            sk_X509_pop_free(stack, X509_free);
            RESULT_BAIL(S2N_ERR_DECODE_CERTIFICATE);
        }

        if (sk_X509_push(stack, cert) <= 0) {
            X509_free(cert);
            sk_X509_pop_free(stack, X509_free);
            RESULT_BAIL(S2N_ERR_ALLOC);
        }
    }

    validated_cert_chain->stack = stack;
    return S2N_RESULT_OK;
}
#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

S2N_RESULT s2n_x509_validator_get_validated_cert_chain(const struct s2n_x509_validator *validator,
        struct s2n_validated_cert_chain *validated_cert_chain)
{
    RESULT_ENSURE_REF(validator);
    RESULT_ENSURE_REF(validated_cert_chain);

    RESULT_ENSURE(s2n_x509_validator_is_cert_chain_validated(validator), S2N_ERR_INVALID_CERT_STATE);

#if S2N_LIBCRYPTO_SUPPORTS_CBS
    /* Zero-copy path: when the validator was driven through the span-based flow
     * (wire_chain populated, no store_ctx), materialize X509 objects on demand
     * from the validated path's DER spans. The result has caller-ownership
     * semantics matching get1_chain. */
    if (validator->wire_chain.data != NULL && validator->validated_path.count > 0) {
        RESULT_GUARD(s2n_x509_validator_materialize_validated_chain(validator, validated_cert_chain));
        validated_cert_chain->owned = true;
        return S2N_RESULT_OK;
    }
#endif

    /* Libcrypto path: get the validated chain from the X509_STORE_CTX. */
    RESULT_ENSURE_REF(validator->store_ctx);

#if S2N_LIBCRYPTO_SUPPORTS_GET0_CHAIN
    /* X509_STORE_CTX_get0_chain is used when available, since it returns a pointer to the
     * validated cert chain in the X509_STORE_CTX, avoiding an allocation/copy.
     */
    validated_cert_chain->stack = X509_STORE_CTX_get0_chain(validator->store_ctx);
    validated_cert_chain->owned = false;
#else
    /* Otherwise, X509_STORE_CTX_get1_chain is used instead, which allocates a new cert chain. */
    validated_cert_chain->stack = X509_STORE_CTX_get1_chain(validator->store_ctx);
    validated_cert_chain->owned = true;
#endif

    RESULT_ENSURE_REF(validated_cert_chain->stack);

    return S2N_RESULT_OK;
}

S2N_CLEANUP_RESULT s2n_x509_validator_validated_cert_chain_free(struct s2n_validated_cert_chain *validated_cert_chain)
{
    RESULT_ENSURE_REF(validated_cert_chain);

    if (validated_cert_chain->owned && validated_cert_chain->stack != NULL) {
        /* The stack was allocated by s2n-tls (via d2i_X509 materialization on the
         * zero-copy path or via X509_STORE_CTX_get1_chain) and MUST be freed. */
        RESULT_GUARD(s2n_openssl_x509_stack_pop_free(&validated_cert_chain->stack));
    }

    /* Even though the cert chain reference is still valid in the case that get0_chain is used, set
     * it to null for consistency with the get1_chain case.
     */
    validated_cert_chain->stack = NULL;

    return S2N_RESULT_OK;
}

/* Validates that the root certificate uses a key allowed by the security policy
 * certificate preferences.
 */
static S2N_RESULT s2n_x509_validator_check_root_cert(struct s2n_x509_validator *validator, struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(validator);
    RESULT_ENSURE_REF(conn);

    const struct s2n_security_policy *security_policy = NULL;
    RESULT_GUARD_POSIX(s2n_connection_get_security_policy(conn, &security_policy));
    RESULT_ENSURE_REF(security_policy);

    DEFER_CLEANUP(struct s2n_validated_cert_chain validated_cert_chain = { 0 }, s2n_x509_validator_validated_cert_chain_free);
    RESULT_GUARD(s2n_x509_validator_get_validated_cert_chain(validator, &validated_cert_chain));
    STACK_OF(X509) *cert_chain = validated_cert_chain.stack;
    RESULT_ENSURE_REF(cert_chain);

    struct s2n_cert_chain_view chain_view = { 0 };
    RESULT_GUARD(s2n_cert_chain_view_init(&chain_view, cert_chain));
    int certs_in_chain = 0;
    RESULT_GUARD(s2n_cert_chain_view_count(&chain_view, &certs_in_chain));
    RESULT_ENSURE(certs_in_chain > 0, S2N_ERR_CERT_UNTRUSTED);
    struct s2n_cert_view root_view = { 0 };
    RESULT_GUARD(s2n_cert_chain_view_get(&chain_view, certs_in_chain - 1, &root_view));

    struct s2n_cert_info info = { 0 };
    RESULT_GUARD(s2n_openssl_x509_get_cert_info(root_view.u.x509, &info));

    RESULT_GUARD(s2n_security_policy_validate_cert_key(security_policy, &info,
            S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_x509_validator_read_cert_chain(struct s2n_x509_validator *validator, struct s2n_connection *conn,
        uint8_t *cert_chain_in, uint32_t cert_chain_len)
{
    RESULT_ENSURE(validator->skip_cert_validation || s2n_x509_trust_store_has_certs(validator->trust_store), S2N_ERR_CERT_UNTRUSTED);
    RESULT_ENSURE(validator->state == INIT, S2N_ERR_INVALID_CERT_STATE);

    struct s2n_blob cert_chain_blob = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&cert_chain_blob, cert_chain_in, cert_chain_len));
    DEFER_CLEANUP(struct s2n_stuffer cert_chain_in_stuffer = { 0 }, s2n_stuffer_free);

    RESULT_GUARD_POSIX(s2n_stuffer_init(&cert_chain_in_stuffer, &cert_chain_blob));
    RESULT_GUARD_POSIX(s2n_stuffer_write(&cert_chain_in_stuffer, &cert_chain_blob));

    while (s2n_stuffer_data_available(&cert_chain_in_stuffer)
            && sk_X509_num(validator->cert_chain_from_wire) < validator->max_chain_depth) {
        struct s2n_blob asn1_cert = { 0 };
        RESULT_GUARD(s2n_x509_validator_read_asn1_cert(&cert_chain_in_stuffer, &asn1_cert));

        /* We only do the trailing byte validation when parsing the leaf cert to
         * match historical s2n-tls behavior.
         */
        DEFER_CLEANUP(X509 *cert = NULL, X509_free_pointer);
        if (sk_X509_num(validator->cert_chain_from_wire) == 0) {
            RESULT_GUARD(s2n_openssl_x509_parse(&asn1_cert, &cert));
        } else {
            RESULT_GUARD(s2n_openssl_x509_parse_without_length_validation(&asn1_cert, &cert));
        }

        if (!validator->skip_cert_validation) {
            RESULT_GUARD(s2n_x509_validator_check_cert_preferences(conn, cert));
        }

        /* add the cert to the chain */
        RESULT_ENSURE(sk_X509_push(validator->cert_chain_from_wire, cert) > 0,
                S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);

        /* After the cert is added to cert_chain_from_wire, it will be freed
         * with the call to s2n_x509_validator_wipe. We disable the cleanup
         * function since cleanup is no longer "owned" by cert.
         */
        ZERO_TO_DISABLE_DEFER_CLEANUP(cert);

        /* certificate extensions is a field in TLS 1.3 - https://tools.ietf.org/html/rfc8446#section-4.4.2 */
        if (conn->actual_protocol_version >= S2N_TLS13) {
            s2n_parsed_extensions_list parsed_extensions_list = { 0 };
            RESULT_GUARD_POSIX(s2n_extension_list_parse(&cert_chain_in_stuffer, &parsed_extensions_list));
        }
    }

    /* if this occurred we exceeded validator->max_chain_depth */
    RESULT_ENSURE(validator->skip_cert_validation || s2n_stuffer_data_available(&cert_chain_in_stuffer) == 0,
            S2N_ERR_CERT_MAX_CHAIN_DEPTH_EXCEEDED);
    RESULT_ENSURE(sk_X509_num(validator->cert_chain_from_wire) > 0, S2N_ERR_NO_CERT_FOUND);

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_x509_validator_process_cert_chain(struct s2n_x509_validator *validator, struct s2n_connection *conn,
        uint8_t *cert_chain_in, uint32_t cert_chain_len)
{
    RESULT_ENSURE(validator->state == INIT, S2N_ERR_INVALID_CERT_STATE);

    RESULT_GUARD(s2n_x509_validator_read_cert_chain(validator, conn, cert_chain_in, cert_chain_len));

    if (validator->skip_cert_validation) {
        return S2N_RESULT_OK;
    }

    X509 *leaf = sk_X509_value(validator->cert_chain_from_wire, 0);
    RESULT_ENSURE_REF(leaf);

    if (conn->verify_host_fn) {
        RESULT_GUARD(s2n_verify_host_information(conn, leaf));
    }

    RESULT_GUARD_OSSL(X509_STORE_CTX_init(validator->store_ctx, validator->trust_store->trust_store, leaf,
                              validator->cert_chain_from_wire),
            S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);

    if (conn->config->crl_lookup_cb) {
        RESULT_GUARD(s2n_crl_invoke_lookup_callbacks(conn, validator));
        RESULT_GUARD(s2n_crl_handle_lookup_callback_result(validator));
    }

    validator->state = READY_TO_VERIFY;

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_x509_validator_set_no_check_time_flag(struct s2n_x509_validator *validator)
{
    RESULT_ENSURE_REF(validator);
    RESULT_ENSURE_REF(validator->store_ctx);

    X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(validator->store_ctx);
    RESULT_ENSURE_REF(param);

#ifdef S2N_LIBCRYPTO_SUPPORTS_FLAG_NO_CHECK_TIME
    RESULT_GUARD_OSSL(X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_NO_CHECK_TIME),
            S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);
#else
    RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
#endif

    return S2N_RESULT_OK;
}

int s2n_disable_time_validation_ossl_verify_callback(int default_ossl_ret, X509_STORE_CTX *ctx)
{
    int err = X509_STORE_CTX_get_error(ctx);
    switch (err) {
        case X509_V_ERR_CERT_NOT_YET_VALID:
        case X509_V_ERR_CERT_HAS_EXPIRED:
            return OSSL_VERIFY_CALLBACK_IGNORE_ERROR;
        default:
            break;
    }

    /* If CRL validation is enabled, setting the time validation verify callback will override the
     * CRL verify callback. The CRL verify callback is manually triggered to work around this
     * issue.
     *
     * The CRL verify callback ignores validation errors exclusively for CRL timestamp fields. So,
     * if CRL validation isn't enabled, the CRL verify callback is a no-op.
     */
    return s2n_crl_ossl_verify_callback(default_ossl_ret, ctx);
}

static S2N_RESULT s2n_x509_validator_disable_time_validation(struct s2n_connection *conn,
        struct s2n_x509_validator *validator)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(conn->config);
    RESULT_ENSURE_REF(validator);
    RESULT_ENSURE_REF(validator->store_ctx);

    /* Setting an X509_STORE verify callback is not recommended with AWS-LC:
     * https://github.com/aws/aws-lc/blob/aa90e509f2e940916fbe9fdd469a4c90c51824f6/include/openssl/x509.h#L2980-L2990
     *
     * If the libcrypto supports the ability to disable time validation with an X509_VERIFY_PARAM
     * NO_CHECK_TIME flag, this method is preferred.
     *
     * However, older versions of AWS-LC and OpenSSL 1.0.2 do not support this flag. In this case,
     * an X509_STORE verify callback is used. This is acceptable in older versions of AWS-LC
     * because the versions are fixed, and updates to AWS-LC will not break the callback
     * implementation.
     */
    if (s2n_libcrypto_supports_flag_no_check_time()) {
        RESULT_GUARD(s2n_x509_validator_set_no_check_time_flag(validator));
    } else {
        X509_STORE_CTX_set_verify_cb(validator->store_ctx,
                s2n_disable_time_validation_ossl_verify_callback);
    }

    return S2N_RESULT_OK;
}

int s2n_no_op_verify_custom_crit_oids_cb(X509_STORE_CTX *ctx, X509 *x509, STACK_OF(ASN1_OBJECT) *oids)
{
    return 1;
}

static S2N_RESULT s2n_x509_validator_add_custom_extensions(struct s2n_x509_validator *validator, struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(validator);
    RESULT_ENSURE_REF(validator->store_ctx);
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(conn->config);

    if (conn->config->custom_x509_extension_oids) {
#if S2N_LIBCRYPTO_SUPPORTS_CUSTOM_OID
        size_t custom_oid_count = sk_ASN1_OBJECT_num(conn->config->custom_x509_extension_oids);
        for (size_t i = 0; i < custom_oid_count; i++) {
            ASN1_OBJECT *critical_oid = sk_ASN1_OBJECT_value(conn->config->custom_x509_extension_oids, i);
            RESULT_ENSURE_REF(critical_oid);
            RESULT_GUARD_OSSL(X509_STORE_CTX_add_custom_crit_oid(validator->store_ctx, critical_oid),
                    S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);
        }
        /* To enable AWS-LC accepting custom extensions, an X509_STORE_CTX_verify_crit_oids_cb must be set.
         * See https://github.com/aws/aws-lc/blob/f0b4afedd7d45fc2517643d890b654856c57f994/include/openssl/x509.h#L2913-L2918.
         * 
         * The `X509_STORE_CTX_verify_crit_oids_cb` callback can be used to implement the validation for the
         * custom certificate extensions. However, s2n-tls consumers are expected to implement this validation
         * in the `s2n_cert_validation_callback` instead. So, a no-op callback is provided to AWS-LC.
         */
        X509_STORE_CTX_set_verify_crit_oids(validator->store_ctx, s2n_no_op_verify_custom_crit_oids_cb);
#else
        RESULT_BAIL(S2N_ERR_UNIMPLEMENTED);
#endif
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_x509_validator_verify_intent_for_cert(struct s2n_connection *conn,
        const struct s2n_cert_view *cert_view, bool is_leaf)
{
    RESULT_ENSURE_REF(cert_view);

    /* The X509_PURPOSE values indicate the purpose that certificates must specify. For servers,
     * received client certificates MUST have a TLS client purpose. For clients, received server
     * certificates MUST have a TLS server purpose.
     */
    s2n_cert_purpose purpose = S2N_CERT_PURPOSE_SSL_CLIENT;
    if (conn->mode == S2N_CLIENT) {
        purpose = S2N_CERT_PURPOSE_SSL_SERVER;
    }

    RESULT_GUARD(s2n_cert_view_check_purpose(cert_view, purpose, !is_leaf));

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_x509_validator_verify_intent(struct s2n_x509_validator *validator, struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(conn->config);

    if (conn->config->disable_x509_intent_verification) {
        return S2N_RESULT_OK;
    }

    DEFER_CLEANUP(struct s2n_validated_cert_chain validated_cert_chain = { 0 }, s2n_x509_validator_validated_cert_chain_free);
    RESULT_GUARD(s2n_x509_validator_get_validated_cert_chain(validator, &validated_cert_chain));

    struct s2n_cert_chain_view chain_view = { 0 };
    RESULT_GUARD(s2n_cert_chain_view_init(&chain_view, validated_cert_chain.stack));

    int cert_count = 0;
    RESULT_GUARD(s2n_cert_chain_view_count(&chain_view, &cert_count));
    RESULT_ENSURE_GT(cert_count, 0);

    /* The validated cert chain returned from the libcrypto includes the trust anchor. The trust
     * anchor is omitted from intent verification since its TLS intent is implicitly indicated by
     * its presence in the s2n-tls trust store.
     */
    cert_count -= 1;

    for (int i = 0; i < cert_count; i++) {
        struct s2n_cert_view cert_view = { 0 };
        RESULT_GUARD(s2n_cert_chain_view_get(&chain_view, i, &cert_view));

        bool is_leaf = (i == 0);
        RESULT_GUARD(s2n_x509_validator_verify_intent_for_cert(conn, &cert_view, is_leaf));
    }

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_x509_validator_verify_cert_chain(struct s2n_x509_validator *validator, struct s2n_connection *conn)
{
    RESULT_ENSURE(validator->state == READY_TO_VERIFY, S2N_ERR_INVALID_CERT_STATE);

    X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(validator->store_ctx);
    X509_VERIFY_PARAM_set_depth(param, validator->max_chain_depth);

    DEFER_CLEANUP(STACK_OF(X509_CRL) *crl_stack = NULL, sk_X509_CRL_free_pointer);

    if (conn->config->crl_lookup_cb) {
        X509_STORE_CTX_set_verify_cb(validator->store_ctx, s2n_crl_ossl_verify_callback);

        crl_stack = sk_X509_CRL_new_null();
        RESULT_GUARD(s2n_crl_get_crls_from_lookup_list(validator, crl_stack));

        /* Set the CRL list that the libcrypto will use to validate certificates with */
        X509_STORE_CTX_set0_crls(validator->store_ctx, crl_stack);

        /* Enable CRL validation for certificates in X509_verify_cert */
        RESULT_GUARD_OSSL(X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK),
                S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);

        /* Enable CRL validation for all certificates, not just the leaf */
        RESULT_GUARD_OSSL(X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK_ALL),
                S2N_ERR_INTERNAL_LIBCRYPTO_ERROR);
    }

    /* Disabling time validation may set a NO_CHECK_TIME flag on the X509_STORE_CTX. Calling
     * X509_STORE_CTX_set_time will override this flag. To prevent this, X509_STORE_CTX_set_time is
     * only called if time validation is enabled.
     */
    if (conn->config->disable_x509_time_validation) {
        RESULT_GUARD(s2n_x509_validator_disable_time_validation(conn, validator));
    } else {
        uint64_t current_sys_time = 0;
        RESULT_GUARD(s2n_config_wall_clock(conn->config, &current_sys_time));
        if (sizeof(time_t) == 4) {
            /* cast value to uint64_t to prevent overflow errors */
            RESULT_ENSURE_LTE(current_sys_time, (uint64_t) MAX_32_TIMESTAMP_NANOS);
        }

        /* this wants seconds not nanoseconds */
        time_t current_time = (time_t) (current_sys_time / ONE_SEC_IN_NANOS);
        X509_STORE_CTX_set_time(validator->store_ctx, 0, current_time);
    }

    /* It's assumed that if a valid certificate chain is received with an issuer that's present in
     * the trust store, the certificate chain should be trusted. This should be the case even if
     * the issuer in the trust store isn't a root certificate. Setting the PARTIAL_CHAIN flag
     * allows the libcrypto to trust certificates in the trust store that aren't root certificates.
     */
    X509_STORE_CTX_set_flags(validator->store_ctx, X509_V_FLAG_PARTIAL_CHAIN);

    RESULT_GUARD(s2n_x509_validator_add_custom_extensions(validator, conn));

    int verify_ret = X509_verify_cert(validator->store_ctx);
    if (verify_ret <= 0) {
        int ossl_error = X509_STORE_CTX_get_error(validator->store_ctx);
        switch (ossl_error) {
            case X509_V_ERR_CERT_NOT_YET_VALID:
                RESULT_BAIL(S2N_ERR_CERT_NOT_YET_VALID);
            case X509_V_ERR_CERT_HAS_EXPIRED:
                RESULT_BAIL(S2N_ERR_CERT_EXPIRED);
            case X509_V_ERR_CERT_REVOKED:
                RESULT_BAIL(S2N_ERR_CERT_REVOKED);
            case X509_V_ERR_UNABLE_TO_GET_CRL:
            case X509_V_ERR_DIFFERENT_CRL_SCOPE:
                RESULT_BAIL(S2N_ERR_CRL_LOOKUP_FAILED);
            case X509_V_ERR_CRL_SIGNATURE_FAILURE:
                RESULT_BAIL(S2N_ERR_CRL_SIGNATURE);
            case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
                RESULT_BAIL(S2N_ERR_CRL_ISSUER);
            case X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION:
                RESULT_BAIL(S2N_ERR_CRL_UNHANDLED_CRITICAL_EXTENSION);
            case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
                RESULT_BAIL(S2N_ERR_CERT_UNHANDLED_CRITICAL_EXTENSION);
            default:
                RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
        }
    }

    validator->state = VALIDATED;

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_x509_validator_parse_leaf_certificate_extensions(struct s2n_connection *conn,
        uint8_t *cert_chain_in, uint32_t cert_chain_len,
        s2n_parsed_extensions_list *first_certificate_extensions)
{
    /* certificate extensions is a field in TLS 1.3 - https://tools.ietf.org/html/rfc8446#section-4.4.2 */
    RESULT_ENSURE_GTE(conn->actual_protocol_version, S2N_TLS13);

    struct s2n_blob cert_chain_blob = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&cert_chain_blob, cert_chain_in, cert_chain_len));
    DEFER_CLEANUP(struct s2n_stuffer cert_chain_in_stuffer = { 0 }, s2n_stuffer_free);

    RESULT_GUARD_POSIX(s2n_stuffer_init(&cert_chain_in_stuffer, &cert_chain_blob));
    RESULT_GUARD_POSIX(s2n_stuffer_write(&cert_chain_in_stuffer, &cert_chain_blob));

    struct s2n_blob asn1_cert = { 0 };
    RESULT_GUARD(s2n_x509_validator_read_asn1_cert(&cert_chain_in_stuffer, &asn1_cert));

    s2n_parsed_extensions_list parsed_extensions_list = { 0 };
    RESULT_GUARD_POSIX(s2n_extension_list_parse(&cert_chain_in_stuffer, &parsed_extensions_list));
    *first_certificate_extensions = parsed_extensions_list;

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_x509_validator_validate_cert_chain_pre_cb(struct s2n_x509_validator *validator, struct s2n_connection *conn,
        uint8_t *cert_chain_in, uint32_t cert_chain_len)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(conn->config);

    switch (validator->state) {
        case INIT:
            break;
        case AWAITING_CRL_CALLBACK:
            RESULT_GUARD(s2n_crl_handle_lookup_callback_result(validator));
            break;
        default:
            RESULT_BAIL(S2N_ERR_INVALID_CERT_STATE);
    }

    if (validator->state == INIT) {
        RESULT_GUARD(s2n_x509_validator_process_cert_chain(validator, conn, cert_chain_in, cert_chain_len));
    }

    if (validator->state == READY_TO_VERIFY) {
        RESULT_GUARD(s2n_x509_validator_verify_cert_chain(validator, conn));
        RESULT_GUARD(s2n_x509_validator_verify_intent(validator, conn));
        RESULT_GUARD(s2n_x509_validator_check_root_cert(validator, conn));
    }

    if (conn->actual_protocol_version >= S2N_TLS13) {
        /* Only process certificate extensions received in the first certificate. Extensions received in all other
         * certificates are ignored.
         *
         *= https://www.rfc-editor.org/rfc/rfc8446#section-4.4.2
         *# If an extension applies to the entire chain, it SHOULD be included in
         *# the first CertificateEntry.
         */
        s2n_parsed_extensions_list first_certificate_extensions = { 0 };
        RESULT_GUARD(s2n_x509_validator_parse_leaf_certificate_extensions(conn, cert_chain_in, cert_chain_len, &first_certificate_extensions));
        RESULT_GUARD_POSIX(s2n_extension_list_process(S2N_EXTENSION_LIST_CERTIFICATE, conn, &first_certificate_extensions));
    }

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_x509_validator_handle_cert_validation_callback_result(struct s2n_x509_validator *validator)
{
    RESULT_ENSURE_REF(validator);

    if (!validator->cert_validation_info.finished) {
        RESULT_BAIL(S2N_ERR_ASYNC_BLOCKED);
    }

    RESULT_ENSURE(validator->cert_validation_info.accepted, S2N_ERR_CERT_REJECTED);
    return S2N_RESULT_OK;
}

#if S2N_LIBCRYPTO_SUPPORTS_CBS
/* Differential_Validator: callback-suppressed verify_host that accepts all names
 * . During the zero-copy run in differential mode, the libcrypto path
 * has already fired the real verify_host callback; this recording variant accepts
 * unconditionally so the zero-copy path exercises its SAN iteration logic without
 * affecting the connection's trust decision. */
static uint8_t s2n_differential_accept_all_hosts(const char *host_name, size_t host_name_len, void *data)
{
    return 1;
}
#endif

S2N_RESULT s2n_x509_validator_validate_cert_chain(struct s2n_x509_validator *validator, struct s2n_connection *conn,
        uint8_t *cert_chain_in, uint32_t cert_chain_len, s2n_pkey_type *pkey_type, struct s2n_pkey *public_key_out)
{
    RESULT_ENSURE_REF(validator);
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(conn->config);

#if S2N_LIBCRYPTO_SUPPORTS_CBS
    /* Backend_Selector dispatch.
     *
     * The backend choice is fixed at validation start with no silent runtime
     * fallback. Zero-copy path uses read_cert_chain_spans + verify_cert_chain_spans
     * instead of the libcrypto flow. Differential mode runs both paths and
     * records divergences. */
    s2n_cert_verify_backend backend = conn->config->cert_verify_backend;

    /* The zero-copy CRL flow shares the async lookup-callback machinery with
     * the libcrypto path, but that machinery iterates cert_chain_from_wire
     * (the X509 stack), which the zero-copy path does not populate. Until the
     * lookup helper is span-aware, route CRL-enabled configs to libcrypto. */
    if (backend == S2N_CERT_BACKEND_ZERO_COPY && conn->config->crl_lookup_cb != NULL) {
        backend = S2N_CERT_BACKEND_LIBCRYPTO;
    }

    /* Certificate key and signature preferences (certificate_key_preferences /
     * certificate_signature_preferences in the security policy) constrain the
     * key type and signature algorithm of every cert in the peer's chain, and
     * reject violations with S2N_ERR_SECURITY_POLICY_INCOMPATIBLE_CERT. The
     * libcrypto path enforces this via s2n_x509_validator_check_cert_preferences,
     * which reads an s2n_cert_info (key NID/bits, signature NID) that the
     * span-based path does not extract. Until the span accessors expose that
     * info, route policies that define these preferences to libcrypto. */
    if (backend == S2N_CERT_BACKEND_ZERO_COPY) {
        const struct s2n_security_policy *security_policy = NULL;
        if (s2n_connection_get_security_policy(conn, &security_policy) == S2N_SUCCESS
                && security_policy != NULL
                && (security_policy->certificate_key_preferences != NULL
                        || security_policy->certificate_signature_preferences != NULL)) {
            backend = S2N_CERT_BACKEND_LIBCRYPTO;
        }
    }

    /* If a previous attempt already invoked the cert validation callback but
     * the zero-copy chain state is absent, that attempt ran on the libcrypto
     * backend (e.g. after a zero-copy failure fell back and wiped the
     * validator). The async retry must complete on the same backend. */
    if (backend == S2N_CERT_BACKEND_ZERO_COPY
            && validator->cert_validation_cb_invoked
            && validator->chain_spans == NULL) {
        backend = S2N_CERT_BACKEND_LIBCRYPTO;
    }

    if (backend == S2N_CERT_BACKEND_ZERO_COPY) {
        /* Async retry: if the cert validation callback was already invoked on
         * a previous attempt (S2N_ERR_ASYNC_BLOCKED), just re-check its result
         * and extract the leaf key — do not re-run verification (matches the
         * libcrypto path's cert_validation_cb_invoked handling). */
        if (validator->cert_validation_cb_invoked) {
            RESULT_GUARD(s2n_x509_validator_handle_cert_validation_callback_result(validator));

            RESULT_ENSURE(validator->chain_spans->count > 0, S2N_ERR_CERT_UNTRUSTED);
            struct s2n_cert_view retry_leaf_view = { 0 };
            RESULT_GUARD(s2n_cert_view_init_span(&retry_leaf_view, &validator->chain_spans->views[0]));
            DEFER_CLEANUP(struct s2n_pkey retry_public_key = { 0 }, s2n_pkey_free);
            RESULT_GUARD(s2n_cert_view_get_public_key(&retry_leaf_view, &retry_public_key, pkey_type));
            *public_key_out = retry_public_key;
            ZERO_TO_DISABLE_DEFER_CLEANUP(retry_public_key);
            return S2N_RESULT_OK;
        }

        s2n_result zc_result = s2n_x509_validator_read_cert_chain_spans(validator, conn,
                cert_chain_in, cert_chain_len, pkey_type, public_key_out);

        if (s2n_result_is_ok(zc_result)) {
            /* TLS 1.3: process the first certificate's extensions (e.g. the
             * stapled OCSP response) unconditionally — both skip and non-skip
             * modes need extension data (OCSP, SCT) available on the connection,
             * matching the libcrypto path. */
            if (conn->actual_protocol_version >= S2N_TLS13) {
                s2n_parsed_extensions_list first_certificate_extensions = { 0 };
                s2n_result ext_result = s2n_x509_validator_parse_leaf_certificate_extensions(conn,
                        cert_chain_in, cert_chain_len, &first_certificate_extensions);
                if (s2n_result_is_ok(ext_result)) {
                    if (s2n_extension_list_process(S2N_EXTENSION_LIST_CERTIFICATE, conn,
                                &first_certificate_extensions)
                            != S2N_SUCCESS) {
                        zc_result = S2N_RESULT_ERROR;
                    }
                } else {
                    zc_result = ext_result;
                }
            }
        }

        if (s2n_result_is_ok(zc_result)) {
            /* In skip mode, read_cert_chain_spans already extracted the leaf key
             * and returned. Invoke the cert validation callback (matching the
             * libcrypto path, which fires it even when validation is skipped)
             * and return. */
            if (validator->skip_cert_validation) {
                if (conn->config->cert_validation_cb) {
                    RESULT_ENSURE(conn->config->cert_validation_cb(conn,
                                          &(validator->cert_validation_info),
                                          conn->config->cert_validation_ctx)
                                    == S2N_SUCCESS,
                            S2N_ERR_CANCELLED);
                    validator->cert_validation_cb_invoked = true;
                    RESULT_GUARD(s2n_x509_validator_handle_cert_validation_callback_result(validator));
                }
                return S2N_RESULT_OK;
            }

            if (s2n_result_is_ok(zc_result)) {
                zc_result = s2n_x509_validator_verify_cert_chain_spans(validator, conn);
            }

            if (s2n_result_is_ok(zc_result)) {
                /* Extract the leaf public key from the validated chain. */
                RESULT_ENSURE(validator->chain_spans->count > 0, S2N_ERR_CERT_UNTRUSTED);
                struct s2n_cert_view leaf_view = { 0 };
                RESULT_GUARD(s2n_cert_view_init_span(&leaf_view, &validator->chain_spans->views[0]));
                DEFER_CLEANUP(struct s2n_pkey public_key = { 0 }, s2n_pkey_free);
                RESULT_GUARD(s2n_cert_view_get_public_key(&leaf_view, &public_key, pkey_type));
                *public_key_out = public_key;
                ZERO_TO_DISABLE_DEFER_CLEANUP(public_key);
                return S2N_RESULT_OK;
            }
        }

        /* Zero-copy path failed. Fall through to libcrypto ONLY if no
         * application callbacks were invoked during the zero-copy attempt.
         * Path-build failures (where ML-DSA and other unsupported algorithms
         * fail) happen before any callback fires. If the cert validation
         * callback already ran, or the failure came from hostname
         * verification (verify_host fired) or the callback itself, falling
         * through would double-invoke application callbacks. */
        if (validator->cert_validation_cb_invoked
                || s2n_errno == S2N_ERR_CERT_INVALID_HOSTNAME
                || s2n_errno == S2N_ERR_CANCELLED
                || s2n_errno == S2N_ERR_CERT_REJECTED
                || s2n_errno == S2N_ERR_ASYNC_BLOCKED
                || s2n_errno == S2N_ERR_CRL_LOOKUP_FAILED) {
            return zc_result;
        }

        struct s2n_x509_trust_store *saved_trust_store = validator->trust_store;
        uint8_t saved_check_ocsp = validator->check_stapled_ocsp;
        uint8_t saved_max_depth = validator->max_chain_depth;
        bool saved_skip = validator->skip_cert_validation;
        s2n_x509_validator_wipe(validator);
        RESULT_GUARD_POSIX(s2n_x509_validator_init(validator, saved_trust_store, saved_check_ocsp));
        s2n_x509_validator_set_max_chain_depth(validator, saved_max_depth);
        validator->skip_cert_validation = saved_skip;
    }
    if (backend == S2N_CERT_BACKEND_DIFFERENTIAL) {
        /* Differential_Validator (, D7).
         *
         * Run both verifiers on the same wire chain:
         *   a) Libcrypto first (authoritative): fires all application callbacks,
         *      produces the connection result.
         *   b) Zero-copy second (callback-suppressed): read + verify with no
         *      callbacks fired (verify_host suppressed, cert_validation_cb not
         *      invoked again, CRL callbacks not re-triggered).
         *   c) Compare decisions: if they diverge, record it.
         *   d) Always return the libcrypto result.
         *   e) If the zero-copy run fails with an internal error (parse failure,
         *      etc.), swallow it and return the libcrypto result. */

        /* === (a) Authoritative libcrypto run === */
        s2n_result libcrypto_result = S2N_RESULT_OK;
        int saved_errno = S2N_ERR_OK;

        if (validator->cert_validation_cb_invoked) {
            libcrypto_result = s2n_x509_validator_handle_cert_validation_callback_result(validator);
        } else {
            libcrypto_result = s2n_x509_validator_validate_cert_chain_pre_cb(
                    validator, conn, cert_chain_in, cert_chain_len);

            if (s2n_result_is_ok(libcrypto_result) && conn->config->cert_validation_cb) {
                int cb_rc = conn->config->cert_validation_cb(conn,
                        &(validator->cert_validation_info), conn->config->cert_validation_ctx);
                if (cb_rc != S2N_SUCCESS) {
                    libcrypto_result = S2N_RESULT_ERROR;
                    saved_errno = S2N_ERR_CANCELLED;
                } else {
                    validator->cert_validation_cb_invoked = true;
                    libcrypto_result = s2n_x509_validator_handle_cert_validation_callback_result(validator);
                }
            }
        }

        bool libcrypto_accepted = s2n_result_is_ok(libcrypto_result);
        if (!libcrypto_accepted && saved_errno == S2N_ERR_OK) {
            saved_errno = s2n_errno;
        }

        /* === (b) Callback-suppressed zero-copy run === */
        bool zc_accepted = false;
        {
            /* Set up a second validator for the zero-copy run. It shares the
             * trust_store pointer but has independent state. */
            struct s2n_x509_validator zc_validator = { 0 };
            int init_rc = s2n_x509_validator_init(&zc_validator,
                    validator->trust_store, validator->check_stapled_ocsp);
            if (init_rc != S2N_SUCCESS) {
                goto differential_done;
            }
            s2n_x509_validator_set_max_chain_depth(&zc_validator,
                    validator->max_chain_depth);

            /* Temporarily suppress callbacks on the connection for the zero-copy
             * run. Save and restore afterward. */
            verify_host saved_verify_host_fn = conn->verify_host_fn;
            void *saved_verify_host_data = conn->data_for_verify_host;
            s2n_cert_validation_callback saved_cert_cb = conn->config->cert_validation_cb;
            s2n_crl_lookup_callback saved_crl_cb = conn->config->crl_lookup_cb;

            /* Use a recording verify_host that accepts all names (the libcrypto
             * run already invoked the real callback — ). */
            conn->verify_host_fn = s2n_differential_accept_all_hosts;
            conn->data_for_verify_host = NULL;
            conn->config->cert_validation_cb = NULL;
            conn->config->crl_lookup_cb = NULL;

            /* Run the zero-copy path (read + verify). */
            s2n_pkey_type zc_pkey_type = S2N_PKEY_TYPE_UNKNOWN;
            struct s2n_pkey zc_public_key = { 0 };
            s2n_pkey_zero_init(&zc_public_key);

            s2n_result zc_result = s2n_x509_validator_read_cert_chain_spans(
                    &zc_validator, conn, cert_chain_in, cert_chain_len,
                    &zc_pkey_type, &zc_public_key);

            if (s2n_result_is_ok(zc_result) && !zc_validator.skip_cert_validation) {
                zc_result = s2n_x509_validator_verify_cert_chain_spans(&zc_validator, conn);
            }

            zc_accepted = s2n_result_is_ok(zc_result);

            /* Clean up the zero-copy validator's resources. */
            s2n_pkey_free(&zc_public_key);
            s2n_x509_validator_wipe(&zc_validator);

            /* Restore callbacks on the connection. */
            conn->verify_host_fn = saved_verify_host_fn;
            conn->data_for_verify_host = saved_verify_host_data;
            conn->config->cert_validation_cb = saved_cert_cb;
            conn->config->crl_lookup_cb = saved_crl_cb;
        }

    differential_done:
        /* === (c) Compare decisions === */
        if (libcrypto_accepted != zc_accepted) {
            /* Divergence detected. Increment counter (recording failure is
             * swallowed — ). Overflow wraps without error. */
            validator->differential_divergence_count++;
        }

        /* === (d) Always return the libcrypto result  === */
        if (!libcrypto_accepted) {
            RESULT_BAIL(saved_errno);
        }

        /* Extract the leaf public key from the libcrypto-validated chain. */
        struct s2n_cert_chain_view wire_chain_view = { 0 };
        RESULT_GUARD(s2n_cert_chain_view_init(&wire_chain_view, validator->cert_chain_from_wire));
        int wire_cert_count = 0;
        RESULT_GUARD(s2n_cert_chain_view_count(&wire_chain_view, &wire_cert_count));
        RESULT_ENSURE_GT(wire_cert_count, 0);
        struct s2n_cert_view leaf_view_diff = { 0 };
        RESULT_GUARD(s2n_cert_chain_view_get(&wire_chain_view, 0, &leaf_view_diff));
        DEFER_CLEANUP(struct s2n_pkey public_key_diff = { 0 }, s2n_pkey_free);
        RESULT_GUARD(s2n_cert_view_get_public_key(&leaf_view_diff, &public_key_diff, pkey_type));
        *public_key_out = public_key_diff;
        ZERO_TO_DISABLE_DEFER_CLEANUP(public_key_diff);

        return S2N_RESULT_OK;
    }
#endif

    if (validator->cert_validation_cb_invoked) {
        RESULT_GUARD(s2n_x509_validator_handle_cert_validation_callback_result(validator));
    } else {
        RESULT_GUARD(s2n_x509_validator_validate_cert_chain_pre_cb(validator, conn, cert_chain_in, cert_chain_len));

        if (conn->config->cert_validation_cb) {
            RESULT_ENSURE(conn->config->cert_validation_cb(conn, &(validator->cert_validation_info), conn->config->cert_validation_ctx) == S2N_SUCCESS,
                    S2N_ERR_CANCELLED);
            validator->cert_validation_cb_invoked = true;
            RESULT_GUARD(s2n_x509_validator_handle_cert_validation_callback_result(validator));
        }
    }

    /* retrieve information from leaf cert */
    struct s2n_cert_chain_view wire_chain_view = { 0 };
    RESULT_GUARD(s2n_cert_chain_view_init(&wire_chain_view, validator->cert_chain_from_wire));
    int wire_cert_count = 0;
    RESULT_GUARD(s2n_cert_chain_view_count(&wire_chain_view, &wire_cert_count));
    RESULT_ENSURE_GT(wire_cert_count, 0);
    struct s2n_cert_view leaf_view = { 0 };
    RESULT_GUARD(s2n_cert_chain_view_get(&wire_chain_view, 0, &leaf_view));
    DEFER_CLEANUP(struct s2n_pkey public_key = { 0 }, s2n_pkey_free);
    RESULT_GUARD(s2n_cert_view_get_public_key(&leaf_view, &public_key, pkey_type));

    *public_key_out = public_key;

    /* Reset the old struct, so we don't clean up public_key_out */
    ZERO_TO_DISABLE_DEFER_CLEANUP(public_key);

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_x509_validator_validate_cert_stapled_ocsp_response(struct s2n_x509_validator *validator,
        struct s2n_connection *conn, const uint8_t *ocsp_response_raw, uint32_t ocsp_response_length)
{
    if (validator->skip_cert_validation || !validator->check_stapled_ocsp) {
        validator->state = OCSP_VALIDATED;
        return S2N_RESULT_OK;
    }

    RESULT_ENSURE(validator->state == VALIDATED, S2N_ERR_INVALID_CERT_STATE);

#if !S2N_OCSP_STAPLING_SUPPORTED
    /* Default to safety */
    RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
#else

    RESULT_ENSURE_REF(ocsp_response_raw);

    DEFER_CLEANUP(OCSP_RESPONSE *ocsp_response = d2i_OCSP_RESPONSE(NULL, &ocsp_response_raw, ocsp_response_length),
            OCSP_RESPONSE_free_pointer);
    RESULT_ENSURE(ocsp_response != NULL, S2N_ERR_INVALID_OCSP_RESPONSE);

    int ocsp_status = OCSP_response_status(ocsp_response);
    RESULT_ENSURE(ocsp_status == OCSP_RESPONSE_STATUS_SUCCESSFUL, S2N_ERR_CERT_UNTRUSTED);

    DEFER_CLEANUP(OCSP_BASICRESP *basic_response = OCSP_response_get1_basic(ocsp_response), OCSP_BASICRESP_free_pointer);
    RESULT_ENSURE(basic_response != NULL, S2N_ERR_INVALID_OCSP_RESPONSE);

    DEFER_CLEANUP(struct s2n_validated_cert_chain validated_cert_chain = { 0 }, s2n_x509_validator_validated_cert_chain_free);
    RESULT_GUARD(s2n_x509_validator_get_validated_cert_chain(validator, &validated_cert_chain));
    STACK_OF(X509) *cert_chain = validated_cert_chain.stack;
    RESULT_ENSURE_REF(cert_chain);

    const int certs_in_chain = sk_X509_num(cert_chain);
    RESULT_ENSURE(certs_in_chain > 0, S2N_ERR_NO_CERT_FOUND);

    /* leaf is the top: not the bottom. */
    X509 *subject = sk_X509_value(cert_chain, 0);
    struct s2n_cert_view subject_view = { 0 };
    RESULT_GUARD(s2n_cert_view_init(&subject_view, subject));
    X509 *issuer = NULL;
    /* find the issuer in the chain. If it's not there. Fail everything. */
    for (int i = 0; i < certs_in_chain; ++i) {
        X509 *issuer_candidate = sk_X509_value(cert_chain, i);
        struct s2n_cert_view issuer_view = { 0 };
        RESULT_GUARD(s2n_cert_view_init(&issuer_view, issuer_candidate));

        bool issued = false;
        RESULT_GUARD(s2n_cert_view_check_issued(&issuer_view, &subject_view, &issued));
        if (issued) {
            issuer = issuer_candidate;
            break;
        }
    }
    RESULT_ENSURE(issuer != NULL, S2N_ERR_CERT_UNTRUSTED);

    /* Important: this checks that the stapled ocsp response CAN be verified, not that it has been verified. */
    const int ocsp_verify_res = OCSP_basic_verify(basic_response, cert_chain, validator->trust_store->trust_store, 0);
    RESULT_GUARD_OSSL(ocsp_verify_res, S2N_ERR_CERT_UNTRUSTED);

    /* do the crypto checks on the response.*/
    int status = 0;
    int reason = 0;

    /* SHA-1 is the only supported hash algorithm for the CertID due to its established use in 
     * OCSP responders. 
     */
    OCSP_CERTID *cert_id = OCSP_cert_to_id(EVP_sha1(), subject, issuer);
    RESULT_ENSURE_REF(cert_id);

    /**
     *= https://www.rfc-editor.org/rfc/rfc6960#section-2.4
     *#
     *# thisUpdate      The most recent time at which the status being
     *#                 indicated is known by the responder to have been
     *#                 correct.
     *#
     *# nextUpdate      The time at or before which newer information will be
     *#                 available about the status of the certificate.
     **/
    ASN1_GENERALIZEDTIME *revtime = NULL, *thisupd = NULL, *nextupd = NULL;
    /* Actual verification of the response */
    const int ocsp_resp_find_status_res = OCSP_resp_find_status(basic_response, cert_id, &status, &reason, &revtime, &thisupd, &nextupd);
    OCSP_CERTID_free(cert_id);
    RESULT_GUARD_OSSL(ocsp_resp_find_status_res, S2N_ERR_CERT_UNTRUSTED);

    uint64_t current_sys_time_nanoseconds = 0;
    RESULT_GUARD(s2n_config_wall_clock(conn->config, &current_sys_time_nanoseconds));
    if (sizeof(time_t) == 4) {
        /* cast value to uint64_t to prevent overflow errors */
        RESULT_ENSURE_LTE(current_sys_time_nanoseconds, (uint64_t) MAX_32_TIMESTAMP_NANOS);
    }
    /* convert the current_sys_time (which is in nanoseconds) to seconds */
    time_t current_sys_time_seconds = (time_t) (current_sys_time_nanoseconds / ONE_SEC_IN_NANOS);

    DEFER_CLEANUP(ASN1_GENERALIZEDTIME *current_sys_time = ASN1_GENERALIZEDTIME_set(NULL, current_sys_time_seconds), s2n_openssl_asn1_time_free_pointer);
    RESULT_ENSURE_REF(current_sys_time);

    /**
     * It is fine to use ASN1_TIME functions with ASN1_GENERALIZEDTIME structures
     * From openssl documentation:
     * It is recommended that functions starting with ASN1_TIME be used instead
     * of those starting with ASN1_UTCTIME or ASN1_GENERALIZEDTIME. The
     * functions starting with ASN1_UTCTIME and ASN1_GENERALIZEDTIME act only on
     * that specific time format. The functions starting with ASN1_TIME will
     * operate on either format.
     * https://www.openssl.org/docs/man1.1.1/man3/ASN1_TIME_to_generalizedtime.html
     *
     * ASN1_TIME_compare has a much nicer API, but is not available in Openssl
     * 1.0.1, so we use ASN1_TIME_diff.
     */
    int pday = 0;
    int psec = 0;
    RESULT_GUARD_OSSL(ASN1_TIME_diff(&pday, &psec, thisupd, current_sys_time), S2N_ERR_CERT_UNTRUSTED);
    /* ensure that current_time is after or the same as "this update" */
    RESULT_ENSURE(pday >= 0 && psec >= 0, S2N_ERR_CERT_INVALID);

    /* ensure that current_time is before or the same as "next update" */
    if (nextupd) {
        RESULT_GUARD_OSSL(ASN1_TIME_diff(&pday, &psec, current_sys_time, nextupd), S2N_ERR_CERT_UNTRUSTED);
        RESULT_ENSURE(pday >= 0 && psec >= 0, S2N_ERR_CERT_EXPIRED);
    } else {
        /**
         * if nextupd isn't present, assume that nextupd is
         * DEFAULT_OCSP_NEXT_UPDATE_PERIOD after thisupd. This means that if the
         * current time is more than DEFAULT_OCSP_NEXT_UPDATE_PERIOD
         * seconds ahead of thisupd, we consider it invalid. We already compared
         * current_sys_time to thisupd, so reuse those values
         */
        uint64_t seconds_after_thisupd = pday * (3600 * 24) + psec;
        RESULT_ENSURE(seconds_after_thisupd < DEFAULT_OCSP_NEXT_UPDATE_PERIOD, S2N_ERR_CERT_EXPIRED);
    }

    switch (status) {
        case V_OCSP_CERTSTATUS_GOOD:
            validator->state = OCSP_VALIDATED;
            return S2N_RESULT_OK;
        case V_OCSP_CERTSTATUS_REVOKED:
            RESULT_BAIL(S2N_ERR_CERT_REVOKED);
        default:
            RESULT_BAIL(S2N_ERR_CERT_UNTRUSTED);
    }
#endif /* S2N_OCSP_STAPLING_SUPPORTED */
}

bool s2n_x509_validator_is_cert_chain_validated(const struct s2n_x509_validator *validator)
{
    return validator && (validator->state == VALIDATED || validator->state == OCSP_VALIDATED);
}

int s2n_cert_validation_accept(struct s2n_cert_validation_info *info)
{
    POSIX_ENSURE_REF(info);
    POSIX_ENSURE(!info->finished, S2N_ERR_INVALID_STATE);

    info->finished = true;
    info->accepted = true;

    return S2N_SUCCESS;
}

int s2n_cert_validation_reject(struct s2n_cert_validation_info *info)
{
    POSIX_ENSURE_REF(info);
    POSIX_ENSURE(!info->finished, S2N_ERR_INVALID_STATE);

    info->finished = true;
    info->accepted = false;

    return S2N_SUCCESS;
}
