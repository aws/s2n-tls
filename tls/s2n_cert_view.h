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

#include "crypto/s2n_certificate.h"
#include "crypto/s2n_pkey.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_result.h"

/* Forward declaration for the span-backed cert view (defined in s2n_cert_parse.h). */
struct s2n_cert_span_view;

/* Tag identifying the backing representation of a cert view. */
typedef enum {
    S2N_CERT_VIEW_X509,
#if S2N_LIBCRYPTO_SUPPORTS_CBS
    S2N_CERT_VIEW_SPAN,
#endif
} s2n_cert_view_backing;

/* A read-only view over a single parsed certificate.
 *
 * This abstraction decouples s2n's cert consumers (public-key extraction, host
 * verification, chain iteration) from libcrypto's X509 object model. It can be
 * backed by either an X509* (the libcrypto path) or a span view (the zero-copy
 * path, CBS-gated). Each accessor dispatches on the backing tag internally;
 * consumer call-sites are unchanged.
 */
struct s2n_cert_view {
    s2n_cert_view_backing backing;
    union {
        X509 *x509; /* Borrowed, not owned */
#if S2N_LIBCRYPTO_SUPPORTS_CBS
        const struct s2n_cert_span_view *span; /* Borrowed from validator */
#endif
    } u;
};

/* Initialize a view over an already-parsed cert. The cert is borrowed. */
S2N_RESULT s2n_cert_view_init(struct s2n_cert_view *view, X509 *cert);

#if S2N_LIBCRYPTO_SUPPORTS_CBS
/* Initialize a view backed by a zero-copy span. The span is borrowed. */
S2N_RESULT s2n_cert_view_init_span(struct s2n_cert_view *view,
        const struct s2n_cert_span_view *span);
#endif

/* Extract the certificate's public key and its type. Mirrors the previous
 * direct s2n_pkey_from_x509() call on the leaf cert. */
S2N_RESULT s2n_cert_view_get_public_key(const struct s2n_cert_view *view,
        struct s2n_pkey *public_key_out, s2n_pkey_type *pkey_type_out);

/* Copy the subject Common Name into cn_out (a caller-owned buffer blob). Sets
 * *cn_found true only when a CN entry with an RFC 5280-permitted string type is
 * present. Hides X509_NAME / ASN1_STRING from the consumer; does not apply the
 * RFC 6125 IP-in-CN policy (that stays with the caller).
 *
 * The span arm walks the subject Name TLV with a CBS cursor applying the same
 * last-CN-wins rule and RFC 5280 Appendix A.1 string-type allow-list as the
 * X509 arm.
 *
 * No IDNA (Internationalized Domain Names) processing is performed by either
 * backing. The returned CN value is the raw string bytes from the certificate;
 * any hostname comparison is byte-for-byte, matching current s2n-tls behavior. */
S2N_RESULT s2n_cert_view_get_common_name(const struct s2n_cert_view *view,
        struct s2n_blob *cn_out, uint32_t *cn_len_out, bool *cn_found);

/* Backing-neutral subject-alternative-name entry yielded by the SAN iterator.
 * `data` is borrowed from the underlying cert and valid only for the duration
 * of the callback. */
typedef enum {
    /* GEN_DNS or GEN_URI: `data`/`data_len` is the IA5String value. */
    S2N_CERT_SAN_DNS_OR_URI,
    /* GEN_IPADD: `data`/`data_len` is the raw address (4 or 16 bytes). */
    S2N_CERT_SAN_IP,
    /* Any other SAN type; `data` is unset. */
    S2N_CERT_SAN_OTHER,
} s2n_cert_san_type;

struct s2n_cert_san_entry {
    s2n_cert_san_type type;
    const uint8_t *data;
    uint32_t data_len;
};

struct s2n_connection;

/* Callback invoked per SAN entry. Sets *san_found for recognized entry types.
 * Returns an ok result if the entry verified successfully (iteration stops),
 * or an error to continue to the next entry. */
typedef S2N_RESULT (*s2n_cert_san_fn)(struct s2n_connection *conn,
        const struct s2n_cert_san_entry *entry, bool *san_found);

/* Iterate the cert's subjectAltName entries, invoking `cb` per entry with a
 * backing-neutral view. Preserves the previous semantics: returns ok on the
 * first entry the callback accepts; if none match, propagates the callback's
 * last error, else fails untrusted. Fails untrusted when no SAN is present.
 * Hides STACK_OF(GENERAL_NAME) / GENERAL_NAME from the consumer.
 *
 * The span arm presents the same raw bytes as the X509 arm: dNSName and URI
 * entries yield IA5String values, iPAddress entries yield raw 4-byte (IPv4) or
 * 16-byte (IPv6) octets. Wildcard matching and any other name-comparison logic
 * is the caller's responsibility; this function only presents raw name bytes.
 *
 * No IDNA (Internationalized Domain Names) processing is performed by either
 * backing. Names are compared byte-for-byte, matching the current s2n-tls
 * hostname verification behavior. */
S2N_RESULT s2n_cert_view_verify_sans(const struct s2n_cert_view *view,
        struct s2n_connection *conn, s2n_cert_san_fn cb, bool *san_found);

/* TLS purpose the cert must satisfy. */
typedef enum {
    S2N_CERT_PURPOSE_SSL_SERVER,
    S2N_CERT_PURPOSE_SSL_CLIENT,
} s2n_cert_purpose;

/* Verify the cert satisfies the given TLS purpose (wraps X509_check_purpose).
 * `require_ca` mirrors the libcrypto x509 "is a CA in the chain" argument. */
S2N_RESULT s2n_cert_view_check_purpose(const struct s2n_cert_view *view,
        s2n_cert_purpose purpose, bool require_ca);

/* Returns true (via *issued) when issuer_view issued subject_view (wraps
 * X509_check_issued == X509_V_OK). */
S2N_RESULT s2n_cert_view_check_issued(const struct s2n_cert_view *issuer_view,
        const struct s2n_cert_view *subject_view, bool *issued);

/* A read-only view over a certificate chain (leaf at index 0). Backed by
 * either a STACK_OF(X509)* (the libcrypto path) or an array of span views
 * (the zero-copy path, CBS-gated). Hides the backing from consumers. */
struct s2n_cert_chain_view {
    s2n_cert_view_backing backing;
    union {
        STACK_OF(X509) *stack; /* Borrowed, not owned */
#if S2N_LIBCRYPTO_SUPPORTS_CBS
        struct {
            const struct s2n_cert_span_view *views; /* Borrowed from validator */
            uint32_t count;
        } spans;
#endif
    } u;
};

/* Initialize a chain view over an already-parsed stack. The stack is borrowed. */
S2N_RESULT s2n_cert_chain_view_init(struct s2n_cert_chain_view *chain, STACK_OF(X509) *stack);

#if S2N_LIBCRYPTO_SUPPORTS_CBS
/* Initialize a chain view backed by an array of zero-copy span views. */
S2N_RESULT s2n_cert_chain_view_init_spans(struct s2n_cert_chain_view *chain,
        const struct s2n_cert_span_view *views, uint32_t count);
#endif

/* Number of certs in the chain. */
S2N_RESULT s2n_cert_chain_view_count(const struct s2n_cert_chain_view *chain, int *count_out);

/* Initialize `cert_out` as a view over the cert at `index` (0 == leaf). */
S2N_RESULT s2n_cert_chain_view_get(const struct s2n_cert_chain_view *chain, int cert_index,
        struct s2n_cert_view *cert_out);
