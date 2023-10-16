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

#include "tls/s2n_signature_algorithms.h"

#include "crypto/s2n_fips.h"
#include "crypto/s2n_rsa_pss.h"
#include "crypto/s2n_rsa_signing.h"
#include "error/s2n_errno.h"
#include "tls/s2n_auth_selection.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_signature_scheme.h"
#include "utils/s2n_safety.h"

static int s2n_signature_scheme_valid_to_offer(struct s2n_connection *conn, const struct s2n_signature_scheme *scheme)
{
    POSIX_ENSURE_REF(conn);

    /* We don't know what protocol version we will eventually negotiate, but we know that it won't be any higher. */
    POSIX_ENSURE_GTE(conn->actual_protocol_version, scheme->minimum_protocol_version);

    /* QUIC only supports TLS1.3 */
    if (s2n_connection_is_quic_enabled(conn) && scheme->maximum_protocol_version) {
        POSIX_ENSURE_GTE(scheme->maximum_protocol_version, S2N_TLS13);
    }

    if (!s2n_is_rsa_pss_signing_supported()) {
        POSIX_ENSURE_NE(scheme->sig_alg, S2N_SIGNATURE_RSA_PSS_RSAE);
    }

    if (!s2n_is_rsa_pss_certs_supported()) {
        POSIX_ENSURE_NE(scheme->sig_alg, S2N_SIGNATURE_RSA_PSS_PSS);
    }

    return 0;
}

static int s2n_signature_scheme_valid_to_accept(struct s2n_connection *conn, const struct s2n_signature_scheme *scheme)
{
    POSIX_ENSURE_REF(scheme);
    POSIX_ENSURE_REF(conn);

    POSIX_GUARD(s2n_signature_scheme_valid_to_offer(conn, scheme));

    if (scheme->maximum_protocol_version != S2N_UNKNOWN_PROTOCOL_VERSION) {
        POSIX_ENSURE_LTE(conn->actual_protocol_version, scheme->maximum_protocol_version);
    }

    POSIX_ENSURE_NE(conn->actual_protocol_version, S2N_UNKNOWN_PROTOCOL_VERSION);
    if (conn->actual_protocol_version >= S2N_TLS13) {
        POSIX_ENSURE_NE(scheme->hash_alg, S2N_HASH_SHA1);
        POSIX_ENSURE_NE(scheme->sig_alg, S2N_SIGNATURE_RSA);
    } else {
        POSIX_ENSURE_NE(scheme->sig_alg, S2N_SIGNATURE_RSA_PSS_PSS);
    }

    return 0;
}

static int s2n_is_signature_scheme_usable(struct s2n_connection *conn, const struct s2n_signature_scheme *candidate)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(candidate);

    POSIX_GUARD(s2n_signature_scheme_valid_to_accept(conn, candidate));
    POSIX_GUARD(s2n_is_sig_scheme_valid_for_auth(conn, candidate));

    return S2N_SUCCESS;
}

static int s2n_choose_sig_scheme(struct s2n_connection *conn, struct s2n_sig_scheme_list *peer_wire_prefs,
        const struct s2n_signature_scheme **chosen_scheme_out)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->secure);
    const struct s2n_signature_preferences *signature_preferences = NULL;
    POSIX_GUARD(s2n_connection_get_signature_preferences(conn, &signature_preferences));
    POSIX_ENSURE_REF(signature_preferences);

    struct s2n_cipher_suite *cipher_suite = conn->secure->cipher_suite;
    POSIX_ENSURE_REF(cipher_suite);

    for (size_t i = 0; i < signature_preferences->count; i++) {
        const struct s2n_signature_scheme *candidate = signature_preferences->signature_schemes[i];

        if (s2n_is_signature_scheme_usable(conn, candidate) != S2N_SUCCESS) {
            continue;
        }

        for (size_t j = 0; j < peer_wire_prefs->len; j++) {
            uint16_t their_iana_val = peer_wire_prefs->iana_list[j];

            if (candidate->iana_value == their_iana_val) {
                *chosen_scheme_out = candidate;
                return S2N_SUCCESS;
            }
        }
    }

    /* do not error even if there's no match */
    return S2N_SUCCESS;
}

/* similar to s2n_choose_sig_scheme() without matching client's preference */
int s2n_tls13_default_sig_scheme(struct s2n_connection *conn,
        const struct s2n_signature_scheme **chosen_scheme_out)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->secure);

    const struct s2n_signature_preferences *signature_preferences = NULL;
    POSIX_GUARD(s2n_connection_get_signature_preferences(conn, &signature_preferences));
    POSIX_ENSURE_REF(signature_preferences);

    struct s2n_cipher_suite *cipher_suite = conn->secure->cipher_suite;
    POSIX_ENSURE_REF(cipher_suite);

    for (size_t i = 0; i < signature_preferences->count; i++) {
        const struct s2n_signature_scheme *candidate = signature_preferences->signature_schemes[i];

        if (s2n_is_signature_scheme_usable(conn, candidate) != S2N_SUCCESS) {
            continue;
        }

        *chosen_scheme_out = candidate;
        return S2N_SUCCESS;
    }

    POSIX_BAIL(S2N_ERR_INVALID_SIGNATURE_SCHEME);
}

int s2n_get_and_validate_negotiated_signature_scheme(struct s2n_connection *conn, struct s2n_stuffer *in,
        const struct s2n_signature_scheme **chosen_sig_scheme)
{
    uint16_t actual_iana_val;
    POSIX_GUARD(s2n_stuffer_read_uint16(in, &actual_iana_val));

    const struct s2n_signature_preferences *signature_preferences = NULL;
    POSIX_GUARD(s2n_connection_get_signature_preferences(conn, &signature_preferences));
    POSIX_ENSURE_REF(signature_preferences);

    for (size_t i = 0; i < signature_preferences->count; i++) {
        const struct s2n_signature_scheme *candidate = signature_preferences->signature_schemes[i];

        if (0 != s2n_signature_scheme_valid_to_accept(conn, candidate)) {
            continue;
        }

        if (candidate->iana_value == actual_iana_val) {
            *chosen_sig_scheme = candidate;
            return S2N_SUCCESS;
        }
    }

    POSIX_BAIL(S2N_ERR_INVALID_SIGNATURE_SCHEME);
}

int s2n_choose_default_sig_scheme(struct s2n_connection *conn,
        const struct s2n_signature_scheme **sig_scheme_out, s2n_mode signer)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(conn->secure);
    POSIX_ENSURE_REF(sig_scheme_out);

    s2n_authentication_method auth_method = 0;
    if (signer == S2N_CLIENT) {
        POSIX_GUARD(s2n_get_auth_method_for_cert_type(conn->handshake_params.client_cert_pkey_type, &auth_method));
    } else {
        POSIX_ENSURE_REF(conn->secure->cipher_suite);
        auth_method = conn->secure->cipher_suite->auth_method;
    }

    /* Default our signature digest algorithms.
     * For >=TLS 1.2 this default may be overridden by the signature_algorithms extension.
     */
    const struct s2n_signature_scheme *default_sig_scheme = &s2n_rsa_pkcs1_md5_sha1;
    if (auth_method == S2N_AUTHENTICATION_ECDSA) {
        default_sig_scheme = &s2n_ecdsa_sha1;
    } else if (conn->actual_protocol_version >= S2N_TLS12) {
        default_sig_scheme = &s2n_rsa_pkcs1_sha1;
    }

    if (conn->actual_protocol_version < S2N_TLS12) {
        /* Before TLS1.2, signature algorithms were fixed, not chosen / negotiated. */
        *sig_scheme_out = default_sig_scheme;
        return S2N_SUCCESS;
    } else {
        /* If we attempt to negotiate a default in TLS1.2, we should ensure that
         * default is allowed by the local security policy.
         */
        const struct s2n_signature_preferences *signature_preferences = NULL;
        POSIX_GUARD(s2n_connection_get_signature_preferences(conn, &signature_preferences));
        POSIX_ENSURE_REF(signature_preferences);
        for (size_t i = 0; i < signature_preferences->count; i++) {
            if (signature_preferences->signature_schemes[i]->iana_value == default_sig_scheme->iana_value) {
                *sig_scheme_out = default_sig_scheme;
                return S2N_SUCCESS;
            }
        }
        /* We cannot bail with an error here because existing logic assumes
         * that this method should always succeed and calls it even when no default
         * is actually necessary.
         * If no valid default exists, set an unusable, invalid empty scheme.
         */
        *sig_scheme_out = &s2n_null_sig_scheme;
        return S2N_SUCCESS;
    }
}

int s2n_choose_sig_scheme_from_peer_preference_list(struct s2n_connection *conn,
        struct s2n_sig_scheme_list *peer_wire_prefs,
        const struct s2n_signature_scheme **sig_scheme_out)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(sig_scheme_out);

    const struct s2n_signature_scheme *chosen_scheme = &s2n_null_sig_scheme;
    if (conn->actual_protocol_version < S2N_TLS13) {
        POSIX_GUARD(s2n_choose_default_sig_scheme(conn, &chosen_scheme, conn->mode));
    } else {
        /* Pick a default signature algorithm in TLS 1.3 https://tools.ietf.org/html/rfc8446#section-4.4.2.2 */
        POSIX_GUARD(s2n_tls13_default_sig_scheme(conn, &chosen_scheme));
    }

    /* SignatureScheme preference list was first added in TLS 1.2. It will be empty in older TLS versions. */
    if (conn->actual_protocol_version >= S2N_TLS12 && peer_wire_prefs != NULL && peer_wire_prefs->len > 0) {
        /* Use a best effort approach to selecting a signature scheme matching client's preferences */
        POSIX_GUARD(s2n_choose_sig_scheme(conn, peer_wire_prefs, &chosen_scheme));
    }

    *sig_scheme_out = chosen_scheme;
    return S2N_SUCCESS;
}

int s2n_send_supported_sig_scheme_list(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    const struct s2n_signature_preferences *signature_preferences = NULL;
    POSIX_GUARD(s2n_connection_get_signature_preferences(conn, &signature_preferences));
    POSIX_ENSURE_REF(signature_preferences);

    POSIX_GUARD(s2n_stuffer_write_uint16(out, s2n_supported_sig_scheme_list_size(conn)));

    for (size_t i = 0; i < signature_preferences->count; i++) {
        const struct s2n_signature_scheme *const scheme = signature_preferences->signature_schemes[i];
        if (0 == s2n_signature_scheme_valid_to_offer(conn, scheme)) {
            POSIX_GUARD(s2n_stuffer_write_uint16(out, scheme->iana_value));
        }
    }

    return 0;
}

int s2n_supported_sig_scheme_list_size(struct s2n_connection *conn)
{
    return s2n_supported_sig_schemes_count(conn) * TLS_SIGNATURE_SCHEME_LEN;
}

int s2n_supported_sig_schemes_count(struct s2n_connection *conn)
{
    const struct s2n_signature_preferences *signature_preferences = NULL;
    POSIX_GUARD(s2n_connection_get_signature_preferences(conn, &signature_preferences));
    POSIX_ENSURE_REF(signature_preferences);

    uint8_t count = 0;
    for (size_t i = 0; i < signature_preferences->count; i++) {
        if (0 == s2n_signature_scheme_valid_to_offer(conn, signature_preferences->signature_schemes[i])) {
            count++;
        }
    }
    return count;
}

int s2n_recv_supported_sig_scheme_list(struct s2n_stuffer *in, struct s2n_sig_scheme_list *sig_hash_algs)
{
    uint16_t length_of_all_pairs;
    POSIX_GUARD(s2n_stuffer_read_uint16(in, &length_of_all_pairs));
    if (length_of_all_pairs > s2n_stuffer_data_available(in)) {
        /* Malformed length, ignore the extension */
        return 0;
    }

    if (length_of_all_pairs % 2) {
        /* Pairs occur in two byte lengths. Malformed length, ignore the extension and skip ahead */
        POSIX_GUARD(s2n_stuffer_skip_read(in, length_of_all_pairs));
        return 0;
    }

    int pairs_available = length_of_all_pairs / 2;

    if (pairs_available > TLS_SIGNATURE_SCHEME_LIST_MAX_LEN) {
        POSIX_BAIL(S2N_ERR_TOO_MANY_SIGNATURE_SCHEMES);
    }

    sig_hash_algs->len = 0;

    for (size_t i = 0; i < (size_t) pairs_available; i++) {
        uint16_t sig_scheme = 0;
        POSIX_GUARD(s2n_stuffer_read_uint16(in, &sig_scheme));

        sig_hash_algs->iana_list[sig_hash_algs->len] = sig_scheme;
        sig_hash_algs->len += 1;
    }

    return 0;
}
