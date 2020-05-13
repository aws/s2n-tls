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

#include "crypto/s2n_fips.h"
#include "crypto/s2n_rsa_signing.h"
#include "crypto/s2n_rsa_pss.h"
#include "error/s2n_errno.h"

#include "tls/s2n_auth_selection.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_tls_digest_preferences.h"
#include "tls/s2n_signature_algorithms.h"
#include "tls/s2n_signature_scheme.h"
#include "tls/s2n_security_policies.h"

#include "utils/s2n_safety.h"

static int s2n_signature_scheme_valid_to_offer(struct s2n_connection *conn, const struct s2n_signature_scheme *scheme)
{
    /* We don't know what protocol version we will eventually negotiate, but we know that it won't be any higher. */
    gte_check(conn->actual_protocol_version, scheme->minimum_protocol_version);

    if (!s2n_is_rsa_pss_signing_supported()) {
        ne_check(scheme->sig_alg, S2N_SIGNATURE_RSA_PSS_RSAE);
    }

    if (!s2n_is_rsa_pss_certs_supported()) {
        ne_check(scheme->sig_alg, S2N_SIGNATURE_RSA_PSS_PSS);
    }

    return 0;
}

static int s2n_signature_scheme_valid_to_accept(struct s2n_connection *conn, const struct s2n_signature_scheme *scheme)
{
    notnull_check(scheme);

    GUARD(s2n_signature_scheme_valid_to_offer(conn, scheme));

    if (scheme->maximum_protocol_version != S2N_UNKNOWN_PROTOCOL_VERSION) {
        lte_check(conn->actual_protocol_version, scheme->maximum_protocol_version);
    }

    return 0;
}

static int s2n_choose_sig_scheme(struct s2n_connection *conn, struct s2n_sig_scheme_list *peer_wire_prefs,
                          struct s2n_signature_scheme *chosen_scheme_out)
{
    notnull_check(conn);
    const struct s2n_signature_preferences *signature_preferences = NULL;
    GUARD(s2n_connection_get_signature_preferences(conn, &signature_preferences));
    notnull_check(signature_preferences);

    struct s2n_cipher_suite *cipher_suite = conn->secure.cipher_suite;
    notnull_check(cipher_suite);

    for (int i = 0; i < signature_preferences->count; i++) {
        const struct s2n_signature_scheme *candidate = signature_preferences->signature_schemes[i];

        if (s2n_signature_scheme_valid_to_accept(conn, candidate) != S2N_SUCCESS) {
            continue;
        }

        if (s2n_is_sig_scheme_valid_for_auth(conn, candidate) != S2N_SUCCESS) {
            continue;
        }

        for (int j = 0; j < peer_wire_prefs->len; j++) {
            uint16_t their_iana_val = peer_wire_prefs->iana_list[j];

            if (candidate->iana_value == their_iana_val) {
                *chosen_scheme_out = *candidate;
                return S2N_SUCCESS;
            }
        }
    }

    S2N_ERROR(S2N_ERR_INVALID_SIGNATURE_SCHEME);
}

int s2n_get_and_validate_negotiated_signature_scheme(struct s2n_connection *conn, struct s2n_stuffer *in,
                                             struct s2n_signature_scheme *chosen_sig_scheme)
{
    uint16_t actual_iana_val;
    GUARD(s2n_stuffer_read_uint16(in, &actual_iana_val));

    const struct s2n_signature_preferences *signature_preferences = NULL;
    GUARD(s2n_connection_get_signature_preferences(conn, &signature_preferences));
    notnull_check(signature_preferences);

    for (int i = 0; i < signature_preferences->count; i++) {
        const struct s2n_signature_scheme *candidate = signature_preferences->signature_schemes[i];

        if (0 != s2n_signature_scheme_valid_to_accept(conn, candidate)) {
            continue;
        }

        if (candidate->iana_value == actual_iana_val) {
            *chosen_sig_scheme = *candidate;
            return S2N_SUCCESS;
        }
    }

    S2N_ERROR(S2N_ERR_INVALID_SIGNATURE_SCHEME);
}

int s2n_choose_default_sig_scheme(struct s2n_connection *conn, struct s2n_signature_scheme *sig_scheme_out)
{
    notnull_check(conn);
    notnull_check(conn->secure.cipher_suite);
    notnull_check(sig_scheme_out);

    s2n_authentication_method cipher_suite_auth_method = conn->secure.cipher_suite->auth_method;

    /* Default our signature digest algorithms. For TLS 1.2 this default is different and may be
     * overridden by the signature_algorithms extension. If the server chooses an ECDHE_ECDSA
     * cipher suite, this will be overridden to SHA1.
     */
    *sig_scheme_out = s2n_rsa_pkcs1_md5_sha1;

    if (cipher_suite_auth_method == S2N_AUTHENTICATION_ECDSA) {
        *sig_scheme_out = s2n_ecdsa_sha1;
    }

    /* Default RSA Hash Algorithm is SHA1 (instead of MD5_SHA1) if TLS 1.2 or FIPS mode */
    if ((conn->actual_protocol_version >= S2N_TLS12 || s2n_is_in_fips_mode())
            && (sig_scheme_out->sig_alg == S2N_SIGNATURE_RSA)) {
        *sig_scheme_out = s2n_rsa_pkcs1_sha1;
    }

    return S2N_SUCCESS;
}

int s2n_choose_sig_scheme_from_peer_preference_list(struct s2n_connection *conn, struct s2n_sig_scheme_list *peer_wire_prefs,
                                                        struct s2n_signature_scheme *sig_scheme_out)
{
    notnull_check(conn);
    notnull_check(sig_scheme_out);

    struct s2n_signature_scheme chosen_scheme;

    GUARD(s2n_choose_default_sig_scheme(conn, &chosen_scheme));

    /* SignatureScheme preference list was first added in TLS 1.2. It will be empty in older TLS versions. */
    if (peer_wire_prefs != NULL && peer_wire_prefs->len > 0) {
        int result = s2n_choose_sig_scheme(conn, peer_wire_prefs, &chosen_scheme);

        /* We require an exact match in TLS 1.3, but all previous versions can fall back to the default.
         * The pre-TLS1.3 behavior is an intentional choice to maximize support. */
        S2N_ERROR_IF(result != S2N_SUCCESS && conn->actual_protocol_version == S2N_TLS13,
                S2N_ERR_INVALID_SIGNATURE_SCHEME);
    } else {
        S2N_ERROR_IF(conn->actual_protocol_version == S2N_TLS13, S2N_ERR_EMPTY_SIGNATURE_SCHEME);
    }

    *sig_scheme_out = chosen_scheme;

    return S2N_SUCCESS;
}

int s2n_send_supported_sig_scheme_list(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    const struct s2n_signature_preferences *signature_preferences = NULL;
    GUARD(s2n_connection_get_signature_preferences(conn, &signature_preferences));
    notnull_check(signature_preferences);

    GUARD(s2n_stuffer_write_uint16(out, s2n_supported_sig_scheme_list_size(conn)));

    for (int i =  0; i < signature_preferences->count; i++) {
        const struct s2n_signature_scheme *const scheme = signature_preferences->signature_schemes[i];
        if (0 == s2n_signature_scheme_valid_to_offer(conn, scheme)) {
            GUARD(s2n_stuffer_write_uint16(out, scheme->iana_value));
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
    GUARD(s2n_connection_get_signature_preferences(conn, &signature_preferences));
    notnull_check(signature_preferences);

    uint8_t count = 0;
    for (int i =  0; i < signature_preferences->count; i++) {
        if (0 == s2n_signature_scheme_valid_to_offer(conn, signature_preferences->signature_schemes[i])) {
            count ++;
        }
    }
    return count;
}

int s2n_recv_supported_sig_scheme_list(struct s2n_stuffer *in, struct s2n_sig_scheme_list *sig_hash_algs)
{
    uint16_t length_of_all_pairs;
    GUARD(s2n_stuffer_read_uint16(in, &length_of_all_pairs));
    if (length_of_all_pairs > s2n_stuffer_data_available(in)) {
        /* Malformed length, ignore the extension */
        return 0;
    }

    if (length_of_all_pairs % 2) {
        /* Pairs occur in two byte lengths. Malformed length, ignore the extension and skip ahead */
        GUARD(s2n_stuffer_skip_read(in, length_of_all_pairs));
        return 0;
    }

    int pairs_available = length_of_all_pairs / 2;

    if (pairs_available > TLS_SIGNATURE_SCHEME_LIST_MAX_LEN) {
        S2N_ERROR(S2N_ERR_TOO_MANY_SIGNATURE_SCHEMES);
    }
    
    sig_hash_algs->len = 0;

    for (int i = 0; i < pairs_available; i++) {
        uint16_t sig_scheme = 0;
        GUARD(s2n_stuffer_read_uint16(in, &sig_scheme));

        sig_hash_algs->iana_list[sig_hash_algs->len] = sig_scheme;
        sig_hash_algs->len += 1;
    }

    return 0;
}
