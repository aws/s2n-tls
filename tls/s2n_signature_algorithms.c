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
#include "error/s2n_errno.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_tls_digest_preferences.h"
#include "tls/s2n_signature_algorithms.h"
#include "tls/s2n_signature_scheme.h"
#include "utils/s2n_safety.h"

/* lookup s2n signature authentication type based on signature algorithm */
int s2n_get_auth_method_from_sig_alg(s2n_signature_algorithm in, s2n_authentication_method* out)
{
    switch(in) {
    case S2N_SIGNATURE_RSA:
    case S2N_SIGNATURE_RSA_PSS_RSAE:
        *out = S2N_AUTHENTICATION_RSA;
        return 0;
    case S2N_SIGNATURE_RSA_PSS_PSS:
        *out = S2N_AUTHENTICATION_RSA_PSS;
        return 0;
    case S2N_SIGNATURE_ECDSA:
        *out = S2N_AUTHENTICATION_ECDSA;
        return 0;
    default:
        S2N_ERROR(S2N_ERR_INVALID_SIGNATURE_ALGORITHM);
    }
}

int s2n_auth_method_requires_ephemeral_kex(const s2n_authentication_method auth_method)
{
    switch (auth_method) {
    case S2N_AUTHENTICATION_RSA_PSS:
        /* RSA-PSS only supports Sign/Verify, and not Encrypt/Decrypt, which means that it MUST be used with an
         * ephemeral Key Exchange Algorithm. */
        return 1;
    default:
        return 0;
    }
}

/* We don't know what protocol version we will eventually negotiate, but we know that it won't be any higher. */
static int s2n_signature_scheme_valid_to_offer(struct s2n_connection *conn, const struct s2n_signature_scheme *scheme)
{
    gte_check(conn->actual_protocol_version, scheme->minimum_protocol_version);
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

static int s2n_signature_scheme_valid_auth_method(struct s2n_connection *conn, const struct s2n_signature_scheme *scheme)
{
    notnull_check(conn);

    struct s2n_cipher_suite *cipher_suite = conn->secure.cipher_suite;
    notnull_check(cipher_suite);

    s2n_authentication_method candidate_auth_method;
    GUARD(s2n_get_auth_method_from_sig_alg(scheme->sig_alg, &candidate_auth_method));
    if (conn->actual_protocol_version < S2N_TLS13) {
        eq_check(candidate_auth_method, cipher_suite->auth_method);
    } else {
        notnull_check(s2n_conn_get_compatible_cert_chain_and_key(conn, candidate_auth_method));
    }

    return 0;
}

int s2n_choose_sig_scheme(struct s2n_connection *conn, struct s2n_sig_scheme_list *peer_wire_prefs,
                          struct s2n_signature_scheme *chosen_scheme_out)
{
    const struct s2n_signature_preferences *signature_preferences = conn->config->signature_preferences;
    notnull_check(signature_preferences);

    struct s2n_cipher_suite *cipher_suite = conn->secure.cipher_suite;
    notnull_check(cipher_suite);

    for (int i = 0; i < signature_preferences->count; i++) {
        const struct s2n_signature_scheme *candidate = signature_preferences->signature_schemes[i];

        if (s2n_signature_scheme_valid_to_accept(conn, candidate) != 0) {
            continue;
        }

        const struct s2n_kex *required_kex_method = cipher_suite->key_exchange_alg;
        if (s2n_auth_method_requires_ephemeral_kex(cipher_suite->auth_method) && !required_kex_method->is_ephemeral) {
            continue;
        }

        if (s2n_signature_scheme_valid_auth_method(conn, candidate) != 0) {
            continue;
        }

        for (int j = 0; j < peer_wire_prefs->len; j++) {
            uint16_t their_iana_val = peer_wire_prefs->iana_list[j];

            if (candidate->iana_value == their_iana_val) {
                *chosen_scheme_out = *candidate;
                return 0;
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

    const struct s2n_signature_preferences *signature_preferences = conn->config->signature_preferences;
    notnull_check(signature_preferences);

    for (int i = 0; i < signature_preferences->count; i++) {
        const struct s2n_signature_scheme *candidate = signature_preferences->signature_schemes[i];

        if (0 != s2n_signature_scheme_valid_to_accept(conn, candidate)) {
            continue;
        }

        if (candidate->iana_value == actual_iana_val) {
            *chosen_sig_scheme = *candidate;
            return 0;
        }
    }

    S2N_ERROR(S2N_ERR_INVALID_SIGNATURE_SCHEME);
}

int s2n_choose_sig_scheme_from_peer_preference_list(struct s2n_connection *conn, struct s2n_sig_scheme_list *peer_wire_prefs,
                                                        struct s2n_signature_scheme *sig_scheme_out)
{
    /* This function could be called in two places: after receiving the
     * ClientHello and parsing the extensions and cipher suites, and after
     * receiving the CertificateRequest which includes supported signature/hash
     * pairs. In both cases, the cipher suite will have been set */
    s2n_authentication_method cipher_suite_auth_method = conn->secure.cipher_suite->auth_method;

    /* Default our signature digest algorithms. For TLS 1.2 this default is different and may be
     * overridden by the signature_algorithms extension. If the server chooses an ECDHE_ECDSA
     * cipher suite, this will be overridden to SHA1.
     */
    struct s2n_signature_scheme chosen_scheme = s2n_rsa_pkcs1_md5_sha1;

    if (cipher_suite_auth_method == S2N_AUTHENTICATION_ECDSA) {
        chosen_scheme = s2n_ecdsa_sha1;
    }

    /* Default RSA Hash Algorithm is SHA1 (instead of MD5_SHA1) if TLS 1.2 or FIPS mode */
    if ((conn->actual_protocol_version >= S2N_TLS12 || s2n_is_in_fips_mode())
            && (chosen_scheme.sig_alg == S2N_SIGNATURE_RSA)) {
        chosen_scheme = s2n_rsa_pkcs1_sha1;
    }

    /* SignatureScheme preference list was first added in TLS 1.2. It will be empty in older TLS versions. */
    if (0 < peer_wire_prefs->len) {
        GUARD(s2n_choose_sig_scheme(conn, peer_wire_prefs, &chosen_scheme));
    } else {
        S2N_ERROR_IF(conn->actual_protocol_version == S2N_TLS13, S2N_ERR_EMPTY_SIGNATURE_SCHEME);
    }

    /* In TLS 1.3, SigScheme also defines the ECDSA curve to use (instead of reusing whatever ECDHE Key Exchange curve
     * was negotiated). In TLS 1.2 and before, chosen_scheme.signature_curve must *always* be NULL, if it's not, it's
     * a bug in s2n's preference list. */
    S2N_ERROR_IF(conn->actual_protocol_version <= S2N_TLS12 && chosen_scheme.signature_curve != NULL, S2N_ERR_INVALID_SIGNATURE_SCHEME);

    /* If TLS 1.3 is negotiated, then every ECDSA SigScheme must also define an ECDSA Curve *except* ECDSA_SHA1, which
     * uses the same curve negotiated in the ECDHE SupportedGroups Extension. */
    S2N_ERROR_IF(conn->actual_protocol_version == S2N_TLS13
            && chosen_scheme.sig_alg == S2N_SIGNATURE_ECDSA
            && chosen_scheme.hash_alg != S2N_HASH_SHA1
            && chosen_scheme.signature_curve == NULL,
            S2N_ERR_ECDSA_UNSUPPORTED_CURVE);

    *sig_scheme_out = chosen_scheme;

    return 0;
}

int s2n_send_supported_sig_scheme_list(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    const struct s2n_signature_preferences *signature_preferences = conn->config->signature_preferences;
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
    const struct s2n_signature_preferences *signature_preferences = conn->config->signature_preferences;
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
