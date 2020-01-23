/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

int s2n_get_auth_method_from_sig_alg(s2n_signature_algorithm in, s2n_authentication_method* out) {
    switch(in) {
        case S2N_SIGNATURE_RSA:
            *out = S2N_AUTHENTICATION_RSA;
            return 0;
        case S2N_SIGNATURE_RSA_PSS_RSAE:
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

int s2n_auth_method_requires_ephemeral_kex(const s2n_authentication_method auth_method) {
    switch (auth_method) {
    case S2N_AUTHENTICATION_RSA_PSS:
        /* RSA-PSS only supports Sign/Verify, and not Encrypt/Decrypt, which means that it MUST be used with an
         * ephemeral Key Exchange Algorithm. */
        return 1;
    default:
        return 0;
    }
}

int s2n_choose_sig_scheme(const struct s2n_signature_scheme* const* our_pref_list, int our_size,
                          struct s2n_cipher_suite *cipher_suite, struct s2n_sig_scheme_list *peer_pref_list,
                          struct s2n_signature_scheme *chosen_scheme_out) {

    notnull_check(cipher_suite);

    const struct s2n_kex *required_kex_method = cipher_suite->key_exchange_alg;
    s2n_authentication_method required_auth_method = cipher_suite->auth_method;

    for (int i = 0; i < our_size; i++) {
        const struct s2n_signature_scheme *candidate = our_pref_list[i];

        if (s2n_auth_method_requires_ephemeral_kex(required_auth_method) && !required_kex_method->is_ephemeral) {
            continue;
        }

        /* If we have a required Auth Method, and it doesn't match, skip the candidate */
        if (required_auth_method != S2N_AUTHENTICATION_METHOD_TLS13) {
            s2n_authentication_method candidate_auth_method;
            GUARD(s2n_get_auth_method_from_sig_alg(candidate->sig_alg, &candidate_auth_method));
            if (candidate_auth_method != required_auth_method) {
                continue;
            }
        }

        for (int j = 0; j < peer_pref_list->len; j++) {
            uint16_t their_iana_val = peer_pref_list->iana_list[j];

            if (candidate->iana_value == their_iana_val) {
                *chosen_scheme_out = *candidate;
                return 0;
            }
        }
    }

    S2N_ERROR(S2N_ERR_INVALID_SIGNATURE_ALGORITHM);
}

int s2n_get_signature_scheme_pref_list(struct s2n_connection *conn,
                                       const struct s2n_signature_scheme* const** pref_list_out, size_t *list_len_out) {

    /* Our SignatureScheme Preference list depends on the TLS version that was negotiated */

    const struct s2n_signature_scheme* const* our_pref_list = s2n_legacy_sig_scheme_pref_list;
    size_t our_pref_len =  s2n_legacy_sig_scheme_pref_list_len;

    if (conn->actual_protocol_version == S2N_TLS13) {
        our_pref_list = s2n_tls13_sig_scheme_pref_list;
        our_pref_len = s2n_tls13_sig_scheme_pref_list_len;
    }

    *pref_list_out = our_pref_list;
    *list_len_out = our_pref_len;

    return 0;
}


int s2n_get_and_validate_negotiated_signature_scheme(struct s2n_connection *conn, struct s2n_stuffer *in,
                                             struct s2n_signature_scheme *chosen_sig_scheme) {
    uint16_t actual_iana_val;
    GUARD(s2n_stuffer_read_uint16(in, &actual_iana_val));

    const struct s2n_signature_scheme* const* our_pref_list;
    size_t our_pref_len;

    GUARD(s2n_get_signature_scheme_pref_list(conn, &our_pref_list, &our_pref_len));

    for (int i = 0; i < our_pref_len; i++) {
        const struct s2n_signature_scheme *candidate = our_pref_list[i];
        if (candidate->iana_value == actual_iana_val) {
            *chosen_sig_scheme = *candidate;
            return 0;
        }
    }

    S2N_ERROR(S2N_ERR_INVALID_SIGNATURE_SCHEME);
}

int s2n_choose_sig_scheme_from_peer_preference_list(struct s2n_connection *conn, struct s2n_sig_scheme_list *peer_pref_list,
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

    /* Default RSA Hash Algorithm is SHA1 (intead of MD5_SHA1) if TLS 1.2 or FIPS mode */
    if ((conn->actual_protocol_version >= S2N_TLS12 || s2n_is_in_fips_mode())
            && (chosen_scheme.sig_alg == S2N_SIGNATURE_RSA)) {
        chosen_scheme = s2n_rsa_pkcs1_sha1;
    }

    const struct s2n_signature_scheme* const* our_pref_list;
    size_t our_pref_len;

    GUARD(s2n_get_signature_scheme_pref_list(conn, &our_pref_list, &our_pref_len));

    /* SignatureScheme preference list was first added in TLS 1.2. It will be empty in older TLS versions. */
    if (0 < (peer_pref_list->len)) {
        GUARD(s2n_choose_sig_scheme(our_pref_list, our_pref_len, conn->secure.cipher_suite, peer_pref_list, &chosen_scheme));
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

int s2n_send_supported_signature_algorithms(struct s2n_stuffer *out)
{
    /* The array of hashes and signature algorithms we support */
    uint16_t num_signature_schemes = s2n_supported_sig_scheme_pref_list_len;
    uint16_t signature_schemes_size = num_signature_schemes * TLS_SIGNATURE_SCHEME_LEN;

    GUARD(s2n_stuffer_write_uint16(out, signature_schemes_size));

    for (int i =  0; i < num_signature_schemes; i++) {
        GUARD(s2n_stuffer_write_uint16(out, s2n_supported_sig_scheme_pref_list[i]->iana_value));
    }

    return 0;
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
