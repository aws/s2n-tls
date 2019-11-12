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
#include "tls/s2n_tls_digest_preferences.h"
#include "tls/s2n_signature_algorithms.h"
#include "tls/s2n_signature_scheme.h"
#include "utils/s2n_safety.h"

static int s2n_is_sig_hash_present_in_list(struct s2n_sig_scheme_list *sig_hash_algs, uint8_t sig_alg, uint8_t hash_alg)
{
	uint16_t iana_sig_scheme_value = (((uint16_t)hash_alg) << 8) | sig_alg;

	int found = 0;
	for (int i = 0; i < sig_hash_algs->len; i++) {
		if (sig_hash_algs->iana_list[i] == iana_sig_scheme_value) {
			found = 1;
		}
	}

    return found;
}


int s2n_choose_sig_scheme(const struct s2n_signature_scheme* const* our_pref_list, int our_size, s2n_signature_algorithm *required_sig,
                          struct s2n_sig_scheme_list *peer_pref_list, struct s2n_signature_scheme *out) {

    for (int i = 0; i < our_size; i++) {
        const struct s2n_signature_scheme *candidate = our_pref_list[i];

        /* If we have a required Signature Algorithm, and it doesn't match, skip the candidate */
        if (required_sig != NULL && candidate->sig_alg != *required_sig) {
            continue;
        }

        for (int j = 0; j < peer_pref_list->len; j++) {
            uint16_t their_iana_val = peer_pref_list->iana_list[j];

            if (candidate->iana_value == their_iana_val) {
                *out = *candidate;
                return 0;
            }
        }
    }

    S2N_ERROR(S2N_ERR_INVALID_SIGNATURE_ALGORITHM);
}


int s2n_set_signature_hash_pair_from_preference_list(struct s2n_connection *conn, struct s2n_sig_scheme_list *peer_pref_list,
                                                        s2n_hash_algorithm *hash_out, s2n_signature_algorithm *sig_out)
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

    s2n_hash_algorithm hash_alg_chosen = S2N_HASH_MD5_SHA1;
    s2n_signature_algorithm sig_alg_chosen = S2N_SIGNATURE_RSA;

    if (cipher_suite_auth_method == S2N_AUTHENTICATION_ECDSA) {
        chosen_scheme = s2n_ecdsa_sha1;
        sig_alg_chosen = S2N_SIGNATURE_ECDSA;
        hash_alg_chosen = S2N_HASH_SHA1;
    }

    if (conn->actual_protocol_version == S2N_TLS12 || s2n_is_in_fips_mode()) {
        if (chosen_scheme.sig_alg == S2N_SIGNATURE_RSA) {
            chosen_scheme = s2n_rsa_pkcs1_sha1;
        }
        hash_alg_chosen = S2N_HASH_SHA1;
    }

    const struct s2n_signature_scheme* const* our_pref_list = s2n_legacy_preferred_signature_schemes;
    size_t our_pref_len =  s2n_array_len(s2n_legacy_preferred_signature_schemes);

    if (conn->actual_protocol_version == S2N_TLS13) {
        our_pref_list = s2n_tls13_preferred_signature_schemes;
        our_pref_len = s2n_array_len(s2n_tls13_preferred_signature_schemes);
    }

    /* Perform New SigScheme Negotiation */
    /* Signature{Algorithm,Scheme} pref list was first added in TLS 1.2. It will be empty in older TLS versions. */
    if (0 < (peer_pref_list->len)) {
        GUARD(s2n_choose_sig_scheme(our_pref_list, our_pref_len, &sig_alg_chosen, peer_pref_list, &chosen_scheme));
    }

    /* Perform Old SigAlg+HashAlg Negotiation*/
    /* Override default if there were signature/hash pairs available for this signature algorithm */
    for(int i = 0; i < sizeof(s2n_preferred_hashes) / sizeof(s2n_preferred_hashes[0]); i++) {
        if (s2n_is_sig_hash_present_in_list(peer_pref_list, sig_alg_chosen, s2n_preferred_hashes[i]) == 1) {
            /* Just set hash_alg_chosen because sig_alg_chosen was set above based on cert type */
            hash_alg_chosen = s2n_hash_tls_to_alg[s2n_preferred_hashes[i]];
            break;
        }
    }

    /* In TLS 1.3, SigScheme also defines the ECDSA curve to use (instead of reusing whatever ECDHE Key Exchange curve
     * was negotiated). In TLS 1.2 and before, chosen_scheme.signature_curve must *always* be NULL, if it's not, it's
     * a bug in s2n's preference list. */
    S2N_ERROR_IF(conn->actual_protocol_version <= S2N_TLS12 && chosen_scheme.signature_curve != NULL, S2N_ERR_ECDSA_UNSUPPORTED_CURVE);

    /* If TLS 1.3 is negotiated, then every ECDSA SigScheme must also define an ECDSA Curve *except* ECDSA_SHA1, which
     * uses the same curve negotiated in the ECDHE SupportedGroups Extension. */
    S2N_ERROR_IF(conn->actual_protocol_version == S2N_TLS13
            && chosen_scheme.sig_alg == S2N_SIGNATURE_ECDSA
            && chosen_scheme.hash_alg != S2N_HASH_SHA1
            && chosen_scheme.signature_curve == NULL,
            S2N_ERR_ECDSA_UNSUPPORTED_CURVE);

    /* Ensure that Old and New negotiation paths match exactly. */
    S2N_ERROR_IF(hash_alg_chosen != chosen_scheme.hash_alg, S2N_ERR_HASH_INVALID_ALGORITHM);
    S2N_ERROR_IF(sig_alg_chosen != chosen_scheme.sig_alg, S2N_ERR_INVALID_SIGNATURE_ALGORITHM);

    *hash_out = hash_alg_chosen;
    *sig_out = sig_alg_chosen;

    return 0;
}

int s2n_get_signature_hash_pair_if_supported(struct s2n_stuffer *in, s2n_hash_algorithm *hash_alg,
                                             s2n_signature_algorithm *signature_alg)
{
    uint8_t hash_algorithm;
    uint8_t signature_algorithm;

    GUARD(s2n_stuffer_read_uint8(in, &hash_algorithm));
    GUARD(s2n_stuffer_read_uint8(in, &signature_algorithm));

    /* This function checks that the s2n_hash_algorithm and s2n_signature_algorithm sent in
     * the stuffer is supported by the library's preference list before returning them
     */
    int sig_alg_matched = 0;
    for (int i = 0; i < sizeof(s2n_preferred_signature_algorithms) / sizeof(s2n_preferred_signature_algorithms[0]); i++) {
        if(s2n_preferred_signature_algorithms[i] == signature_algorithm) {
            sig_alg_matched = 1;
        }
    }
    if (sig_alg_matched) {
        *signature_alg = signature_algorithm;
    } else {
        S2N_ERROR(S2N_ERR_INVALID_SIGNATURE_ALGORITHM);
    }

    int hash_matched = 0;
    for (int j = 0; j < sizeof(s2n_preferred_hashes) / sizeof(s2n_preferred_hashes[0]); j++) {
        if (s2n_preferred_hashes[j] == hash_algorithm) {
            hash_matched = 1;
            break;
        }
    }
    if (hash_matched) {
        *hash_alg = s2n_hash_tls_to_alg[hash_algorithm];
    } else {
        S2N_ERROR(S2N_ERR_HASH_INVALID_ALGORITHM);
    }

    return 0;
}

int s2n_send_supported_signature_algorithms(struct s2n_stuffer *out)
{
    /* The array of hashes and signature algorithms we support */
    uint16_t preferred_hashes_len = sizeof(s2n_preferred_hashes) / sizeof(s2n_preferred_hashes[0]);
    uint16_t num_signature_algs = 2;
    uint16_t preferred_hashes_size = preferred_hashes_len * num_signature_algs * 2;
    GUARD(s2n_stuffer_write_uint16(out, preferred_hashes_size));

    for (int i =  0; i < preferred_hashes_len; i++) {
        GUARD(s2n_stuffer_write_uint8(out, s2n_preferred_hashes[i]));
        GUARD(s2n_stuffer_write_uint8(out, TLS_SIGNATURE_ALGORITHM_ECDSA));

        GUARD(s2n_stuffer_write_uint8(out, s2n_preferred_hashes[i]));
        GUARD(s2n_stuffer_write_uint8(out, TLS_SIGNATURE_ALGORITHM_RSA));
    }
    return 0;
}

int s2n_recv_supported_signature_algorithms(struct s2n_connection *conn, struct s2n_stuffer *in,
                                            struct s2n_sig_scheme_list *sig_hash_algs)
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
