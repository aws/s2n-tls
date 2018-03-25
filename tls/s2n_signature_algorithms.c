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
#include "utils/s2n_safety.h"

static int s2n_sig_hash_algs_pairs_set(struct s2n_sig_hash_alg_pairs *sig_hash_algs, uint8_t sig_alg, uint8_t hash_alg)
{
    /* Skip unknown or unsupported values. If we receive any of these in the signature_algorithms extension 
     * or CertificateRequest, we can ignore them and fall back to using the default signature-hash algorithm combination */
    if (hash_alg < TLS_HASH_ALGORITHM_COUNT && sig_alg < TLS_SIGNATURE_ALGORITHM_COUNT) {
        sig_hash_algs->matrix[sig_alg][hash_alg] = 1;
    }
    
    return 0;
}

static int s2n_sig_hash_alg_pairs_get(struct s2n_sig_hash_alg_pairs *sig_hash_algs, uint8_t sig_alg, uint8_t hash_alg)
{
    S2N_ERROR_IF(hash_alg >= TLS_HASH_ALGORITHM_COUNT, S2N_ERR_HASH_INVALID_ALGORITHM);
    S2N_ERROR_IF(sig_alg >= TLS_SIGNATURE_ALGORITHM_COUNT, S2N_ERR_INVALID_SIGNATURE_ALGORITHM);

    return sig_hash_algs->matrix[sig_alg][hash_alg];
}

int s2n_set_signature_hash_pair_from_preference_list(struct s2n_connection *conn, struct s2n_sig_hash_alg_pairs *sig_hash_algs, 
                                                        s2n_hash_algorithm *hash, s2n_signature_algorithm *sig)
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
    s2n_hash_algorithm hash_alg_chosen = S2N_HASH_MD5_SHA1;
    s2n_signature_algorithm sig_alg_chosen = S2N_SIGNATURE_RSA;
    if (cipher_suite_auth_method == S2N_AUTHENTICATION_ECDSA) {
        sig_alg_chosen = S2N_SIGNATURE_ECDSA;
        hash_alg_chosen = S2N_HASH_SHA1;
    }

    if (conn->actual_protocol_version == S2N_TLS12 || s2n_is_in_fips_mode()) {
        hash_alg_chosen = S2N_HASH_SHA1;
    }

    /* Override default if there were signature/hash pairs available for this signature algorithm */
    for(int i = 0; i < sizeof(s2n_preferred_hashes) / sizeof(s2n_preferred_hashes[0]); i++) {
        if (s2n_sig_hash_alg_pairs_get(sig_hash_algs, sig_alg_chosen, s2n_preferred_hashes[i]) == 1) {
            /* Just set hash_alg_chosen because sig_alg_chosen was set above based on cert type */
            hash_alg_chosen = s2n_hash_tls_to_alg[s2n_preferred_hashes[i]];
        }
    }

    *hash = hash_alg_chosen;
    *sig = sig_alg_chosen;
    
    return 0;
}

int s2n_get_signature_hash_pair_if_supported(struct s2n_stuffer *in, s2n_hash_algorithm *hash_alg, s2n_signature_algorithm *signature_alg)
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

int s2n_recv_supported_signature_algorithms(struct s2n_connection *conn, struct s2n_stuffer *in, struct s2n_sig_hash_alg_pairs *sig_hash_algs)
{
    uint16_t length_of_all_pairs;
    GUARD(s2n_stuffer_read_uint16(in, &length_of_all_pairs));
    if (length_of_all_pairs > s2n_stuffer_data_available(in)) {
        /* Malformed length, ignore the extension */
        return 0;
    }

    if (length_of_all_pairs % 2 || s2n_stuffer_data_available(in) % 2) {
        /* Pairs occur in two byte lengths. Malformed length, ignore the extension. */
        return 0;
    }

    int pairs_available = length_of_all_pairs / 2;

    uint8_t *hash_sig_pairs = s2n_stuffer_raw_read(in, pairs_available * 2);
    notnull_check(hash_sig_pairs);

    /* Store all of the pairs received. Preference order and whether or not the
     * algorithms are even supported will factor in during selection */
    for(int i = 0; i < pairs_available; i++) {
        uint8_t hash_alg = hash_sig_pairs[2 * i];
        uint8_t sig_alg = hash_sig_pairs[2 * i + 1];

        GUARD(s2n_sig_hash_algs_pairs_set(sig_hash_algs, sig_alg, hash_alg));
    }
    
    return 0;
}
