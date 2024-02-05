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
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_tls_parameters.h"
#include "utils/s2n_result.h"

/* FIPS requires at least 112 bits of security.
 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-107r1.pdf */
const s2n_hash_algorithm fips_hash_algs[] = {
    S2N_HASH_SHA224,
    S2N_HASH_SHA256,
    S2N_HASH_SHA384,
    S2N_HASH_SHA512,
};
S2N_RESULT s2n_fips_validate_hash_algorithm(s2n_hash_algorithm hash_alg, bool *valid)
{
    RESULT_ENSURE_REF(valid);
    *valid = false;
    for (size_t i = 0; i < s2n_array_len(fips_hash_algs); i++) {
        if (fips_hash_algs[i] == hash_alg) {
            *valid = true;
            return S2N_RESULT_OK;
        }
    }
    return S2N_RESULT_OK;
}

/* https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf */
const uint8_t fips_cipher_suite_ianas[][2] = {
    /* 3.3.1.1.1 Cipher Suites for ECDSA Certificates */
    { TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 },
    { TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 },
    { TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 },
    { TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 },
    { TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA },
    { TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA },

    /* 3.3.1.1.2 Cipher Suites for RSA Certificates */
    { TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 },
    { TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 },
    { TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 },
    { TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 },
    { TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 },
    { TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 },
    { TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 },
    { TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 },
    { TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA },
    { TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA },
    { TLS_DHE_RSA_WITH_AES_128_CBC_SHA },
    { TLS_DHE_RSA_WITH_AES_256_CBC_SHA },

    /* 3.3.1.2 Cipher Suites for TLS 1.3 */
    { TLS_AES_128_GCM_SHA256 },
    { TLS_AES_256_GCM_SHA384 },
};

S2N_RESULT s2n_fips_validate_cipher_suite(const struct s2n_cipher_suite *cipher_suite, bool *valid)
{
    RESULT_ENSURE_REF(cipher_suite);
    RESULT_ENSURE_REF(valid);

    *valid = false;
    for (size_t i = 0; i < s2n_array_len(fips_cipher_suite_ianas); i++) {
        if (fips_cipher_suite_ianas[i][0] != cipher_suite->iana_value[0]) {
            continue;
        }
        if (fips_cipher_suite_ianas[i][1] != cipher_suite->iana_value[1]) {
            continue;
        }
        *valid = true;
        return S2N_RESULT_OK;
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_fips_validate_signature_scheme(const struct s2n_signature_scheme *sig_alg, bool *valid)
{
    RESULT_ENSURE_REF(sig_alg);
    RESULT_GUARD(s2n_fips_validate_hash_algorithm(sig_alg->hash_alg, valid));
    return S2N_RESULT_OK;
}

/* https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf */
const struct s2n_ecc_named_curve *fips_curves[] = {
    &s2n_ecc_curve_secp256r1,
    &s2n_ecc_curve_secp384r1,
    &s2n_ecc_curve_secp521r1,
};
S2N_RESULT s2n_fips_validate_curve(const struct s2n_ecc_named_curve *curve, bool *valid)
{
    RESULT_ENSURE_REF(curve);
    RESULT_ENSURE_REF(valid);
    *valid = false;
    for (size_t i = 0; i < s2n_array_len(fips_curves); i++) {
        if (fips_curves[i] == curve) {
            *valid = true;
            return S2N_RESULT_OK;
        }
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_fips_validate_version(uint8_t version, bool *valid)
{
    RESULT_ENSURE_REF(valid);
    /* Technically FIPS 140-3 still allows TLS1.0 and TLS1.1 for some use cases,
     * but for simplicity s2n-tls does not.
     */
    *valid = (version >= S2N_TLS12);
    return S2N_RESULT_OK;
}
