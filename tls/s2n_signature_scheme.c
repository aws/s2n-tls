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

#include <s2n.h>

#include "crypto/s2n_hash.h"
#include "crypto/s2n_signature.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_signature_scheme.h"
#include "crypto/s2n_ecc_evp.h"
#include "utils/s2n_safety.h"

/* RSA PKCS1 */
const struct s2n_signature_scheme s2n_rsa_pkcs1_md5_sha1 = {
        .iana_value = TLS_SIGNATURE_SCHEME_PRIVATE_INTERNAL_RSA_PKCS1_MD5_SHA1,
        .hash_alg = S2N_HASH_MD5_SHA1,
        .sig_alg = S2N_SIGNATURE_RSA,
        .signature_curve = NULL, /* Elliptic Curve not needed for RSA */
        .maximum_protocol_version = S2N_TLS12, /* TLS1.3 does not support pkcs1 or sha1 */
};

const struct s2n_signature_scheme s2n_rsa_pkcs1_sha1 = {
        .iana_value = TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA1,
        .hash_alg = S2N_HASH_SHA1,
        .sig_alg = S2N_SIGNATURE_RSA,
        .signature_curve = NULL, /* Elliptic Curve not needed for RSA */
        .maximum_protocol_version = S2N_TLS12, /* TLS1.3 does not support pkcs1 or sha1 */
};

const struct s2n_signature_scheme s2n_rsa_pkcs1_sha224 = {
        .iana_value = TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA224,
        .hash_alg = S2N_HASH_SHA224,
        .sig_alg = S2N_SIGNATURE_RSA,
        .signature_curve = NULL, /* Elliptic Curve not needed for RSA */
        .maximum_protocol_version = S2N_TLS12, /* TLS1.3 does not support pkcs1 */
};

const struct s2n_signature_scheme s2n_rsa_pkcs1_sha256 = {
        .iana_value = TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA256,
        .hash_alg = S2N_HASH_SHA256,
        .sig_alg = S2N_SIGNATURE_RSA,
        .signature_curve = NULL, /* Elliptic Curve not needed for RSA */
        .maximum_protocol_version = S2N_TLS12, /* TLS1.3 does not support pkcs1 */
};

const struct s2n_signature_scheme s2n_rsa_pkcs1_sha384 = {
        .iana_value = TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA384,
        .hash_alg = S2N_HASH_SHA384,
        .sig_alg = S2N_SIGNATURE_RSA,
        .signature_curve = NULL, /* Elliptic Curve not needed for RSA */
        .maximum_protocol_version = S2N_TLS12, /* TLS1.3 does not support pkcs1 */
};

const struct s2n_signature_scheme s2n_rsa_pkcs1_sha512 = {
        .iana_value = TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA512,
        .hash_alg = S2N_HASH_SHA512,
        .sig_alg = S2N_SIGNATURE_RSA,
        .signature_curve = NULL, /* Elliptic Curve not needed for RSA */
        .maximum_protocol_version = S2N_TLS12, /* TLS1.3 does not support pkcs1 */
};

/* TLS 1.2 Compatible ECDSA Signature Schemes */
const struct s2n_signature_scheme s2n_ecdsa_sha1 = {
        .iana_value = TLS_SIGNATURE_SCHEME_ECDSA_SHA1,
        .hash_alg = S2N_HASH_SHA1,
        .sig_alg = S2N_SIGNATURE_ECDSA,
        .signature_curve = NULL, /* Decided by supported_groups Extension in TLS 1.2 and before */
        .maximum_protocol_version = S2N_TLS12, /* TLS1.3 does not support sha1 and requires a signature curve */
};

const struct s2n_signature_scheme s2n_ecdsa_sha224 = {
        .iana_value = TLS_SIGNATURE_SCHEME_ECDSA_SHA224,
        .hash_alg = S2N_HASH_SHA224,
        .sig_alg = S2N_SIGNATURE_ECDSA,
        .signature_curve = NULL, /* Decided by supported_groups Extension in TLS 1.2 and before */
        .maximum_protocol_version = S2N_TLS12, /* TLS1.3 requires a signature curve */
};

const struct s2n_signature_scheme s2n_ecdsa_sha256 = {
        .iana_value = TLS_SIGNATURE_SCHEME_ECDSA_SHA256,
        .hash_alg = S2N_HASH_SHA256,
        .sig_alg = S2N_SIGNATURE_ECDSA,
        .signature_curve = NULL, /* Decided by supported_groups Extension in TLS 1.2 and before */
        .maximum_protocol_version = S2N_TLS12, /* TLS1.3 requires a signature curve */
};

const struct s2n_signature_scheme s2n_ecdsa_sha384 = {
        .iana_value = TLS_SIGNATURE_SCHEME_ECDSA_SHA384,
        .hash_alg = S2N_HASH_SHA384,
        .sig_alg = S2N_SIGNATURE_ECDSA,
        .signature_curve = NULL, /* Decided by supported_groups Extension in TLS 1.2 and before */
        .maximum_protocol_version = S2N_TLS12, /* TLS1.3 requires a signature curve */
};

const struct s2n_signature_scheme s2n_ecdsa_sha512 = {
        .iana_value = TLS_SIGNATURE_SCHEME_ECDSA_SHA512,
        .hash_alg = S2N_HASH_SHA512,
        .sig_alg = S2N_SIGNATURE_ECDSA,
        .signature_curve = NULL, /* Decided by supported_groups Extension in TLS 1.2 and before */
        .maximum_protocol_version = S2N_TLS12, /* TLS1.3 requires a signature curve */
};

/* TLS 1.3 Compatible ECDSA Schemes */
/* In TLS 1.3 the two byte IANA value also defines the Curve to use for signing */

const struct s2n_signature_scheme s2n_ecdsa_secp256r1_sha256 = {
        .iana_value = TLS_SIGNATURE_SCHEME_ECDSA_SECP256R1_SHA256,
        .hash_alg = S2N_HASH_SHA256,
        .sig_alg = S2N_SIGNATURE_ECDSA,
        .signature_curve = &s2n_ecc_curve_secp256r1, /* Hardcoded as of TLS 1.3 */
        .minimum_protocol_version = S2N_TLS13,
};

const struct s2n_signature_scheme s2n_ecdsa_secp384r1_sha384 = {
        .iana_value = TLS_SIGNATURE_SCHEME_ECDSA_SECP384R1_SHA384,
        .hash_alg = S2N_HASH_SHA384,
        .sig_alg = S2N_SIGNATURE_ECDSA,
        .signature_curve = &s2n_ecc_curve_secp384r1, /* Hardcoded as of TLS 1.3 */
        .minimum_protocol_version = S2N_TLS13,
};

/**
 * RSA-PSS-RSAE
 */
const struct s2n_signature_scheme s2n_rsa_pss_rsae_sha256 = {
        .iana_value = TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256,
        .hash_alg = S2N_HASH_SHA256,
        .sig_alg = S2N_SIGNATURE_RSA_PSS_RSAE,
        .signature_curve = NULL, /* Elliptic Curve not needed for RSA */
};

const struct s2n_signature_scheme s2n_rsa_pss_rsae_sha384 = {
        .iana_value = TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA384,
        .hash_alg = S2N_HASH_SHA384,
        .sig_alg = S2N_SIGNATURE_RSA_PSS_RSAE,
        .signature_curve = NULL, /* Elliptic Curve not needed for RSA */
};

const struct s2n_signature_scheme s2n_rsa_pss_rsae_sha512 = {
        .iana_value = TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA512,
        .hash_alg = S2N_HASH_SHA512,
        .sig_alg = S2N_SIGNATURE_RSA_PSS_RSAE,
        .signature_curve = NULL, /* Elliptic Curve not needed for RSA */
};

/**
 * RSA-PSS-PSS
 */
const struct s2n_signature_scheme s2n_rsa_pss_pss_sha256 = {
        .iana_value = TLS_SIGNATURE_SCHEME_RSA_PSS_PSS_SHA256,
        .hash_alg = S2N_HASH_SHA256,
        .sig_alg = S2N_SIGNATURE_RSA_PSS_PSS,
        .signature_curve = NULL, /* Elliptic Curve not needed for RSA */
        .minimum_protocol_version = S2N_TLS13,
};

const struct s2n_signature_scheme s2n_rsa_pss_pss_sha384 = {
        .iana_value = TLS_SIGNATURE_SCHEME_RSA_PSS_PSS_SHA384,
        .hash_alg = S2N_HASH_SHA384,
        .sig_alg = S2N_SIGNATURE_RSA_PSS_PSS,
        .signature_curve = NULL, /* Elliptic Curve not needed for RSA */
        .minimum_protocol_version = S2N_TLS13,
};

const struct s2n_signature_scheme s2n_rsa_pss_pss_sha512 = {
        .iana_value = TLS_SIGNATURE_SCHEME_RSA_PSS_PSS_SHA512,
        .hash_alg = S2N_HASH_SHA512,
        .sig_alg = S2N_SIGNATURE_RSA_PSS_PSS,
        .signature_curve = NULL, /* Elliptic Curve not needed for RSA */
        .minimum_protocol_version = S2N_TLS13,
};

/* All Supported SignatureSchemes. */
/* No MD5 to avoid SLOTH Vulnerability */
const struct s2n_signature_scheme* const s2n_sig_scheme_pref_list_20140601[] = {
        /* RSA PKCS1 */
        &s2n_rsa_pkcs1_sha256,
        &s2n_rsa_pkcs1_sha384,
        &s2n_rsa_pkcs1_sha512,
        &s2n_rsa_pkcs1_sha224,

        /* ECDSA - TLS 1.2 */
        &s2n_ecdsa_sha256, /* same iana value as TLS 1.3 s2n_ecdsa_secp256r1_sha256 */
        &s2n_ecdsa_secp256r1_sha256,
        &s2n_ecdsa_sha384, /* same iana value as TLS 1.3 s2n_ecdsa_secp384r1_sha384 */
        &s2n_ecdsa_secp384r1_sha384,
        &s2n_ecdsa_sha512,
        &s2n_ecdsa_sha224,

        /* SHA-1 Legacy */
        &s2n_rsa_pkcs1_sha1,
        &s2n_ecdsa_sha1,
};

/* The original preference list, but with rsa_pss supported. */
const struct s2n_signature_scheme* const s2n_sig_scheme_pref_list_20200207[] = {
        /* RSA PSS */
        &s2n_rsa_pss_pss_sha256,
        &s2n_rsa_pss_pss_sha384,
        &s2n_rsa_pss_pss_sha512,
        &s2n_rsa_pss_rsae_sha256,
        &s2n_rsa_pss_rsae_sha384,
        &s2n_rsa_pss_rsae_sha512,

        /* RSA PKCS1 */
        &s2n_rsa_pkcs1_sha256,
        &s2n_rsa_pkcs1_sha384,
        &s2n_rsa_pkcs1_sha512,
        &s2n_rsa_pkcs1_sha224,

        /* ECDSA - TLS 1.2 */
        &s2n_ecdsa_sha256, /* same iana value as TLS 1.3 s2n_ecdsa_secp256r1_sha256 */
        &s2n_ecdsa_secp256r1_sha256,
        &s2n_ecdsa_sha384, /* same iana value as TLS 1.3 s2n_ecdsa_secp384r1_sha384 */
        &s2n_ecdsa_secp384r1_sha384,
        &s2n_ecdsa_sha512,
        &s2n_ecdsa_sha224,

        /* SHA-1 Legacy */
        &s2n_rsa_pkcs1_sha1,
        &s2n_ecdsa_sha1,
};

const struct s2n_signature_preferences s2n_signature_preferences_20140601 = {
        .count = s2n_array_len(s2n_sig_scheme_pref_list_20140601),
        .signature_schemes = s2n_sig_scheme_pref_list_20140601,
};

const struct s2n_signature_preferences s2n_signature_preferences_20200207 = {
        .count = s2n_array_len(s2n_sig_scheme_pref_list_20200207),
        .signature_schemes = s2n_sig_scheme_pref_list_20200207,
};

static struct {
    const char *version;
    const struct s2n_signature_preferences *preferences;
} selection[] = {
        {.version = "default", .preferences = &s2n_signature_preferences_20140601 },
        {.version = "default_tls13", .preferences = &s2n_signature_preferences_20200207 },
        {.version = "20200207", .preferences = &s2n_signature_preferences_20200207 },
        {.version = "20140601", .preferences = &s2n_signature_preferences_20140601 },
        {.version = NULL, .preferences = NULL }, /* Sentinel */
};

static int s2n_find_signature_pref_from_version(const char *version, const struct s2n_signature_preferences **signature_preferences)
{
    notnull_check(version);
    notnull_check(signature_preferences);

    for (int i = 0; selection[i].version != NULL; i++) {
        if (!strcasecmp(version, selection[i].version)) {
            *signature_preferences = selection[i].preferences;
            return 0;
        }
    }

    S2N_ERROR(S2N_ERR_INVALID_SIGNATURE_ALGORITHMS_PREFERENCES);
}

int s2n_config_set_signature_preferences(struct s2n_config *config, const char *version)
{
    GUARD(s2n_find_signature_pref_from_version(version, &config->signature_preferences));
    return 0;
}

