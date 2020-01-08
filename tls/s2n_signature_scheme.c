/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include "tls/s2n_signature_scheme.h"
#include "crypto/s2n_ecc_evp.h"
#include "utils/s2n_safety.h"


/* RSA PKCS1 */
const struct s2n_signature_scheme s2n_rsa_pkcs1_md5_sha1 = {
        .iana_value = TLS_SIGNATURE_SCHEME_PRIVATE_INTERNAL_RSA_PKCS1_MD5_SHA1,
        .hash_alg = S2N_HASH_MD5_SHA1,
        .sig_alg = S2N_SIGNATURE_RSA,
        .signature_curve = NULL /* Elliptic Curve not needed for RSA */
};

const struct s2n_signature_scheme s2n_rsa_pkcs1_sha1 = {
        .iana_value = TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA1,
        .hash_alg = S2N_HASH_SHA1,
        .sig_alg = S2N_SIGNATURE_RSA,
        .signature_curve = NULL /* Elliptic Curve not needed for RSA */
};

const struct s2n_signature_scheme s2n_rsa_pkcs1_sha224 = {
        .iana_value = TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA224,
        .hash_alg = S2N_HASH_SHA224,
        .sig_alg = S2N_SIGNATURE_RSA,
        .signature_curve = NULL /* Elliptic Curve not needed for RSA */
};

const struct s2n_signature_scheme s2n_rsa_pkcs1_sha256 = {
        .iana_value = TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA256,
        .hash_alg = S2N_HASH_SHA256,
        .sig_alg = S2N_SIGNATURE_RSA,
        .signature_curve = NULL /* Elliptic Curve not needed for RSA */
};

const struct s2n_signature_scheme s2n_rsa_pkcs1_sha384 = {
        .iana_value = TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA384,
        .hash_alg = S2N_HASH_SHA384,
        .sig_alg = S2N_SIGNATURE_RSA,
        .signature_curve = NULL /* Elliptic Curve not needed for RSA */
};

const struct s2n_signature_scheme s2n_rsa_pkcs1_sha512 = {
        .iana_value = TLS_SIGNATURE_SCHEME_RSA_PKCS1_SHA512,
        .hash_alg = S2N_HASH_SHA512,
        .sig_alg = S2N_SIGNATURE_RSA,
        .signature_curve = NULL /* Elliptic Curve not needed for RSA */
};

/* TLS 1.2 Compatible ECDSA Signature Schemes */
const struct s2n_signature_scheme s2n_ecdsa_sha1 = {
        .iana_value = TLS_SIGNATURE_SCHEME_ECDSA_SHA1,
        .hash_alg = S2N_HASH_SHA1,
        .sig_alg = S2N_SIGNATURE_ECDSA,
        .signature_curve = NULL /* Decided by supported_groups Extension in TLS 1.2 and before */
};

const struct s2n_signature_scheme s2n_ecdsa_sha224 = {
        .iana_value = TLS_SIGNATURE_SCHEME_ECDSA_SHA224,
        .hash_alg = S2N_HASH_SHA224,
        .sig_alg = S2N_SIGNATURE_ECDSA,
        .signature_curve = NULL /* Decided by supported_groups Extension in TLS 1.2 and before */
};

const struct s2n_signature_scheme s2n_ecdsa_sha256 = {
        .iana_value = TLS_SIGNATURE_SCHEME_ECDSA_SHA256,
        .hash_alg = S2N_HASH_SHA256,
        .sig_alg = S2N_SIGNATURE_ECDSA,
        .signature_curve = NULL /* Decided by supported_groups Extension in TLS 1.2 and before */
};

const struct s2n_signature_scheme s2n_ecdsa_sha384 = {
        .iana_value = TLS_SIGNATURE_SCHEME_ECDSA_SHA384,
        .hash_alg = S2N_HASH_SHA384,
        .sig_alg = S2N_SIGNATURE_ECDSA,
        .signature_curve = NULL /* Decided by supported_groups Extension in TLS 1.2 and before */
};

const struct s2n_signature_scheme s2n_ecdsa_sha512 = {
        .iana_value = TLS_SIGNATURE_SCHEME_ECDSA_SHA512,
        .hash_alg = S2N_HASH_SHA512,
        .sig_alg = S2N_SIGNATURE_ECDSA,
        .signature_curve = NULL /* Decided by supported_groups Extension in TLS 1.2 and before */
};

/* TLS 1.3 Compatible ECDSA Schemes */
/* In TLS 1.3 the two byte IANA value also defines the Curve to use for signing */

const struct s2n_signature_scheme s2n_ecdsa_secp256r1_sha256 = {
        .iana_value = TLS_SIGNATURE_SCHEME_ECDSA_SECP256R1_SHA256,
        .hash_alg = S2N_HASH_SHA256,
        .sig_alg = S2N_SIGNATURE_ECDSA,
        .signature_curve = &s2n_ecc_curve_secp256r1 /* Hardcoded as of TLS 1.3 */
};

const struct s2n_signature_scheme s2n_ecdsa_secp384r1_sha384 = {
        .iana_value = TLS_SIGNATURE_SCHEME_ECDSA_SECP384R1_SHA384,
        .hash_alg = S2N_HASH_SHA384,
        .sig_alg = S2N_SIGNATURE_ECDSA,
        .signature_curve = &s2n_ecc_curve_secp384r1 /* Hardcoded as of TLS 1.3 */
};

/**
 * RSA-PSS-RSAE
 */
const struct s2n_signature_scheme s2n_rsa_pss_rsae_sha256 = {
        .iana_value = TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256,
        .hash_alg = S2N_HASH_SHA256,
        .sig_alg = S2N_SIGNATURE_RSA_PSS_RSAE,
        .signature_curve = NULL /* Elliptic Curve not needed for RSA */
};

const struct s2n_signature_scheme s2n_rsa_pss_rsae_sha384 = {
        .iana_value = TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA384,
        .hash_alg = S2N_HASH_SHA384,
        .sig_alg = S2N_SIGNATURE_RSA_PSS_RSAE,
        .signature_curve = NULL /* Elliptic Curve not needed for RSA */
};

const struct s2n_signature_scheme s2n_rsa_pss_rsae_sha512 = {
        .iana_value = TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA512,
        .hash_alg = S2N_HASH_SHA512,
        .sig_alg = S2N_SIGNATURE_RSA_PSS_RSAE,
        .signature_curve = NULL /* Elliptic Curve not needed for RSA */
};

/* All Supported SignatureSchemes (Both TLS 1.2 and 1.3) to send in the ClientHello to the Server. */
/* No MD5 to avoid SLOTH Vulnerability */
const struct s2n_signature_scheme* const s2n_supported_sig_scheme_pref_list[] = {
        /* RSA PSS - Commented out until it is actually supported */
        /* &s2n_rsa_pss_rsae_sha256, */
        /* &s2n_rsa_pss_rsae_sha384, */
        /* &s2n_rsa_pss_rsae_sha512, */

        /* RSA PKCS1 */
        &s2n_rsa_pkcs1_sha256,
        &s2n_rsa_pkcs1_sha384,
        &s2n_rsa_pkcs1_sha512,
        &s2n_rsa_pkcs1_sha224,

        /* ECDSA - TLS 1.3 */
        &s2n_ecdsa_secp256r1_sha256,
        &s2n_ecdsa_secp384r1_sha384,

        /* ECDSA - TLS 1.2*/
        &s2n_ecdsa_sha256,
        &s2n_ecdsa_sha384,
        &s2n_ecdsa_sha512,
        &s2n_ecdsa_sha224,

        /* SHA-1 Legacy */
        &s2n_rsa_pkcs1_sha1,
        &s2n_ecdsa_sha1,
};

/* Signature Scheme Preference List to use when picking a <=TLS 1.2 SignatureAlgorithm/SignatureScheme */
/* As per RFC: This list MUST NOT contain any s2n_signature_scheme's with a non-null signature_curve defined. */
const struct s2n_signature_scheme* const s2n_legacy_sig_scheme_pref_list[] = {
        /* RSA PSS - Commented out until it is actually supported */
        /* &s2n_rsa_pss_rsae_sha256, */
        /* &s2n_rsa_pss_rsae_sha384, */
        /* &s2n_rsa_pss_rsae_sha512, */

        /* RSA PKCS1 */
        &s2n_rsa_pkcs1_sha256,
        &s2n_rsa_pkcs1_sha384,
        &s2n_rsa_pkcs1_sha512,
        &s2n_rsa_pkcs1_sha224,
        &s2n_rsa_pkcs1_sha1,

        /* ECDSA */
        &s2n_ecdsa_sha256,
        &s2n_ecdsa_sha384,
        &s2n_ecdsa_sha512,
        &s2n_ecdsa_sha224,
        &s2n_ecdsa_sha1,
};

/* Signature Scheme Preference List:  TLS 1.3 */
/* This list MUST NOT contain any ECDSA s2n_signature_scheme's with a NULL signature_curve (except ECDSA_SHA1). */
const struct s2n_signature_scheme * const s2n_tls13_sig_scheme_pref_list[] = {
        /* RSA PSS - Commented out until it is actually supported */
        /* &s2n_rsa_pss_rsae_sha256, */
        /* &s2n_rsa_pss_rsae_sha384, */
        /* &s2n_rsa_pss_rsae_sha512, */

        /* RSA PKCS1 */
        &s2n_rsa_pkcs1_sha256,
        &s2n_rsa_pkcs1_sha384,
        &s2n_rsa_pkcs1_sha512,

        /* ECDSA */
        &s2n_ecdsa_secp256r1_sha256,
        &s2n_ecdsa_secp384r1_sha384,

        /* SHA-1 Legacy */
        &s2n_rsa_pkcs1_sha1,
        &s2n_ecdsa_sha1,
};

const size_t s2n_supported_sig_scheme_pref_list_len = s2n_array_len(s2n_supported_sig_scheme_pref_list);
const size_t s2n_legacy_sig_scheme_pref_list_len = s2n_array_len(s2n_legacy_sig_scheme_pref_list);
const size_t s2n_tls13_sig_scheme_pref_list_len = s2n_array_len(s2n_tls13_sig_scheme_pref_list);

