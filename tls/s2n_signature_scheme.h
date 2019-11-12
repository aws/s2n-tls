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

#pragma once

#include <s2n.h>

#include "crypto/s2n_hash.h"
#include "crypto/s2n_signature.h"
#include "crypto/s2n_ecc.h"

struct s2n_signature_scheme {
    uint16_t iana_value;
    s2n_hash_algorithm hash_alg;
    s2n_signature_algorithm sig_alg;

    /* Curve is only specified for ECDSA Signatures */
    struct s2n_ecc_named_curve *signature_curve;
};

/* RSA PKCS1 */
extern const struct s2n_signature_scheme s2n_rsa_pkcs1_md5_sha1;
extern const struct s2n_signature_scheme s2n_rsa_pkcs1_sha1;
extern const struct s2n_signature_scheme s2n_rsa_pkcs1_sha224;
extern const struct s2n_signature_scheme s2n_rsa_pkcs1_sha256;
extern const struct s2n_signature_scheme s2n_rsa_pkcs1_sha384;
extern const struct s2n_signature_scheme s2n_rsa_pkcs1_sha512;

/* TLS 1.2 Compatible ECDSA Schemes */
extern const struct s2n_signature_scheme s2n_ecdsa_sha1;
extern const struct s2n_signature_scheme s2n_ecdsa_sha224;
extern const struct s2n_signature_scheme s2n_ecdsa_sha256;
extern const struct s2n_signature_scheme s2n_ecdsa_sha384;
extern const struct s2n_signature_scheme s2n_ecdsa_sha512;

/* TLS 1.3 Compatible ECDSA Schemes */
extern const struct s2n_signature_scheme s2n_ecdsa_secp256r1_sha256;
extern const struct s2n_signature_scheme s2n_ecdsa_secp384r1_sha384;

/* RSA PSS */
/*
 * Use RSA-PSS-RSAE instead of RSA-PSS-PSS in order to work with older certificates.
 * For more info see: https://crypto.stackexchange.com/a/58708
 */
extern const struct s2n_signature_scheme s2n_rsa_pss_rsae_sha256;
extern const struct s2n_signature_scheme s2n_rsa_pss_rsae_sha384;
extern const struct s2n_signature_scheme s2n_rsa_pss_rsae_sha512;

/* Signature Scheme Preference List: TLS 1.2 and previous */
/* This list MUST NOT contain any s2n_signature_scheme's with a non-null signature_curve defined. */
static const struct s2n_signature_scheme* const s2n_legacy_preferred_signature_schemes[] = {
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
static const struct s2n_signature_scheme * const s2n_tls13_preferred_signature_schemes[] = {
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
