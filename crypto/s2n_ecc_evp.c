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

#include "crypto/s2n_ecc_evp.h"

#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <stdint.h>

#include "tls/s2n_tls_parameters.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_safety.h"

DEFINE_POINTER_CLEANUP_FUNC(EVP_PKEY *, EVP_PKEY_free);
DEFINE_POINTER_CLEANUP_FUNC(EVP_PKEY_CTX *, EVP_PKEY_CTX_free);

#if MODERN_EC_SUPPORTED
const struct s2n_ecc_named_curve s2n_ecc_curve_x25519 = {
    .iana_id = TLS_EC_CURVE_ECDH_X25519, 
    .libcrypto_nid = NID_X25519, 
    .name = "x25519", 
    .share_size = 32
};
#endif

const struct s2n_ecc_named_curve *const s2n_ecc_evp_supported_curves_list[] = {
    &s2n_ecc_curve_secp256r1,
    &s2n_ecc_curve_secp384r1,
#if MODERN_EC_SUPPORTED
    &s2n_ecc_curve_x25519,
#endif
};

const size_t s2n_ecc_evp_supported_curves_list_len = s2n_array_len(s2n_ecc_evp_supported_curves_list);

#if MODERN_EC_SUPPORTED
static int s2n_ecc_evp_generate_key_x25519(const struct s2n_ecc_named_curve *named_curve, EVP_PKEY **evp_pkey);
#endif

static int s2n_ecc_evp_generate_key_nist_curves(const struct s2n_ecc_named_curve *named_curve, EVP_PKEY **evp_pkey);
static int s2n_ecc_evp_generate_own_key(const struct s2n_ecc_named_curve *named_curve, EVP_PKEY **evp_pkey);
static int s2n_ecc_evp_compute_shared_secret(EVP_PKEY *own_key, EVP_PKEY *peer_public, struct s2n_blob *shared_secret);

#if MODERN_EC_SUPPORTED
static int s2n_ecc_evp_generate_key_x25519(const struct s2n_ecc_named_curve *named_curve, EVP_PKEY **evp_pkey) {

    DEFER_CLEANUP(EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(named_curve->libcrypto_nid, NULL),
                  EVP_PKEY_CTX_free_pointer);
    S2N_ERROR_IF(pctx == NULL, S2N_ERR_ECDHE_GEN_KEY);

    GUARD_OSSL(EVP_PKEY_keygen_init(pctx), S2N_ERR_ECDHE_GEN_KEY);
    GUARD_OSSL(EVP_PKEY_keygen(pctx, evp_pkey), S2N_ERR_ECDHE_GEN_KEY);
    S2N_ERROR_IF(evp_pkey == NULL, S2N_ERR_ECDHE_GEN_KEY);

    return 0;
}
#endif

static int s2n_ecc_evp_generate_key_nist_curves(const struct s2n_ecc_named_curve *named_curve, EVP_PKEY **evp_pkey) {

    DEFER_CLEANUP(EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL), EVP_PKEY_CTX_free_pointer);
    S2N_ERROR_IF(pctx == NULL, S2N_ERR_ECDHE_GEN_KEY);

    GUARD_OSSL(EVP_PKEY_paramgen_init(pctx), S2N_ERR_ECDHE_GEN_KEY);
    GUARD_OSSL(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, named_curve->libcrypto_nid), S2N_ERR_ECDHE_GEN_KEY);

    DEFER_CLEANUP(EVP_PKEY *params = NULL, EVP_PKEY_free_pointer);
    GUARD_OSSL(EVP_PKEY_paramgen(pctx, &params), S2N_ERR_ECDHE_GEN_KEY);
    S2N_ERROR_IF(params == NULL, S2N_ERR_ECDHE_GEN_KEY);

    DEFER_CLEANUP(EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL), EVP_PKEY_CTX_free_pointer);
    S2N_ERROR_IF(kctx == NULL, S2N_ERR_ECDHE_GEN_KEY);

    GUARD_OSSL(EVP_PKEY_keygen_init(kctx), S2N_ERR_ECDHE_GEN_KEY);
    GUARD_OSSL(EVP_PKEY_keygen(kctx, evp_pkey), S2N_ERR_ECDHE_GEN_KEY);
    S2N_ERROR_IF(evp_pkey == NULL, S2N_ERR_ECDHE_GEN_KEY);

    return 0;
}

static int s2n_ecc_evp_generate_own_key(const struct s2n_ecc_named_curve *named_curve, EVP_PKEY **evp_pkey) {
#if MODERN_EC_SUPPORTED
    if (named_curve->libcrypto_nid == NID_X25519) {
        return s2n_ecc_evp_generate_key_x25519(named_curve, evp_pkey);
    }
#endif
    if (named_curve->libcrypto_nid == NID_X9_62_prime256v1 || named_curve->libcrypto_nid == NID_secp384r1) {
        return s2n_ecc_evp_generate_key_nist_curves(named_curve, evp_pkey);
    }
    S2N_ERROR(S2N_ERR_ECDHE_GEN_KEY);
}

static int s2n_ecc_evp_compute_shared_secret(EVP_PKEY *own_key, EVP_PKEY *peer_public, struct s2n_blob *shared_secret) {
    size_t shared_secret_size;

    DEFER_CLEANUP(EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(own_key, NULL), EVP_PKEY_CTX_free_pointer);
    S2N_ERROR_IF(ctx == NULL, S2N_ERR_ECDHE_SHARED_SECRET);

    GUARD_OSSL(EVP_PKEY_derive_init(ctx), S2N_ERR_ECDHE_SHARED_SECRET);
    GUARD_OSSL(EVP_PKEY_derive_set_peer(ctx, peer_public), S2N_ERR_ECDHE_SHARED_SECRET);
    GUARD_OSSL(EVP_PKEY_derive(ctx, NULL, &shared_secret_size), S2N_ERR_ECDHE_SHARED_SECRET);
    GUARD(s2n_alloc(shared_secret, shared_secret_size));

    if (EVP_PKEY_derive(ctx, shared_secret->data, &shared_secret_size) != 1) {
        GUARD(s2n_free(shared_secret));
        S2N_ERROR(S2N_ERR_ECDHE_SHARED_SECRET);
    }

    return 0;
}

int s2n_ecc_evp_generate_ephemeral_key(struct s2n_ecc_evp_params *ecc_evp_params) {
    notnull_check(ecc_evp_params->negotiated_curve);
    S2N_ERROR_IF(s2n_ecc_evp_generate_own_key(ecc_evp_params->negotiated_curve, &ecc_evp_params->evp_pkey) != 0,
                 S2N_ERR_ECDHE_GEN_KEY);
    S2N_ERROR_IF(ecc_evp_params->evp_pkey == NULL, S2N_ERR_ECDHE_GEN_KEY);
    return 0;
}

int s2n_ecc_evp_compute_shared_secret_from_params(struct s2n_ecc_evp_params *private_ecc_evp_params,
                                                  struct s2n_ecc_evp_params *public_ecc_evp_params,
                                                  struct s2n_blob *shared_key) {
    notnull_check(private_ecc_evp_params->negotiated_curve);
    notnull_check(private_ecc_evp_params->evp_pkey);
    notnull_check(public_ecc_evp_params->negotiated_curve);
    notnull_check(public_ecc_evp_params->evp_pkey);
    S2N_ERROR_IF(private_ecc_evp_params->negotiated_curve->iana_id != public_ecc_evp_params->negotiated_curve->iana_id,
                 S2N_ERR_ECDHE_UNSUPPORTED_CURVE);
    GUARD(s2n_ecc_evp_compute_shared_secret(private_ecc_evp_params->evp_pkey, public_ecc_evp_params->evp_pkey,
                                            shared_key));
    return 0;
}

int s2n_ecc_evp_params_free(struct s2n_ecc_evp_params *ecc_evp_params) {
    if (ecc_evp_params->evp_pkey != NULL) {
        EVP_PKEY_free(ecc_evp_params->evp_pkey);
        ecc_evp_params->evp_pkey = NULL;
    }
    return 0;
}
