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

#include "crypto/s2n_ecc_x25519.h"

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ecdh.h>
#include <openssl/obj_mac.h>
#include <stdint.h>

#include "tls/s2n_tls_parameters.h"
#include "tls/s2n_kex.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_mem.h"

/* IANA values can be found here: https://tools.ietf.org/html/rfc8446#appendix-B.3.1.4 */
/* Share sizes are described here: https://tools.ietf.org/html/rfc8446#section-4.2.8.2
 * and include the extra "legacy_form" byte */
const struct s2n_ecc_named_curve s2n_X25519 = {
    .iana_id = TLS_EC_CURVE_ECDH_X25519, .libcrypto_nid = NID_X25519, .name = "x25519", .share_size = 32};

const struct s2n_ecc_named_curve s2n_ecc_evp_supported_curves[S2N_ECC_EVP_SUPPORTED_CURVES_COUNT] = {
    {.iana_id = TLS_EC_CURVE_SECP_256_R1, .libcrypto_nid = NID_X9_62_prime256v1, .name = "secp256r1", .share_size = (32 * 2) + 1},
    {.iana_id = TLS_EC_CURVE_SECP_384_R1, .libcrypto_nid = NID_secp384r1, .name = "secp384r1", .share_size = (48 * 2) + 1},
    {.iana_id = TLS_EC_CURVE_ECDH_X25519, .libcrypto_nid = NID_X25519, .name = "x25519", .share_size = 32},
};

static EVP_PKEY *s2n_ecc_evp_generate_own_key(const struct s2n_ecc_named_curve *named_curve);
static int s2n_ecc_evp_compute_shared_secret(EVP_PKEY *own_key, EVP_PKEY *peer_public, struct s2n_blob *shared_secret);

static EVP_PKEY *s2n_ecc_evp_generate_own_key(const struct s2n_ecc_named_curve *named_curve)
{
    EVP_PKEY *evp_pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *params = NULL;

    if (named_curve->libcrypto_nid == NID_X25519)
    {
        pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL);
        if (pctx == NULL)
            goto err1;
        if (EVP_PKEY_keygen_init(pctx) != 1)
            goto err1;
        if (EVP_PKEY_keygen(pctx, &evp_pkey) != 1)
            goto err1;

        EVP_PKEY_CTX_free(pctx);
        return evp_pkey;
    err1:
        if (pctx != NULL)
            EVP_PKEY_CTX_free(pctx);
        S2N_ERROR_PTR(S2N_ERR_ECDHE_GEN_KEY);
    }
    else
    {
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (pctx == NULL)
            goto err2;
        if (EVP_PKEY_paramgen_init(pctx) != 1)
            goto err2;
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, named_curve->libcrypto_nid) != 1)
            goto err2;
        if (!EVP_PKEY_paramgen(pctx, &params))
            goto err2;
        kctx = EVP_PKEY_CTX_new(params, NULL);
        if (kctx == NULL)
            goto err2;
        if (EVP_PKEY_keygen_init(kctx) != 1)
            goto err2;
        if (EVP_PKEY_keygen(kctx, &evp_pkey) != 1)
            goto err2;

        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_CTX_free(kctx);
        EVP_PKEY_free(params);
        return evp_pkey;
    err2:
        if (pctx != NULL)
            EVP_PKEY_CTX_free(pctx);
        if (kctx != NULL)
            EVP_PKEY_CTX_free(kctx);
        if (params != NULL)
            EVP_PKEY_free(params);
        S2N_ERROR_PTR(S2N_ERR_ECDHE_GEN_KEY);
    }
}

static int s2n_ecc_evp_compute_shared_secret(EVP_PKEY *own_key, EVP_PKEY *peer_public, struct s2n_blob *shared_secret)
{
    EVP_PKEY_CTX *ctx = NULL;
    size_t shared_secret_size;

    ctx = EVP_PKEY_CTX_new(own_key, NULL);
    if (ctx == NULL)
        goto err;
    if (EVP_PKEY_derive_init(ctx) != 1)
        goto err;
    if (EVP_PKEY_derive_set_peer(ctx, peer_public) != 1)
        goto err;
    if (EVP_PKEY_derive(ctx, NULL, &shared_secret_size) != 1)
        goto err;
    GUARD(s2n_alloc(shared_secret, shared_secret_size));
    if (EVP_PKEY_derive(ctx, shared_secret->data, &shared_secret_size) != 1)
        goto err;
    EVP_PKEY_CTX_free(ctx);
    return 0;

err:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    S2N_ERROR(S2N_ERR_ECDHE_SHARED_SECRET);
}

int s2n_ecc_evp_generate_ephemeral_key(struct s2n_ecc_evp_params *ecc_evp_params)
{
    notnull_check(ecc_evp_params->negotiated_curve);
    ecc_evp_params->evp_pkey = s2n_ecc_evp_generate_own_key(ecc_evp_params->negotiated_curve);
    S2N_ERROR_IF(ecc_evp_params->evp_pkey == NULL, S2N_ERR_ECDHE_GEN_KEY);
    return 0;
}

int s2n_ecc_evp_compute_shared_secret_as_server(struct s2n_ecc_evp_params *ecc_evp_params, struct s2n_blob *Yc_in, struct s2n_blob *shared_key)
{
    EVP_PKEY *client_key = EVP_PKEY_new();

    /* Copy EVP_PKEY Paramaters */
    S2N_ERROR_IF(client_key == NULL, S2N_ERR_ECDHE_GEN_KEY);
    S2N_ERROR_IF(EVP_PKEY_copy_parameters(client_key, ecc_evp_params->evp_pkey) != 1, S2N_ERR_ECDHE_SERIALIZING);

    /* Decode the client public obtained from the wire*/
    S2N_ERROR_IF(Yc_in->size != ecc_evp_params->negotiated_curve->share_size, S2N_ERR_ECDHE_SERIALIZING);
    S2N_ERROR_IF(1 != EVP_PKEY_set1_tls_encodedpoint(client_key, Yc_in->data, Yc_in->size), S2N_ERR_ECDHE_SERIALIZING);
    S2N_ERROR_IF(client_key == NULL, S2N_ERR_ECDHE_SERIALIZING);

    /* Compute the key and free the point */
    if (s2n_ecc_evp_compute_shared_secret(ecc_evp_params->evp_pkey, client_key, shared_key) != 0)
    {

        EVP_PKEY_free(client_key);
        S2N_ERROR(S2N_ERR_ECDHE_SHARED_SECRET);
    }

    EVP_PKEY_free(client_key);
    return 0;
}

int s2n_ecc_evp_compute_shared_secret_as_client(struct s2n_ecc_evp_params *ecc_evp_params, struct s2n_blob *Yc_out, struct s2n_blob *shared_key)
{
    EVP_PKEY *client_key;

    /* Generate the client key */
    notnull_check(ecc_evp_params->negotiated_curve);
    client_key = s2n_ecc_evp_generate_own_key(ecc_evp_params->negotiated_curve);
    S2N_ERROR_IF(client_key == NULL, S2N_ERR_ECDHE_GEN_KEY);

    /* Encode the client public to send across wire */
    Yc_out->size = EVP_PKEY_get1_tls_encodedpoint(client_key, &Yc_out->data);
    S2N_ERROR_IF(Yc_out->size != ecc_evp_params->negotiated_curve->share_size, S2N_ERR_ECDHE_SERIALIZING);

    /* Compute the shared secret */
    if (s2n_ecc_evp_compute_shared_secret(client_key, ecc_evp_params->evp_pkey, shared_key) != 0)
    {
        EVP_PKEY_free(client_key);
        S2N_ERROR(S2N_ERR_ECDHE_SHARED_SECRET);
    }

    EVP_PKEY_free(client_key);
    return 0;
}

int s2n_ecc_evp_params_free(struct s2n_ecc_evp_params *ecc_evp_params)
{
    if (ecc_evp_params->evp_pkey != NULL)
    {
        EVP_PKEY_free(ecc_evp_params->evp_pkey);
        ecc_evp_params->evp_pkey = NULL;
    }

    return 0;
}
