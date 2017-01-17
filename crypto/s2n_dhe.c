/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <stdint.h>

#include "error/s2n_errno.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_dhe.h"
#include "crypto/s2n_openssl.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"

#define S2N_MIN_DH_PRIME_SIZE_BYTES (2048 / 8)

/* Caller is not responsible for freeing values returned by these accessors
 * Per https://www.openssl.org/docs/man1.1.0/crypto/DH_get0_pqg.html
 */
static const BIGNUM *s2n_get_Ys_dh_param(struct s2n_dh_params *dh_params)
{
    const BIGNUM *Ys;

    /* DH made opaque in Openssl 1.1.0 */
    #if S2N_OPENSSL_VERSION_AT_LEAST(1,1,0) && !defined(LIBRESSL_VERSION_NUMBER)
        DH_get0_key(dh_params->dh, &Ys, NULL);
    #else
        Ys = dh_params->dh->pub_key;
    #endif

    return Ys;
}

static const BIGNUM *s2n_get_p_dh_param(struct s2n_dh_params *dh_params)
{
    const BIGNUM *p;
    #if S2N_OPENSSL_VERSION_AT_LEAST(1,1,0) && !defined(LIBRESSL_VERSION_NUMBER)
        DH_get0_pqg(dh_params->dh, &p, NULL, NULL);
    #else
        p = dh_params->dh->p;
    #endif

    return p;
}

static const BIGNUM *s2n_get_g_dh_param(struct s2n_dh_params *dh_params)
{
    const BIGNUM *g;
    #if S2N_OPENSSL_VERSION_AT_LEAST(1,1,0) && !defined(LIBRESSL_VERSION_NUMBER)
        DH_get0_pqg(dh_params->dh, NULL, NULL, &g);
    #else
        g = dh_params->dh->g;
    #endif

    return g;
}

static int s2n_check_p_g_dh_params(struct s2n_dh_params *dh_params)
{
    notnull_check(dh_params);
    notnull_check(dh_params->dh);

    const BIGNUM *p = s2n_get_p_dh_param(dh_params);
    const BIGNUM *g = s2n_get_g_dh_param(dh_params);

    notnull_check(g);
    notnull_check(p);

    if (DH_size(dh_params->dh) < S2N_MIN_DH_PRIME_SIZE_BYTES) {
        S2N_ERROR(S2N_ERR_DH_PARAMS_CREATE);
    }

    if (BN_is_zero(g)) {
        S2N_ERROR(S2N_ERR_DH_PARAMS_CREATE);
    }

    if (BN_is_zero(p)) {
        S2N_ERROR(S2N_ERR_DH_PARAMS_CREATE);
    }

    return 0;
}

static int s2n_check_pub_key_dh_params(struct s2n_dh_params *dh_params)
{
    const BIGNUM *pub_key = s2n_get_Ys_dh_param(dh_params);

    notnull_check(pub_key);

    if (BN_is_zero(pub_key)) {
        S2N_ERROR(S2N_ERR_DH_PARAMS_CREATE);
    }

    return 0;
}

static int s2n_set_p_g_Ys_dh_params(struct s2n_dh_params *dh_params, struct s2n_blob *p, struct s2n_blob *g, struct s2n_blob *Ys)
{
    BIGNUM *bn_p = BN_bin2bn((const unsigned char *)p->data, p->size, NULL);
    BIGNUM *bn_g = BN_bin2bn((const unsigned char *)g->data, g->size, NULL);
    BIGNUM *bn_Ys = BN_bin2bn((const unsigned char *)Ys->data, Ys->size, NULL);

    #if S2N_OPENSSL_VERSION_AT_LEAST(1,1,0) && !defined(LIBRESSL_VERSION_NUMBER)
        if (DH_set0_pqg(dh_params->dh, bn_p, NULL, bn_g) == 0) {
            /* Per https://www.openssl.org/docs/man1.1.0/crypto/DH_get0_pqg.html:
             * values that have been passed in should not be freed directly after this function has been called
             */
            S2N_ERROR(S2N_ERR_DH_PARAMS_CREATE);
        }

        if (DH_set0_key(dh_params->dh, bn_Ys, NULL) == 0) {
            /* Same as DH_set0_pqg */
            S2N_ERROR(S2N_ERR_DH_PARAMS_CREATE);
        }
    #else
        dh_params->dh->p = bn_p;
        dh_params->dh->g = bn_g;
        dh_params->dh->pub_key = bn_Ys;
    #endif

    return 0;
}

int s2n_check_all_dh_params(struct s2n_dh_params *dh_params)
{
    GUARD(s2n_check_p_g_dh_params(dh_params));
    GUARD(s2n_check_pub_key_dh_params(dh_params));

    return 0;
}

int s2n_pkcs3_to_dh_params(struct s2n_dh_params *dh_params, struct s2n_blob *pkcs3)
{
    uint8_t *original_ptr = pkcs3->data;
    dh_params->dh = d2i_DHparams(NULL, (const unsigned char **)(void *)&pkcs3->data, pkcs3->size);
    GUARD(s2n_check_p_g_dh_params(dh_params));
    if (pkcs3->data - original_ptr != pkcs3->size) {
        DH_free(dh_params->dh);
        S2N_ERROR(S2N_ERR_INVALID_PKCS3);
    }
    pkcs3->data = original_ptr;

    /* Require at least 2048 bits for the DH size */
    if (DH_size(dh_params->dh) < S2N_MIN_DH_PRIME_SIZE_BYTES) {
        DH_free(dh_params->dh);
        S2N_ERROR(S2N_ERR_DH_TOO_SMALL);
    }

    /* Check the generator and prime */
    GUARD(s2n_dh_params_check(dh_params));

    return 0;
}

int s2n_dh_p_g_Ys_to_dh_params(struct s2n_dh_params *server_dh_params, struct s2n_blob *p, struct s2n_blob *g, struct s2n_blob *Ys)
{
    server_dh_params->dh = DH_new();
    if (server_dh_params->dh == NULL) {
        S2N_ERROR(S2N_ERR_DH_PARAMS_CREATE);
    }

    GUARD(s2n_set_p_g_Ys_dh_params(server_dh_params, p, g, Ys));
    GUARD(s2n_check_all_dh_params(server_dh_params));

    return 0;
}

int s2n_dh_params_to_p_g_Ys(struct s2n_dh_params *server_dh_params, struct s2n_stuffer *out, struct s2n_blob *output)
{
    GUARD(s2n_check_all_dh_params(server_dh_params));

    const BIGNUM *bn_p = s2n_get_p_dh_param(server_dh_params);
    const BIGNUM *bn_g = s2n_get_g_dh_param(server_dh_params);
    const BIGNUM *bn_Ys = s2n_get_Ys_dh_param(server_dh_params);

    uint16_t p_size = BN_num_bytes(bn_p);
    uint16_t g_size = BN_num_bytes(bn_g);
    uint16_t Ys_size = BN_num_bytes(bn_Ys);
    uint8_t *p;
    uint8_t *g;
    uint8_t *Ys;

    output->data = s2n_stuffer_raw_write(out, 0);
    notnull_check(output->data);

    GUARD(s2n_stuffer_write_uint16(out, p_size));
    p = s2n_stuffer_raw_write(out, p_size);
    notnull_check(p);
    if (BN_bn2bin(bn_p, p) != p_size) {
        S2N_ERROR(S2N_ERR_DH_SERIALIZING);
    }

    GUARD(s2n_stuffer_write_uint16(out, g_size));
    g = s2n_stuffer_raw_write(out, g_size);
    notnull_check(g);
    if (BN_bn2bin(bn_g, g) != g_size) {
        S2N_ERROR(S2N_ERR_DH_SERIALIZING);
    }

    GUARD(s2n_stuffer_write_uint16(out, Ys_size));
    Ys = s2n_stuffer_raw_write(out, Ys_size);
    notnull_check(Ys);
    if (BN_bn2bin(bn_Ys, Ys) != Ys_size) {
        S2N_ERROR(S2N_ERR_DH_SERIALIZING);
    }

    output->size = p_size + 2 + g_size + 2 + Ys_size + 2;

    return 0;
}

int s2n_dh_compute_shared_secret_as_client(struct s2n_dh_params *server_dh_params, struct s2n_stuffer *Yc_out, struct s2n_blob *shared_key)
{
    struct s2n_dh_params client_params;
    uint8_t *client_pub_key;
    uint16_t client_pub_key_size;
    int shared_key_size;

    GUARD(s2n_dh_params_check(server_dh_params));
    GUARD(s2n_dh_params_copy(server_dh_params, &client_params));
    GUARD(s2n_dh_generate_ephemeral_key(&client_params));
    GUARD(s2n_alloc(shared_key, DH_size(server_dh_params->dh)));

    const BIGNUM *client_pub_key_bn = s2n_get_Ys_dh_param(&client_params);
    client_pub_key_size = BN_num_bytes(client_pub_key_bn);
    GUARD(s2n_stuffer_write_uint16(Yc_out, client_pub_key_size));
    client_pub_key = s2n_stuffer_raw_write(Yc_out, client_pub_key_size);
    if (client_pub_key == NULL) {
        GUARD(s2n_free(shared_key));
        GUARD(s2n_dh_params_free(&client_params));
        S2N_ERROR(S2N_ERR_DH_WRITING_PUBLIC_KEY);
    }

    if (BN_bn2bin(client_pub_key_bn, client_pub_key) != client_pub_key_size) {
        GUARD(s2n_free(shared_key));
        GUARD(s2n_dh_params_free(&client_params));
        S2N_ERROR(S2N_ERR_DH_COPYING_PUBLIC_KEY);
    }

    /* server_dh_params already validated */
    const BIGNUM *server_pub_key_bn = s2n_get_Ys_dh_param(server_dh_params);
    shared_key_size = DH_compute_key(shared_key->data, server_pub_key_bn, client_params.dh);
    if (shared_key_size < 0) {
        GUARD(s2n_free(shared_key));
        GUARD(s2n_dh_params_free(&client_params));
        S2N_ERROR(S2N_ERR_DH_SHARED_SECRET);
    }

    shared_key->size = shared_key_size;

    GUARD(s2n_dh_params_free(&client_params));

    return 0;
}

int s2n_dh_compute_shared_secret_as_server(struct s2n_dh_params *server_dh_params, struct s2n_stuffer *Yc_in, struct s2n_blob *shared_key)
{
    uint16_t Yc_length;
    struct s2n_blob Yc;
    int shared_key_size;
    BIGNUM *pub_key;

    GUARD(s2n_check_all_dh_params(server_dh_params));

    GUARD(s2n_stuffer_read_uint16(Yc_in, &Yc_length));
    Yc.size = Yc_length;
    Yc.data = s2n_stuffer_raw_read(Yc_in, Yc.size);
    notnull_check(Yc.data);

    pub_key = BN_bin2bn((const unsigned char *)Yc.data, Yc.size, NULL);
    notnull_check(pub_key);
    GUARD(s2n_alloc(shared_key, DH_size(server_dh_params->dh)));

    shared_key_size = DH_compute_key(shared_key->data, pub_key, server_dh_params->dh);
    if (shared_key_size <= 0) {
        BN_free(pub_key);
        S2N_ERROR(S2N_ERR_DH_SHARED_SECRET);
    }

    shared_key->size = shared_key_size;

    BN_free(pub_key);

    return 0;
}

int s2n_dh_params_check(struct s2n_dh_params *params)
{
    int codes = 0;

    if (DH_check(params->dh, &codes) == 0) {
        S2N_ERROR(S2N_ERR_DH_PARAMETER_CHECK);
    }

    if (codes != 0) {
        S2N_ERROR(S2N_ERR_DH_PARAMETER_CHECK);
    }

    return 0;
}

int s2n_dh_params_copy(struct s2n_dh_params *from, struct s2n_dh_params *to)
{
    GUARD(s2n_check_p_g_dh_params(from));

    to->dh = DHparams_dup(from->dh);
    if (to->dh == NULL) {
        S2N_ERROR(S2N_ERR_DH_COPYING_PARAMETERS);
    }

    return 0;
}

int s2n_dh_generate_ephemeral_key(struct s2n_dh_params *dh_params)
{
    GUARD(s2n_check_p_g_dh_params(dh_params));

    if (DH_generate_key(dh_params->dh) == 0) {
        S2N_ERROR(S2N_ERR_DH_GENERATING_PARAMETERS);
    }

    return 0;
}

int s2n_dh_params_free(struct s2n_dh_params *dh_params)
{
    notnull_check(dh_params);
    DH_free(dh_params->dh);
    dh_params->dh = NULL;

    return 0;
}
