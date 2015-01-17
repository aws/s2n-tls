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

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"

int s2n_pkcs3_to_dh_params(struct s2n_dh_params *dh_params, struct s2n_blob *pkcs3)
{
    uint8_t *original_ptr = pkcs3->data;
    dh_params->dh = d2i_DHparams(NULL, (const unsigned char **)(void *)&pkcs3->data, pkcs3->size);
    if (pkcs3->data - original_ptr != pkcs3->size) {
        DH_free(dh_params->dh);
        S2N_ERROR(S2N_ERR_INVALID_PKCS3);
    }
    pkcs3->data = original_ptr;

    return 0;
}

int s2n_dh_p_g_Ys_to_dh_params(struct s2n_dh_params *server_dh_params, struct s2n_blob *p, struct s2n_blob *g, struct s2n_blob *Ys)
{
    server_dh_params->dh = DH_new();
    if (server_dh_params->dh == NULL) {
        S2N_ERROR(S2N_ERR_DH_PARAMS_CREATE);
    }

    server_dh_params->dh->p = BN_bin2bn((const unsigned char *)p->data, p->size, NULL);
    server_dh_params->dh->g = BN_bin2bn((const unsigned char *)g->data, g->size, NULL);
    server_dh_params->dh->pub_key = BN_bin2bn((const unsigned char *)Ys->data, Ys->size, NULL);

    return 0;
}

int s2n_dh_params_to_p_g_Ys(struct s2n_dh_params *server_dh_params, struct s2n_stuffer *out, struct s2n_blob *output)
{
    uint16_t p_size = BN_num_bytes(server_dh_params->dh->p);
    uint16_t g_size = BN_num_bytes(server_dh_params->dh->g);
    uint16_t Ys_size = BN_num_bytes(server_dh_params->dh->pub_key);
    uint8_t *p;
    uint8_t *g;
    uint8_t *Ys;

    output->data = s2n_stuffer_raw_write(out, 0);
    notnull_check(output->data);

    GUARD(s2n_stuffer_write_uint16(out, p_size));
    p = s2n_stuffer_raw_write(out, p_size);
    notnull_check(p);
    if (BN_bn2bin(server_dh_params->dh->p, p) != p_size) {
        S2N_ERROR(S2N_ERR_DH_SERIAZING);
    }

    GUARD(s2n_stuffer_write_uint16(out, g_size));
    g = s2n_stuffer_raw_write(out, g_size);
    notnull_check(g);
    if (BN_bn2bin(server_dh_params->dh->g, g) != g_size) {
        S2N_ERROR(S2N_ERR_DH_SERIAZING);
    }

    GUARD(s2n_stuffer_write_uint16(out, Ys_size));
    Ys = s2n_stuffer_raw_write(out, Ys_size);
    notnull_check(Ys);
    if (BN_bn2bin(server_dh_params->dh->pub_key, Ys) != Ys_size) {
        S2N_ERROR(S2N_ERR_DH_SERIAZING);
    }

    output->size = p_size + 2 + g_size + 2 + Ys_size + 2;

    return 0;
}

int s2n_dh_compute_shared_secret_as_client(struct s2n_dh_params *server_dh_params, struct s2n_stuffer *Yc, struct s2n_blob *shared_key)
{
    struct s2n_dh_params client_params;
    uint8_t *public_key;
    uint16_t public_key_size;
    int shared_key_size;

    GUARD(s2n_dh_params_copy(server_dh_params, &client_params));
    GUARD(s2n_dh_generate_ephemeral_key(&client_params));

    GUARD(s2n_alloc(shared_key, DH_size(server_dh_params->dh)));

    public_key_size = BN_num_bytes(client_params.dh->pub_key);
    GUARD(s2n_stuffer_write_uint16(Yc, public_key_size));
    public_key = s2n_stuffer_raw_write(Yc, public_key_size);
    if (public_key == NULL) {
        S2N_ERROR(S2N_ERR_DH_WRITING_PUBLIC_KEY);
    }

    if (BN_bn2bin(client_params.dh->pub_key, public_key) != public_key_size) {
        S2N_ERROR(S2N_ERR_DH_COPYING_PUBLIC_KEY);
    }

    shared_key_size = DH_compute_key(shared_key->data, server_dh_params->dh->pub_key, client_params.dh);
    if (shared_key_size < 0) {
        S2N_ERROR(S2N_ERR_DH_SHARED_SECRET);
    }

    shared_key->size = shared_key_size;

    GUARD(s2n_dh_params_free(&client_params));

    return 0;
}

int s2n_dh_compute_shared_secret_as_server(struct s2n_dh_params *server_dh_params, struct s2n_blob *Yc, struct s2n_blob *shared_key)
{
    int shared_key_size;
    BIGNUM *pub_key;

    pub_key = BN_bin2bn((const unsigned char *)Yc->data, Yc->size, NULL);
    notnull_check(pub_key);
    GUARD(s2n_alloc(shared_key, DH_size(server_dh_params->dh)));

    shared_key_size = DH_compute_key(shared_key->data, pub_key, server_dh_params->dh);
    if (shared_key_size < 0) {
        BN_free(pub_key);
        S2N_ERROR(S2N_ERR_DH_SHARED_SECRET);
    }

    shared_key->size = shared_key_size;

    BN_free(pub_key);

    return 0;
}

int s2n_dh_params_copy(struct s2n_dh_params *from, struct s2n_dh_params *to)
{
    to->dh = DHparams_dup(from->dh);
    if (to->dh == NULL) {
        S2N_ERROR(S2N_ERR_DH_COPYING_PARAMETERS);
    }

    return 0;
}

int s2n_dh_generate_ephemeral_key(struct s2n_dh_params *dh_params)
{
    if (DH_generate_key(dh_params->dh) == 0) {
        S2N_ERROR(S2N_ERR_DH_GENERATING_PARAMETERS);
    }

    return 0;
}

int s2n_dh_params_free(struct s2n_dh_params *dh_params)
{
    DH_free(dh_params->dh);
    dh_params->dh = NULL;

    return 0;
}
