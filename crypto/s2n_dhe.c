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

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_dhe.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"

int s2n_pkcs3_to_dh_params(struct s2n_dh_params *dh_params, struct s2n_blob *pkcs3, const char **err)
{
    uint8_t *original_ptr = pkcs3->data;
    dh_params->dh = d2i_DHparams(NULL, (const unsigned char **)(void *)&pkcs3->data, pkcs3->size);
    if (pkcs3->data - original_ptr != pkcs3->size) {
        *err = "Extraneous data in DH params PKCS3";
        DH_free(dh_params->dh);
        return -1;
    }
    pkcs3->data = original_ptr;

    return 0;
}

int s2n_dh_p_g_Ys_to_dh_params(struct s2n_dh_params *server_dh_params, struct s2n_blob *p, struct s2n_blob *g, struct s2n_blob *Ys, const char **err)
{
    server_dh_params->dh = DH_new();
    if (server_dh_params->dh == NULL) {
        *err = "Failed to create new DH params";
        return -1;
    }

    server_dh_params->dh->p = BN_bin2bn((const unsigned char *)p->data, p->size, NULL);
    server_dh_params->dh->g = BN_bin2bn((const unsigned char *)g->data, g->size, NULL);
    server_dh_params->dh->pub_key = BN_bin2bn((const unsigned char *)Ys->data, Ys->size, NULL);

    return 0;
}

int s2n_dh_params_to_p_g_Ys(struct s2n_dh_params *server_dh_params, struct s2n_stuffer *out, struct s2n_blob *output, const char **err)
{
    uint16_t p_size = BN_num_bytes(server_dh_params->dh->p);
    uint16_t g_size = BN_num_bytes(server_dh_params->dh->g);
    uint16_t Ys_size = BN_num_bytes(server_dh_params->dh->pub_key);
    uint8_t *p;
    uint8_t *g;
    uint8_t *Ys;

    output->data = s2n_stuffer_raw_write(out, 0, err);
    notnull_check(output->data);

    GUARD(s2n_stuffer_write_uint16(out, p_size, err));
    p = s2n_stuffer_raw_write(out, p_size, err);
    notnull_check(p);
    if (BN_bn2bin(server_dh_params->dh->p, p) != p_size) {
        *err = "Error serializing diffie hellman values";
        return -1;
    }

    GUARD(s2n_stuffer_write_uint16(out, g_size, err));
    g = s2n_stuffer_raw_write(out, g_size, err);
    notnull_check(g);
    if (BN_bn2bin(server_dh_params->dh->g, g) != g_size) {
        *err = "Error serializing diffie hellman values";
        return -1;
    }

    GUARD(s2n_stuffer_write_uint16(out, Ys_size, err));
    Ys = s2n_stuffer_raw_write(out, Ys_size, err);
    notnull_check(Ys);
    if (BN_bn2bin(server_dh_params->dh->pub_key, Ys) != Ys_size) {
        *err = "Error serializing diffie hellman values";
        return -1;
    }

    output->size = p_size + 2 + g_size + 2 + Ys_size + 2;

    return 0;
}

int s2n_dh_compute_shared_secret_as_client(struct s2n_dh_params *server_dh_params, struct s2n_stuffer *Yc, struct s2n_blob *shared_key, const char **err)
{
    struct s2n_dh_params client_params;
    uint8_t *public_key;
    uint16_t public_key_size;
    int shared_key_size;

    GUARD(s2n_dh_params_copy(server_dh_params, &client_params, err));
    GUARD(s2n_dh_generate_ephemeral_key(&client_params, err));

    GUARD(s2n_alloc(shared_key, DH_size(server_dh_params->dh), err));

    public_key_size = BN_num_bytes(client_params.dh->pub_key);
    GUARD(s2n_stuffer_write_uint16(Yc, public_key_size, err));
    public_key = s2n_stuffer_raw_write(Yc, public_key_size, err);
    if (public_key == NULL) {
        *err = "Error writing Diffie Hellman public key";
        return -1;
    }

    if (BN_bn2bin(client_params.dh->pub_key, public_key) != public_key_size) {
        *err = "Error copying Diffie Hellman public key";
        return -1;
    }

    shared_key_size = DH_compute_key(shared_key->data, server_dh_params->dh->pub_key, client_params.dh);
    if (shared_key_size < 0) {
        *err = "Error computing Diffie Hellman shared secret";
        return -1;
    }

    shared_key->size = shared_key_size;

    GUARD(s2n_dh_params_free(&client_params, err));

    return 0;
}

int s2n_dh_compute_shared_secret_as_server(struct s2n_dh_params *server_dh_params, struct s2n_blob *Yc, struct s2n_blob *shared_key, const char **err)
{
    int shared_key_size;
    BIGNUM *pub_key;

    pub_key = BN_bin2bn((const unsigned char *)Yc->data, Yc->size, NULL);
    notnull_check(pub_key);
    GUARD(s2n_alloc(shared_key, DH_size(server_dh_params->dh), err));

    shared_key_size = DH_compute_key(shared_key->data, pub_key, server_dh_params->dh);
    if (shared_key_size < 0) {
        *err = "Error computing Diffie Hellman shared secret";
        BN_free(pub_key);
        return -1;
    }

    shared_key->size = shared_key_size;

    BN_free(pub_key);

    return 0;
}

int s2n_dh_params_copy(struct s2n_dh_params *from, struct s2n_dh_params *to, const char **err)
{
    to->dh = DHparams_dup(from->dh);
    if (to->dh == NULL) {
        *err = "Failed to copy DH parameters";
        return -1;
    }

    return 0;
}

int s2n_dh_generate_ephemeral_key(struct s2n_dh_params *dh_params, const char **err)
{
    if (DH_generate_key(dh_params->dh) == 0) {
        *err = "Failed to generated ephemeral DH key";
        return -1;
    }

    return 0;
}

int s2n_dh_params_free(struct s2n_dh_params *dh_params, const char **err)
{
    DH_free(dh_params->dh);
    dh_params->dh = NULL;

    return 0;
}
