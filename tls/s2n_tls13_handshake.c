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

#include "tls/s2n_tls13_handshake.h"

int s2n_tls13_mac_verify(struct s2n_tls13_keys *keys, struct s2n_blob *finished_verify, struct s2n_blob *wire_verify)
{
    notnull_check(wire_verify->data);
    eq_check(wire_verify->size, keys->size);

    S2N_ERROR_IF(!s2n_constant_time_equals(finished_verify->data, wire_verify->data, keys->size), S2N_ERR_BAD_MESSAGE);

    return 0;
}

/*
 * Initalizes the tls13_keys struct
 */
static int s2n_tls13_keys_init_with_ref(struct s2n_tls13_keys *handshake, s2n_hmac_algorithm alg, uint8_t * extract,  uint8_t * derive)
{
    notnull_check(handshake);

    handshake->hmac_algorithm = alg;
    GUARD(s2n_hmac_hash_alg(alg, &handshake->hash_algorithm));
    GUARD(s2n_hash_digest_size(handshake->hash_algorithm, &handshake->size));
    GUARD(s2n_blob_init(&handshake->extract_secret, extract, handshake->size));
    GUARD(s2n_blob_init(&handshake->derive_secret, derive, handshake->size));
    GUARD(s2n_hmac_new(&handshake->hmac));

    return 0;
}

int s2n_tls13_keys_from_conn(struct s2n_tls13_keys *keys, struct s2n_connection *conn)
{
    GUARD(s2n_tls13_keys_init_with_ref(keys, conn->secure.cipher_suite->tls12_prf_alg, conn->secure.rsa_premaster_secret, conn->secure.master_secret));

    return 0;
}
