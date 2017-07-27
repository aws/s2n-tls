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

#include <s2n.h>

#include "error/s2n_errno.h"

#include "tls/s2n_client_extensions.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_config.h"
#include "tls/s2n_tls.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"


int s2n_client_cert_verify_recv(struct s2n_connection *conn)
{
    struct s2n_stuffer *in = &conn->handshake.io;

    s2n_hash_algorithm chosen_hash_alg = S2N_HASH_MD5_SHA1;
    s2n_signature_algorithm chosen_signature_alg = S2N_SIGNATURE_RSA;

    if(conn->actual_protocol_version == S2N_TLS12){
        int pairs_available = 1;
        /* Make sure the client is actually using one of the {sig,hash} pairs that we sent in the ClientCertificateRequest */
        GUARD(s2n_choose_preferred_signature_hash_pair(in, pairs_available, &chosen_hash_alg, &chosen_signature_alg));
    }

    uint16_t signature_size;
    struct s2n_blob signature;
    GUARD(s2n_stuffer_read_uint16(in, &signature_size));
    signature.size = signature_size;
    signature.data = s2n_stuffer_raw_read(in, signature.size);
    notnull_check(signature.data);

    struct s2n_hash_state hash_state;
    GUARD(s2n_handshake_get_hash_state(conn, chosen_hash_alg, &hash_state));

    switch (chosen_signature_alg) {
    /* s2n currently only supports RSA Signatures */
    case S2N_SIGNATURE_RSA:
        GUARD(s2n_rsa_verify(&conn->secure.client_rsa_public_key, &hash_state, &signature));
        break;
    default:
        S2N_ERROR(S2N_ERR_INVALID_SIGNATURE_ALGORITHM);
    }

    return 0;
}


int s2n_client_cert_verify_send(struct s2n_connection *conn)
{
    struct s2n_stuffer *out = &conn->handshake.io;

    s2n_hash_algorithm chosen_hash_alg = S2N_HASH_MD5_SHA1;
    s2n_signature_algorithm chosen_signature_alg = S2N_SIGNATURE_RSA;

    if(conn->actual_protocol_version == S2N_TLS12){
        chosen_hash_alg = conn->secure.client_cert_hash_algorithm;
        chosen_signature_alg = conn->secure.client_cert_sig_alg;

        GUARD(s2n_stuffer_write_uint8(out, (uint8_t) chosen_hash_alg));
        GUARD(s2n_stuffer_write_uint8(out, (uint8_t) chosen_signature_alg));
    }

    struct s2n_hash_state hash_state;
    GUARD(s2n_handshake_get_hash_state(conn, chosen_hash_alg, &hash_state));

    struct s2n_blob signature;

    switch (chosen_signature_alg) {
    /* s2n currently only supports RSA Signatures */
    case S2N_SIGNATURE_RSA:
        signature.size = s2n_rsa_private_encrypted_size(&conn->config->cert_and_key_pairs->private_key);
        GUARD(s2n_stuffer_write_uint16(out, signature.size));

        signature.data = s2n_stuffer_raw_write(out, signature.size);
        notnull_check(signature.data);
        GUARD(s2n_rsa_sign(&conn->config->cert_and_key_pairs->private_key, &hash_state, &signature));
        break;
    default:
        S2N_ERROR(S2N_ERR_INVALID_SIGNATURE_ALGORITHM);
    }

    return 0;
}
