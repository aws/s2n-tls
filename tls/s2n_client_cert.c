/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "crypto/s2n_certificate.h"
#include "error/s2n_errno.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_config.h"
#include "tls/s2n_tls.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"


int s2n_client_cert_recv(struct s2n_connection *conn)
{
    struct s2n_stuffer *in = &conn->handshake.io;
    struct s2n_blob client_cert_chain;

    GUARD(s2n_stuffer_read_uint24(in, &client_cert_chain.size));

    if (client_cert_chain.size > s2n_stuffer_data_available(in) || client_cert_chain.size == 0) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    client_cert_chain.data = s2n_stuffer_raw_read(in, client_cert_chain.size);
    notnull_check(client_cert_chain.data);

    struct s2n_cert_public_key cert_public_key;

    /* Determine the Cert Type, Verify the Cert, and extract the Public Key */
    GUARD(conn->verify_cert_chain_cb(client_cert_chain.data, client_cert_chain.size, &cert_public_key, conn->verify_cert_context));

    switch (cert_public_key.cert_type) {
    /* s2n currently only supports RSA Certificates */
    case S2N_CERT_TYPE_RSA_SIGN:
        notnull_check(cert_public_key.public_key.rsa.rsa);
        conn->secure.client_cert_type = S2N_CERT_TYPE_RSA_SIGN;
        s2n_dup(&client_cert_chain, &conn->secure.client_cert_chain);
        conn->secure.client_rsa_public_key.rsa = cert_public_key.public_key.rsa.rsa;
        break;
    default:
        S2N_ERROR(S2N_ERR_CERT_TYPE_UNSUPPORTED);
    }

    return 0;
}


int s2n_client_cert_send(struct s2n_connection *conn)
{
    struct s2n_cert_chain_and_key *chain = conn->config->cert_and_key_pairs;
    /* TODO: Check that RSA is in conn->server_preferred_cert_types and conn->secure.client_cert_sig_algorithm */

    GUARD(s2n_send_cert_chain(&conn->handshake.io, chain));
    return 0;
}
