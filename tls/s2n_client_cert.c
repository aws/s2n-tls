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

    if (client_cert_chain.size > s2n_stuffer_data_available(in)) {
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    if (client_cert_chain.size == 0) {
        GUARD(s2n_conn_set_handshake_no_client_cert(conn));
        return 0;
    }

    client_cert_chain.data = s2n_stuffer_raw_read(in, client_cert_chain.size);
    notnull_check(client_cert_chain.data);

    s2n_cert_public_key public_key;
    GUARD(s2n_pkey_zero_init(&public_key));
    
    s2n_cert_type cert_type;

    /* Determine the Cert Type, Verify the Cert, and extract the Public Key */
    const s2n_cert_validation_code rc = conn->config->verify_cert_chain_cb(conn, client_cert_chain.data, client_cert_chain.size,
            &cert_type, &public_key, conn->config->verify_cert_context);

    if (rc != S2N_CERT_OK) {
        /* Don't use GUARD for verify_cert_chain_cb so that s2n_errno is set. */
        S2N_ERROR(S2N_ERR_CERT_UNTRUSTED);
    }

    switch (cert_type) {
    /* s2n currently only supports RSA Certificates */
    case S2N_CERT_TYPE_RSA_SIGN:
        GUARD(s2n_rsa_check_key_exists(&public_key));
        GUARD(s2n_pkey_setup_for_type(&public_key, cert_type));
        conn->secure.client_cert_type = S2N_CERT_TYPE_RSA_SIGN;
        s2n_dup(&client_cert_chain, &conn->secure.client_cert_chain);
        conn->secure.client_public_key = public_key;
        break;
    default:
        S2N_ERROR(S2N_ERR_CERT_TYPE_UNSUPPORTED);
    }

    return 0;
}


int s2n_client_cert_send(struct s2n_connection *conn)
{
    struct s2n_cert_chain_and_key *chain_and_key = conn->config->cert_and_key_pairs;
    /* TODO: Check that RSA is in conn->server_preferred_cert_types and conn->secure.client_cert_sig_algorithm */

    if (chain_and_key == NULL) {
        GUARD(s2n_conn_set_handshake_no_client_cert(conn));
        GUARD(s2n_send_empty_cert_chain(&conn->handshake.io));
        return 0;
    }

    GUARD(s2n_send_cert_chain(&conn->handshake.io, &chain_and_key->cert_chain));
    return 0;
}
