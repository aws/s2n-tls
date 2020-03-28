/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
    struct s2n_blob client_cert_chain = {0};

    GUARD(s2n_stuffer_read_uint24(in, &client_cert_chain.size));

    S2N_ERROR_IF(client_cert_chain.size > s2n_stuffer_data_available(in), S2N_ERR_BAD_MESSAGE);

    if (client_cert_chain.size == 0) {
        GUARD(s2n_conn_set_handshake_no_client_cert(conn));
        return 0;
    }

    client_cert_chain.data = s2n_stuffer_raw_read(in, client_cert_chain.size);
    notnull_check(client_cert_chain.data);

    s2n_cert_public_key public_key;
    GUARD(s2n_pkey_zero_init(&public_key));

    s2n_pkey_type pkey_type;

    /* Determine the Cert Type, Verify the Cert, and extract the Public Key */
    S2N_ERROR_IF(s2n_x509_validator_validate_cert_chain(&conn->x509_validator, conn,
                                                 client_cert_chain.data, client_cert_chain.size,
                                                        &pkey_type, &public_key) != S2N_CERT_OK, S2N_ERR_CERT_UNTRUSTED);

    conn->secure.client_cert_pkey_type = pkey_type;
    GUARD(s2n_pkey_setup_for_type(&public_key, pkey_type));
    
    GUARD(s2n_pkey_check_key_exists(&public_key));
    GUARD(s2n_dup(&client_cert_chain, &conn->secure.client_cert_chain));
    conn->secure.client_public_key = public_key;
    
    return 0;
}


int s2n_client_cert_send(struct s2n_connection *conn)
{
    struct s2n_cert_chain_and_key *chain_and_key = conn->handshake_params.our_chain_and_key;

    if (chain_and_key == NULL) {
        GUARD(s2n_conn_set_handshake_no_client_cert(conn));
        GUARD(s2n_send_empty_cert_chain(&conn->handshake.io));
        return 0;
    }

    GUARD(s2n_send_cert_chain(conn, &conn->handshake.io, chain_and_key));
    return 0;
}
