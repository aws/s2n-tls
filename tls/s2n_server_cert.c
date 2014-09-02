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

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_config.h"

#include "stuffer/s2n_stuffer.h"

#include "utils/s2n_safety.h"

int s2n_server_cert_recv(struct s2n_connection *conn, const char **err)
{
    uint32_t size_of_all_certificates;

    GUARD(s2n_stuffer_read_uint24(&conn->handshake.io, &size_of_all_certificates, err));

    if (size_of_all_certificates > s2n_stuffer_data_available(&conn->handshake.io)) {
        *err = "Invalid size of certificates message";
        return -1;
    }

    int certificate = 0;
    while (s2n_stuffer_data_available(&conn->handshake.io)) {
        uint32_t certificate_size;

        GUARD(s2n_stuffer_read_uint24(&conn->handshake.io, &certificate_size, err));

        if (certificate_size > s2n_stuffer_data_available(&conn->handshake.io)) {
            *err = "Invalid certificate size encountered";
            return -1;
        }

        struct s2n_blob asn1cert;
        asn1cert.data = s2n_stuffer_raw_read(&conn->handshake.io, certificate_size, err);
        asn1cert.size = certificate_size;
        notnull_check(asn1cert.data);

        /* TODO: certificate validation goes here */

        /* Pull the public key from the first certificate */
        if (certificate == 0) {
            GUARD(s2n_asn1der_to_rsa_public_key(&conn->pending.server_rsa_public_key, &asn1cert, err));
        }

        certificate++;
    }

    conn->handshake.next_state = SERVER_HELLO_DONE;

    if (conn->pending.cipher_suite->key_exchange_alg == S2N_DHE) {
        conn->handshake.next_state = SERVER_KEY;
    }

    return 0;
}

int s2n_server_cert_send(struct s2n_connection *conn, const char **err)
{
    struct s2n_cert_chain *head = conn->server->chosen_cert_chain->head;

    GUARD(s2n_stuffer_write_uint24(&conn->handshake.io, conn->server->chosen_cert_chain->chain_size, err));

    while (head) {
        GUARD(s2n_stuffer_write_uint24(&conn->handshake.io, head->cert.size, err));
        GUARD(s2n_stuffer_write_bytes(&conn->handshake.io, head->cert.data, head->cert.size, err));
        head = head->next;
    }

    conn->handshake.next_state = SERVER_HELLO_DONE;

    if (conn->pending.cipher_suite->key_exchange_alg == S2N_DHE) {
        conn->handshake.next_state = SERVER_KEY;
    }

    return 0;
}
