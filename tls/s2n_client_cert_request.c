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

#include <s2n.h>

#include "crypto/s2n_certificate.h"
#include "error/s2n_errno.h"
#include "tls/s2n_client_cert_preferences.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_config.h"
#include "tls/s2n_signature_algorithms.h"
#include "tls/s2n_tls.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_array.h"

static int s2n_set_cert_chain_as_client(struct s2n_connection *conn)
{
    struct s2n_array *certs = conn->config->cert_and_key_pairs;
    if (s2n_array_num_elements(certs) > 0) {
        conn->handshake_params.our_chain_and_key = *((struct s2n_cert_chain_and_key**) s2n_array_get(certs, 0));
    }

    return 0;
}

int s2n_client_cert_req_recv(struct s2n_connection *conn)
{
    struct s2n_stuffer *in = &conn->handshake.io;

    GUARD(s2n_recv_client_cert_preferences(in, &conn->secure.client_cert_type));

    if (conn->actual_protocol_version == S2N_TLS12) {
        s2n_recv_supported_signature_algorithms(conn, in, &conn->handshake_params.server_sig_hash_algs);

        s2n_hash_algorithm chosen_hash_algorithm;
        s2n_signature_algorithm chosen_signature_algorithm;
        GUARD(s2n_set_signature_hash_pair_from_preference_list(conn, &conn->handshake_params.server_sig_hash_algs, &chosen_hash_algorithm, &chosen_signature_algorithm));
        conn->secure.client_cert_hash_algorithm = chosen_hash_algorithm;
        conn->secure.client_cert_sig_alg = chosen_signature_algorithm;
    }
    uint16_t cert_authorities_len = 0;
    GUARD(s2n_stuffer_read_uint16(in, &cert_authorities_len));

    /* For now we don't parse X.501 encoded CA Distinguished Names.
     * Don't fail just yet as we still may succeed if we provide
     * right certificate or if ClientAuth is optional. */
    GUARD(s2n_stuffer_skip_read(in, cert_authorities_len));

    /* In the future we may have more advanced logic to match a set of configured certificates against
     * The cert authorities extension and the signature algorithms advertised.
     * For now, this will just set the only certificate configured.
     */
    GUARD(s2n_set_cert_chain_as_client(conn));

    return 0;
}


int s2n_client_cert_req_send(struct s2n_connection *conn)
{
    struct s2n_stuffer *out = &conn->handshake.io;

    uint8_t client_cert_preference_list_size = sizeof(s2n_cert_type_preference_list);
    GUARD(s2n_stuffer_write_uint8(out, client_cert_preference_list_size));

    for (int i = 0; i < client_cert_preference_list_size; i++) {
        GUARD(s2n_stuffer_write_uint8(out, s2n_cert_type_preference_list[i]));
    }

    if (conn->actual_protocol_version == S2N_TLS12) {
        GUARD(s2n_send_supported_signature_algorithms(out));
    }

    /* RFC 5246 7.4.4 - If the certificate_authorities list is empty, then the
     * client MAY send any certificate of the appropriate ClientCertificateType */
    uint16_t acceptable_cert_authorities_len = 0;
    GUARD(s2n_stuffer_write_uint16(out, acceptable_cert_authorities_len));

    return 0;
}
