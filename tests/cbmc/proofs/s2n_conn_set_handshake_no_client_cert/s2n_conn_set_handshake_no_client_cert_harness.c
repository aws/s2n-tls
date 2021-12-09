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

#include <tls/s2n_connection.h>

void s2n_conn_set_handshake_no_client_cert_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_connection *s2n_connection = malloc(sizeof(*s2n_connection));
    if (s2n_connection) {
        s2n_connection->config = malloc(sizeof(*(s2n_connection->config)));
    }

    /* Operation under verification. */
    int result = s2n_conn_set_handshake_no_client_cert(s2n_connection);

    /* Post-conditions. */
    assert(S2N_IMPLIES(result == S2N_SUCCESS, s2n_connection->client_cert_auth_type == S2N_CERT_AUTH_OPTIONAL || s2n_connection->config->client_cert_auth_type == S2N_CERT_AUTH_OPTIONAL));
    assert(S2N_IMPLIES(result == S2N_SUCCESS, s2n_handshake_type_check_flag(s2n_connection, NO_CLIENT_CERT)));
}
