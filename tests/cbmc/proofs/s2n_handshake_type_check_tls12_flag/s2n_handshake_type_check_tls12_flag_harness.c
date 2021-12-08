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

void s2n_handshake_type_check_tls12_flag_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_connection *s2n_connection = malloc(sizeof(*s2n_connection));
    s2n_handshake_type_flag flag;

    /* Operation under verification. */
    bool ret = s2n_handshake_type_check_tls12_flag(s2n_connection, flag);

    /* Post-conditions. */
    assert(ret == (s2n_connection && s2n_connection_get_protocol_version(s2n_connection) < S2N_TLS13 && (s2n_connection->handshake.handshake_type & flag)));
}
