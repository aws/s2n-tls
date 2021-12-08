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

void s2n_handshake_type_set_tls13_flag_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_connection *s2n_connection = malloc(sizeof(*s2n_connection));
    s2n_handshake_type_flag flag;

    /* Compute expected result. */
    s2n_handshake_type_flag expected_result;
    if (s2n_connection) expected_result = s2n_connection->handshake.handshake_type | flag;

    /* Operation under verification. */
    S2N_RESULT ret = s2n_handshake_type_set_tls13_flag(s2n_connection, flag);

    /* Post-conditions. */
    assert(S2N_IMPLIES(ret == S2N_RESULT_OK, s2n_connection->handshake.handshake_type == expected_result));
}
