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

#include <assert.h>

void s2n_connection_get_last_message_name_harness()
{
    /* Non-deterministic inputs. */
    struct s2n_connection *s2n_connection = malloc(sizeof(*s2n_connection));

    /* Operation under verification. */
    const char* last_message_name = s2n_connection_get_last_message_name(s2n_connection);

    /* Post-conditions. */
    assert(S2N_IMPLIES(
      s2n_connection != NULL && s2n_result_is_ok(s2n_handshake_validate(&(s2n_connection->handshake))),
      last_message_name != NULL
    ));
}
