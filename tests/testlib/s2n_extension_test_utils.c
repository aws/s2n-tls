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

#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "utils/s2n_bitmap.h"

const s2n_parsed_extension EMPTY_PARSED_EXTENSIONS[S2N_PARSED_EXTENSIONS_COUNT] = { 0 };

int s2n_connection_allow_all_response_extensions(struct s2n_connection *conn)
{
    POSIX_CHECKED_MEMSET(&conn->extension_requests_received, 0xFF, S2N_SUPPORTED_EXTENSIONS_BITFIELD_LEN);
    POSIX_CHECKED_MEMSET(&conn->extension_requests_sent, 0xFF, S2N_SUPPORTED_EXTENSIONS_BITFIELD_LEN);
    return S2N_SUCCESS;
}

int s2n_connection_mark_extension_received(struct s2n_connection *conn, uint16_t iana_value)
{
    s2n_extension_type_id extension_id = s2n_unsupported_extension;
    POSIX_GUARD(s2n_extension_supported_iana_value_to_id(iana_value, &extension_id));
    S2N_CBIT_SET(conn->extension_requests_received, extension_id);
    S2N_CBIT_SET(conn->extension_responses_received, extension_id);
    return S2N_SUCCESS;
}

int s2n_connection_allow_response_extension(struct s2n_connection *conn, uint16_t iana_value)
{
    s2n_extension_type_id extension_id = s2n_unsupported_extension;
    POSIX_GUARD(s2n_extension_supported_iana_value_to_id(iana_value, &extension_id));
    S2N_CBIT_SET(conn->extension_requests_sent, extension_id);
    S2N_CBIT_SET(conn->extension_requests_received, extension_id);
    return S2N_SUCCESS;
}
