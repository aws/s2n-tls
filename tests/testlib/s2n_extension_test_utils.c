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

#include "tls/s2n_connection.h"
#include "testlib/s2n_testlib.h"

const s2n_parsed_extension EMPTY_PARSED_EXTENSIONS[S2N_PARSED_EXTENSIONS_COUNT] = { 0 };

int s2n_connection_allow_all_response_extensions(struct s2n_connection *conn)
{
    memset_check(&conn->extension_requests_received, 0xFF, S2N_SUPPORTED_EXTENSIONS_BITFIELD_LEN);
    memset_check(&conn->extension_requests_sent, 0xFF, S2N_SUPPORTED_EXTENSIONS_BITFIELD_LEN);
    return S2N_SUCCESS;
}
