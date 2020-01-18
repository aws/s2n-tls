/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <stdbool.h>

#include "error/s2n_errno.h"
#include "utils/s2n_blob.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

/* from RFC: https://tools.ietf.org/html/rfc8446#section-4.1.3*/
const uint8_t hello_retry_req_random[] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
};

inline bool s2n_is_hello_retry_req(struct s2n_connection *conn)
{
    return s2n_constant_time_equals(hello_retry_req_random, conn->secure.server_random, S2N_TLS_RANDOM_DATA_LEN);
}


int s2n_server_hello_retry_send(struct s2n_connection *conn)
{
    S2N_ERROR(S2N_ERR_UNIMPLEMENTED);
}

int s2n_server_hello_retry_recv(struct s2n_connection *conn)
{
    S2N_ERROR(S2N_ERR_UNIMPLEMENTED);
}
