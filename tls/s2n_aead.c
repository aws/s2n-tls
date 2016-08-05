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

#include "error/s2n_errno.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_mem.h"

#include "tls/s2n_record.h"

/* Derive the AAD for an AEAD mode cipher suite from the connection state, per
 * RFC 5246 section 6.2.3.3 */
int s2n_aead_aad_init(const struct s2n_connection *conn, uint8_t * sequence_number, uint8_t content_type, uint16_t record_length, struct s2n_stuffer *ad)
{
    /* ad = seq_num || record_type || version || length */
    GUARD(s2n_stuffer_write_bytes(ad, sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));
    GUARD(s2n_stuffer_write_uint8(ad, content_type));
    GUARD(s2n_stuffer_write_uint8(ad, conn->actual_protocol_version / 10));
    GUARD(s2n_stuffer_write_uint8(ad, conn->actual_protocol_version % 10));
    GUARD(s2n_stuffer_write_uint16(ad, record_length));

    return 0;
}
