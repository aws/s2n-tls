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
int s2n_aead_aad_init(const struct s2n_connection *conn, uint8_t *sequence_number, uint8_t content_type, uint16_t record_length, struct s2n_blob *ad)
{
    gte_check(ad->size, S2N_TLS_GCM_AAD_LEN);

    /* ad = seq_num || record_type || version || length */
    memcpy_check(ad->data, sequence_number, S2N_TLS_SEQUENCE_NUM_LEN);
    int ad_len = S2N_TLS_SEQUENCE_NUM_LEN;
    ad->data[ad_len++] = content_type;
    ad->data[ad_len++] = conn->actual_protocol_version / 10;
    ad->data[ad_len++] = conn->actual_protocol_version % 10; 
    ad->data[ad_len++] = record_length >> 8;
    ad->data[ad_len++] = record_length & 0xFF;

    ad->size = ad_len;

    return 0;
}

