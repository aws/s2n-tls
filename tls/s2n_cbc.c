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

#include <stdint.h>

#include "error/s2n_errno.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_mem.h"

#include "crypto/s2n_hmac.h"

#include "tls/s2n_record.h"
#include "tls/s2n_prf.h"

static uint8_t masks[256][255];

int s2n_cbc_masks_init()
{
    /* We have 256 different 255-byte sized masks for checking padding. 0's indicate where we would expect
     * payload or MAC data to be. 0xff's indicate where we expected padding bytes, or the padding length
     * byte to be. 
     */
    for (int i = 0; i < 256; i++) {
        memset_check(&masks[i][0], 0, 255 - i);
        memset_check(&masks[i][255 - i], 0xFF, i);
    }

    return 0;
}

/* A TLS CBC record looks like ..
 *
 * [ Payload data ] [ HMAC ] [ Padding ] [ Padding length byte ]
 *
 * Each byte in the padding is expected to be set to the same value
 * as the padding length byte. So if the padding length byte is '2'
 * then the padding will be [ '2', '2' ] (there'll be three bytes
 * set to that value if you include the padding length byte).
 *
 * The goal of s2n_verify_cbc() is to verify that the padding and hmac
 * are correct, without leaking (via timing) how much padding there
 * actually is: this is considered secret. 
 */
int s2n_verify_cbc(struct s2n_connection *conn, struct s2n_hmac_state *hmac, struct s2n_blob *decrypted)
{
    struct s2n_hmac_state copy;

    int mac_digest_size = s2n_hmac_digest_size(hmac->alg);
    
    /* The record has to be at least big enough to contain the MAC,
     * plus the padding length byte */
    gt_check(decrypted->size, mac_digest_size);
    
    int payload_and_padding_size = decrypted->size - mac_digest_size;

    /* Determine what the padding length is */
    uint8_t padding_length = decrypted->data[decrypted->size - 1];

    int payload_length = payload_and_padding_size - padding_length - 1;
    if (payload_length < 0) {
        payload_length = 0;
    }

    /* Update the MAC */
    GUARD(s2n_hmac_update(hmac, decrypted->data, payload_length));
    GUARD(s2n_hmac_copy(&copy, hmac));

    /* Check the MAC */
    uint8_t check_digest[S2N_MAX_DIGEST_LEN];
    lte_check(mac_digest_size, sizeof(check_digest));
    GUARD(s2n_hmac_digest(hmac, check_digest, mac_digest_size));

    int mismatches = s2n_constant_time_equals(decrypted->data + payload_length, check_digest, mac_digest_size) ^ 1;

    /* Compute a MAC on the rest of the data so that we perform the same number of hash operations */
    GUARD(s2n_hmac_update(&copy, decrypted->data + payload_length + mac_digest_size, decrypted->size - payload_length - mac_digest_size - 1));

    /* SSLv3 doesn't specify what the padding should actualy be */
    if (conn->actual_protocol_version == S2N_SSLv3) {
        return 0 - mismatches;
    }

    /* Check the padding */
    uint8_t *mask = masks[ padding_length ];

    int check = 255;
    if (check > payload_and_padding_size) {
        check = payload_and_padding_size;
    }

    for (int i = 255 - check, j = decrypted->size - check; i < 255 && j < decrypted->size; i++, j++) {
        mismatches |= (decrypted->data[j] ^ padding_length) & mask[i];
    }

    if (mismatches) {
        S2N_ERROR(S2N_ERR_CBC_VERIFY);
    }

    return 0;
}
