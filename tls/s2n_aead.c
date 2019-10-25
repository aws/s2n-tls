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

/* Prepares an AAD (additional authentication data) for a TLS 1.3 AEAD record */
int s2n_tls13_aead_aad_init(uint16_t record_length, uint8_t tag_length, struct s2n_stuffer *additional_data)
{
    gt_check(tag_length, 0);
    notnull_check(additional_data);

    /*
     * tls1.3 additional_data = opaque_type || legacy_record_version || length
     *
     * https://tools.ietf.org/html/rfc8446#section-5.2
     *
     *  opaque_type: The outer opaque_type field of a TLSCiphertext record
     *      is always set to the value 23 (application_data) for outward
     *      compatibility with middleboxes accustomed to parsing previous
     *      versions of TLS.  The actual content type of the record is found
     *      in TLSInnerPlaintext.type after decryption.
     *  legacy_record_version:  The legacy_record_version field is always
     *      0x0303.  TLS 1.3 TLSCiphertexts are not generated until after
     *      TLS 1.3 has been negotiated, so there are no historical
     *      compatibility concerns where other values might be received.  Note
     *      that the handshake protocol, including the ClientHello and
     *      ServerHello messages, authenticates the protocol version, so this
     *      value is redundant.
     *  length:  The length (in bytes) of the following
     *      TLSCiphertext.encrypted_record, which is the sum of the lengths of
     *      the content and the padding, plus one for the inner content type,
     *      plus any expansion added by the AEAD algorithm.  The length
     *      MUST NOT exceed 2^14 + 256 bytes.  An endpoint that receives a
     *      record that exceeds this length MUST terminate the connection with
     *      a "record_overflow" alert.
     */

    uint16_t length = record_length + tag_length;
    S2N_ERROR_IF(length > (1 << 14) + 256, S2N_ERR_RECORD_LIMIT);

    GUARD(s2n_stuffer_write_uint8(additional_data, TLS_APPLICATION_DATA)); /* fixed to 0x17 */
    GUARD(s2n_stuffer_write_uint8(additional_data, 3)); /* TLS record layer              */
    GUARD(s2n_stuffer_write_uint8(additional_data, 3)); /* version fixed at 1.2 (0x0303) */
    GUARD(s2n_stuffer_write_uint16(additional_data, length));

    return 0;
}
