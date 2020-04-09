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

#include "crypto/s2n_sequence.h"
#include "crypto/s2n_cipher.h"
#include "crypto/s2n_hmac.h"

#include "error/s2n_errno.h"

#include "stuffer/s2n_stuffer.h"

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_crypto.h"
#include "tls/s2n_record.h"
#include "tls/s2n_record_read.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

int s2n_record_parse_cbc(
    const struct s2n_cipher_suite *cipher_suite,
    struct s2n_connection *conn,
    uint8_t content_type,
    uint16_t encrypted_length,
    uint8_t * implicit_iv,
    struct s2n_hmac_state *mac,
    uint8_t * sequence_number,
    struct s2n_session_key *session_key)
{
    struct s2n_blob iv = {.data = implicit_iv,.size = cipher_suite->record_alg->cipher->io.cbc.record_iv_size };
    uint8_t ivpad[S2N_TLS_MAX_IV_LEN];

    /* Add the header to the HMAC */
    uint8_t *header = s2n_stuffer_raw_read(&conn->header_in, S2N_TLS_RECORD_HEADER_LENGTH);
    notnull_check(header);

    lte_check(cipher_suite->record_alg->cipher->io.cbc.record_iv_size, S2N_TLS_MAX_IV_LEN);

    /* For TLS >= 1.1 the IV is in the packet */
    if (conn->actual_protocol_version > S2N_TLS10) {
        GUARD(s2n_stuffer_read(&conn->in, &iv));
        gte_check(encrypted_length, iv.size);
        encrypted_length -= iv.size;
    }

    struct s2n_blob en = {.size = encrypted_length,.data = s2n_stuffer_raw_read(&conn->in, encrypted_length) };
    notnull_check(en.data);

    uint16_t payload_length = encrypted_length;
    uint8_t mac_digest_size;
    GUARD(s2n_hmac_digest_size(mac->alg, &mac_digest_size));

    gte_check(payload_length, mac_digest_size);
    payload_length -= mac_digest_size;

    /* Decrypt stuff! */
    /* Check that we have some data to decrypt */
    ne_check(en.size, 0);

    /* ... and that we have a multiple of the block size */
    eq_check(en.size % iv.size, 0);

    /* Copy the last encrypted block to be the next IV */
    if (conn->actual_protocol_version < S2N_TLS11) {
        memcpy_check(ivpad, en.data + en.size - iv.size, iv.size);
    }

    GUARD(cipher_suite->record_alg->cipher->io.cbc.decrypt(session_key, &iv, &en, &en));

    if (conn->actual_protocol_version < S2N_TLS11) {
        memcpy_check(implicit_iv, ivpad, iv.size);
    }

    /* Subtract the padding length */
    gt_check(en.size, 0);
    payload_length -= (en.data[en.size - 1] + 1);

    /* Update the MAC */
    header[3] = (payload_length >> 8);
    header[4] = payload_length & 0xff;
    GUARD(s2n_hmac_reset(mac));
    GUARD(s2n_hmac_update(mac, sequence_number, S2N_TLS_SEQUENCE_NUM_LEN));

    if (conn->actual_protocol_version == S2N_SSLv3) {
        GUARD(s2n_hmac_update(mac, header, 1));
        GUARD(s2n_hmac_update(mac, header + 3, 2));
    } else {
        GUARD(s2n_hmac_update(mac, header, S2N_TLS_RECORD_HEADER_LENGTH));
    }

    struct s2n_blob seq = {.data = sequence_number,.size = S2N_TLS_SEQUENCE_NUM_LEN };
    GUARD(s2n_increment_sequence_number(&seq));

    /* Padding */
    if (s2n_verify_cbc(conn, mac, &en) < 0) {
        GUARD(s2n_stuffer_wipe(&conn->in));
        S2N_ERROR(S2N_ERR_BAD_MESSAGE);
    }

    /* O.k., we've successfully read and decrypted the record, now we need to align the stuffer
     * for reading the plaintext data.
     */
    GUARD(s2n_stuffer_reread(&conn->in));
    GUARD(s2n_stuffer_reread(&conn->header_in));

    /* Skip the IV, if any */
    if (conn->actual_protocol_version > S2N_TLS10) {
        GUARD(s2n_stuffer_skip_read(&conn->in, cipher_suite->record_alg->cipher->io.cbc.record_iv_size));
    }

    /* Truncate and wipe the MAC and any padding */
    GUARD(s2n_stuffer_wipe_n(&conn->in, s2n_stuffer_data_available(&conn->in) - payload_length));
    conn->in_status = PLAINTEXT;

    return 0;
}
