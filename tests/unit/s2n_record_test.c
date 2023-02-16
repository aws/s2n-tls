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

#include "tls/s2n_record.h"

#include <stdio.h>
#include <string.h>

#include "api/s2n.h"
#include "crypto/s2n_cipher.h"
#include "crypto/s2n_hmac.h"
#include "s2n_test.h"
#include "stuffer/s2n_stuffer.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_prf.h"
#include "utils/s2n_random.h"

/* Mock block cipher that does nothing */
int mock_block_endecrypt(struct s2n_session_key *key, struct s2n_blob *iv, struct s2n_blob *in, struct s2n_blob *out)
{
    return 0;
}

struct s2n_cipher mock_block_cipher = {
    .type = S2N_CBC,
    .key_material_size = 0,
    .io.cbc = {
            .block_size = 16,
            .record_iv_size = 16,
            .encrypt = mock_block_endecrypt,
            .decrypt = mock_block_endecrypt },
    .set_encryption_key = NULL,
    .set_decryption_key = NULL,
    .destroy_key = NULL,
};

struct s2n_record_algorithm mock_block_record_alg = {
    .cipher = &mock_block_cipher,
    .hmac_alg = S2N_HMAC_SHA1,
};

struct s2n_cipher_suite mock_block_cipher_suite = {
    .available = 1,
    .name = "TLS_MOCK_CBC",
    .iana_value = { 0x12, 0x34 },
    .key_exchange_alg = &s2n_rsa,
    .record_alg = &mock_block_record_alg,
};

struct s2n_record_algorithm mock_null_sha1_record_alg = {
    .cipher = &s2n_null_cipher,
    .hmac_alg = S2N_HMAC_SHA1,
};

int main(int argc, char **argv)
{
    struct s2n_connection *conn;
    uint8_t mac_key[] = "sample mac key";
    struct s2n_blob fixed_iv = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&fixed_iv, mac_key, sizeof(mac_key)));
    struct s2n_hmac_state check_mac;
    uint8_t random_data[S2N_DEFAULT_FRAGMENT_LENGTH + 1];
    struct s2n_blob r = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&r, random_data, sizeof(random_data)));

    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    EXPECT_SUCCESS(s2n_hmac_new(&check_mac));

    EXPECT_SUCCESS(s2n_hmac_init(&check_mac, S2N_HMAC_SHA1, fixed_iv.data, fixed_iv.size));
    EXPECT_OK(s2n_get_public_random_data(&r));
    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

    /* Peer and we are in sync */
    conn->server = conn->initial;
    conn->client = conn->initial;

    /* test the null cipher. */
    conn->initial->cipher_suite = &s2n_null_cipher_suite;
    conn->actual_protocol_version = S2N_TLS11;

    for (size_t i = 0; i <= S2N_DEFAULT_FRAGMENT_LENGTH + 1; i++) {
        struct s2n_blob in = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&in, random_data, i));
        int bytes_written;

        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));

        s2n_result result = s2n_record_write(conn, TLS_ALERT, &in);
        if (i <= S2N_DEFAULT_FRAGMENT_LENGTH) {
            EXPECT_OK(result);
            bytes_written = i;
        } else {
            EXPECT_ERROR_WITH_ERRNO(result, S2N_ERR_FRAGMENT_LENGTH_TOO_LARGE);
            bytes_written = S2N_DEFAULT_FRAGMENT_LENGTH;
        }

        EXPECT_EQUAL(conn->out.blob.data[0], TLS_ALERT);
        EXPECT_EQUAL(conn->out.blob.data[1], 3);
        EXPECT_EQUAL(conn->out.blob.data[2], 2);
        EXPECT_EQUAL(conn->out.blob.data[3], (bytes_written >> 8) & 0xff);
        EXPECT_EQUAL(conn->out.blob.data[4], bytes_written & 0xff);
        EXPECT_EQUAL(memcmp(conn->out.blob.data + 5, random_data, bytes_written), 0);

        EXPECT_SUCCESS(s2n_stuffer_resize_if_empty(&conn->in, S2N_LARGE_FRAGMENT_LENGTH));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, 5));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));

        uint8_t content_type;
        uint16_t fragment_length;
        EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
        EXPECT_SUCCESS(s2n_record_parse(conn));
        EXPECT_EQUAL(content_type, TLS_ALERT);
        EXPECT_EQUAL(fragment_length, bytes_written);
    }

    /* test a fake streaming cipher with a MAC */
    conn->initial->cipher_suite->record_alg = &mock_null_sha1_record_alg;
    EXPECT_SUCCESS(s2n_hmac_init(&conn->initial->client_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
    EXPECT_SUCCESS(s2n_hmac_init(&conn->initial->server_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
    conn->initial->cipher_suite = &s2n_null_cipher_suite;
    conn->actual_protocol_version = S2N_TLS11;

    for (size_t i = 0; i <= S2N_DEFAULT_FRAGMENT_LENGTH + 1; i++) {
        struct s2n_blob in = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&in, random_data, i));
        int bytes_written;

        EXPECT_SUCCESS(s2n_hmac_reset(&check_mac));
        EXPECT_SUCCESS(s2n_hmac_update(&check_mac, conn->initial->server_sequence_number, 8));

        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));

        s2n_result result = s2n_record_write(conn, TLS_ALERT, &in);
        if (i <= S2N_DEFAULT_FRAGMENT_LENGTH) {
            EXPECT_OK(result);
            bytes_written = i;
        } else {
            EXPECT_ERROR_WITH_ERRNO(result, S2N_ERR_FRAGMENT_LENGTH_TOO_LARGE);
            bytes_written = S2N_DEFAULT_FRAGMENT_LENGTH;
        }

        uint16_t predicted_length = bytes_written + 20;
        EXPECT_EQUAL(conn->out.blob.data[0], TLS_ALERT);
        EXPECT_EQUAL(conn->out.blob.data[1], 3);
        EXPECT_EQUAL(conn->out.blob.data[2], 2);
        EXPECT_EQUAL(conn->out.blob.data[3], (predicted_length >> 8) & 0xff);
        EXPECT_EQUAL(conn->out.blob.data[4], predicted_length & 0xff);
        EXPECT_EQUAL(memcmp(conn->out.blob.data + 5, random_data, bytes_written), 0);

        uint8_t top = bytes_written >> 8;
        uint8_t bot = bytes_written & 0xff;
        EXPECT_SUCCESS(s2n_hmac_update(&check_mac, conn->out.blob.data, 3));
        EXPECT_SUCCESS(s2n_hmac_update(&check_mac, &top, 1));
        EXPECT_SUCCESS(s2n_hmac_update(&check_mac, &bot, 1));
        EXPECT_SUCCESS(s2n_hmac_update(&check_mac, random_data, bytes_written));

        uint8_t check_digest[20];
        EXPECT_SUCCESS(s2n_hmac_digest(&check_mac, check_digest, 20));
        EXPECT_SUCCESS(s2n_hmac_digest_verify(conn->out.blob.data + 5 + bytes_written, check_digest, 20));

        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, 5));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));

        uint8_t original_seq_num[8];
        EXPECT_MEMCPY_SUCCESS(original_seq_num, conn->server->client_sequence_number, 8);

        uint8_t content_type;
        uint16_t fragment_length;
        EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
        EXPECT_SUCCESS(s2n_record_parse(conn));
        EXPECT_EQUAL(content_type, TLS_ALERT);
        EXPECT_EQUAL(fragment_length, predicted_length);

        /* Simulate a replay attack and verify that replaying the same record
         * fails due to the sequence number check */
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        EXPECT_SUCCESS(s2n_stuffer_reread(&conn->out));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));
        EXPECT_FAILURE(s2n_record_parse(conn));

        /* Restore the original sequence number */
        EXPECT_MEMCPY_SUCCESS(conn->server->client_sequence_number, original_seq_num, 8);

        /* Deliberately corrupt a byte of the output and check that the record
         * won't parse
         */
        uint64_t byte_to_corrupt;
        EXPECT_OK(s2n_public_random(fragment_length, &byte_to_corrupt));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        EXPECT_SUCCESS(s2n_stuffer_reread(&conn->out));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, 5));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));

        conn->in.blob.data[byte_to_corrupt] += 1;
        EXPECT_FAILURE_WITH_ERRNO(s2n_record_parse(conn), S2N_ERR_BAD_MESSAGE);
    }

    /* Test a mock block cipher with a mac - in TLS1.0 mode */
    EXPECT_SUCCESS(s2n_hmac_init(&conn->initial->client_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
    EXPECT_SUCCESS(s2n_hmac_init(&conn->initial->server_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
    conn->actual_protocol_version = S2N_TLS10;
    conn->initial->cipher_suite = &mock_block_cipher_suite;

    for (size_t i = 0; i <= S2N_DEFAULT_FRAGMENT_LENGTH + 1; i++) {
        struct s2n_blob in = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&in, random_data, i));
        int bytes_written;

        EXPECT_SUCCESS(s2n_hmac_reset(&check_mac));
        EXPECT_SUCCESS(s2n_hmac_update(&check_mac, conn->initial->client_sequence_number, 8));

        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));

        s2n_result result = s2n_record_write(conn, TLS_APPLICATION_DATA, &in);
        if (i <= S2N_DEFAULT_FRAGMENT_LENGTH) {
            EXPECT_OK(result);
            bytes_written = i;
        } else {
            EXPECT_ERROR_WITH_ERRNO(result, S2N_ERR_FRAGMENT_LENGTH_TOO_LARGE);
            bytes_written = S2N_DEFAULT_FRAGMENT_LENGTH;
        }

        uint16_t predicted_length = bytes_written + 1 + 20;
        if (predicted_length % 16) {
            predicted_length += (16 - (predicted_length % 16));
        }
        EXPECT_EQUAL(conn->out.blob.data[0], TLS_APPLICATION_DATA);
        EXPECT_EQUAL(conn->out.blob.data[1], 3);
        EXPECT_EQUAL(conn->out.blob.data[2], 1);
        EXPECT_EQUAL(conn->out.blob.data[3], (predicted_length >> 8) & 0xff);
        EXPECT_EQUAL(conn->out.blob.data[4], predicted_length & 0xff);
        EXPECT_EQUAL(memcmp(conn->out.blob.data + 5, random_data, bytes_written), 0);

        /* The last byte of out should indicate how much padding there was */
        uint8_t p = conn->out.blob.data[conn->out.write_cursor - 1];
        const uint32_t remaining = 5 + bytes_written + 20 + p + 1;
        EXPECT_EQUAL(remaining, s2n_stuffer_data_available(&conn->out));

        /* Check that the last 'p' bytes are all set to 'p' */
        for (size_t j = 0; j <= (size_t) p; j++) {
            EXPECT_EQUAL(conn->out.blob.data[5 + bytes_written + 20 + j], p);
        }

        uint8_t top = bytes_written >> 8;
        uint8_t bot = bytes_written & 0xff;
        EXPECT_SUCCESS(s2n_hmac_update(&check_mac, conn->out.blob.data, 3));
        EXPECT_SUCCESS(s2n_hmac_update(&check_mac, &top, 1));
        EXPECT_SUCCESS(s2n_hmac_update(&check_mac, &bot, 1));
        EXPECT_SUCCESS(s2n_hmac_update(&check_mac, random_data, bytes_written));

        uint8_t check_digest[20];
        EXPECT_SUCCESS(s2n_hmac_digest(&check_mac, check_digest, 20));
        EXPECT_SUCCESS(s2n_hmac_digest_verify(conn->out.blob.data + 5 + bytes_written, check_digest, 20));

        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, 5));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));

        uint8_t content_type;
        uint16_t fragment_length;
        EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
        EXPECT_SUCCESS(s2n_record_parse(conn));
        EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);
        EXPECT_EQUAL(fragment_length, predicted_length);
    }

    /* Test a mock block cipher with a mac - in TLS1.1+ mode */
    EXPECT_SUCCESS(s2n_hmac_init(&conn->initial->client_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
    EXPECT_SUCCESS(s2n_hmac_init(&conn->initial->server_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
    conn->actual_protocol_version = S2N_TLS11;
    conn->initial->cipher_suite = &mock_block_cipher_suite;

    for (int i = 0; i <= S2N_DEFAULT_FRAGMENT_LENGTH + 1; i++) {
        struct s2n_blob in = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&in, random_data, i));
        int bytes_written;

        EXPECT_SUCCESS(s2n_hmac_reset(&check_mac));
        EXPECT_SUCCESS(s2n_hmac_update(&check_mac, conn->initial->client_sequence_number, 8));

        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));

        s2n_result result = s2n_record_write(conn, TLS_APPLICATION_DATA, &in);
        if (i <= S2N_DEFAULT_FRAGMENT_LENGTH) {
            EXPECT_OK(result);
            bytes_written = i;
        } else {
            EXPECT_ERROR_WITH_ERRNO(result, S2N_ERR_FRAGMENT_LENGTH_TOO_LARGE);
            bytes_written = S2N_DEFAULT_FRAGMENT_LENGTH;
        }

        uint16_t predicted_length = bytes_written + 1 + 20 + 16;
        if (predicted_length % 16) {
            predicted_length += (16 - (predicted_length % 16));
        }
        EXPECT_EQUAL(conn->out.blob.data[0], TLS_APPLICATION_DATA);
        EXPECT_EQUAL(conn->out.blob.data[1], 3);
        EXPECT_EQUAL(conn->out.blob.data[2], 2);
        EXPECT_EQUAL(conn->out.blob.data[3], (predicted_length >> 8) & 0xff);
        EXPECT_EQUAL(conn->out.blob.data[4], predicted_length & 0xff);
        EXPECT_EQUAL(memcmp(conn->out.blob.data + 16 + 5, random_data, bytes_written), 0);

        /* The last byte of out should indicate how much padding there was */
        uint8_t p = conn->out.blob.data[conn->out.write_cursor - 1];
        EXPECT_EQUAL(5 + bytes_written + 20 + 16 + p + 1, s2n_stuffer_data_available(&conn->out));

        /* Check that the last 'p' bytes are all set to 'p' */
        for (size_t j = 0; j <= (size_t) p; j++) {
            EXPECT_EQUAL(conn->out.blob.data[5 + bytes_written + 16 + 20 + j], p);
        }

        uint8_t top = bytes_written >> 8;
        uint8_t bot = bytes_written & 0xff;
        EXPECT_SUCCESS(s2n_hmac_update(&check_mac, conn->out.blob.data, 3));
        EXPECT_SUCCESS(s2n_hmac_update(&check_mac, &top, 1));
        EXPECT_SUCCESS(s2n_hmac_update(&check_mac, &bot, 1));
        EXPECT_SUCCESS(s2n_hmac_update(&check_mac, random_data, bytes_written));

        uint8_t check_digest[20];
        EXPECT_SUCCESS(s2n_hmac_digest(&check_mac, check_digest, 20));
        EXPECT_SUCCESS(s2n_hmac_digest_verify(conn->out.blob.data + 16 + 5 + bytes_written, check_digest, 20));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, 5));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));

        uint8_t content_type;
        uint16_t fragment_length;
        EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));
        EXPECT_SUCCESS(s2n_record_parse(conn));
        EXPECT_EQUAL(content_type, TLS_APPLICATION_DATA);
        EXPECT_EQUAL(fragment_length, predicted_length);
    }

    /* Test TLS record limit */
    struct s2n_blob empty_blob = { 0 };
    EXPECT_SUCCESS(s2n_blob_init(&empty_blob, NULL, 0));
    conn->initial->cipher_suite = &s2n_null_cipher_suite;

    /* Fast forward the sequence number */
    uint8_t max_num_records[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    EXPECT_MEMCPY_SUCCESS(conn->initial->server_sequence_number, max_num_records, sizeof(max_num_records));
    EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));
    /* Sequence number should wrap around */
    EXPECT_ERROR_WITH_ERRNO(s2n_record_write(conn, TLS_ALERT, &empty_blob), S2N_ERR_RECORD_LIMIT);

    /* Test TLS 1.3 Record should reflect as TLS 1.2 version on the wire */
    {
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));

        conn->actual_protocol_version = S2N_TLS13;
        EXPECT_OK(s2n_record_write(conn, TLS_ALERT, &empty_blob));

        /* Make sure that TLS 1.3 records appear as TLS 1.2 version */
        EXPECT_EQUAL(conn->out.blob.data[1], 3);
        EXPECT_EQUAL(conn->out.blob.data[2], 3);

        /* Copy written bytes for reading */
        EXPECT_SUCCESS(s2n_stuffer_resize_if_empty(&conn->in, S2N_LARGE_FRAGMENT_LENGTH));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->in));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->header_in, 5));
        EXPECT_SUCCESS(s2n_stuffer_copy(&conn->out, &conn->in, s2n_stuffer_data_available(&conn->out)));

        /* Trigger condition to check for protocol version */
        conn->actual_protocol_version_established = 1;
        uint8_t content_type;
        uint16_t fragment_length;
        EXPECT_SUCCESS(s2n_record_header_parse(conn, &content_type, &fragment_length));

        /* If record version on wire is TLS 1.3, check s2n_record_header_parse fails */
        EXPECT_SUCCESS(s2n_stuffer_reread(&conn->header_in));
        conn->header_in.blob.data[1] = 3;
        conn->header_in.blob.data[2] = 4;
        EXPECT_FAILURE_WITH_ERRNO(s2n_record_header_parse(conn, &content_type, &fragment_length), S2N_ERR_BAD_MESSAGE);
    };

    /* Test: ApplicationData MUST be encrypted */
    {
        EXPECT_SUCCESS(s2n_connection_wipe(conn));
        conn->actual_protocol_version = S2N_TLS13;

        /* Write fails with no secrets / cipher set */
        EXPECT_ERROR_WITH_ERRNO(s2n_record_write(conn, TLS_APPLICATION_DATA, &empty_blob), S2N_ERR_ENCRYPT);

        /* Read fails with no secrets / cipher set */
        uint8_t header_bytes[] = { TLS_APPLICATION_DATA, 0x03, 0x04, 0x00, 0x00 };
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->header_in, header_bytes, sizeof(header_bytes)));
        EXPECT_FAILURE_WITH_ERRNO(s2n_record_parse(conn), S2N_ERR_DECRYPT);
    };

    /* Test s2n_sslv2_record_header_parse fails when fragment_length < 3 */
    {
        EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->header_in));

        uint8_t record_type = 0;
        uint8_t protocol_version = 0;
        uint16_t fragment_length = 0;

        /* First two bytes are the fragment length */
        uint8_t header_bytes[] = { 0x00, 0x00, 0x00, 0x00, 0x00 };
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->header_in, header_bytes, sizeof(header_bytes)));

        EXPECT_FAILURE_WITH_ERRNO(s2n_sslv2_record_header_parse(conn, &record_type, &protocol_version, &fragment_length), S2N_ERR_SAFETY);

        /* Check the rest of the stuffer has not been read yet */
        EXPECT_EQUAL(s2n_stuffer_data_available(&conn->header_in), 3);
    };

    EXPECT_SUCCESS(s2n_hmac_free(&check_mac));

    EXPECT_SUCCESS(s2n_connection_free(conn));

    END_TEST();
}
