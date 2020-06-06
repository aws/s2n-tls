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

#include "s2n_test.h"

#include <string.h>
#include <stdio.h>

#include <s2n.h>

#include "testlib/s2n_testlib.h"

#include "tls/s2n_cipher_suites.h"
#include "stuffer/s2n_stuffer.h"
#include "crypto/s2n_cipher.h"
#include "utils/s2n_random.h"
#include "crypto/s2n_hmac.h"
#include "tls/s2n_record.h"
#include "tls/s2n_prf.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    struct s2n_connection *conn;
    uint8_t mac_key[] = "sample mac key";
    uint8_t aes128_key[] = "123456789012345";
    struct s2n_blob aes128 = {.data = aes128_key,.size = sizeof(aes128_key) };
    uint8_t random_data[S2N_LARGE_RECORD_LENGTH + 1];
    struct s2n_blob r = {.data = random_data, .size = sizeof(random_data)};

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    EXPECT_OK(s2n_get_urandom_data(&r));

    /* Peer and we are in sync */
    conn->server = &conn->secure;
    conn->client = &conn->secure;

    /* test the AES128 cipher with a SHA1 hash */
    conn->secure.cipher_suite->record_alg = &s2n_record_alg_aes128_sha;
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->init(&conn->secure.server_key));
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->init(&conn->secure.client_key));
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->set_encryption_key(&conn->secure.server_key, &aes128));
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->set_decryption_key(&conn->secure.client_key, &aes128));
    EXPECT_SUCCESS(s2n_hmac_init(&conn->secure.client_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
    EXPECT_SUCCESS(s2n_hmac_init(&conn->secure.server_record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
    conn->actual_protocol_version = S2N_TLS11;

    /* Align the record size, then subtract 20 bytes for the HMAC, 16 bytes for the explicit IV, and one byte
     * for the padding length byte.
     */
    int small_aligned_payload = S2N_SMALL_FRAGMENT_LENGTH - (S2N_SMALL_FRAGMENT_LENGTH % 16) - 20 - 16 - 1;
    int large_aligned_payload = S2N_LARGE_FRAGMENT_LENGTH - (S2N_LARGE_FRAGMENT_LENGTH % 16) - 20 - 16 - 1;
    int medium_aligned_payload = S2N_DEFAULT_FRAGMENT_LENGTH - (S2N_DEFAULT_FRAGMENT_LENGTH % 16) - 20 - 16 - 1;
    int bytes_written;

    /* Check the default: medium records */
    EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));
    EXPECT_SUCCESS(bytes_written = s2n_record_write(conn, TLS_APPLICATION_DATA, &r));
    EXPECT_EQUAL(bytes_written, medium_aligned_payload);

    /* Check explicitly small records */
    EXPECT_SUCCESS(s2n_connection_prefer_low_latency(conn));
    EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));
    EXPECT_SUCCESS(bytes_written = s2n_record_write(conn, TLS_APPLICATION_DATA, &r));
    EXPECT_EQUAL(bytes_written, small_aligned_payload);

    /* Check explicitly large records */
    EXPECT_SUCCESS(s2n_connection_prefer_throughput(conn));
    EXPECT_SUCCESS(s2n_stuffer_wipe(&conn->out));
    EXPECT_SUCCESS(bytes_written = s2n_record_write(conn, TLS_APPLICATION_DATA, &r));
    EXPECT_EQUAL(bytes_written, large_aligned_payload);

    /* Clean up */
    conn->secure.cipher_suite->record_alg = &s2n_record_alg_null; /* restore mutated null cipher suite */
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->destroy_key(&conn->secure.server_key));
    EXPECT_SUCCESS(conn->secure.cipher_suite->record_alg->cipher->destroy_key(&conn->secure.client_key));
    EXPECT_SUCCESS(s2n_connection_free(conn));

    #define ONE_BLOCK 1024
    #define ONE_HUNDRED_K 100000

    /* Test s2n_record_max_write_payload_size() have proper checks in place */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

        /* we deal with the default null cipher suite for now, as it makes reasoning
         * about easier s2n_record_max_write_payload_size(), as it incur 0 overheads */
        int size;
        server_conn->max_outgoing_fragment_length = ONE_BLOCK;
        EXPECT_SUCCESS(size = s2n_record_max_write_payload_size(server_conn));
        EXPECT_EQUAL(size, ONE_BLOCK);

        /* Trigger an overlarge payload by setting a maximum uint16_t value to max fragment length */
        server_conn->max_outgoing_fragment_length = UINT16_MAX;
        /* Check that we are bound by S2N_TLS_MAXIMUM_FRAGMENT_LENGTH */
        EXPECT_SUCCESS(size = s2n_record_max_write_payload_size(server_conn));
        EXPECT_EQUAL(size, S2N_TLS_MAXIMUM_FRAGMENT_LENGTH);

        /* trigger a payload that is under the limits */
        server_conn->max_outgoing_fragment_length = 0;
        EXPECT_FAILURE_WITH_ERRNO(s2n_record_max_write_payload_size(server_conn), S2N_ERR_FRAGMENT_LENGTH_TOO_SMALL);

        /* Test boundary cases */

        /* This is the theorical maximum mfl allowed */
        server_conn->max_outgoing_fragment_length = S2N_TLS_MAXIMUM_FRAGMENT_LENGTH;
        EXPECT_SUCCESS(s2n_record_max_write_payload_size(server_conn));

        /* This is not allowed, and reduced to S2N_TLS_MAXIMUM_FRAGMENT_LENGTH*/
        server_conn->max_outgoing_fragment_length++;
        EXPECT_SUCCESS(size = s2n_record_max_write_payload_size(server_conn));
        EXPECT_EQUAL(size, S2N_TLS_MAXIMUM_FRAGMENT_LENGTH);

        /* Test against different cipher suites */
        server_conn->actual_protocol_version = S2N_TLS13;
        server_conn->server->cipher_suite =  &s2n_tls13_aes_128_gcm_sha256;
        server_conn->max_outgoing_fragment_length = ONE_BLOCK;
        /* note that we are testing the current s2n_record_max_write_payload_size() behavior */
        EXPECT_SUCCESS(size = s2n_record_max_write_payload_size(server_conn));
        EXPECT_EQUAL(size, ONE_BLOCK
            - S2N_TLS_GCM_TAG_LEN /* S2N_TLS_GCM_TAG_LEN */
        );

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Test large fragment/record sending for TLS 1.3 */
    {
        struct s2n_connection *server_conn;
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        struct s2n_cipher_suite *cipher_suite = &s2n_tls13_aes_128_gcm_sha256;
        server_conn->actual_protocol_version = S2N_TLS13;
        server_conn->server->cipher_suite = cipher_suite;

        struct s2n_session_key *session_key = &server_conn->server->server_key;
        uint8_t *implicit_iv = server_conn->server->server_implicit_iv;

        /* init record algorithm */
        EXPECT_SUCCESS(cipher_suite->record_alg->cipher->init(session_key));
        S2N_BLOB_FROM_HEX(key, "0123456789abcdef0123456789abcdef");
        EXPECT_SUCCESS(cipher_suite->record_alg->cipher->set_encryption_key(session_key, &key));
        EXPECT_SUCCESS(cipher_suite->record_alg->cipher->set_decryption_key(session_key, &key));

        S2N_BLOB_FROM_HEX(iv, "0123456789abcdef01234567");

        /* copy iv bytes from input data */
        for (size_t i = 0; i < iv.size; i++) {
            implicit_iv[i] = iv.data[i];
        }

        /* Configure to use s2n maximum fragment / record settings */
        EXPECT_SUCCESS(s2n_connection_prefer_throughput(server_conn));

        /* Testing with a small blob */
        s2n_stack_blob(small_blob, ONE_BLOCK, ONE_BLOCK);

        int bytes_taken;

        const uint16_t TLS13_RECORD_OVERHEAD = 22;
        EXPECT_SUCCESS(bytes_taken = s2n_record_write(server_conn, TLS_APPLICATION_DATA, &small_blob));
        EXPECT_EQUAL(bytes_taken, ONE_BLOCK); /* we wrote the full blob size */
        EXPECT_EQUAL(server_conn->wire_bytes_out, ONE_BLOCK + TLS13_RECORD_OVERHEAD); /* bytes on the wire */

        /* Check we get a friendly error if we use s2n_record_write again */
        EXPECT_FAILURE_WITH_ERRNO(s2n_record_write(server_conn, TLS_APPLICATION_DATA, &small_blob), S2N_ERR_RECORD_STUFFER_NEEDS_DRAINING);
        EXPECT_SUCCESS(s2n_stuffer_wipe(&server_conn->out));
        EXPECT_SUCCESS(s2n_record_write(server_conn, TLS_APPLICATION_DATA, &small_blob));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&server_conn->out));

        /* Testing a big 100k blob to be written */
        s2n_stack_blob(big_blob, ONE_HUNDRED_K, ONE_HUNDRED_K);

        /* These tests serve a few purposes. The values acts as documentation
         * knowing the number of bytes taken and written. The numbers may not be most
         * optimal, but they act as snapshot tests here.
         *
         * More importantly, we want to make sure that s2n_record_write() doesn't error
         * on writting large records.
         **/
        server_conn->wire_bytes_out = 0;
        EXPECT_SUCCESS(bytes_taken = s2n_record_write(server_conn, TLS_APPLICATION_DATA, &big_blob));

        /* These values are subjected to change based on our implementation (which is currently not the true max frag len) */
        const uint16_t CURRENT_MAX_FRAG_LEN = 16368;
        EXPECT_EQUAL(bytes_taken, CURRENT_MAX_FRAG_LEN); /* plaintext bytes taken */
        EXPECT_EQUAL(server_conn->wire_bytes_out, CURRENT_MAX_FRAG_LEN + TLS13_RECORD_OVERHEAD); /* bytes sent on the wire */

        /* These are invariant regardless of s2n implementation */
        EXPECT_TRUE(bytes_taken <= S2N_TLS_MAXIMUM_FRAGMENT_LENGTH); /* Plaintext max size - 2^14 = 16384 */
        EXPECT_TRUE(bytes_taken <= (S2N_TLS_MAXIMUM_FRAGMENT_LENGTH + 255)); /* Max record size for TLS 1.3 - 2^14 + 255 = 16639 */
        EXPECT_TRUE(server_conn->wire_bytes_out <= S2N_TLS_MAXIMUM_RECORD_LENGTH);
        EXPECT_TRUE(server_conn->wire_bytes_out <= S2N_TLS13_MAXIMUM_RECORD_LENGTH);

        EXPECT_SUCCESS(s2n_stuffer_wipe(&server_conn->out));

        /* Now we escape the sandbox and attempt to get record_write to use a larger plaintext bytes */
        /* However, we bound the max fragment length based on the protocol specification */
        const uint16_t MAX_FORCED_OUTGOING_FRAGMENT_LENGTH = 16400;

        server_conn->max_outgoing_fragment_length = MAX_FORCED_OUTGOING_FRAGMENT_LENGTH; /* Trigger fragment length bounding */
        EXPECT_SUCCESS(bytes_taken = s2n_record_write(server_conn, TLS_APPLICATION_DATA, &big_blob));
        EXPECT_EQUAL(bytes_taken, CURRENT_MAX_FRAG_LEN);
        EXPECT_SUCCESS(s2n_stuffer_wipe(&server_conn->out));

        /* Force a generous 100k resize on the outgoing record stuffer */
        EXPECT_SUCCESS(s2n_stuffer_resize(&server_conn->out, ONE_HUNDRED_K));
        server_conn->max_outgoing_fragment_length = MAX_FORCED_OUTGOING_FRAGMENT_LENGTH;
        EXPECT_SUCCESS(bytes_taken = s2n_record_write(server_conn, TLS_APPLICATION_DATA, &big_blob));
        EXPECT_EQUAL(bytes_taken, CURRENT_MAX_FRAG_LEN);

        EXPECT_SUCCESS(s2n_stuffer_wipe(&server_conn->out));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    END_TEST();
}
