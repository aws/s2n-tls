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

#include "testlib/s2n_testlib.h"

#include "tls/extensions/s2n_cookie.h"
#include "tls/extensions/s2n_key_share.h"
#include "tls/extensions/s2n_server_supported_versions.h"
#include "tls/extensions/s2n_server_key_share.h"

#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_tls13_handshake.h"

#include "error/s2n_errno.h"

#define TEST_COOKIE_SIZE    32

const uint8_t SESSION_ID_SIZE = 1;
const uint8_t COMPRESSION_METHOD_SIZE = 1;

/* from RFC: https://tools.ietf.org/html/rfc8446#section-4.1.3*/
const uint8_t hello_retry_request_random_test_buffer[S2N_TLS_RANDOM_DATA_LEN] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
};

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_SUCCESS(s2n_enable_tls13());

    /* Send and receive Hello Retry Request messages */
    {
        struct s2n_config *server_config;
        struct s2n_config *client_config;

        struct s2n_connection *server_conn;
        struct s2n_connection *client_conn;

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        struct s2n_stuffer *server_stuffer = &server_conn->handshake.io;

        uint32_t total = S2N_TLS_PROTOCOL_VERSION_LEN
            + S2N_TLS_RANDOM_DATA_LEN
            + SESSION_ID_SIZE
            + server_conn->session_id_len
            + S2N_TLS_CIPHER_SUITE_LEN
            + COMPRESSION_METHOD_SIZE;

        server_conn->actual_protocol_version = S2N_TLS13;
        server_conn->secure.cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;
        server_conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
        server_conn->secure.client_ecc_evp_params[0].negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_conn->secure.client_ecc_evp_params[0]));

        server_conn->handshake.server_requires_hrr = 1;

        /* The client will need a key share extension to properly parse the hello */
        /* Total extension size + size of each extension */
        total += 2 + s2n_extensions_server_supported_versions_size(server_conn) + s2n_extensions_server_key_share_send_size(server_conn);

        EXPECT_SUCCESS(s2n_server_hello_send(server_conn));

        EXPECT_EQUAL(s2n_stuffer_data_available(server_stuffer), total);

        /* Copy server stuffer to client stuffer */
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io, total));

        /* Test s2n_server_hello_recv() */
        struct s2n_stuffer *client_stuffer = &client_conn->handshake.io;
        client_conn->secure.client_ecc_evp_params[0].negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_conn->secure.client_ecc_evp_params[0]));

        memcpy_check(client_conn->secure.server_random, hello_retry_request_random_test_buffer, S2N_TLS_RANDOM_DATA_LEN);
        client_conn->server_protocol_version = S2N_TLS13;
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));

        printf("XXX data avail %d\n", s2n_stuffer_data_available(client_stuffer));
        EXPECT_EQUAL(s2n_stuffer_data_available(client_stuffer), 0);

        EXPECT_EQUAL(client_conn->handshake.client_received_hrr, 1);
        EXPECT_EQUAL(server_conn->handshake.server_sent_hrr, 1);

        /* Verify that multiple hello retry messages will fail */
        EXPECT_SUCCESS(s2n_stuffer_reread(client_stuffer));
        EXPECT_FAILURE(s2n_server_hello_recv(client_conn));

        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    }

    /* Verify the requires_retry flag causes a retry to be sent */
    {
        struct s2n_config *conf;
        struct s2n_connection *conn;

        EXPECT_NOT_NULL(conf = s2n_config_new());
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, conf));

        conn->client_protocol_version = S2N_TLS13;
        conn->server_protocol_version = S2N_TLS13;
        conn->actual_protocol_version = S2N_TLS13;

        conn->secure.cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;
        conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
        conn->secure.client_ecc_evp_params[0].negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->secure.client_ecc_evp_params[0]));

        EXPECT_SUCCESS(s2n_server_should_retry(conn));
        EXPECT_SUCCESS(s2n_server_hello_send(conn));

        EXPECT_EQUAL(conn->handshake.server_sent_hrr, 1);

        /* If the server has to send another HelloRetryRequest, then it should fail the connection */
        EXPECT_FAILURE(s2n_server_should_retry(conn));

        EXPECT_SUCCESS(s2n_config_free(conf));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Retry requests with incorrect random data are not accepted */
    {
        struct s2n_config *conf;
        struct s2n_connection *conn;

        EXPECT_NOT_NULL(conf = s2n_config_new());
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, conf));

        struct s2n_stuffer *io = &conn->handshake.io;
        conn->server_protocol_version = S2N_TLS13;

        /* protocol version */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS12 / 10));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS12 % 10));

        /* random data */
        uint8_t bad_retry_random[S2N_TLS_RANDOM_DATA_LEN] = {0};
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(io, bad_retry_random, S2N_TLS_RANDOM_DATA_LEN));

        /* session id */
        uint8_t session_id[S2N_TLS_SESSION_ID_MAX_LEN] = {0};
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS_SESSION_ID_MAX_LEN));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(io, session_id, S2N_TLS_SESSION_ID_MAX_LEN));

        /* cipher suites */
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(io, 0x1301));

        /* no compression */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, 0));

        EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_recv(conn), S2N_ERR_BAD_MESSAGE);

        EXPECT_EQUAL(conn->handshake.client_received_hrr, 0);

        EXPECT_SUCCESS(s2n_config_free(conf));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Retry requests without a supported version extension are not accepted */
    {
        struct s2n_config *conf;
        struct s2n_connection *conn;

        EXPECT_NOT_NULL(conf = s2n_config_new());
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, conf));

        struct s2n_stuffer *io = &conn->handshake.io;
        conn->server_protocol_version = S2N_TLS13;

        /* protocol version */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS12 / 10));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS12 % 10));

        /* random data */
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(io, hello_retry_request_random_test_buffer, S2N_TLS_RANDOM_DATA_LEN));

        /* session id */
        uint8_t session_id[S2N_TLS_SESSION_ID_MAX_LEN] = {0};
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS_SESSION_ID_MAX_LEN));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(io, session_id, S2N_TLS_SESSION_ID_MAX_LEN));

        /* cipher suites */
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(io, (0x13 << 8) + 0x01));

        /* no compression */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, 0));

        EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_recv(conn), S2N_ERR_BAD_MESSAGE);

        EXPECT_EQUAL(conn->handshake.client_received_hrr, 0);

        EXPECT_SUCCESS(s2n_config_free(conf));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Verify the client key share extension properly handles HelloRetryRequests */
    {
        struct s2n_connection *server_send_conn;
        struct s2n_connection *client_recv_conn;

        EXPECT_NOT_NULL(server_send_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_recv_conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_stuffer* extension_stuffer = &server_send_conn->handshake.io;

        server_send_conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
        server_send_conn->secure.client_ecc_evp_params[0].negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
        EXPECT_SUCCESS(s2n_server_should_retry(server_send_conn));
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_send_conn->secure.client_ecc_evp_params[0]));
        EXPECT_SUCCESS(s2n_extensions_server_key_share_send(server_send_conn, extension_stuffer));

        S2N_STUFFER_READ_EXPECT_EQUAL(extension_stuffer, TLS_EXTENSION_KEY_SHARE, uint16);
        /* 4 = S2N_SIZE_OF_EXTENSION_TYPE + S2N_SIZE_OF_EXTENSION_DATA_SIZE */
        S2N_STUFFER_READ_EXPECT_EQUAL(extension_stuffer, s2n_extensions_server_key_share_send_size(server_send_conn) - 4, uint16);

        client_recv_conn->secure.client_ecc_evp_params[0].negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_recv_conn->secure.client_ecc_evp_params[0]));

        /* Parse key share */

        /* Setup the client to receive a HelloRetryRequest */
        memcpy_check(client_recv_conn->secure.server_random, hello_retry_request_random_test_buffer, S2N_TLS_RANDOM_DATA_LEN);
        client_recv_conn->server_protocol_version = S2N_TLS13;
        EXPECT_SUCCESS(s2n_extensions_server_key_share_recv(client_recv_conn, extension_stuffer));
        EXPECT_EQUAL(s2n_stuffer_data_available(extension_stuffer), 0);

        /* This curve will be NULL even though the extension succeeded */
        EXPECT_NULL(client_recv_conn->secure.server_ecc_evp_params.negotiated_curve);

        /* When client side HelloRetryRequests are supported we need to verify the selected group was set correctly */

        EXPECT_SUCCESS(s2n_connection_free(server_send_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_recv_conn));
    }

    /* Verify that the hash transcript recreation function correctly takes the existing ClientHello1
     * hash, and generates a synthetic message. */
    {
        struct s2n_config *conf;
        struct s2n_connection *conn;

        EXPECT_NOT_NULL(conf = s2n_config_new());
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, conf));

        conn->server_protocol_version = S2N_TLS13;
        conn->secure.cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;
        conn->secure.server_ecc_evp_params.negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
        conn->secure.client_ecc_evp_params[0].negotiated_curve = s2n_ecc_evp_supported_curves_list[0];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->secure.client_ecc_evp_params[0]));

        /* This blob is taken from the functional test RFC. That RFC does not actually provide hash transcript
         * values, so the expected hashes are taken from what our hash functions generated and the hash
         * generated from the transcript recreation.
         * https://tools.ietf.org/html/rfc8448#section-5 */
        S2N_BLOB_FROM_HEX(client_hello1,
            "010000c00303cb34ecb1e78163"
            "ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283"
            "024dece7000006130113031302010000910000000b"
            "0009000006736572766572ff01000100000a001400"
            "12001d001700180019010001010102010301040023"
            "0000003300260024001d002099381de560e4bd43d2"
            "3d8e435a7dbafeb3c06e51c13cae4d5413691e529a"
            "af2c002b0003020304000d0020001e040305030603"
            "020308040805080604010501060102010402050206"
            "020202002d00020101001c00024001");

        S2N_BLOB_FROM_HEX(client_hello1_expected_hash,
            "4db255f30da09a407c841720be831a06a5aa9b3662a5f44267d37706b73c2b8c");

        S2N_BLOB_FROM_HEX(synthetic_message_with_ch1_expected_hash,
            "ff1135ed878322e29699da3e451d2f08bf11fc693038769978e75bb63304a225");

        EXPECT_SUCCESS(s2n_conn_update_handshake_hashes(conn, &client_hello1));

        s2n_tls13_connection_keys(keys, conn);
        uint8_t hash_digest_length = keys.size;
        struct s2n_blob compare_blob;

        struct s2n_hash_state hash_state, client_hello1_hash;
        GUARD(s2n_handshake_get_hash_state(conn, keys.hash_algorithm, &hash_state));

        uint8_t client_hello1_digest_out[S2N_MAX_DIGEST_LEN];
        EXPECT_SUCCESS(s2n_hash_new(&client_hello1_hash));
        EXPECT_SUCCESS(s2n_hash_copy(&client_hello1_hash, &hash_state));
        EXPECT_SUCCESS(s2n_hash_digest(&client_hello1_hash, client_hello1_digest_out, hash_digest_length));
        EXPECT_SUCCESS(s2n_hash_free(&client_hello1_hash));

        EXPECT_SUCCESS(s2n_blob_init(&compare_blob, client_hello1_digest_out, hash_digest_length));
        S2N_BLOB_EXPECT_EQUAL(client_hello1_expected_hash, compare_blob);

        EXPECT_SUCCESS(s2n_server_hello_retry_recreate_transcript(conn));

        struct s2n_hash_state recreated_hash;
        uint8_t recreated_transcript_digest_out[S2N_MAX_DIGEST_LEN];
        GUARD(s2n_handshake_get_hash_state(conn, keys.hash_algorithm, &hash_state));
        EXPECT_SUCCESS(s2n_hash_new(&recreated_hash));
        EXPECT_SUCCESS(s2n_hash_copy(&recreated_hash, &hash_state));
        EXPECT_SUCCESS(s2n_hash_digest(&recreated_hash, recreated_transcript_digest_out, hash_digest_length));
        EXPECT_SUCCESS(s2n_hash_free(&recreated_hash));

        EXPECT_SUCCESS(s2n_blob_init(&compare_blob, recreated_transcript_digest_out, hash_digest_length));
        S2N_BLOB_EXPECT_EQUAL(synthetic_message_with_ch1_expected_hash, compare_blob);

        EXPECT_SUCCESS(s2n_config_free(conf));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    EXPECT_SUCCESS(s2n_disable_tls13());

    END_TEST();
}
