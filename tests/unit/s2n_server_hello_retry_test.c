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

#include "error/s2n_errno.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/extensions/s2n_key_share.h"
#include "tls/extensions/s2n_server_key_share.h"
#include "tls/extensions/s2n_server_supported_versions.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_internal.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_tls13_handshake.h"
#include "utils/s2n_bitmap.h"
#include "utils/s2n_result.h"

#define HELLO_RETRY_MSG_NO 1

const uint8_t SESSION_ID_SIZE = 1;
const uint8_t COMPRESSION_METHOD_SIZE = 1;

struct client_hello_context {
    int invocations;
    s2n_client_hello_cb_mode mode;
    bool mark_done;
};

int s2n_negotiate_poll_hello_retry(struct s2n_connection *server_conn,
        struct s2n_connection *client_conn,
        struct client_hello_context *client_hello_ctx)
{
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(client_conn, &blocked), S2N_ERR_IO_BLOCKED);

    /* complete the callback on the next call */
    client_hello_ctx->mark_done = true;
    EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

    /*
     * hello retry will invoke the s2n_negotiate twice but the callback should
     * be called once regardless of polling
     */
    EXPECT_EQUAL(client_hello_ctx->invocations, 1);

    return S2N_SUCCESS;
}

static int client_hello_detect_duplicate_calls(struct s2n_connection *conn, void *ctx)
{
    if (ctx == NULL) {
        return -1;
    }

    struct client_hello_context *client_hello_ctx = ctx;

    /* Incremet counter */
    client_hello_ctx->invocations++;
    EXPECT_EQUAL(client_hello_ctx->invocations, 1);
    if (client_hello_ctx->mode == S2N_CLIENT_HELLO_CB_NONBLOCKING) {
        EXPECT_SUCCESS(s2n_client_hello_cb_done(conn));
    }
    return 0;
}

int s2n_client_hello_poll_cb(struct s2n_connection *conn, void *ctx)
{
    struct client_hello_context *client_hello_ctx;
    if (ctx == NULL) {
        return -1;
    }
    client_hello_ctx = ctx;
    /* Increment counter to ensure that callback was invoked */
    client_hello_ctx->invocations++;

    if (client_hello_ctx->mark_done) {
        EXPECT_SUCCESS(s2n_client_hello_cb_done(conn));
        return S2N_SUCCESS;
    }

    return S2N_SUCCESS;
}

S2N_RESULT hello_retry_client_hello_cb_test()
{
    struct s2n_cert_chain_and_key *tls13_chain_and_key = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&tls13_chain_and_key,
            S2N_ECDSA_P384_PKCS1_CERT_CHAIN, S2N_ECDSA_P384_PKCS1_KEY));
    EXPECT_NOT_NULL(tls13_chain_and_key);

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(config);

    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, tls13_chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));

    DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
    DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
    EXPECT_NOT_NULL(server_conn);
    EXPECT_NOT_NULL(client_conn);

    EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
    EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

    struct s2n_test_io_pair io_pair = { 0 };
    EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
    EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

    /* Force HRR path */
    client_conn->security_policy_override = &security_policy_test_tls13_retry;

    /* setup the client hello callback */
    struct client_hello_context client_hello_ctx = { .invocations = 0,
        .mode = S2N_CLIENT_HELLO_CB_NONBLOCKING,
        .mark_done = false };
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config,
            s2n_client_hello_poll_cb, &client_hello_ctx));
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb_mode(config,
            S2N_CLIENT_HELLO_CB_NONBLOCKING));

    /* negotiate and make assertions */
    EXPECT_SUCCESS(s2n_negotiate_poll_hello_retry(server_conn, client_conn, &client_hello_ctx));

    /* check hello retry state */
    EXPECT_TRUE(IS_HELLO_RETRY_HANDSHAKE(client_conn));
    EXPECT_TRUE(IS_HELLO_RETRY_HANDSHAKE(server_conn));

    /* cleanup */
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls13_chain_and_key));
    EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    EXPECT_SUCCESS(s2n_enable_tls13_in_test());

    /* Send Hello Retry Request messages */
    {
        struct s2n_config *server_config;
        struct s2n_connection *server_conn;

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_allow_all_response_extensions(server_conn));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        struct s2n_stuffer *server_stuffer = &server_conn->handshake.io;

        uint32_t total = S2N_TLS_PROTOCOL_VERSION_LEN
                + S2N_TLS_RANDOM_DATA_LEN
                + SESSION_ID_SIZE
                + server_conn->session_id_len
                + S2N_TLS_CIPHER_SUITE_LEN
                + COMPRESSION_METHOD_SIZE;

        EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));
        server_conn->secure->cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;
        server_conn->kex_params.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];
        server_conn->kex_params.client_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_conn->kex_params.client_ecc_evp_params));

        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(server_conn));
        EXPECT_OK(s2n_conn_choose_state_machine(server_conn, S2N_TLS13));

        /* The client will need a key share extension to properly parse the hello */
        /* Total extension size + size of each extension */
        total += 2 + s2n_extensions_server_supported_versions_size(server_conn)
                + s2n_extensions_server_key_share_send_size(server_conn);

        EXPECT_TRUE(s2n_is_hello_retry_message(server_conn));
        EXPECT_SUCCESS(s2n_server_hello_retry_send(server_conn));

        EXPECT_EQUAL(s2n_stuffer_data_available(server_stuffer), total);

        EXPECT_NOT_NULL(server_conn->kex_params.server_ecc_evp_params.negotiated_curve);
        EXPECT_NULL(server_conn->kex_params.server_ecc_evp_params.evp_pkey);
        EXPECT_TRUE(memcmp(server_conn->handshake_params.server_random, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN) == 0);

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
    };

    /* Verify the requires_retry flag causes a retry to be sent */
    {
        struct s2n_config *conf;
        struct s2n_connection *conn;

        EXPECT_NOT_NULL(conf = s2n_config_new());
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, conf));

        EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(conn, S2N_TLS13));
        conn->secure->cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;
        conn->kex_params.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];
        conn->kex_params.client_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.client_ecc_evp_params));

        EXPECT_OK(s2n_conn_choose_state_machine(conn, S2N_TLS13));
        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(conn));

        EXPECT_TRUE(s2n_is_hello_retry_message(conn));
        EXPECT_SUCCESS(s2n_server_hello_retry_send(conn));

        EXPECT_SUCCESS(s2n_config_free(conf));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Retry requests with incorrect random data are not accepted */
    {
        struct s2n_config *conf;
        struct s2n_connection *conn;

        EXPECT_NOT_NULL(conf = s2n_config_new());
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, conf));

        struct s2n_stuffer *io = &conn->handshake.io;
        EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(conn, S2N_TLS13));

        /* protocol version */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS12 / 10));
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS12 % 10));

        /* random data */
        uint8_t bad_retry_random[S2N_TLS_RANDOM_DATA_LEN] = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(io, bad_retry_random, S2N_TLS_RANDOM_DATA_LEN));

        /* session id */
        uint8_t session_id[S2N_TLS_SESSION_ID_MAX_LEN] = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, S2N_TLS_SESSION_ID_MAX_LEN));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(io, session_id, S2N_TLS_SESSION_ID_MAX_LEN));

        /* cipher suites */
        EXPECT_SUCCESS(s2n_stuffer_write_uint16(io, 0x1301));

        /* no compression */
        EXPECT_SUCCESS(s2n_stuffer_write_uint8(io, 0));

        EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_recv(conn), S2N_ERR_BAD_MESSAGE);

        EXPECT_FALSE(s2n_is_hello_retry_message(conn));

        EXPECT_SUCCESS(s2n_config_free(conf));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Verify the client key share extension properly handles HelloRetryRequests */
    {
        struct s2n_connection *server_conn;
        struct s2n_connection *client_conn;

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        struct s2n_stuffer *extension_stuffer = &server_conn->handshake.io;

        EXPECT_SUCCESS(s2n_connection_allow_response_extension(client_conn, s2n_server_key_share_extension.iana_value));
        EXPECT_SUCCESS(s2n_connection_allow_response_extension(server_conn, s2n_server_key_share_extension.iana_value));

        POSIX_CHECKED_MEMCPY(server_conn->handshake_params.server_random, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN);
        EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));
        server_conn->kex_params.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];
        server_conn->kex_params.client_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];
        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(server_conn));
        EXPECT_OK(s2n_conn_choose_state_machine(server_conn, S2N_TLS13));
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&server_conn->kex_params.client_ecc_evp_params));
        EXPECT_SUCCESS(s2n_extensions_server_key_share_send(server_conn, extension_stuffer));

        S2N_STUFFER_READ_EXPECT_EQUAL(extension_stuffer, TLS_EXTENSION_KEY_SHARE, uint16);
        /* 4 = S2N_SIZE_OF_EXTENSION_TYPE + S2N_SIZE_OF_EXTENSION_DATA_SIZE */
        S2N_STUFFER_READ_EXPECT_EQUAL(extension_stuffer, s2n_extensions_server_key_share_send_size(server_conn) - 4, uint16);

        client_conn->kex_params.client_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&client_conn->kex_params.client_ecc_evp_params));

        /* Setup the client to receive a HelloRetryRequest */
        POSIX_CHECKED_MEMCPY(client_conn->handshake_params.server_random, hello_retry_req_random, S2N_TLS_RANDOM_DATA_LEN);
        EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(client_conn, S2N_TLS13));

        /* Setup the handshake type and message number to simulate a condition where a HelloRetry should be sent */
        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(client_conn));
        EXPECT_OK(s2n_conn_choose_state_machine(client_conn, S2N_TLS13));
        EXPECT_SUCCESS(s2n_set_hello_retry_required(client_conn));

        /* Parse the key share */
        EXPECT_SUCCESS(s2n_extensions_server_key_share_recv(client_conn, extension_stuffer));
        EXPECT_EQUAL(s2n_stuffer_data_available(extension_stuffer), 0);

        /* Server negotiated curve value will be non-null, if the extension succeeded */
        EXPECT_NOT_NULL(client_conn->kex_params.server_ecc_evp_params.negotiated_curve);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    };

    /* Verify that the hash transcript recreation function correctly takes the existing ClientHello1
     * hash, and generates a synthetic message. */
    {
        struct s2n_config *conf;
        struct s2n_connection *conn;

        EXPECT_NOT_NULL(conf = s2n_config_new());
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, conf));

        conn->server_protocol_version = S2N_TLS13;
        conn->secure->cipher_suite = &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256;
        conn->kex_params.server_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];
        conn->kex_params.client_ecc_evp_params.negotiated_curve = s2n_all_supported_curves_list[0];
        EXPECT_SUCCESS(s2n_ecc_evp_generate_ephemeral_key(&conn->kex_params.client_ecc_evp_params));

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
        struct s2n_blob compare_blob = { 0 };

        DEFER_CLEANUP(struct s2n_hash_state client_hello1_hash = { 0 }, s2n_hash_free);
        EXPECT_SUCCESS(s2n_hash_new(&client_hello1_hash));
        POSIX_GUARD_RESULT(s2n_handshake_copy_hash_state(conn, keys.hash_algorithm, &client_hello1_hash));

        uint8_t client_hello1_digest_out[S2N_MAX_DIGEST_LEN] = { 0 };
        EXPECT_SUCCESS(s2n_hash_digest(&client_hello1_hash, client_hello1_digest_out, hash_digest_length));

        EXPECT_SUCCESS(s2n_blob_init(&compare_blob, client_hello1_digest_out, hash_digest_length));
        S2N_BLOB_EXPECT_EQUAL(client_hello1_expected_hash, compare_blob);

        EXPECT_SUCCESS(s2n_server_hello_retry_recreate_transcript(conn));

        DEFER_CLEANUP(struct s2n_hash_state recreated_hash = { 0 }, s2n_hash_free);
        uint8_t recreated_transcript_digest_out[S2N_MAX_DIGEST_LEN] = { 0 };
        EXPECT_SUCCESS(s2n_hash_new(&recreated_hash));
        POSIX_GUARD_RESULT(s2n_handshake_copy_hash_state(conn, keys.hash_algorithm, &recreated_hash));
        EXPECT_SUCCESS(s2n_hash_digest(&recreated_hash, recreated_transcript_digest_out, hash_digest_length));

        EXPECT_SUCCESS(s2n_blob_init(&compare_blob, recreated_transcript_digest_out, hash_digest_length));
        S2N_BLOB_EXPECT_EQUAL(synthetic_message_with_ch1_expected_hash, compare_blob);

        EXPECT_SUCCESS(s2n_config_free(conf));
        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Send and receive Hello Retry Request messages */
    {
        struct s2n_config *server_config;
        struct s2n_config *client_config;

        struct s2n_connection *server_conn;
        struct s2n_connection *client_conn;

        struct s2n_cert_chain_and_key *tls13_chain_and_key;

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(client_config = s2n_config_new());

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default_tls13"));

        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&tls13_chain_and_key,
                S2N_ECDSA_P384_PKCS1_CERT_CHAIN, S2N_ECDSA_P384_PKCS1_KEY));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, tls13_chain_and_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, tls13_chain_and_key));

        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));
        struct client_hello_context client_hello_ctx = { .invocations = 0, .mode = S2N_CLIENT_HELLO_CB_BLOCKING };
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(server_config, client_hello_detect_duplicate_calls, &client_hello_ctx));

        EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(server_conn, S2N_TLS13));
        EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(client_conn, S2N_TLS13));

        /* Force HRR path */
        client_conn->security_policy_override = &security_policy_test_tls13_retry;

        /* Send the first CH message */
        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                s2n_stuffer_data_available(&client_conn->handshake.io)));

        /* Receive the CH and send an HRR, which will execute the HRR code paths */
        EXPECT_EQUAL(client_hello_ctx.invocations, 0);
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));
        EXPECT_EQUAL(client_hello_ctx.invocations, 1);

        EXPECT_TRUE(s2n_is_hello_retry_handshake(server_conn));
        EXPECT_SUCCESS(s2n_set_connection_hello_retry_flags(server_conn));
        EXPECT_TRUE(s2n_is_hello_retry_message(server_conn));

        EXPECT_SUCCESS(s2n_server_hello_retry_send(server_conn));

        EXPECT_SUCCESS(s2n_stuffer_wipe(&client_conn->handshake.io));
        EXPECT_SUCCESS(s2n_stuffer_copy(&server_conn->handshake.io, &client_conn->handshake.io,
                s2n_stuffer_data_available(&server_conn->handshake.io)));
        client_conn->handshake.message_number = HELLO_RETRY_MSG_NO;
        EXPECT_SUCCESS(s2n_server_hello_recv(client_conn));

        /* Send the second CH message */
        EXPECT_SUCCESS(s2n_client_hello_send(client_conn));
        EXPECT_SUCCESS(s2n_stuffer_wipe(&server_conn->handshake.io));
        EXPECT_SUCCESS(s2n_stuffer_copy(&client_conn->handshake.io, &server_conn->handshake.io,
                s2n_stuffer_data_available(&client_conn->handshake.io)));

        /* Verify that receiving the second CH message does not execute the callback */
        EXPECT_SUCCESS(s2n_client_hello_recv(server_conn));
        EXPECT_EQUAL(client_hello_ctx.invocations, 1);

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls13_chain_and_key));
    };

    /* Send and receive Hello Retry Request messages, test for non blocking client hello callback */
    {
        struct s2n_config *server_config;
        struct s2n_config *client_config;

        struct s2n_connection *server_conn;
        struct s2n_connection *client_conn;

        struct s2n_cert_chain_and_key *tls13_chain_and_key;

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_NOT_NULL(client_config = s2n_config_new());

        EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default_tls13"));

        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(server_config));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));

        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&tls13_chain_and_key,
                S2N_ECDSA_P384_PKCS1_CERT_CHAIN, S2N_ECDSA_P384_PKCS1_KEY));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, tls13_chain_and_key));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, tls13_chain_and_key));

        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Force HRR path */
        client_conn->security_policy_override = &security_policy_test_tls13_retry;

        /* setup the client hello callback */
        struct client_hello_context client_hello_ctx = { .invocations = 0,
            .mode = S2N_CLIENT_HELLO_CB_NONBLOCKING };
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(server_config,
                client_hello_detect_duplicate_calls, &client_hello_ctx));
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb_mode(server_config,
                S2N_CLIENT_HELLO_CB_NONBLOCKING));

        /* ensure that handshake succeeds via HRR path using non_blocking CH */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(server_conn->handshake.handshake_type & HELLO_RETRY_REQUEST);
        EXPECT_EQUAL(client_hello_ctx.invocations, 1);

        EXPECT_NOT_NULL(s2n_connection_get_client_hello(server_conn));
        EXPECT_TRUE(IS_HELLO_RETRY_HANDSHAKE(client_conn));
        EXPECT_TRUE(IS_HELLO_RETRY_HANDSHAKE(server_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_config_free(client_config));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls13_chain_and_key));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    };

    /* Hello Retry Request + (poll and no-poll) client hello callback */
    {
        EXPECT_OK(hello_retry_client_hello_cb_test());
    };

    /* Test s2n_set_hello_retry_required correctly sets the handshake type to HELLO_RETRY_REQUEST,
     * when conn->actual_protocol_version is set to TLS1.3 version */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_all_protocol_versions(conn, S2N_TLS13));

        EXPECT_SUCCESS(s2n_set_hello_retry_required(conn));
        EXPECT_TRUE(conn->handshake.handshake_type & HELLO_RETRY_REQUEST);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /* Test s2n_set_hello_retry_required raises a S2N_ERR_INVALID_HELLO_RETRY error
     * when conn->actual_protocol_version is less than TLS1.3 */
    {
        struct s2n_connection *conn;
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        conn->actual_protocol_version = S2N_TLS12;

        EXPECT_FAILURE_WITH_ERRNO(s2n_set_hello_retry_required(conn), S2N_ERR_INVALID_HELLO_RETRY);
        EXPECT_FALSE(conn->handshake.handshake_type & HELLO_RETRY_REQUEST);

        EXPECT_SUCCESS(s2n_connection_free(conn));
    };

    /*
     *= https://tools.ietf.org/rfc/rfc8446#section-4.1.4
     *= type=test
     *# Clients MUST abort the handshake with an
     *# "illegal_parameter" alert if the HelloRetryRequest would not result
     *# in any change in the ClientHello.
     */
    {
        const struct s2n_security_policy *security_policy = NULL;
        EXPECT_SUCCESS(s2n_find_security_policy_from_version("20201021", &security_policy));
        EXPECT_NOT_NULL(security_policy);
        const struct s2n_ecc_named_curve *test_curve = security_policy->ecc_preferences->ecc_curves[0];

        /**
         * Retry for key share is valid
         *
         *= https://tools.ietf.org/rfc/rfc8446#4.2.8
         *= type=test
         *# and (2) the selected_group field does not
         *# correspond to a group which was provided in the "key_share" extension
         *# in the original ClientHello.
         **/
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "20201021"));
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;

            conn->kex_params.server_ecc_evp_params.negotiated_curve = test_curve;

            /* Server requested key share is NOT present: allow retry */
            EXPECT_SUCCESS(s2n_server_hello_retry_recv(conn));

            /* Server requested key share is present: do NOT allow retry */
            conn->kex_params.client_ecc_evp_params.negotiated_curve = test_curve;
            conn->kex_params.client_ecc_evp_params.evp_pkey = EVP_PKEY_new();
            EXPECT_NOT_NULL(conn->kex_params.client_ecc_evp_params.evp_pkey);
            EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_retry_recv(conn),
                    S2N_ERR_INVALID_HELLO_RETRY);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };

        /* Retry for multiple reasons is valid */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "20201021"));
            conn->actual_protocol_version = S2N_TLS13;
            conn->secure->cipher_suite = &s2n_tls13_aes_256_gcm_sha384;

            conn->kex_params.server_ecc_evp_params.negotiated_curve = test_curve;

            /* All retry conditions met: allow retry */
            conn->early_data_state = S2N_EARLY_DATA_REQUESTED;
            EXPECT_SUCCESS(s2n_server_hello_retry_recv(conn));

            /* No retry conditions met: do NOT allow retry */
            conn->early_data_state = S2N_EARLY_DATA_NOT_REQUESTED;
            conn->kex_params.client_ecc_evp_params.negotiated_curve = test_curve;
            conn->kex_params.client_ecc_evp_params.evp_pkey = EVP_PKEY_new();
            EXPECT_NOT_NULL(conn->kex_params.client_ecc_evp_params.evp_pkey);
            EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_retry_recv(conn),
                    S2N_ERR_INVALID_HELLO_RETRY);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        };
    };

    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    END_TEST();
}
