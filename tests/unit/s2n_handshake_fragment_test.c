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

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

#define S2N_FRAG_LEN_SMALLER_THAN_CH 150

#define TIMES_TO_BLOCK 3

/* Handling blocked IO is important to fragmentation.
 * Even if we fail to read or write one fragment, we should be able to
 * retry and eventually write all fragments.
 *
 * Therefore, wrap our normal test IO in special logic to block
 * repeatedly on every read and write call.
 */
struct s2n_io_wrapper {
    uint8_t times_recv_blocked;
    uint8_t times_send_blocked;
    s2n_recv_fn *inner_recv;
    s2n_send_fn *inner_send;
    void *inner_recv_ctx;
    void *inner_send_ctx;
};

struct s2n_io_wrapper_pair {
    struct s2n_io_wrapper client;
    struct s2n_io_wrapper server;
};

static int s2n_blocking_read(void *io_context, uint8_t *buf, uint32_t len)
{
    struct s2n_io_wrapper *context = (struct s2n_io_wrapper *) io_context;
    if (context->times_recv_blocked < TIMES_TO_BLOCK) {
        context->times_recv_blocked++;
        errno = EAGAIN;
        return -1;
    }
    context->times_recv_blocked = 0;
    return context->inner_recv(context->inner_recv_ctx, buf, len);
}

static int s2n_blocking_write(void *io_context, const uint8_t *buf, uint32_t len)
{
    struct s2n_io_wrapper *context = (struct s2n_io_wrapper *) io_context;
    if (context->times_send_blocked < TIMES_TO_BLOCK) {
        context->times_send_blocked++;
        errno = EAGAIN;
        return -1;
    }
    context->times_send_blocked = 0;
    return context->inner_send(context->inner_send_ctx, buf, len);
}

static int s2n_client_hello_test_fn(struct s2n_connection *conn, void *ctx)
{
    return S2N_SUCCESS;
}

struct s2n_async_pkey_op *pkey_op = NULL;
static int async_pkey_test_fn(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    pkey_op = op;

    /* Extract pkey */
    struct s2n_cert_chain_and_key *chain_and_key = s2n_connection_get_selected_cert(conn);
    POSIX_ENSURE_REF(chain_and_key);

    s2n_cert_private_key *pkey = s2n_cert_chain_and_key_get_private_key(chain_and_key);
    POSIX_ENSURE_REF(pkey);

    /* Perform, but don't apply yet. We want the handshake to block. */
    EXPECT_SUCCESS(s2n_async_pkey_op_perform(pkey_op, pkey));

    return S2N_SUCCESS;
}

static struct s2n_config *s2n_test_config_new(struct s2n_cert_chain_and_key *chain_and_key)
{
    struct s2n_config *config = s2n_config_new();
    PTR_GUARD_POSIX(s2n_config_set_cipher_preferences(config, "default_tls13"));
    PTR_GUARD_POSIX(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    PTR_GUARD_POSIX(s2n_config_disable_x509_verification(config));
    return config;
}

static S2N_RESULT s2n_connections_set_blocking_io_pair(struct s2n_io_wrapper_pair *io_context,
        struct s2n_connection *client_conn, struct s2n_connection *server_conn, struct s2n_test_io_stuffer_pair *io_pair)
{
    RESULT_GUARD(s2n_io_stuffer_pair_init(io_pair));
    RESULT_GUARD(s2n_connections_set_io_stuffer_pair(client_conn, server_conn, io_pair));

    io_context->client = (struct s2n_io_wrapper){
        .inner_recv = client_conn->recv,
        .inner_send = client_conn->send,
        .inner_recv_ctx = client_conn->recv_io_context,
        .inner_send_ctx = client_conn->send_io_context,
    };

    RESULT_GUARD_POSIX(s2n_connection_set_recv_cb(client_conn, s2n_blocking_read));
    RESULT_GUARD_POSIX(s2n_connection_set_recv_ctx(client_conn, &io_context->client));
    RESULT_GUARD_POSIX(s2n_connection_set_send_cb(client_conn, s2n_blocking_write));
    RESULT_GUARD_POSIX(s2n_connection_set_send_ctx(client_conn, &io_context->client));

    io_context->server = (struct s2n_io_wrapper){
        .inner_recv = server_conn->recv,
        .inner_send = server_conn->send,
        .inner_recv_ctx = server_conn->recv_io_context,
        .inner_send_ctx = server_conn->send_io_context,
    };

    RESULT_GUARD_POSIX(s2n_connection_set_recv_cb(server_conn, s2n_blocking_read));
    RESULT_GUARD_POSIX(s2n_connection_set_recv_ctx(server_conn, &io_context->server));
    RESULT_GUARD_POSIX(s2n_connection_set_send_cb(server_conn, s2n_blocking_write));
    RESULT_GUARD_POSIX(s2n_connection_set_send_ctx(server_conn, &io_context->server));

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const uint32_t fragment_sizes[] = {
        1,
        2,
        TLS_HANDSHAKE_HEADER_LENGTH,
        TLS_HANDSHAKE_HEADER_LENGTH + 1,
        S2N_FRAG_LEN_SMALLER_THAN_CH,
        S2N_DEFAULT_FRAGMENT_LENGTH,
    };

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_ECDSA_P384_PKCS1_CERT_CHAIN, S2N_ECDSA_P384_PKCS1_KEY));

    /* Test sending and receiving fragmented handshake messages */
    for (size_t i = 0; i < s2n_array_len(fragment_sizes); i++) {
        /* Use different fragment sizes for the client and server,
         * to ensure that they handle outgoing and incoming fragment sizes separately.
         */
        uint32_t server_fragment_size = fragment_sizes[i];
        uint32_t client_fragment_size = fragment_sizes[i] + 1;

        /* Test: basic TLS1.3 handshake with fragmented messages */
        if (s2n_is_tls13_fully_supported()) {
            DEFER_CLEANUP(struct s2n_config *config = s2n_test_config_new(chain_and_key),
                    s2n_config_ptr_free);

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            server_conn->max_outgoing_fragment_length = server_fragment_size;

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            client_conn->max_outgoing_fragment_length = client_fragment_size;

            struct s2n_io_wrapper_pair io_wrapper = { 0 };
            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_connections_set_blocking_io_pair(&io_wrapper, client_conn, server_conn, &io_pair));

            while (s2n_negotiate_test_server_and_client(server_conn, client_conn) < S2N_SUCCESS) {
                POSIX_ENSURE(s2n_errno, S2N_ERR_IO_BLOCKED);
            }

            /* Handshake completed */
            EXPECT_TRUE(IS_NEGOTIATED(server_conn));
            EXPECT_TRUE(IS_NEGOTIATED(client_conn));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), APPLICATION_DATA);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), APPLICATION_DATA);

            /* TLS1.3 negotiated */
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);
            EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);
        };

        /* Test: basic TLS1.2 handshake with fragmented messages */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_test_config_new(chain_and_key),
                    s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all_tls12"));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            server_conn->max_outgoing_fragment_length = server_fragment_size;

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            client_conn->max_outgoing_fragment_length = client_fragment_size;

            struct s2n_io_wrapper_pair io_wrapper = { 0 };
            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_connections_set_blocking_io_pair(&io_wrapper, client_conn, server_conn, &io_pair));

            while (s2n_negotiate_test_server_and_client(server_conn, client_conn) < S2N_SUCCESS) {
                POSIX_ENSURE(s2n_errno, S2N_ERR_IO_BLOCKED);
            }

            /* Handshake completed */
            EXPECT_TRUE(IS_NEGOTIATED(server_conn));
            EXPECT_TRUE(IS_NEGOTIATED(client_conn));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), APPLICATION_DATA);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), APPLICATION_DATA);

            /* TLS1.2 negotiated */
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
            EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
        };

        /* Test: handshake with reader async callback and fragmented messages
         *
         * Resuming the handshake after an async callback follows a different code path.
         *
         * We use the client hello callback because it triggers when reading the client hello message.
         */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_test_config_new(chain_and_key),
                    s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, s2n_client_hello_test_fn, NULL));
            EXPECT_SUCCESS(s2n_config_set_client_hello_cb_mode(config, S2N_CLIENT_HELLO_CB_NONBLOCKING));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            server_conn->max_outgoing_fragment_length = server_fragment_size;

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            client_conn->max_outgoing_fragment_length = client_fragment_size;

            struct s2n_io_wrapper_pair io_wrapper = { 0 };
            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_connections_set_blocking_io_pair(&io_wrapper, client_conn, server_conn, &io_pair));

            bool async_block_triggered = false;
            while (s2n_negotiate_test_server_and_client(server_conn, client_conn) < S2N_SUCCESS) {
                if (s2n_errno == S2N_ERR_ASYNC_BLOCKED) {
                    EXPECT_SUCCESS(s2n_client_hello_cb_done(server_conn));
                    async_block_triggered = true;
                } else {
                    POSIX_ENSURE(s2n_errno, S2N_ERR_IO_BLOCKED);
                }
            }
            EXPECT_TRUE(async_block_triggered);

            /* Handshake completed */
            EXPECT_TRUE(IS_NEGOTIATED(server_conn));
            EXPECT_TRUE(IS_NEGOTIATED(client_conn));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), APPLICATION_DATA);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), APPLICATION_DATA);
        };

        /* Test: handshake with writer async callback and fragmented messages
         *
         * Resuming the handshake after an async callback follows a different code path.
         *
         * We use the async pkey callback because it triggers when writing the server cert verify message.
         * It would also trigger for the client when reading the server cert verify message,
         * except that this test disables x509 validation.
         */
        {
            DEFER_CLEANUP(struct s2n_config *config = s2n_test_config_new(chain_and_key),
                    s2n_config_ptr_free);
            EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(config, async_pkey_test_fn));

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            server_conn->max_outgoing_fragment_length = server_fragment_size;

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            client_conn->max_outgoing_fragment_length = client_fragment_size;

            struct s2n_io_wrapper_pair io_wrapper = { 0 };
            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_connections_set_blocking_io_pair(&io_wrapper, client_conn, server_conn, &io_pair));

            bool async_block_triggered = false;
            while (s2n_negotiate_test_server_and_client(server_conn, client_conn) < S2N_SUCCESS) {
                if (s2n_errno == S2N_ERR_ASYNC_BLOCKED) {
                    EXPECT_SUCCESS(s2n_async_pkey_op_apply(pkey_op, server_conn));
                    EXPECT_SUCCESS(s2n_async_pkey_op_free(pkey_op));
                    async_block_triggered = true;
                } else {
                    POSIX_ENSURE(s2n_errno, S2N_ERR_IO_BLOCKED);
                }
            }
            EXPECT_TRUE(async_block_triggered);

            /* Handshake completed */
            EXPECT_TRUE(IS_NEGOTIATED(server_conn));
            EXPECT_TRUE(IS_NEGOTIATED(client_conn));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), APPLICATION_DATA);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), APPLICATION_DATA);
        };

        /* Test: handshake with early data and fragmented messages */
        if (s2n_is_tls13_fully_supported()) {
            uint8_t early_data_bytes[] = "hello world";
            struct s2n_blob early_data = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&early_data, early_data_bytes, sizeof(early_data_bytes)));

            DEFER_CLEANUP(struct s2n_config *config = s2n_test_config_new(chain_and_key),
                    s2n_config_ptr_free);

            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_OK(s2n_append_test_psk_with_early_data(server_conn, early_data.size, &s2n_tls13_aes_256_gcm_sha384));
            server_conn->max_outgoing_fragment_length = server_fragment_size;

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_OK(s2n_append_test_psk_with_early_data(client_conn, early_data.size, &s2n_tls13_aes_256_gcm_sha384));
            client_conn->max_outgoing_fragment_length = client_fragment_size;

            struct s2n_io_wrapper_pair io_wrapper = { 0 };
            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_connections_set_blocking_io_pair(&io_wrapper, client_conn, server_conn, &io_pair));

            uint8_t recv_buffer[sizeof(early_data_bytes)] = { 0 };
            struct s2n_blob early_data_received = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&early_data_received, recv_buffer, sizeof(recv_buffer)));

            EXPECT_ERROR_WITH_ERRNO(s2n_negotiate_test_server_and_client_with_early_data(server_conn, client_conn,
                                            &early_data, &early_data_received),
                    S2N_ERR_IO_BLOCKED);

            /* All early data received */
            EXPECT_TRUE(WITH_EARLY_DATA(server_conn));
            EXPECT_TRUE(WITH_EARLY_DATA(client_conn));
            S2N_BLOB_EXPECT_EQUAL(early_data, early_data_received);

            while (s2n_negotiate_test_server_and_client(server_conn, client_conn) < S2N_SUCCESS) {
                POSIX_ENSURE(s2n_errno, S2N_ERR_IO_BLOCKED);
            }

            /* Handshake completed */
            EXPECT_TRUE(IS_NEGOTIATED(server_conn));
            EXPECT_TRUE(IS_NEGOTIATED(client_conn));
            EXPECT_EQUAL(s2n_conn_get_current_message_type(server_conn), APPLICATION_DATA);
            EXPECT_EQUAL(s2n_conn_get_current_message_type(client_conn), APPLICATION_DATA);
        };
    }

    END_TEST();
}
