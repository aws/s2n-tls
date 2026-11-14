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

/* Included to test static function */
#include "tls/s2n_resume.c"

#define ARE_FULL_HANDSHAKES(client, server) \
    (IS_FULL_HANDSHAKE(client) && IS_FULL_HANDSHAKE(server))

#define IS_HELLO_RETRY(client, server)                          \
    (((client->handshake.handshake_type) & HELLO_RETRY_REQUEST) \
            && ((server->handshake.handshake_type) & HELLO_RETRY_REQUEST))

#define EXPECT_TICKETS_SENT(conn, count) EXPECT_OK(s2n_assert_tickets_sent(conn, count))

struct s2n_early_data_test_case {
    bool ticket_supported;
    bool client_supported;
    bool server_supported;
    bool expect_early_data;
};

static S2N_RESULT s2n_assert_tickets_sent(struct s2n_connection *conn, uint16_t expected_tickets_sent)
{
    uint16_t tickets_sent = 0;
    RESULT_GUARD_POSIX(s2n_connection_get_tickets_sent(conn, &tickets_sent));
    RESULT_ENSURE_EQ(tickets_sent, expected_tickets_sent);
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_wipe_connections(struct s2n_connection *client_conn, struct s2n_connection *server_conn,
        struct s2n_test_io_pair *io_pair)
{
    RESULT_GUARD_POSIX(s2n_connection_wipe(server_conn));
    RESULT_GUARD_POSIX(s2n_connection_wipe(client_conn));
    RESULT_GUARD_POSIX(s2n_io_pair_close(io_pair));
    RESULT_GUARD_POSIX(s2n_io_pair_init_non_blocking(io_pair));
    RESULT_GUARD_POSIX(s2n_connections_set_io_pair(client_conn, server_conn, io_pair));
    return S2N_RESULT_OK;
}

static int s2n_cache_retrieve_cb(struct s2n_connection *conn, void *ctx, const void *key,
        uint64_t key_size, void *value, uint64_t *value_size)
{
    return S2N_SUCCESS;
}

static int s2n_cache_store_cb(struct s2n_connection *conn, void *ctx, uint64_t ttl_in_seconds,
        const void *key, uint64_t key_size, const void *value, uint64_t value_size)
{
    return S2N_SUCCESS;
}

static int s2n_cache_delete_cb(struct s2n_connection *conn, void *ctx, const void *key, uint64_t key_size)
{
    return S2N_SUCCESS;
}

static int s2n_test_session_ticket_cb(struct s2n_connection *conn, void *ctx, struct s2n_session_ticket *ticket)
{
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(ticket);

    size_t data_len = 0;
    EXPECT_SUCCESS(s2n_session_ticket_get_data_len(ticket, &data_len));

    struct s2n_stuffer *stuffer = (struct s2n_stuffer *) ctx;
    EXPECT_SUCCESS(s2n_stuffer_wipe(stuffer));
    EXPECT_SUCCESS(s2n_stuffer_resize(stuffer, data_len));
    EXPECT_SUCCESS(s2n_session_ticket_get_data(ticket, data_len, stuffer->blob.data));
    EXPECT_SUCCESS(s2n_stuffer_skip_write(stuffer, data_len));

    return S2N_SUCCESS;
}

static S2N_RESULT s2n_test_issue_new_session_ticket(struct s2n_connection *server_conn, struct s2n_connection *client_conn,
        const struct s2n_early_data_test_case *early_data_case)
{
    RESULT_ENSURE_REF(server_conn);
    RESULT_ENSURE_REF(client_conn);
    RESULT_ENSURE_REF(early_data_case);

    uint8_t data = 1;
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    RESULT_GUARD_POSIX(s2n_connection_add_new_tickets_to_send(server_conn, 1));

    if (early_data_case->ticket_supported) {
        RESULT_GUARD_POSIX(s2n_connection_set_server_max_early_data_size(server_conn, UINT16_MAX));
    } else {
        RESULT_GUARD_POSIX(s2n_connection_set_server_max_early_data_size(server_conn, 0));
    }

    RESULT_ENSURE_NE(server_conn->tickets_to_send, server_conn->tickets_sent);
    RESULT_GUARD_POSIX(s2n_send(server_conn, &data, 1, &blocked));
    RESULT_GUARD_POSIX(s2n_recv(client_conn, &data, 1, &blocked));
    RESULT_ENSURE_EQ(server_conn->tickets_to_send, server_conn->tickets_sent);

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_negotiate(struct s2n_connection *server_conn, struct s2n_connection *client_conn,
        const struct s2n_early_data_test_case *early_data_case)
{
    RESULT_ENSURE_REF(server_conn);
    RESULT_ENSURE_REF(client_conn);
    RESULT_ENSURE_REF(early_data_case);

    uint8_t early_data[] = "very early hello world";
    uint8_t empty_data[sizeof(early_data)] = { 0 };

    uint8_t early_data_recv_data[sizeof(early_data)] = { 0 };
    struct s2n_blob early_data_recv = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&early_data_recv, early_data_recv_data, sizeof(early_data_recv_data)));

    if (early_data_case->server_supported) {
        RESULT_GUARD_POSIX(s2n_connection_set_server_max_early_data_size(server_conn, UINT16_MAX));
    } else {
        RESULT_GUARD_POSIX(s2n_connection_set_server_max_early_data_size(server_conn, 0));
    }

    struct s2n_blob early_data_send = { 0 };
    if (early_data_case->client_supported) {
        RESULT_GUARD_POSIX(s2n_blob_init(&early_data_send, early_data, sizeof(early_data)));
    }

    RESULT_GUARD(s2n_negotiate_test_server_and_client_with_early_data(server_conn, client_conn,
            &early_data_send, &early_data_recv));

    if (early_data_case->expect_early_data) {
        RESULT_ENSURE_EQ(early_data_recv.size, sizeof(early_data));
        EXPECT_BYTEARRAY_EQUAL(early_data_recv.data, early_data, sizeof(early_data));
    } else {
        RESULT_ENSURE_EQ(early_data_recv.size, 0);
        EXPECT_BYTEARRAY_EQUAL(early_data_recv.data, empty_data, sizeof(empty_data));
    }

    return S2N_RESULT_OK;
}

/* Accepts any host name in the client certificate */
static uint8_t s2n_test_accept_any_host(const char *host_name, size_t host_name_len, void *data)
{
    return 1;
}

/* Configures a TLS1.3 server with client auth that issues session tickets */
static S2N_RESULT s2n_test_client_auth_server_config(struct s2n_config *config,
        struct s2n_cert_chain_and_key *chain, const char *client_ca_path, s2n_cert_auth_type auth_type)
{
    RESULT_ENSURE_REF(config);
    RESULT_GUARD_POSIX(s2n_config_add_cert_chain_and_key_to_store(config, chain));
    RESULT_GUARD_POSIX(s2n_config_set_cipher_preferences(config, "default_tls13"));
    RESULT_GUARD_POSIX(s2n_config_set_verification_ca_location(config, client_ca_path, NULL));
    RESULT_GUARD_POSIX(s2n_config_set_verify_host_callback(config, s2n_test_accept_any_host, NULL));
    RESULT_GUARD_POSIX(s2n_config_set_client_auth_type(config, auth_type));
    RESULT_GUARD_POSIX(s2n_config_set_session_tickets_onoff(config, true));
    RESULT_GUARD(s2n_resumption_test_ticket_key_setup(config));
    return S2N_RESULT_OK;
}

/* Like s2n_test_client_auth_server_config, and enables s2n_config_set_client_auth_resumption */
static S2N_RESULT s2n_test_opt_in_server_config(struct s2n_config *config,
        struct s2n_cert_chain_and_key *chain, const char *client_ca_path, s2n_cert_auth_type auth_type)
{
    RESULT_GUARD(s2n_test_client_auth_server_config(config, chain, client_ca_path, auth_type));
    RESULT_GUARD_POSIX(s2n_config_set_client_auth_resumption(config, true));
    return S2N_RESULT_OK;
}

/* PSK selection callback that chooses the first offered PSK that s2n accepts */
static int s2n_test_choose_first_resumption_psk_cb(struct s2n_connection *conn, void *context,
        struct s2n_offered_psk_list *psk_list)
{
    struct s2n_offered_psk offered_psk = { 0 };
    while (s2n_offered_psk_list_has_next(psk_list)) {
        POSIX_GUARD(s2n_offered_psk_list_next(psk_list, &offered_psk));
        if (s2n_offered_psk_list_choose_psk(psk_list, &offered_psk) == S2N_SUCCESS) {
            break;
        }
    }
    return S2N_SUCCESS;
}

/* ClientHello callback that lowers REQUIRED client auth to OPTIONAL when a PSK is offered */
static int s2n_test_optional_client_auth_with_psk_cb(struct s2n_connection *conn, void *ctx)
{
    bool has_psk = false;
    POSIX_GUARD(s2n_client_hello_has_extension(s2n_connection_get_client_hello(conn),
            TLS_EXTENSION_PRE_SHARED_KEY, &has_psk));
    s2n_cert_auth_type auth_type = S2N_CERT_AUTH_NONE;
    POSIX_GUARD(s2n_connection_get_client_auth_type(conn, &auth_type));
    if (has_psk && auth_type == S2N_CERT_AUTH_REQUIRED) {
        POSIX_GUARD(s2n_connection_set_client_auth_type(conn, S2N_CERT_AUTH_OPTIONAL));
    }
    return S2N_SUCCESS;
}

/* Wipes both connections, then negotiates a TLS1.3 handshake. The client offers the session in
 * `session` if it is not NULL, and sends `server_name` as SNI if it is not NULL. */
static S2N_RESULT s2n_test_tls13_handshake(struct s2n_connection *client_conn,
        struct s2n_connection *server_conn, struct s2n_test_io_pair *io_pair,
        struct s2n_config *client_config, struct s2n_config *server_config,
        const char *server_name, struct s2n_stuffer *session)
{
    RESULT_GUARD(s2n_wipe_connections(client_conn, server_conn, io_pair));
    RESULT_GUARD_POSIX(s2n_connection_set_config(client_conn, client_config));
    RESULT_GUARD_POSIX(s2n_connection_set_config(server_conn, server_config));
    if (server_name != NULL) {
        RESULT_GUARD_POSIX(s2n_set_server_name(client_conn, server_name));
    }
    if (session != NULL) {
        RESULT_GUARD_POSIX(s2n_connection_set_session(client_conn, session->blob.data,
                s2n_stuffer_data_available(session)));
    }
    RESULT_GUARD_POSIX(s2n_negotiate_test_server_and_client(server_conn, client_conn));
    RESULT_ENSURE_EQ(server_conn->actual_protocol_version, S2N_TLS13);
    return S2N_RESULT_OK;
}

/* Copies the most recently received session ticket from `from`
 * (the client's session ticket callback buffer) into `to` */
static S2N_RESULT s2n_test_save_session(struct s2n_stuffer *from, struct s2n_stuffer *to)
{
    uint32_t len = s2n_stuffer_data_available(from);
    RESULT_ENSURE_GT(len, 0);
    RESULT_GUARD_POSIX(s2n_stuffer_wipe(to));
    RESULT_GUARD_POSIX(s2n_stuffer_copy(from, to, len));
    RESULT_GUARD_POSIX(s2n_stuffer_reread(from));
    return S2N_RESULT_OK;
}

/* Negotiates a full handshake, issues a ticket, and saves it from `session_data`
 * (the client's session ticket callback buffer) into `ticket` */
static S2N_RESULT s2n_test_get_ticket(struct s2n_connection *client_conn, struct s2n_connection *server_conn,
        struct s2n_test_io_pair *io_pair, struct s2n_config *client_config, struct s2n_config *server_config,
        const char *server_name, struct s2n_stuffer *session_data, struct s2n_stuffer *ticket)
{
    const struct s2n_early_data_test_case no_early_data = { 0 };
    RESULT_GUARD(s2n_test_tls13_handshake(client_conn, server_conn, io_pair, client_config,
            server_config, server_name, NULL));
    RESULT_ENSURE(ARE_FULL_HANDSHAKES(client_conn, server_conn), S2N_ERR_SAFETY);
    RESULT_GUARD(s2n_test_issue_new_session_ticket(server_conn, client_conn, &no_early_data));
    RESULT_GUARD(s2n_test_save_session(session_data, ticket));
    return S2N_RESULT_OK;
}

/* Asserts that neither connection resumed and the server received a client certificate */
static S2N_RESULT s2n_assert_full_client_auth_handshake(struct s2n_connection *client_conn,
        struct s2n_connection *server_conn)
{
    RESULT_ENSURE(ARE_FULL_HANDSHAKES(client_conn, server_conn), S2N_ERR_SAFETY);
    RESULT_ENSURE(IS_CLIENT_AUTH_HANDSHAKE(server_conn), S2N_ERR_SAFETY);
    RESULT_ENSURE(!(server_conn->handshake.handshake_type & NO_CLIENT_CERT), S2N_ERR_SAFETY);
    RESULT_ENSURE_EQ(s2n_connection_client_cert_used(server_conn), 1);
    RESULT_ENSURE_GT(server_conn->handshake_params.client_cert_chain.size, 0);
    return S2N_RESULT_OK;
}

/* Asserts that both connections resumed without a client certificate */
static S2N_RESULT s2n_assert_resumed_handshake(struct s2n_connection *client_conn,
        struct s2n_connection *server_conn)
{
    RESULT_ENSURE_EQ(s2n_connection_is_session_resumed(client_conn), 1);
    RESULT_ENSURE_EQ(s2n_connection_is_session_resumed(server_conn), 1);
    RESULT_ENSURE(!IS_CLIENT_AUTH_HANDSHAKE(server_conn), S2N_ERR_SAFETY);
    RESULT_ENSURE_EQ(s2n_connection_client_cert_used(server_conn), 0);
    RESULT_ENSURE_EQ(server_conn->handshake_params.client_cert_chain.size, 0);
    return S2N_RESULT_OK;
}

static int s2n_wipe_psk_ke_ext(struct s2n_connection *conn, void *ctx)
{
    struct s2n_client_hello *client_hello = s2n_connection_get_client_hello(conn);
    POSIX_ENSURE_REF(client_hello);
    s2n_parsed_extension *parsed_extension = NULL;
    POSIX_GUARD(s2n_client_hello_get_parsed_extension(TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES, &client_hello->extensions, &parsed_extension));
    POSIX_ENSURE_REF(parsed_extension);
    POSIX_GUARD(s2n_blob_zero(&parsed_extension->extension));

    return S2N_SUCCESS;
}

static int s2n_alter_psk_ke_ext(struct s2n_connection *conn, void *ctx)
{
    struct s2n_client_hello *client_hello = s2n_connection_get_client_hello(conn);
    POSIX_ENSURE_REF(client_hello);
    s2n_parsed_extension *parsed_extension = NULL;
    POSIX_GUARD(s2n_client_hello_get_parsed_extension(TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES, &client_hello->extensions, &parsed_extension));
    POSIX_ENSURE_REF(parsed_extension);

    /* Overwrite the extension so it only supports PSK_KE mode */
    struct s2n_stuffer psk_ke_extension = { 0 };
    POSIX_GUARD(s2n_stuffer_init(&psk_ke_extension, &parsed_extension->extension));
    POSIX_GUARD(s2n_stuffer_skip_write(&psk_ke_extension, 1));
    uint8_t mode = TLS_PSK_KE_MODE;
    POSIX_GUARD(s2n_stuffer_write_bytes(&psk_ke_extension, &mode, 1));

    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    if (!s2n_is_tls13_fully_supported()) {
        END_TEST();
    }

    /* For some session resumption test cases, we want to test all possible configurations of 0-RTT support. */
    size_t test_case_i = 0;
    struct s2n_early_data_test_case early_data_test_cases[2 * 2 * 2] = { 0 };
    for (size_t ticket_supported = 0; ticket_supported < 2; ticket_supported++) {
        for (size_t client_supported = 0; client_supported < 2; client_supported++) {
            for (size_t server_supported = 0; server_supported < 2; server_supported++) {
                EXPECT_TRUE(test_case_i < s2n_array_len(early_data_test_cases));
                early_data_test_cases[test_case_i].ticket_supported = ticket_supported;
                early_data_test_cases[test_case_i].client_supported = client_supported;
                early_data_test_cases[test_case_i].server_supported = server_supported;
                early_data_test_cases[test_case_i].expect_early_data = client_supported && server_supported && ticket_supported;
                test_case_i++;
            }
        }
    }
    EXPECT_EQUAL(test_case_i, s2n_array_len(early_data_test_cases));

    /* For some session resumption test cases, we don't want to test or don't care about 0-RTT */
    const struct s2n_early_data_test_case no_early_data = {
        .client_supported = false,
        .server_supported = false,
        .expect_early_data = false
    };

    /* Setup server config */
    struct s2n_config *server_config = s2n_config_new();
    EXPECT_NOT_NULL(server_config);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "AWS-CRT-SDK-TLSv1.0"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(server_config));
    struct s2n_cert_chain_and_key *tls13_chain_and_key = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&tls13_chain_and_key, S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN,
            S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, tls13_chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(server_config, true));
    EXPECT_OK(s2n_resumption_test_ticket_key_setup(server_config));

    /* Setup TLS1.2 server config */
    struct s2n_config *tls12_server_config = s2n_config_new();
    EXPECT_NOT_NULL(tls12_server_config);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(tls12_server_config, "test_all_tls12"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(tls12_server_config));
    struct s2n_cert_chain_and_key *tls12_chain_and_key = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&tls12_chain_and_key, S2N_DEFAULT_TEST_CERT_CHAIN,
            S2N_DEFAULT_TEST_PRIVATE_KEY));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(tls12_server_config, tls12_chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(tls12_server_config, true));
    EXPECT_OK(s2n_resumption_test_ticket_key_setup(tls12_server_config));

    /* Setup TLS1.3 client config */
    struct s2n_config *tls13_client_config = s2n_config_new();
    EXPECT_NOT_NULL(tls13_client_config);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(tls13_client_config, "AWS-CRT-SDK-TLSv1.0"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(tls13_client_config));
    EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(tls13_client_config, true));
    DEFER_CLEANUP(struct s2n_stuffer cb_session_data = { 0 }, s2n_stuffer_free);
    EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&cb_session_data, 0));
    EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(tls13_client_config, s2n_test_session_ticket_cb, &cb_session_data));

    /* Setup TLS1.2 client config */
    struct s2n_config *tls12_client_config = s2n_config_new();
    EXPECT_NOT_NULL(tls12_client_config);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(tls12_client_config, "ELBSecurityPolicy-2016-08"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(tls12_client_config));
    EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(tls12_client_config, true));
    EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(tls12_client_config, s2n_test_session_ticket_cb, &cb_session_data));

    /* Test: Server and client resume a session multiple times */
    for (size_t early_data_i = 0; early_data_i < s2n_array_len(early_data_test_cases); early_data_i++) {
        const struct s2n_early_data_test_case early_data_case = early_data_test_cases[early_data_i];

        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_NOT_NULL(server_conn);

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_client_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Negotiate initial handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(ARE_FULL_HANDSHAKES(client_conn, server_conn));

        /* Receive and save the issued session ticket for the next connection */
        EXPECT_OK(s2n_test_issue_new_session_ticket(server_conn, client_conn, &early_data_case));

        for (size_t i = 0; i < 10; i++) {
            /* Prepare client and server for new connection */
            EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
            EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
            EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Client sets up a resumption connection with the received session ticket data */
            size_t cb_session_data_len = s2n_stuffer_data_available(&cb_session_data);
            EXPECT_SUCCESS(s2n_connection_set_session(client_conn, cb_session_data.blob.data, cb_session_data_len));
            EXPECT_SUCCESS(s2n_stuffer_rewrite(&cb_session_data));

            /* Negotiate new connection */
            EXPECT_OK(s2n_test_negotiate(server_conn, client_conn, &early_data_case));
            EXPECT_FALSE(ARE_FULL_HANDSHAKES(client_conn, server_conn));

            /* Verify we can free the handshakes */
            EXPECT_SUCCESS(s2n_connection_free_handshake(client_conn));
            EXPECT_SUCCESS(s2n_connection_free_handshake(server_conn));

            /* Receive and save the issued session ticket for the next connection */
            EXPECT_OK(s2n_test_issue_new_session_ticket(server_conn, client_conn, &early_data_case));
        }

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_stuffer_rewrite(&cb_session_data));
    }

    /* Test: Client does not accept a handshake that does not match its stored session */
    {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls12_client_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls12_server_config));

        /* Setup: initial handshake */
        DEFER_CLEANUP(struct s2n_blob tls12_ticket = { 0 }, s2n_free);
        {
            /* Create nonblocking pipes */
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Negotiate initial handshake */
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_TRUE(ARE_FULL_HANDSHAKES(client_conn, server_conn));
            EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

            /* Store TLS1.2 ticket */
            int tls12_ticket_length = s2n_connection_get_session_length(client_conn);
            EXPECT_SUCCESS(s2n_alloc(&tls12_ticket, tls12_ticket_length));
            EXPECT_SUCCESS(s2n_connection_get_session(client_conn, tls12_ticket.data, tls12_ticket.size));
        }

        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));

        /* Reject incorrect protocol version */
        {
            /* Create nonblocking pipes */
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Client sets up a resumption connection with the received session ticket data */
            EXPECT_SUCCESS(s2n_connection_set_session(client_conn, tls12_ticket.data, tls12_ticket.size));

            /* Change the protocol version */
            client_conn->resume_protocol_version = S2N_TLS10;

            /* Expect handshake rejected */
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                    S2N_ERR_BAD_MESSAGE);
        }

        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));

        /* Reject incorrect cipher suite */
        {
            /* Create nonblocking pipes */
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Client sets up a resumption connection with the received session ticket data */
            EXPECT_SUCCESS(s2n_connection_set_session(client_conn, tls12_ticket.data, tls12_ticket.size));

            /* Change the cipher suite */
            EXPECT_NOT_EQUAL(client_conn->secure->cipher_suite, &s2n_rsa_with_aes_256_cbc_sha);
            client_conn->secure->cipher_suite = &s2n_rsa_with_aes_256_cbc_sha;

            /* Expect handshake rejected */
            EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
            EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn),
                    S2N_ERR_BAD_MESSAGE);
        }

        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));

        /* Sanity check: unmodified session accepted */
        {
            /* Create nonblocking pipes */
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Client sets up a resumption connection with the received session ticket data */
            EXPECT_SUCCESS(s2n_connection_set_session(client_conn, tls12_ticket.data, tls12_ticket.size));

            /* Expect handshake accepted */
            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_FALSE(ARE_FULL_HANDSHAKES(client_conn, server_conn));
        }
    }

    /* Test: Server does not accept an expired ticket and instead does a full handshake */
    {
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_NOT_NULL(server_conn);

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_client_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Negotiate initial handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(ARE_FULL_HANDSHAKES(client_conn, server_conn));

        /* Receive and save the issued session ticket for the next connection */
        EXPECT_OK(s2n_test_issue_new_session_ticket(server_conn, client_conn, &no_early_data));

        /* Prepare client and server for new connection */
        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Client sets up a resumption connection with the received session ticket data */
        size_t cb_session_data_len = s2n_stuffer_data_available(&cb_session_data);
        EXPECT_SUCCESS(s2n_connection_set_session(client_conn, cb_session_data.blob.data, cb_session_data_len));
        EXPECT_SUCCESS(s2n_stuffer_rewrite(&cb_session_data));

        /* Setup conditions to make the server think the ticket has expired */
        EXPECT_SUCCESS(s2n_config_set_session_state_lifetime(server_config, 0));

        /* Negotiate new connection */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(ARE_FULL_HANDSHAKES(client_conn, server_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_stuffer_rewrite(&cb_session_data));
        EXPECT_SUCCESS(s2n_config_set_session_state_lifetime(server_config, S2N_STATE_LIFETIME_IN_NANOS));
    };

    /* Test: A TLS1.2 client with a valid TLS1.3 ticket falls back to a TLS1.2 connection */
    for (size_t early_data_i = 0; early_data_i < s2n_array_len(early_data_test_cases); early_data_i++) {
        struct s2n_early_data_test_case early_data_case = early_data_test_cases[early_data_i];
        /* Early data is never sent in TLS1.2 (or in a full handshake) */
        early_data_case.expect_early_data = false;

        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_NOT_NULL(server_conn);

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_client_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Negotiate initial handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(ARE_FULL_HANDSHAKES(client_conn, server_conn));

        /* Receive and save the issued session ticket for the next connection */
        EXPECT_OK(s2n_test_issue_new_session_ticket(server_conn, client_conn, &early_data_case));

        /* Prepare client and server for a second connection */
        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Client sets up a resumption connection with the received session ticket data */
        size_t cb_session_data_len = s2n_stuffer_data_available(&cb_session_data);
        EXPECT_SUCCESS(s2n_connection_set_session(client_conn, cb_session_data.blob.data, cb_session_data_len));
        EXPECT_SUCCESS(s2n_stuffer_rewrite(&cb_session_data));

        /* Set client config to TLS1.2 cipher preferences */
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls12_client_config));

        /* Negotiate second connection */
        EXPECT_OK(s2n_test_negotiate(server_conn, client_conn, &early_data_case));

        /* Falls back to TLS1.2 handshake */
        EXPECT_TRUE(ARE_FULL_HANDSHAKES(client_conn, server_conn));
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    }

    /* Test: A TLS1.3 client with a valid TLS1.2 ticket can fall back to a
     * TLS1.3 connection.
     *
     * This scenario could occur when upgrading a fleet of TLS1.2 servers to
     * TLS1.3 without disabling session resumption.
     */
    {
        DEFER_CLEANUP(struct s2n_blob ticket = { 0 }, s2n_free);
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_NOT_NULL(server_conn);

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls12_client_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Create nonblocking pipes */
        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Negotiate initial handshake to produce TLS1.2 session ticket */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(ARE_FULL_HANDSHAKES(client_conn, server_conn));
        EXPECT_TRUE(IS_ISSUING_NEW_SESSION_TICKET(server_conn));
        EXPECT_TRUE(client_conn->ems_negotiated);

        /* Store the TLS1.2 session ticket */
        size_t tls12_session_ticket_len = s2n_connection_get_session_length(client_conn);
        EXPECT_SUCCESS(s2n_realloc(&ticket, tls12_session_ticket_len));
        EXPECT_SUCCESS(s2n_connection_get_session(client_conn, ticket.data, ticket.size));

        /* Prepare client and server for a second connection */
        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));

        /* Client sets up a resumption connection with the received TLS1.2 session ticket data */
        EXPECT_SUCCESS(s2n_connection_set_session(client_conn, ticket.data, ticket.size));
        /* We want to ensure that ems is handled properly too */
        EXPECT_TRUE(client_conn->ems_negotiated);

        /* Set client config to TLS1.3 cipher preferences */
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_client_config));

        /* Negotiate second connection */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(ARE_FULL_HANDSHAKES(client_conn, server_conn));
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);

        /* since TLS 1.3 was negotiated, and the client hasn't called recv yet
         * there should be no session ticket available.
         */
        EXPECT_EQUAL(s2n_connection_get_session_length(client_conn), 0);
        EXPECT_EQUAL(s2n_connection_get_session(client_conn, ticket.data, ticket.size), 0);
    };

    /* HRR when issuing a session resumption ticket and when resuming a session */
    for (size_t early_data_i = 0; early_data_i < s2n_array_len(early_data_test_cases); early_data_i++) {
        struct s2n_early_data_test_case early_data_case = early_data_test_cases[early_data_i];
        /* Never use early data on a HRR */
        early_data_case.expect_early_data = false;

        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_NOT_NULL(server_conn);

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_client_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
        client_conn->security_policy_override = &security_policy_test_tls13_retry;

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Negotiate handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Validate handshake type */
        EXPECT_TRUE(ARE_FULL_HANDSHAKES(client_conn, server_conn));
        EXPECT_TRUE(IS_HELLO_RETRY(client_conn, server_conn));

        /* Receive and save the issued session ticket for the next connection */
        EXPECT_OK(s2n_test_issue_new_session_ticket(server_conn, client_conn, &early_data_case));

        /* Prepare client and server for new connection */
        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));
        client_conn->security_policy_override = &security_policy_test_tls13_retry;

        /* Client sets up a resumption connection with the received session ticket data */
        size_t cb_session_data_len = s2n_stuffer_data_available(&cb_session_data);
        EXPECT_SUCCESS(s2n_connection_set_session(client_conn, cb_session_data.blob.data, cb_session_data_len));
        EXPECT_SUCCESS(s2n_stuffer_rewrite(&cb_session_data));

        /* Negotiate new connection */
        EXPECT_OK(s2n_test_negotiate(server_conn, client_conn, &early_data_case));
        EXPECT_FALSE(ARE_FULL_HANDSHAKES(client_conn, server_conn));
        EXPECT_TRUE(IS_HELLO_RETRY(client_conn, server_conn));

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    }

    /* Test: reuse a connection for both TLS1.2 and TLS1.3 session resumption.
     *
     * TLS1.2 and TLS1.3 reuse some of the same code / memory. We should verify that using
     * one doesn't affect our ability to use the other after wiping the connection.
     */
    {
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        DEFER_CLEANUP(struct s2n_stuffer tls12_ticket = { 0 }, s2n_stuffer_free);
        DEFER_CLEANUP(struct s2n_stuffer tls13_ticket = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&tls12_ticket, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&tls13_ticket, 0));

        /* Negotiate initial TLS1.3 handshake */
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_client_config));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(ARE_FULL_HANDSHAKES(client_conn, server_conn));
        EXPECT_OK(s2n_test_issue_new_session_ticket(server_conn, client_conn, &no_early_data));
        EXPECT_SUCCESS(s2n_stuffer_copy(&cb_session_data, &tls13_ticket, s2n_stuffer_data_available(&cb_session_data)));

        /* Prepare client and server for a second connection */
        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Negotiate initial TLS1.2 handshake */
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls12_client_config));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(ARE_FULL_HANDSHAKES(client_conn, server_conn));
        int tls12_ticket_length = s2n_connection_get_session_length(client_conn);
        EXPECT_SUCCESS(s2n_stuffer_skip_write(&tls12_ticket, tls12_ticket_length));
        EXPECT_SUCCESS(s2n_connection_get_session(client_conn, tls12_ticket.blob.data, tls12_ticket_length));

        /* Switch between TLS1.2 and TLS1.3 resumption */
        for (size_t i = 0; i < 10; i++) {
            EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
            EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
            EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            bool do_tls13 = (i % 2 == 0);

            uint8_t expected_version = 0;
            if (do_tls13) {
                expected_version = S2N_TLS13;
                EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_client_config));
                EXPECT_SUCCESS(s2n_connection_set_session(client_conn, tls13_ticket.blob.data,
                        s2n_stuffer_data_available(&tls13_ticket)));
            } else {
                expected_version = S2N_TLS12;
                EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls12_client_config));
                EXPECT_SUCCESS(s2n_connection_set_session(client_conn, tls12_ticket.blob.data,
                        s2n_stuffer_data_available(&tls12_ticket)));
            }

            EXPECT_OK(s2n_test_negotiate(server_conn, client_conn, &no_early_data));
            EXPECT_FALSE(ARE_FULL_HANDSHAKES(client_conn, server_conn));
            EXPECT_EQUAL(client_conn->actual_protocol_version, expected_version);
            EXPECT_EQUAL(server_conn->actual_protocol_version, expected_version);

            if (do_tls13) {
                EXPECT_SUCCESS(s2n_stuffer_wipe(&tls13_ticket));
                EXPECT_OK(s2n_test_issue_new_session_ticket(server_conn, client_conn, &no_early_data));
                EXPECT_SUCCESS(s2n_stuffer_copy(&cb_session_data, &tls13_ticket, s2n_stuffer_data_available(&cb_session_data)));
            } else {
                EXPECT_SUCCESS(s2n_stuffer_wipe(&tls12_ticket));
                tls12_ticket_length = s2n_connection_get_session_length(client_conn);
                EXPECT_SUCCESS(s2n_stuffer_skip_write(&tls12_ticket, tls12_ticket_length));
                EXPECT_SUCCESS(s2n_connection_get_session(client_conn, tls12_ticket.blob.data, tls12_ticket_length));
            }
        }

        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    };

    /* Test output of s2n_connection_get_session_length/get_session during different stages of the handshake */
    {
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        EXPECT_NOT_NULL(client_conn);

        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        DEFER_CLEANUP(struct s2n_stuffer tls12_ticket = { 0 }, s2n_stuffer_free);
        DEFER_CLEANUP(struct s2n_stuffer tls13_ticket = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&tls12_ticket, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&tls13_ticket, 0));

        /* Negotiate initial TLS1.3 handshake */
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_client_config));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_OK(s2n_test_issue_new_session_ticket(server_conn, client_conn, &no_early_data));
        EXPECT_TICKETS_SENT(server_conn, 2);
        EXPECT_SUCCESS(s2n_stuffer_copy(&cb_session_data, &tls13_ticket, s2n_stuffer_data_available(&cb_session_data)));

        /* Prepare client and server for a second connection */
        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Negotiate initial TLS1.2 handshake */
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls12_client_config));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TICKETS_SENT(server_conn, 1);
        int tls12_ticket_length = s2n_connection_get_session_length(client_conn);
        EXPECT_SUCCESS(s2n_stuffer_skip_write(&tls12_ticket, tls12_ticket_length));
        EXPECT_SUCCESS(s2n_connection_get_session(client_conn, tls12_ticket.blob.data, tls12_ticket_length));

        struct s2n_config *client_config[] = { tls12_client_config, tls13_client_config };
        DEFER_CLEANUP(struct s2n_blob session_state = { 0 }, s2n_free);

        /* A quirk of the TLS1.2 session resumption behavior is that if a ticket is set
         * on the connection using s2n_connection_set_session, s2n_connection_get_session
         * will return a valid ticket, even before actually receiving a new session ticket
         * from the server. Here we test that behavior to ensure it is consistent. */
        for (size_t j = 0; j < s2n_array_len(client_config); j++) {
            /* Prepare client and server for new connection */
            EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
            EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config[j]));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls12_server_config));

            /* Client sets up a resumption connection with the received session ticket data */
            EXPECT_SUCCESS(s2n_connection_set_session(client_conn, tls12_ticket.blob.data, s2n_stuffer_data_available(&tls12_ticket)));

            /* Check that no ticket has actually been sent */
            EXPECT_TICKETS_SENT(server_conn, 0);

            /* s2n_connection_get_session will be non-zero if a TLS1.2 ticket was set on the connection */
            uint32_t session_length = s2n_connection_get_session_length(client_conn);
            EXPECT_TRUE(session_length > 0);

            EXPECT_SUCCESS(s2n_realloc(&session_state, session_length));

            /* Call get_session to retrieve session ticket */
            EXPECT_SUCCESS(s2n_connection_get_session(client_conn, session_state.data, session_length));

            /* Check that the session ticket returned is valid by deserializing it */
            struct s2n_stuffer session_state_stuffer = { 0 };
            EXPECT_SUCCESS(s2n_stuffer_init(&session_state_stuffer, &session_state));
            EXPECT_SUCCESS(s2n_stuffer_skip_write(&session_state_stuffer, session_length));
            EXPECT_SUCCESS(s2n_client_deserialize_resumption_state(client_conn, &session_state_stuffer));
        }

        /* Tests that if a TLS1.3 ticket is set on the connection, s2n_connection_get_session will
         * not return a ticket until a session ticket is sent by the server as a post-handshake
         * message. */
        for (size_t j = 0; j < s2n_array_len(client_config); j++) {
            /* Prepare client and server for new connection */
            EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
            EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config[j]));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

            /* Client sets up a resumption connection with the received session ticket data */
            EXPECT_SUCCESS(s2n_connection_set_session(client_conn, tls13_ticket.blob.data, s2n_stuffer_data_available(&tls13_ticket)));

            /* s2n_connection_get_session will be zero before receiving a session ticket
            * if a TLS1.3 ticket was set on the connection. */
            EXPECT_EQUAL(s2n_connection_get_session_length(client_conn), 0);

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

            if (client_conn->actual_protocol_version < S2N_TLS13) {
                EXPECT_TRUE(s2n_connection_get_session_length(client_conn) > 0);
            } else {
                /* The session length should be zero before a client has received a session ticket */
                EXPECT_EQUAL(s2n_connection_get_session_length(client_conn), 0);

                /* Receive the issued TLS1.3 session ticket */
                EXPECT_OK(s2n_test_issue_new_session_ticket(server_conn, client_conn, &no_early_data));

                /* The session length should be non-zero after a client has received a session ticket */
                EXPECT_TRUE(s2n_connection_get_session_length(client_conn) > 0);
            }
        }
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
    };

    /* If the server has no ticket key, no session tickets are issued or accepted.
     * We should always fall back to a full handshake.
     */
    {
        /* Setup config without session ticket key */
        struct s2n_config *no_key_config = s2n_config_new();
        EXPECT_NOT_NULL(no_key_config);
        no_key_config->security_policy = server_config->security_policy;
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(no_key_config));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(no_key_config, tls13_chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(no_key_config, true));

        struct s2n_config *no_key_config_with_cache = s2n_config_new();
        EXPECT_NOT_NULL(no_key_config_with_cache);
        no_key_config_with_cache->security_policy = server_config->security_policy;
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(no_key_config_with_cache));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(no_key_config_with_cache, tls13_chain_and_key));
        EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(no_key_config_with_cache, true));
        EXPECT_SUCCESS(s2n_config_set_cache_store_callback(no_key_config_with_cache, s2n_cache_store_cb, NULL));
        EXPECT_SUCCESS(s2n_config_set_cache_retrieve_callback(no_key_config_with_cache, s2n_cache_retrieve_cb, NULL));
        EXPECT_SUCCESS(s2n_config_set_cache_delete_callback(no_key_config_with_cache, s2n_cache_delete_cb, NULL));
        EXPECT_SUCCESS(s2n_config_set_session_cache_onoff(no_key_config_with_cache, true));
        EXPECT_TRUE(no_key_config_with_cache->use_session_cache);

        /* TLS1.2 */
        {
            DEFER_CLEANUP(struct s2n_stuffer ticket = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&ticket, 0));

            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls12_client_config));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Initial handshake */
            {
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
                EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
                EXPECT_TRUE(IS_FULL_HANDSHAKE(server_conn));
                EXPECT_TRUE(IS_ISSUING_NEW_SESSION_TICKET(server_conn));
                EXPECT_SUCCESS(s2n_stuffer_copy(&cb_session_data, &ticket, s2n_stuffer_data_available(&cb_session_data)));
                EXPECT_TRUE(s2n_stuffer_data_available(&ticket) > 0);

                EXPECT_OK(s2n_wipe_connections(client_conn, server_conn, &io_pair));
            };

            /* Initial handshake with no ticket keys */
            {
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, no_key_config));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
                EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
                EXPECT_TRUE(IS_FULL_HANDSHAKE(server_conn));
                EXPECT_FALSE(IS_ISSUING_NEW_SESSION_TICKET(server_conn));

                EXPECT_OK(s2n_wipe_connections(client_conn, server_conn, &io_pair));
            };

            /* Initial handshake with no ticket keys and session id caching */
            {
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, no_key_config_with_cache));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
                EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
                EXPECT_TRUE(IS_FULL_HANDSHAKE(server_conn));
                EXPECT_FALSE(IS_ISSUING_NEW_SESSION_TICKET(server_conn));

                EXPECT_OK(s2n_wipe_connections(client_conn, server_conn, &io_pair));
            };

            /* Resumption handshake */
            {
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
                EXPECT_SUCCESS(s2n_connection_set_session(client_conn,
                        ticket.blob.data, s2n_stuffer_data_available(&ticket)));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
                EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
                EXPECT_FALSE(IS_FULL_HANDSHAKE(server_conn));
                EXPECT_FALSE(IS_ISSUING_NEW_SESSION_TICKET(server_conn));

                EXPECT_OK(s2n_wipe_connections(client_conn, server_conn, &io_pair));
            };

            /* Resumption handshake with no ticket keys */
            {
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, no_key_config));
                EXPECT_SUCCESS(s2n_connection_set_session(client_conn,
                        ticket.blob.data, s2n_stuffer_data_available(&ticket)));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
                EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
                EXPECT_TRUE(IS_FULL_HANDSHAKE(server_conn));
                EXPECT_FALSE(IS_ISSUING_NEW_SESSION_TICKET(server_conn));

                EXPECT_OK(s2n_wipe_connections(client_conn, server_conn, &io_pair));
            };

            /* Resumption handshake with no ticket keys and session id caching */
            {
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, no_key_config_with_cache));
                EXPECT_SUCCESS(s2n_connection_set_session(client_conn,
                        ticket.blob.data, s2n_stuffer_data_available(&ticket)));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
                EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
                EXPECT_TRUE(IS_FULL_HANDSHAKE(server_conn));
                EXPECT_FALSE(IS_ISSUING_NEW_SESSION_TICKET(server_conn));

                EXPECT_OK(s2n_wipe_connections(client_conn, server_conn, &io_pair));
            };

            EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        };

        /* TLS1.3 */
        {
            DEFER_CLEANUP(struct s2n_stuffer ticket = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&ticket, 0));

            struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_client_config));

            struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
            EXPECT_NOT_NULL(server_conn);

            struct s2n_test_io_pair io_pair = { 0 };
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Initial handshake */
            {
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
                EXPECT_OK(s2n_test_issue_new_session_ticket(server_conn, client_conn, &no_early_data));
                EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);
                EXPECT_TRUE(IS_FULL_HANDSHAKE(server_conn));
                EXPECT_TRUE(server_conn->tickets_sent > 1);
                EXPECT_SUCCESS(s2n_stuffer_copy(&cb_session_data, &ticket, s2n_stuffer_data_available(&cb_session_data)));
                EXPECT_TRUE(s2n_stuffer_data_available(&ticket) > 0);

                EXPECT_OK(s2n_wipe_connections(client_conn, server_conn, &io_pair));
            };

            /* Initial handshake with no ticket keys */
            {
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, no_key_config));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
                EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);
                EXPECT_TRUE(IS_FULL_HANDSHAKE(server_conn));
                EXPECT_EQUAL(server_conn->tickets_sent, 0);

                EXPECT_OK(s2n_wipe_connections(client_conn, server_conn, &io_pair));
            };

            /* Initial handshake with no ticket keys and session id caching */
            {
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, no_key_config_with_cache));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
                EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);
                EXPECT_TRUE(IS_FULL_HANDSHAKE(server_conn));
                EXPECT_EQUAL(server_conn->tickets_sent, 0);

                EXPECT_OK(s2n_wipe_connections(client_conn, server_conn, &io_pair));
            };

            /* Resumption handshake */
            {
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
                EXPECT_SUCCESS(s2n_connection_set_session(client_conn,
                        ticket.blob.data, s2n_stuffer_data_available(&ticket)));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
                EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);
                EXPECT_FALSE(IS_FULL_HANDSHAKE(server_conn));
                EXPECT_EQUAL(server_conn->tickets_sent, 1);

                EXPECT_OK(s2n_wipe_connections(client_conn, server_conn, &io_pair));
            };

            /* Resumption handshake with no ticket keys */
            {
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, no_key_config));
                EXPECT_SUCCESS(s2n_connection_set_session(client_conn,
                        ticket.blob.data, s2n_stuffer_data_available(&ticket)));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
                EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);
                EXPECT_TRUE(IS_FULL_HANDSHAKE(server_conn));
                EXPECT_EQUAL(server_conn->tickets_sent, 0);

                EXPECT_OK(s2n_wipe_connections(client_conn, server_conn, &io_pair));
            };

            /* Resumption handshake with no ticket keys and session id caching */
            {
                EXPECT_SUCCESS(s2n_connection_set_config(server_conn, no_key_config_with_cache));
                EXPECT_SUCCESS(s2n_connection_set_session(client_conn,
                        ticket.blob.data, s2n_stuffer_data_available(&ticket)));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
                EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);
                EXPECT_TRUE(IS_FULL_HANDSHAKE(server_conn));
                EXPECT_EQUAL(server_conn->tickets_sent, 0);

                EXPECT_OK(s2n_wipe_connections(client_conn, server_conn, &io_pair));
            };

            EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        };

        EXPECT_SUCCESS(s2n_config_free(no_key_config));
        EXPECT_SUCCESS(s2n_config_free(no_key_config_with_cache));
    };

    /* Test: Client that supports TLS1.3 can resume sessions with a server that does not support TLS 1.3 */
    {
        struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
        struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_NOT_NULL(server_conn);

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_client_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, tls12_server_config));

        /* Create nonblocking pipes */
        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Negotiate initial handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(ARE_FULL_HANDSHAKES(client_conn, server_conn));

        /* The server does not support TLS13 so we are using TLS12 */
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);

        /* Store the TLS1.2 session ticket */
        size_t tls12_session_ticket_len = s2n_connection_get_session_length(client_conn);
        uint8_t tls12_session_ticket[S2N_TLS12_SESSION_SIZE] = { 0 };
        EXPECT_SUCCESS(s2n_connection_get_session(client_conn, tls12_session_ticket, tls12_session_ticket_len));

        for (size_t i = 0; i < 10; i++) {
            /* Prepare client and server for new connection */
            EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
            EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
            EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            /* Client sets up a resumption connection with the received TLS1.2 session ticket data */
            EXPECT_SUCCESS(s2n_connection_set_session(client_conn, tls12_session_ticket, tls12_session_ticket_len));

            /* Negotiate new connection */
            EXPECT_OK(s2n_test_negotiate(server_conn, client_conn, &no_early_data));
            EXPECT_FALSE(ARE_FULL_HANDSHAKES(client_conn, server_conn));

            /* Verify we can free the handshakes */
            EXPECT_SUCCESS(s2n_connection_free_handshake(client_conn));
            EXPECT_SUCCESS(s2n_connection_free_handshake(server_conn));
        }

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_connection_free(server_conn));
        EXPECT_SUCCESS(s2n_connection_free(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_stuffer_rewrite(&cb_session_data));
    }

    /* Functional: Server in QUIC mode does not send a session ticket if psk_ke extension was not received */
    {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_client_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Enable QUIC mode */
        EXPECT_SUCCESS(s2n_connection_enable_quic(client_conn));
        EXPECT_SUCCESS(s2n_connection_enable_quic(server_conn));

        /* Create nonblocking pipes */
        DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
        DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, server_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&output, &input, client_conn));

        /* Wipe psk_ke extension when it is received */
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(server_config, s2n_wipe_psk_ke_ext, NULL));

        /* Negotiate handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Server did not send a ticket since the client did not send the psk_ke extension */
        uint16_t tickets_sent = 0;
        EXPECT_SUCCESS(s2n_connection_get_tickets_sent(server_conn, &tickets_sent));
        EXPECT_EQUAL(tickets_sent, 0);
    };

    /* Functional: Server in QUIC mode does not send a session ticket if psk_ke extension does not support psk_dhe_ke */
    {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_client_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Enable QUIC mode */
        EXPECT_SUCCESS(s2n_connection_enable_quic(client_conn));
        EXPECT_SUCCESS(s2n_connection_enable_quic(server_conn));

        /* Create nonblocking pipes */
        DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
        DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, server_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&output, &input, client_conn));

        /* Alter psk_ke extension when it is received so that it only supports psk_ke mode */
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(server_config, s2n_alter_psk_ke_ext, NULL));

        /* Negotiate handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Server did not send a ticket since the client does not support psk_dhe_ke mode */
        uint16_t tickets_sent = 0;
        EXPECT_SUCCESS(s2n_connection_get_tickets_sent(server_conn, &tickets_sent));
        EXPECT_EQUAL(tickets_sent, 0);
    };

    /* Functional: Server in QUIC mode sends a session ticket if the client indicates it supports psk_dhe_ke mode */
    {
        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, tls13_client_config));
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));

        /* Enable QUIC mode */
        EXPECT_SUCCESS(s2n_connection_enable_quic(client_conn));
        EXPECT_SUCCESS(s2n_connection_enable_quic(server_conn));

        /* Create nonblocking pipes */
        DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
        DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, server_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&output, &input, client_conn));

        /* Disable any client hello cb changes */
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(server_config, NULL, NULL));

        /* Negotiate handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Server sent one ticket since the client by default indicates it supports psk_dhe_ke mode */
        uint16_t tickets_sent = 0;
        EXPECT_SUCCESS(s2n_connection_get_tickets_sent(server_conn, &tickets_sent));
        EXPECT_EQUAL(tickets_sent, 1);
    };

    /* Regression tests: TLS1.3 resumption must be refused when the server
     * requires client auth, since a resumed handshake skips the
     * CertificateRequest and would otherwise bypass mTLS.
     */
    {
        /* Server uses an RSA cert; the client uses an ECDSA cert for its mTLS
         * identity. Each side trusts the other's CA. */
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *server_chain = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_permutation_load_server_chain(&server_chain,
                "rsae", "pkcs", "2048", "sha256"));
        DEFER_CLEANUP(struct s2n_cert_chain_and_key *client_chain = NULL, s2n_cert_chain_and_key_ptr_free);
        EXPECT_SUCCESS(s2n_test_cert_permutation_load_server_chain(&client_chain,
                "ec", "ecdsa", "p256", "sha256"));

        char server_ca_path[S2N_MAX_TEST_PEM_PATH_LENGTH] = { 0 };
        EXPECT_SUCCESS(s2n_test_cert_permutation_get_ca_path(server_ca_path, "rsae", "pkcs", "2048", "sha256"));
        char client_ca_path[S2N_MAX_TEST_PEM_PATH_LENGTH] = { 0 };
        EXPECT_SUCCESS(s2n_test_cert_permutation_get_ca_path(client_ca_path, "ec", "ecdsa", "p256", "sha256"));

        /* Client presents its ECDSA cert if asked, but uses OPTIONAL so it can
         * connect to both the public (no client auth) and mTLS servers. */
        DEFER_CLEANUP(struct s2n_config *mtls_client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(mtls_client_config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(mtls_client_config, client_chain));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(mtls_client_config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(mtls_client_config, server_ca_path, NULL));
        EXPECT_SUCCESS(s2n_config_set_client_auth_type(mtls_client_config, S2N_CERT_AUTH_OPTIONAL));
        EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(mtls_client_config, true));
        DEFER_CLEANUP(struct s2n_stuffer mtls_session_data = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&mtls_session_data, 0));
        EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(mtls_client_config,
                s2n_test_session_ticket_cb, &mtls_session_data));

        /* "Public" server: no client auth, issues tickets. */
        DEFER_CLEANUP(struct s2n_config *public_server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(public_server_config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(public_server_config, server_chain));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(public_server_config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(public_server_config, true));
        EXPECT_OK(s2n_resumption_test_ticket_key_setup(public_server_config));

        /* mTLS server: requires client auth, shares the public server's ticket key. */
        DEFER_CLEANUP(struct s2n_config *mtls_server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(mtls_server_config);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(mtls_server_config, server_chain));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(mtls_server_config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(mtls_server_config, client_ca_path, NULL));
        EXPECT_SUCCESS(s2n_config_set_client_auth_type(mtls_server_config, S2N_CERT_AUTH_REQUIRED));
        EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(mtls_server_config, true));
        EXPECT_OK(s2n_resumption_test_ticket_key_setup(mtls_server_config));

        /* Like mtls_server_config, and selects PSKs with a PSK selection callback */
        DEFER_CLEANUP(struct s2n_config *mtls_cb_server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(mtls_cb_server_config);
        EXPECT_OK(s2n_test_client_auth_server_config(mtls_cb_server_config, server_chain, client_ca_path,
                S2N_CERT_AUTH_REQUIRED));
        EXPECT_SUCCESS(s2n_config_set_psk_selection_callback(mtls_cb_server_config,
                s2n_test_choose_first_resumption_psk_cb, NULL));

        /* Servers with client auth that did not opt in to client auth resumption */
        struct s2n_config *mtls_server_configs[] = { mtls_server_config, mtls_cb_server_config };

        /* A ticket minted without client auth cannot resume against an mTLS server. */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_NOT_NULL(server_conn);
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

            DEFER_CLEANUP(struct s2n_stuffer ticket = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&ticket, 0));

            for (size_t i = 0; i < s2n_array_len(mtls_server_configs); i++) {
                EXPECT_OK(s2n_test_get_ticket(client_conn, server_conn, &io_pair, mtls_client_config,
                        public_server_config, "localhost", &mtls_session_data, &ticket));
                EXPECT_OK(s2n_test_tls13_handshake(client_conn, server_conn, &io_pair,
                        mtls_client_config, mtls_server_configs[i], "localhost", &ticket));
                EXPECT_OK(s2n_assert_full_client_auth_handshake(client_conn, server_conn));
            }
        };

        /* A server with client auth does not issue tickets. */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_NOT_NULL(server_conn);
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, mtls_client_config));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, mtls_server_config));
            EXPECT_SUCCESS(s2n_set_server_name(client_conn, "localhost"));

            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
            EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

            EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
            EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);
            EXPECT_TRUE(IS_CLIENT_AUTH_HANDSHAKE(server_conn));

            uint16_t tickets_sent = 0;
            EXPECT_SUCCESS(s2n_connection_get_tickets_sent(server_conn, &tickets_sent));
            EXPECT_EQUAL(tickets_sent, 0);

            EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
        };

        /* Requires client auth and opts in to client auth resumption */
        DEFER_CLEANUP(struct s2n_config *opt_in_server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(opt_in_server_config);
        EXPECT_OK(s2n_test_opt_in_server_config(opt_in_server_config, server_chain, client_ca_path,
                S2N_CERT_AUTH_REQUIRED));

        /* Like opt_in_server_config, and lowers client auth to OPTIONAL when a PSK is offered */
        DEFER_CLEANUP(struct s2n_config *relaxing_server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(relaxing_server_config);
        EXPECT_OK(s2n_test_opt_in_server_config(relaxing_server_config, server_chain, client_ca_path,
                S2N_CERT_AUTH_REQUIRED));
        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(relaxing_server_config,
                s2n_test_optional_client_auth_with_psk_cb, NULL));

        /* Like opt_in_server_config, and selects PSKs with a PSK selection callback */
        DEFER_CLEANUP(struct s2n_config *opt_in_cb_server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(opt_in_cb_server_config);
        EXPECT_OK(s2n_test_opt_in_server_config(opt_in_cb_server_config, server_chain, client_ca_path,
                S2N_CERT_AUTH_REQUIRED));
        EXPECT_SUCCESS(s2n_config_set_psk_selection_callback(opt_in_cb_server_config,
                s2n_test_choose_first_resumption_psk_cb, NULL));

        /* With s2n_config_set_client_auth_resumption:
         * a ticket from a server without client auth gets a full handshake,
         * a ticket issued after a full handshake with client auth resumes,
         * and the resumed connection issues a ticket that also resumes.
         */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_NOT_NULL(server_conn);
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

            DEFER_CLEANUP(struct s2n_stuffer ticket = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&ticket, 0));

            struct s2n_config *opt_in_server_configs[] = { opt_in_server_config, relaxing_server_config,
                opt_in_cb_server_config };
            for (size_t i = 0; i < s2n_array_len(opt_in_server_configs); i++) {
                EXPECT_OK(s2n_test_get_ticket(client_conn, server_conn, &io_pair, mtls_client_config,
                        public_server_config, "localhost", &mtls_session_data, &ticket));
                EXPECT_OK(s2n_test_tls13_handshake(client_conn, server_conn, &io_pair,
                        mtls_client_config, opt_in_server_configs[i], "localhost", &ticket));
                EXPECT_OK(s2n_assert_full_client_auth_handshake(client_conn, server_conn));

                EXPECT_OK(s2n_test_get_ticket(client_conn, server_conn, &io_pair, mtls_client_config,
                        opt_in_server_configs[i], "localhost", &mtls_session_data, &ticket));
                EXPECT_OK(s2n_assert_full_client_auth_handshake(client_conn, server_conn));

                for (size_t resumption = 0; resumption < 2; resumption++) {
                    EXPECT_OK(s2n_test_tls13_handshake(client_conn, server_conn, &io_pair,
                            mtls_client_config, opt_in_server_configs[i], "localhost", &ticket));
                    EXPECT_OK(s2n_assert_resumed_handshake(client_conn, server_conn));
                    EXPECT_NOT_NULL(server_conn->psk_params.chosen_psk);
                    EXPECT_TRUE(server_conn->psk_params.chosen_psk->labeled_ticket);

                    EXPECT_OK(s2n_test_issue_new_session_ticket(server_conn, client_conn, &no_early_data));
                    EXPECT_OK(s2n_test_save_session(&mtls_session_data, &ticket));
                }
            }
        };

        /* A client auth ticket gets a full handshake on servers with client auth that did not opt in */
        {
            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_NOT_NULL(server_conn);
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

            DEFER_CLEANUP(struct s2n_stuffer ticket = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&ticket, 0));

            EXPECT_OK(s2n_test_get_ticket(client_conn, server_conn, &io_pair, mtls_client_config,
                    opt_in_server_config, "localhost", &mtls_session_data, &ticket));
            for (size_t i = 0; i < s2n_array_len(mtls_server_configs); i++) {
                EXPECT_OK(s2n_test_tls13_handshake(client_conn, server_conn, &io_pair,
                        mtls_client_config, mtls_server_configs[i], "localhost", &ticket));
                EXPECT_OK(s2n_assert_full_client_auth_handshake(client_conn, server_conn));
            }
        };

        /* OPTIONAL client auth and no client certificate: no ticket is issued */
        {
            /* Opts in to client auth resumption with OPTIONAL client auth */
            DEFER_CLEANUP(struct s2n_config *optional_opt_in_server_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(optional_opt_in_server_config);
            EXPECT_OK(s2n_test_opt_in_server_config(optional_opt_in_server_config, server_chain, client_ca_path,
                    S2N_CERT_AUTH_OPTIONAL));

            /* Like mtls_client_config, but without a certificate */
            DEFER_CLEANUP(struct s2n_config *no_cert_client_config = s2n_config_new(), s2n_config_ptr_free);
            EXPECT_NOT_NULL(no_cert_client_config);
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(no_cert_client_config, "default_tls13"));
            EXPECT_SUCCESS(s2n_config_set_verification_ca_location(no_cert_client_config, server_ca_path, NULL));
            EXPECT_SUCCESS(s2n_config_set_client_auth_type(no_cert_client_config, S2N_CERT_AUTH_OPTIONAL));
            EXPECT_SUCCESS(s2n_config_set_session_tickets_onoff(no_cert_client_config, true));
            EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(no_cert_client_config,
                    s2n_test_session_ticket_cb, &mtls_session_data));

            DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            EXPECT_NOT_NULL(client_conn);
            EXPECT_NOT_NULL(server_conn);
            DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
            EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

            EXPECT_SUCCESS(s2n_stuffer_wipe(&mtls_session_data));
            EXPECT_OK(s2n_test_tls13_handshake(client_conn, server_conn, &io_pair,
                    no_cert_client_config, optional_opt_in_server_config, "localhost", NULL));
            EXPECT_TRUE(IS_CLIENT_AUTH_HANDSHAKE(server_conn));
            EXPECT_TRUE(IS_CLIENT_AUTH_NO_CERT(server_conn));
            EXPECT_EQUAL(s2n_connection_client_cert_used(server_conn), 0);

            /* Let the client read any post-handshake messages */
            EXPECT_SUCCESS(s2n_connection_add_new_tickets_to_send(server_conn, 1));
            uint8_t data = 1;
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            EXPECT_EQUAL(s2n_send(server_conn, &data, 1, &blocked), 1);
            EXPECT_EQUAL(s2n_recv(client_conn, &data, 1, &blocked), 1);
            EXPECT_TICKETS_SENT(server_conn, 0);
            EXPECT_EQUAL(s2n_stuffer_data_available(&mtls_session_data), 0);
        };
    };

    /* Clean-up */
    EXPECT_SUCCESS(s2n_config_free(server_config));
    EXPECT_SUCCESS(s2n_config_free(tls12_server_config));
    EXPECT_SUCCESS(s2n_config_free(tls13_client_config));
    EXPECT_SUCCESS(s2n_config_free(tls12_client_config));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls12_chain_and_key));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(tls13_chain_and_key));

    END_TEST();
}
