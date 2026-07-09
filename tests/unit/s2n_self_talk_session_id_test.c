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

#include <stdint.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "utils/s2n_bitmap.h"

#define MAX_KEY_LEN 32
#define MAX_VAL_LEN 255

static const char SESSION_ID[] = "0123456789abcdef0123456789abcdef";
static const char TEST_MSG[] = "Test";

struct session_cache_entry {
    uint8_t key[MAX_KEY_LEN];
    uint8_t key_len;
    uint8_t value[MAX_VAL_LEN];
    uint8_t value_len;
    uint8_t lock;
};

struct session_cache_entry session_cache[256];

int cache_store_callback(struct s2n_connection *conn, void *ctx, uint64_t ttl, const void *key, uint64_t key_size, const void *value, uint64_t value_size)
{
    struct session_cache_entry *cache = ctx;

    if (key_size == 0 || key_size > MAX_KEY_LEN) {
        return -1;
    }
    if (value_size == 0 || value_size > MAX_VAL_LEN) {
        return -1;
    }

    uint8_t idx = ((const uint8_t *) key)[0];

    EXPECT_MEMCPY_SUCCESS(cache[idx].key, key, key_size);
    EXPECT_MEMCPY_SUCCESS(cache[idx].value, value, value_size);

    cache[idx].key_len = key_size;
    cache[idx].value_len = value_size;

    return 0;
}

int cache_retrieve_callback(struct s2n_connection *conn, void *ctx, const void *key, uint64_t key_size, void *value, uint64_t *value_size)
{
    struct session_cache_entry *cache = ctx;

    if (key_size == 0 || key_size > MAX_KEY_LEN) {
        return -1;
    }

    uint8_t idx = ((const uint8_t *) key)[0];

    if (cache[idx].lock) {
        /* here we mock a remote connection/event blocking the handshake
         * state machine, until lock is free
         */
        cache[idx].lock = 0;
        return S2N_CALLBACK_BLOCKED;
    }

    if (cache[idx].key_len != key_size) {
        return -1;
    }

    if (memcmp(cache[idx].key, key, key_size)) {
        return -1;
    }

    if (*value_size < cache[idx].value_len) {
        return -1;
    }

    *value_size = cache[idx].value_len;
    EXPECT_MEMCPY_SUCCESS(value, cache[idx].value, cache[idx].value_len);

    return 0;
}

int cache_delete_callback(struct s2n_connection *conn, void *ctx, const void *key, uint64_t key_size)
{
    struct session_cache_entry *cache = ctx;

    if (key_size == 0 || key_size > MAX_KEY_LEN) {
        return -1;
    }

    uint8_t idx = ((const uint8_t *) key)[0];

    if (cache[idx].key_len == 0) {
        return 0;
    }

    if (cache[idx].key_len != key_size) {
        return -1;
    }

    if (memcmp(cache[idx].key, key, key_size)) {
        return -1;
    }

    cache[idx].key_len = 0;
    cache[idx].value_len = 0;

    return 0;
}

/* init session cache lock field, which is used to mock a remote
 * connection/event block
 */
static void initialize_cache()
{
    for (int i = 0; i < 256; i++) {
        session_cache[i].lock = 1;
    }
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* aes keys. Used for session ticket/session data encryption. Taken from test vectors in https://tools.ietf.org/html/rfc5869 */
    uint8_t ticket_key_name[16] = "2018.07.26.15\0";
    uint8_t ticket_key[32] = { 0x19, 0xef, 0x24, 0xa3, 0x2c, 0x71, 0x7b, 0x16, 0x7f, 0x33,
        0xa9, 0x1d, 0x6f, 0x64, 0x8b, 0xdf, 0x96, 0x59, 0x67, 0x76,
        0xaf, 0xdb, 0x63, 0x77, 0xac, 0x43, 0x4c, 0x1c, 0x29, 0x3c,
        0xcb, 0x04 };

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(config);
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20240501"));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_disable_x509_verification(config));
    EXPECT_SUCCESS(s2n_config_set_cache_store_callback(config, cache_store_callback, session_cache));
    EXPECT_SUCCESS(s2n_config_set_cache_retrieve_callback(config, cache_retrieve_callback, session_cache));
    EXPECT_SUCCESS(s2n_config_set_cache_delete_callback(config, cache_delete_callback, session_cache));

    /* Although we disable session ticket, as long as session cache
     * callbacks are binded, session ticket key storage would be initialized
     */
    EXPECT_SUCCESS(s2n_config_set_session_cache_onoff(config, 1));
    uint64_t now = 0;
    POSIX_GUARD(config->wall_clock(config->sys_clock_ctx, &now));
    EXPECT_SUCCESS(s2n_config_add_ticket_crypto_key(config, ticket_key_name, strlen((char *) ticket_key_name),
            ticket_key, sizeof(ticket_key), now / ONE_SEC_IN_NANOS));

    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    uint8_t session_id_from_server[MAX_KEY_LEN] = { 0 };

    /* Saved session state for resumption tests */
    size_t serialized_session_state_length = 0;
    uint8_t serialized_session_state[256] = { 0 };

    /* Initial handshake with session ID fallback to full handshake */
    {
        initialize_cache();

        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));

        /* Set the session id to ensure we're able to fallback to full handshake
         * if session is not in server cache */
        EXPECT_MEMCPY_SUCCESS(client_conn->session_id, SESSION_ID, S2N_TLS_SESSION_ID_MAX_LEN);
        client_conn->session_id_len = S2N_TLS_SESSION_ID_MAX_LEN;

        /* Server will block the first time cache is accessed */
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn), S2N_ERR_ASYNC_BLOCKED);

        /* Negotiate succeeds on retry */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Make sure the get_session_id and get_session_id_length APIs are working */
        EXPECT_EQUAL(s2n_connection_get_session_id_length(server_conn), MAX_KEY_LEN);
        EXPECT_EQUAL(s2n_connection_get_session_id(server_conn, session_id_from_server, MAX_KEY_LEN),
                s2n_connection_get_session_id_length(server_conn));

        /* Make sure we did a full TLS1.2 handshake */
        EXPECT_TRUE(IS_FULL_HANDSHAKE(server_conn));
        EXPECT_TRUE(IS_FULL_HANDSHAKE(client_conn));
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);

        /* Server would choose a session ID for client (different from what client sent) */
        EXPECT_TRUE(memcmp(client_conn->session_id, SESSION_ID, S2N_TLS_SESSION_ID_MAX_LEN) != 0);

        /* Save session state from the connection for resumption tests */
        serialized_session_state_length = s2n_connection_get_session_length(client_conn);
        EXPECT_TRUE(serialized_session_state_length <= sizeof(serialized_session_state));

        /* Send very low session buffer size and see that you can get an error */
        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_get_session(client_conn, serialized_session_state, 1),
                S2N_ERR_SERIALIZED_SESSION_STATE_TOO_LONG);

        /* Get the full session state */
        EXPECT_EQUAL((size_t) s2n_connection_get_session(client_conn, serialized_session_state,
                             serialized_session_state_length),
                serialized_session_state_length);

        /* Verify data transfer works */
        EXPECT_EQUAL(s2n_send(client_conn, TEST_MSG, sizeof(TEST_MSG), &blocked), sizeof(TEST_MSG));
        char buffer[256] = { 0 };
        EXPECT_EQUAL(s2n_recv(server_conn, buffer, sizeof(buffer), &blocked), sizeof(TEST_MSG));
        EXPECT_EQUAL(memcmp(buffer, TEST_MSG, sizeof(TEST_MSG)), 0);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    };

    /* Session resumption */
    {
        initialize_cache();

        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_OK(s2n_connection_set_tls12_security_policy(client_conn));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));

        /* Set session state on client connection */
        EXPECT_SUCCESS(s2n_connection_set_session(client_conn, serialized_session_state, serialized_session_state_length));

        /* Server will block the first time cache is accessed */
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn), S2N_ERR_ASYNC_BLOCKED);

        /* Negotiate succeeds on retry */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Make sure the get_session_id and get_session_id_length APIs are working */
        uint8_t session_id_from_client[MAX_KEY_LEN] = { 0 };
        EXPECT_EQUAL(s2n_connection_get_session_id_length(server_conn), MAX_KEY_LEN);
        EXPECT_EQUAL(s2n_connection_get_session_id(server_conn, session_id_from_client, MAX_KEY_LEN),
                s2n_connection_get_session_id_length(server_conn));
        EXPECT_EQUAL(0, memcmp(session_id_from_client, session_id_from_server, MAX_KEY_LEN));

        /* Make sure we did an abbreviated handshake */
        EXPECT_TRUE(IS_RESUMPTION_HANDSHAKE(server_conn));
        EXPECT_TRUE(IS_RESUMPTION_HANDSHAKE(client_conn));

        /* Verify data transfer works */
        EXPECT_EQUAL(s2n_send(client_conn, TEST_MSG, sizeof(TEST_MSG), &blocked), sizeof(TEST_MSG));
        char buffer[256] = { 0 };
        EXPECT_EQUAL(s2n_recv(server_conn, buffer, sizeof(buffer), &blocked), sizeof(TEST_MSG));
        EXPECT_EQUAL(memcmp(buffer, TEST_MSG, sizeof(TEST_MSG)), 0);

        EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    };

    /* Session resumption with bad session state */
    {
        initialize_cache();

        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));
        EXPECT_OK(s2n_connection_set_tls12_security_policy(client_conn));
        EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));

        /* Change the format of the session state and check we cannot deserialize it */
        uint8_t bad_session_state[256] = { 0 };
        memcpy(bad_session_state, serialized_session_state, serialized_session_state_length);
        bad_session_state[0] = 3;
        EXPECT_FAILURE_WITH_ERRNO(
                s2n_connection_set_session(client_conn, bad_session_state, serialized_session_state_length),
                S2N_ERR_INVALID_SERIALIZED_SESSION_STATE);

        /* Change the protocol version (36th byte) in session state */
        EXPECT_TRUE(serialized_session_state_length >= 36);
        memcpy(bad_session_state, serialized_session_state, serialized_session_state_length);
        bad_session_state[35] = 30;
        EXPECT_SUCCESS(s2n_connection_set_session(client_conn, bad_session_state, serialized_session_state_length));

        /* Server will block the first time cache is accessed */
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn), S2N_ERR_ASYNC_BLOCKED);

        /* Verify negotiation fails due to bad session state */
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn), S2N_ERR_BAD_MESSAGE);

        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    };

    /* Session caching with a server that does not support EMS */
    {
        initialize_cache();

        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Negotiate until server has read the Client Hello message but hasn't written the server hello message */
        EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, SERVER_HELLO));
        EXPECT_OK(s2n_negotiate_until_message(server_conn, &blocked, SERVER_HELLO));

        /* s2n servers by default support EMS. We turn it off by manually setting ems_negotiated to false
        * and removing the EMS extension from our received extensions. */
        server_conn->ems_negotiated = false;
        s2n_extension_type_id ems_ext_id = 0;
        EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(TLS_EXTENSION_EMS, &ems_ext_id));
        S2N_CBIT_CLR(server_conn->extension_requests_received, ems_ext_id);

        /* Connection is successful and EMS is not negotiated */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_FALSE(server_conn->ems_negotiated);
        EXPECT_FALSE(client_conn->ems_negotiated);
        EXPECT_TRUE(IS_FULL_HANDSHAKE(server_conn));
        EXPECT_TRUE(IS_FULL_HANDSHAKE(client_conn));

        size_t tls12_session_ticket_len = s2n_connection_get_session_length(client_conn);
        uint8_t tls12_session_ticket[S2N_TLS12_SESSION_SIZE] = { 0 };
        EXPECT_SUCCESS(s2n_connection_get_session(client_conn, tls12_session_ticket, tls12_session_ticket_len));

        /* Wipe connections and set up new handshake */
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));
        EXPECT_SUCCESS(s2n_connection_set_session(client_conn, tls12_session_ticket, tls12_session_ticket_len));

        /* Server will block the first time cache is accessed */
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn), S2N_ERR_ASYNC_BLOCKED);

        /* Resumed connection is successful and EMS is not negotiated */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_EQUAL(S2N_CBIT_TEST(server_conn->extension_requests_received, ems_ext_id), 0);
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_FALSE(server_conn->ems_negotiated);
        EXPECT_FALSE(client_conn->ems_negotiated);
        EXPECT_FALSE(IS_FULL_HANDSHAKE(server_conn));
        EXPECT_FALSE(IS_FULL_HANDSHAKE(client_conn));

        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    };

    /**
     *= https://www.rfc-editor.org/rfc/rfc7627#section-5.3
     *= type=test
     *# If the original session used the "extended_master_secret"
     *# extension but the new ClientHello does not contain it, the server
     *# MUST abort the abbreviated handshake.
     **/
    {
        initialize_cache();

        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Connection is successful and EMS is negotiated */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_TRUE(server_conn->ems_negotiated);
        EXPECT_TRUE(client_conn->ems_negotiated);

        size_t tls12_session_ticket_len = s2n_connection_get_session_length(client_conn);
        uint8_t tls12_session_ticket[S2N_TLS12_SESSION_SIZE] = { 0 };
        EXPECT_SUCCESS(s2n_connection_get_session(client_conn, tls12_session_ticket, tls12_session_ticket_len));

        /* Wipe connections and set up new handshake */
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Force the client to not send the EMS extension */
        EXPECT_SUCCESS(s2n_connection_set_session(client_conn, tls12_session_ticket, tls12_session_ticket_len));
        client_conn->ems_negotiated = false;

        /* Server will block the first time cache is accessed */
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn), S2N_ERR_ASYNC_BLOCKED);

        /* Server did not receive the EMS extension from client */
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn), S2N_ERR_MISSING_EXTENSION);

        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    };

    /**
     *= https://www.rfc-editor.org/rfc/rfc7627#section-5.3
     *= type=test
     *# If the original session did not use the "extended_master_secret"
     *# extension but the new ClientHello contains the extension, then the
     *# server MUST NOT perform the abbreviated handshake.  Instead, it
     *# SHOULD continue with a full handshake (as described in
     *# Section 5.2) to negotiate a new session.
     **/
    {
        initialize_cache();

        struct s2n_test_io_pair io_pair;
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Negotiate until server has read the Client Hello message but hasn't written the Server Hello message */
        EXPECT_OK(s2n_negotiate_until_message(client_conn, &blocked, SERVER_HELLO));
        EXPECT_OK(s2n_negotiate_until_message(server_conn, &blocked, SERVER_HELLO));

        /* s2n servers by default support EMS. We turn it off by manually setting ems_negotiated to false
        * and removing the EMS extension from our received extensions. */
        server_conn->ems_negotiated = false;
        s2n_extension_type_id ems_ext_id = 0;
        EXPECT_SUCCESS(s2n_extension_supported_iana_value_to_id(TLS_EXTENSION_EMS, &ems_ext_id));
        S2N_CBIT_CLR(server_conn->extension_requests_received, ems_ext_id);

        /* Connection is successful and EMS is not negotiated */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS12);
        EXPECT_FALSE(server_conn->ems_negotiated);
        EXPECT_FALSE(client_conn->ems_negotiated);
        EXPECT_TRUE(IS_FULL_HANDSHAKE(server_conn));
        EXPECT_TRUE(IS_FULL_HANDSHAKE(client_conn));

        size_t tls12_session_ticket_len = s2n_connection_get_session_length(client_conn);
        uint8_t tls12_session_ticket[S2N_TLS12_SESSION_SIZE] = { 0 };
        EXPECT_SUCCESS(s2n_connection_get_session(client_conn, tls12_session_ticket, tls12_session_ticket_len));

        /* Wipe connections and set up new handshake */
        EXPECT_SUCCESS(s2n_connection_wipe(server_conn));
        EXPECT_SUCCESS(s2n_connection_wipe(client_conn));
        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* Force the client to send the EMS extension even though the original session did not negotiate EMS */
        EXPECT_SUCCESS(s2n_connection_set_session(client_conn, tls12_session_ticket, tls12_session_ticket_len));
        client_conn->ems_negotiated = true;

        /* Server will block the first time cache is accessed */
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn), S2N_ERR_ASYNC_BLOCKED);

        /* Fallback to full handshake */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_EQUAL(S2N_CBIT_TEST(server_conn->extension_requests_received, ems_ext_id), 1);
        EXPECT_TRUE(server_conn->ems_negotiated);
        EXPECT_TRUE(client_conn->ems_negotiated);
        EXPECT_TRUE(IS_FULL_HANDSHAKE(server_conn));
        EXPECT_TRUE(IS_FULL_HANDSHAKE(client_conn));

        EXPECT_SUCCESS(s2n_io_pair_close(&io_pair));
    };

    END_TEST();
}
