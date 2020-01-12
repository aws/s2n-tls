/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>

#include <s2n.h>
#include <errno.h>

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"

#define MAX_KEY_LEN 32
#define MAX_VAL_LEN 255

static const char SESSION_ID[] = "0123456789abcdef0123456789abcdef";
static const char MSG[] = "Test";

struct session_cache_entry {
    uint8_t key[MAX_KEY_LEN];
    uint8_t key_len;
    uint8_t value[MAX_VAL_LEN];
    uint8_t value_len;
    uint8_t lock;
};

struct session_cache_entry session_cache[256];

int cache_store(struct s2n_connection *conn, void *ctx, uint64_t ttl, const void *key, uint64_t key_size, const void *value, uint64_t value_size)
{
    struct session_cache_entry *cache = ctx;

    if (key_size == 0 || key_size > MAX_KEY_LEN) {
        return -1;
    }
    if (value_size == 0 || value_size > MAX_VAL_LEN) {
        return -1;
    }

    uint8_t index = ((const uint8_t *)key)[0];

    memcpy(cache[index].key, key, key_size);
    memcpy(cache[index].value, value, value_size);

    cache[index].key_len = key_size;
    cache[index].value_len = value_size;

    return 0;
}

int cache_retrieve(struct s2n_connection *conn, void *ctx, const void *key, uint64_t key_size, void *value, uint64_t * value_size)
{
    struct session_cache_entry *cache = ctx;

    if (key_size == 0 || key_size > MAX_KEY_LEN) {
        return -1;
    }

    uint8_t index = ((const uint8_t *)key)[0];

    if (cache[index].lock) {
        /* here we mock a remote connection/event blocking the handshake
         * state machine, until lock is free
         */
        cache[index].lock = 0;
        return -2;
    }

    if (cache[index].key_len != key_size) {
        return -1;
    }

    if (memcmp(cache[index].key, key, key_size)) {
        return -1;
    }

    if (*value_size < cache[index].value_len) {
        return -1;
    }

    *value_size = cache[index].value_len;
    memcpy(value, cache[index].value, cache[index].value_len);

    return 0;
}

int cache_delete(struct s2n_connection *conn, void *ctx, const void *key, uint64_t key_size)
{
    struct session_cache_entry *cache = ctx;

    if (key_size == 0 || key_size > MAX_KEY_LEN) {
        return -1;
    }

    uint8_t index = ((const uint8_t *)key)[0];

    if (cache[index].key_len != key_size) {
        return -1;
    }

    if (memcmp(cache[index].key, key, key_size)) {
        return -1;
    }

    cache[index].key_len = 0;
    cache[index].value_len = 0;

    return 0;
}

void mock_client(int writefd, int readfd)
{
    size_t serialized_session_state_length = 0;
    uint8_t serialized_session_state[256] = { 0 };

    struct s2n_connection *conn;
    struct s2n_config *config;
    s2n_blocked_status blocked;
    int result = 0;

    /* Give the server a chance to listen */
    sleep(1);

    /* Initial handshake */
    conn = s2n_connection_new(S2N_CLIENT);
    config = s2n_config_new();
    s2n_config_disable_x509_verification(config);
    s2n_connection_set_config(conn, config);

    s2n_connection_set_read_fd(conn, readfd);
    s2n_connection_set_write_fd(conn, writefd);

    /* Set the session id to ensure we're able to fallback to full handshake if session is not in server cache */
    memcpy(conn->session_id, SESSION_ID, S2N_TLS_SESSION_ID_MAX_LEN);
    conn->session_id_len = S2N_TLS_SESSION_ID_MAX_LEN;

    if (s2n_negotiate(conn, &blocked) != 0) {
        result = 1;
    }

    /* Make sure we did a full handshake */
    if (!IS_FULL_HANDSHAKE(conn->handshake.handshake_type)) {
        result = 2;
    }

    /* Save session state from the connection */
    memset(serialized_session_state, 0, sizeof(serialized_session_state));
    serialized_session_state_length = s2n_connection_get_session_length(conn);
    if (serialized_session_state_length > sizeof(serialized_session_state)) {
        result = 3;
    }

    /* Send very low session buffer size and see that you can get an error */
    if (s2n_connection_get_session(conn, serialized_session_state, 1) == 0) {
        result = 4;
    }

    if (s2n_errno != S2N_ERR_SERIALIZED_SESSION_STATE_TOO_LONG) {
        result = 5;
    }

    if (s2n_connection_get_session(conn, serialized_session_state, serialized_session_state_length) != serialized_session_state_length) {
        result = 6;
    }

    if (s2n_send(conn, MSG, sizeof(MSG), &blocked) != sizeof(MSG)) {
        result = 7;
    }

    int shutdown_rc = -1;
    while(shutdown_rc != 0) {
        shutdown_rc = s2n_shutdown(conn, &blocked);
    }

    s2n_connection_free(conn);

    /* Give the server a chance to avoid sigpipe */
    sleep(1);

    /* Session resumption */
    conn = s2n_connection_new(S2N_CLIENT);
    s2n_connection_set_read_fd(conn, readfd);
    s2n_connection_set_write_fd(conn, writefd);

    /* Set session state on client connection */
    if (s2n_connection_set_session(conn, serialized_session_state, serialized_session_state_length) < 0) {
        result = 8;
    }

    if (s2n_negotiate(conn, &blocked) != 0) {
        result = 9;
    }

    /* Make sure we did a abbreviated handshake */
    if (!IS_RESUMPTION_HANDSHAKE(conn->handshake.handshake_type)) {
        result = 10;
    }

    if (s2n_send(conn, MSG, sizeof(MSG), &blocked) != sizeof(MSG)) {
        result = 11;
    }

    shutdown_rc = -1;
    while(shutdown_rc != 0) {
        shutdown_rc = s2n_shutdown(conn, &blocked);
    }

    s2n_connection_free(conn);

    /* Give the server a chance to avoid sigpipe */
    sleep(1);

    /* Session resumption with bad session state */
    conn = s2n_connection_new(S2N_CLIENT);
    s2n_connection_set_read_fd(conn, readfd);
    s2n_connection_set_write_fd(conn, writefd);

    /* Change the format of the session state and check we cannot deserialize it */
    serialized_session_state[0] = 3;
    if (s2n_connection_set_session(conn, serialized_session_state, serialized_session_state_length) == 0) {
        result = 12;
    }

    if (s2n_errno != S2N_ERR_INVALID_SERIALIZED_SESSION_STATE) {
        result = 13;
    }

    serialized_session_state[0] = 0;
    /* Change the protocol version (36th byte) in session state */
    if (serialized_session_state_length < 36) {
        result = 14;
    }

    serialized_session_state[35] = 30;
    if (s2n_connection_set_session(conn, serialized_session_state, serialized_session_state_length) < 0) {
        result = 15;
    }

    if (s2n_negotiate(conn, &blocked) == 0) {
        result = 16;
    }

    if (s2n_errno != S2N_ERR_BAD_MESSAGE) {
        result = 17;
    }

    s2n_connection_free(conn);
    s2n_config_free(config);

    /* Give the server a chance to avoid sigpipe */
    sleep(1);

    _exit(result);
}

int main(int argc, char **argv)
{
    struct s2n_connection *conn;
    struct s2n_config *config;
    s2n_blocked_status blocked;
    int status;
    pid_t pid;
    int server_to_client[2];
    int client_to_server[2];
    char *cert_chain_pem;
    char *private_key_pem;
    char buffer[256];
    int bytes_read;
    int shutdown_rc = -1;

    /* init session cache lock field, which is used to mock a remote
     * connection/event block
     */
    for (int i = 0; i < 256; i++) {
        session_cache[i].lock = 1;
    }

    BEGIN_TEST();
    EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
    EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

    EXPECT_SUCCESS(setenv("S2N_ENABLE_CLIENT_MODE", "1", 0));

    /* Create a pipe */
    EXPECT_SUCCESS(pipe(server_to_client));
    EXPECT_SUCCESS(pipe(client_to_server));

    /* Create a child process */
    pid = fork();
    if (pid == 0) {
        /* This is the child process, close the read end of the pipe */
        EXPECT_SUCCESS(close(client_to_server[0]));
        EXPECT_SUCCESS(close(server_to_client[1]));

        /* Write the fragmented hello message */
        mock_client(client_to_server[1], server_to_client[0]);
    }

    /* This is the parent */
    EXPECT_SUCCESS(close(client_to_server[1]));
    EXPECT_SUCCESS(close(server_to_client[0]));

    /* initial handshake */
    {
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_NOT_NULL(config = s2n_config_new());
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(config, cert_chain_pem, private_key_pem));
        EXPECT_SUCCESS(s2n_config_set_cache_store_callback(config, cache_store, session_cache));
        EXPECT_SUCCESS(s2n_config_set_cache_retrieve_callback(config, cache_retrieve, session_cache));
        EXPECT_SUCCESS(s2n_config_set_cache_delete_callback(config, cache_delete, session_cache));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* Set up the connection to read from the fd */
        EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(conn, server_to_client[1]));

        /* Negotiate the handshake. */
        s2n_errno = S2N_ERR_T_OK;
        int r = s2n_negotiate(conn, &blocked);
        /* first time it always blocks the handshake, as we mock a remote
         * connection/event from the lock
         */
        EXPECT_EQUAL(r, -1);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_APPLICATION_INPUT);
        s2n_errno = S2N_ERR_T_OK;
        EXPECT_SUCCESS(s2n_negotiate(conn, &blocked));

        /* Make sure we did a full handshake */
        EXPECT_TRUE(IS_FULL_HANDSHAKE(conn->handshake.handshake_type));

        /* Ensure the message was delivered */
        EXPECT_SUCCESS(bytes_read = s2n_recv(conn, buffer, sizeof(buffer), &blocked));
        EXPECT_EQUAL(bytes_read, sizeof(MSG));
        EXPECT_EQUAL(memcmp(buffer, MSG, sizeof(MSG)), 0);

        /* Shutdown handshake */
        do {
            shutdown_rc = s2n_shutdown(conn, &blocked);
            EXPECT_TRUE(shutdown_rc == 0 || (errno == EAGAIN && blocked));
        } while(shutdown_rc != 0);

        /* Clean up */
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Session resumption */
    {
        EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
        EXPECT_SUCCESS(s2n_connection_set_config(conn, config));

        /* Set up the connection to read from the fd */
        EXPECT_SUCCESS(s2n_connection_set_read_fd(conn, client_to_server[0]));
        EXPECT_SUCCESS(s2n_connection_set_write_fd(conn, server_to_client[1]));

        /* Negotiate the handshake. */
        s2n_errno = S2N_ERR_T_OK;
        int r = s2n_negotiate(conn, &blocked);
        /* first time it always blocks the handshake, as we mock a remote
         * connection/event from the lock
         */
        EXPECT_EQUAL(r, -1);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_APPLICATION_INPUT);
        s2n_errno = S2N_ERR_T_OK;
        EXPECT_SUCCESS(s2n_negotiate(conn, &blocked));

        /* Make sure we did a abbreviated handshake */
        EXPECT_TRUE(IS_RESUMPTION_HANDSHAKE(conn->handshake.handshake_type));

        /* Ensure the message was delivered */
        memset(buffer, 0, sizeof(buffer));
        EXPECT_SUCCESS(bytes_read = s2n_recv(conn, buffer, sizeof(buffer), &blocked));
        EXPECT_EQUAL(bytes_read, sizeof(MSG));
        EXPECT_EQUAL(memcmp(buffer, MSG, sizeof(MSG)), 0);

        /* Shutdown handshake */
        do {
            shutdown_rc = s2n_shutdown(conn, &blocked);
            EXPECT_TRUE(shutdown_rc == 0 || (errno == EAGAIN && blocked));
        } while(shutdown_rc != 0);

        /* Clean up */
        EXPECT_SUCCESS(s2n_connection_free(conn));
    }

    /* Close the pipes */
    EXPECT_SUCCESS(close(client_to_server[0]));
    EXPECT_SUCCESS(close(server_to_client[1]));

    /* Clean up */
    EXPECT_SUCCESS(s2n_config_free(config));
    EXPECT_EQUAL(waitpid(-1, &status, 0), pid);

    free(cert_chain_pem);
    free(private_key_pem);

    END_TEST();
    return 0;
}
