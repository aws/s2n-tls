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

#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <s2n.h>

#include "crypto/s2n_fips.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_cipher_suites.h"
#include "utils/s2n_safety.h"

static int try_handshake(struct s2n_connection *server_conn, struct s2n_connection *client_conn)
{
    s2n_blocked_status server_blocked;
    s2n_blocked_status client_blocked;

    int tries = 0;
    do {
        int client_rc = s2n_negotiate(client_conn, &client_blocked);
        if (!(client_rc == 0 || (client_blocked && errno == EAGAIN))) {
            return -1;
        }

        int server_rc = s2n_negotiate(server_conn, &server_blocked);
        if (!(server_rc == 0 || (server_blocked && errno == EAGAIN))) {
            return -1;
        }

        tries += 1;
        if (tries == 100) {
            return -1;
        }
    } while (client_blocked || server_blocked);

    uint8_t server_shutdown = 0;
    uint8_t client_shutdown = 0;
    do {
        if (!server_shutdown) {
            int server_rc = s2n_shutdown(server_conn, &server_blocked);
            if (server_rc == 0) {
                server_shutdown = 1;
            } else if (!(server_blocked && errno == EAGAIN)) {
                return -1;
            }
        }

        if (!client_shutdown) {
            int client_rc = s2n_shutdown(client_conn, &client_blocked);
            if (client_rc == 0) {
                client_shutdown = 1;
            } else if (!(client_blocked && errno == EAGAIN)) {
                return -1;
            }
        }
    } while (!server_shutdown || !client_shutdown);

    return 0;
}

int test_conn(struct s2n_config *server_config, struct s2n_config *client_config) {
    struct s2n_connection *client_conn;
    struct s2n_connection *server_conn;
    server_conn = s2n_connection_new(S2N_SERVER);
    notnull_check(server_conn);
    int server_to_client[2];
    int client_to_server[2];

    /* Create nonblocking pipes */
    GUARD(pipe(server_to_client));
    GUARD(pipe(client_to_server));
    for (int i = 0; i < 2; i++) {
       ne_check(fcntl(server_to_client[i], F_SETFL, fcntl(server_to_client[i], F_GETFL) | O_NONBLOCK), -1);
       ne_check(fcntl(client_to_server[i], F_SETFL, fcntl(client_to_server[i], F_GETFL) | O_NONBLOCK), -1);
    }

    client_conn = s2n_connection_new(S2N_CLIENT);
    notnull_check(client_conn);
    GUARD(s2n_connection_set_read_fd(client_conn, server_to_client[0]));
    GUARD(s2n_connection_set_write_fd(client_conn, client_to_server[1]));
    GUARD(s2n_connection_set_config(client_conn, client_config));

    GUARD(s2n_connection_set_read_fd(server_conn, client_to_server[0]));
    GUARD(s2n_connection_set_write_fd(server_conn, server_to_client[1]));
    GUARD(s2n_connection_set_config(server_conn, server_config));

    GUARD(try_handshake(server_conn, client_conn));

    GUARD(s2n_connection_free(server_conn));
    GUARD(s2n_connection_free(client_conn));

    for (int i = 0; i < 2; i++) {
       GUARD(close(server_to_client[i]));
       GUARD(close(client_to_server[i]));
    }

    return 0;
}

void check_keylog(struct s2n_connection *conn, const char *line, void *ctx)
{
    char *keylog_cb_invocations = (char *)ctx;

    for (int i = 0; i < 10; i++) {
        if (!keylog_cb_invocations[i * 256]) {
            strncpy(&keylog_cb_invocations[i * 256], line, 255);
            return;
        }
    }
}

int main(int argc, char **argv)
{

    BEGIN_TEST();

    char keylog_cb_invocations[10][256] = { { "" } };

    {
        struct s2n_config *server_config, *client_config;
        char *cert_chain_pem;
        char *private_key_pem;
        char *dhparams_pem;

        EXPECT_NOT_NULL(cert_chain_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(private_key_pem = malloc(S2N_MAX_TEST_PEM_SIZE));
        EXPECT_NOT_NULL(dhparams_pem = malloc(S2N_MAX_TEST_PEM_SIZE));

        EXPECT_NOT_NULL(server_config = s2n_config_new());

        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_CERT_CHAIN, cert_chain_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_PRIVATE_KEY, private_key_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key(server_config, cert_chain_pem, private_key_pem));
        EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dhparams_pem));
        EXPECT_SUCCESS(s2n_config_set_keylog_cb(server_config, check_keylog, &keylog_cb_invocations[0][0]));

        GUARD_NONNULL(client_config = s2n_config_new());
        GUARD(s2n_config_set_unsafe_for_testing(client_config));

        EXPECT_SUCCESS(s2n_config_set_verification_ca_location(client_config, S2N_DEFAULT_TEST_CERT_CHAIN, NULL));

        EXPECT_SUCCESS(test_conn(server_config, client_config));

        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));
        free(cert_chain_pem);
        free(private_key_pem);
        free(dhparams_pem);

        /* Both client and server should have logged the same line */
        EXPECT_NOT_EQUAL(keylog_cb_invocations[0], 0);
        EXPECT_NOT_EQUAL(keylog_cb_invocations[1], 0);
        EXPECT_BYTEARRAY_EQUAL(keylog_cb_invocations[0], "CLIENT_RANDOM ", sizeof("CLIENT_RANDOM ") - 1);
        EXPECT_STRING_EQUAL(keylog_cb_invocations[0], keylog_cb_invocations[1]);
    }

    END_TEST();
    return 0;
}

