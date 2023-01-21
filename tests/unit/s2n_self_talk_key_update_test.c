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

#include "s2n.h"
#include "s2n_test.h"
#include "stdio.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "utils/s2n_safety.h"
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/wait.h>

#define S2N_MODE_COUNT 2
#define S2N_SECRET_TYPE_COUNT 5


/* test cases */
/*
 * server always writes
 *
 * TX
 * - ktls conn: send msg  (send key_update + rekey)     send msg
 *   norm conn:       rx msg              rx key_update    rx msg
 *
 * RX
 * - ktls conn:       rx msg          rx key_update   rx msg
 *   norm conn: send msg   send key_update       send msg
 *
 */
bool ktls_enable_send = false;

#define KTLS_enable() \
    if (ktls_enable_send) \
        EXPECT_SUCCESS(s2n_config_ktls_enable(config));

#define KTLS_enable_check(conn) \
    if (ktls_enable_send) \
        EXPECT_TRUE(conn->ktls_enabled_send_io);

/*
 * conn
 * c: the char to write
 */
#define KTLS_send(conn, c) \
    send_buffer[0] = c; \
    if (ktls_enable_send) \
        EXPECT_SUCCESS(write(fd, send_buffer, 1)); \
    else \
        EXPECT_SUCCESS(s2n_send(conn, send_buffer, 1, &blocked));

/*
 * conn
 * curr_gen: the current generation
 *
* without kernel patch \
*   expect fail \
* with kernel patch \
*   expect rekey and success \
 */
#define KTLS_send_ku(conn, curr_gen) \
    EXPECT_TRUE(conn->generation == curr_gen); \
    if (ktls_enable_send) { \
        uint8_t key_update_data[S2N_KEY_UPDATE_MESSAGE_SIZE]; \
        struct s2n_blob key_update_blob = {0}; \
        EXPECT_SUCCESS(s2n_blob_init(&key_update_blob, key_update_data, sizeof(key_update_data))); \
        EXPECT_SUCCESS(s2n_key_update_write(&key_update_blob)); \
        EXPECT_SUCCESS(s2n_klts_send_ctrl_msg(fd, TLS_HANDSHAKE, key_update_blob.data, S2N_KEY_UPDATE_MESSAGE_SIZE)); \
    } else { \
        conn->key_update_pending = true; \
        EXPECT_SUCCESS(s2n_key_update_send(conn, &blocked)); \
        EXPECT_TRUE(conn->generation == (curr_gen + 1)); \
    }

pid_t child;
const char a = 'a';
const char b = 'b';

static void ch_handler(int sig)
{
	  return;
}

static S2N_RESULT start_client(int fd, int read_pipe)
{
    char sync;
    s2n_blocked_status blocked = 0;
    char recv_buffer[10];

    /* Setup connections */
    DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
            s2n_connection_ptr_free);
    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    /* Setup config */
    EXPECT_SUCCESS(s2n_connection_set_blinding(client_conn, S2N_SELF_SERVICE_BLINDING));
    EXPECT_SUCCESS(s2n_connection_set_fd(client_conn, fd));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

    /* Do handshake */
    EXPECT_SUCCESS(s2n_negotiate(client_conn, &blocked));
    EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);

    printf("\n===========-----------=================\n");
    {
        read(read_pipe, &sync, 1);
        printf("----------client read 1\n");

        EXPECT_SUCCESS(s2n_recv(client_conn, recv_buffer, 1, &blocked));
        EXPECT_TRUE(memcmp(&a, &recv_buffer[0], 1) == 0);
        EXPECT_TRUE(client_conn->generation == 0);

        read(read_pipe, &sync, 1);
        printf("----------client read 2\n");

        int ret = s2n_recv(client_conn, recv_buffer, 1, &blocked);
        EXPECT_TRUE(client_conn->generation == 1);
        EXPECT_SUCCESS(ret);
        EXPECT_TRUE(memcmp(&b, &recv_buffer[0], 1) == 0);
    }

    return S2N_RESULT_OK;
}

static S2N_RESULT start_server(int fd, int write_pipe)
{
    char sync = 0;
    s2n_blocked_status blocked = 0;
    char send_buffer[10];

    /* Setup connections */
    DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
            s2n_connection_ptr_free);
    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    /* Setup config */
    EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));
    EXPECT_EQUAL(s2n_connection_get_delay(server_conn), 0);
    EXPECT_SUCCESS(s2n_connection_set_fd(server_conn, fd));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    KTLS_enable();
    EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

    /* Do handshake */
    EXPECT_SUCCESS(s2n_negotiate(server_conn, &blocked));
    EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);

    {
        KTLS_enable_check(server_conn);

        KTLS_send(server_conn, a);
        write(write_pipe, &sync, 1);

        /* send key update */
        KTLS_send_ku(server_conn, 0);

        KTLS_send(server_conn, b);
        write(write_pipe, &sync, 1);
    }

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    signal(SIGPIPE, SIG_IGN);
	  signal(SIGCHLD, ch_handler);

    //used for synchronizing read and writes between client and server
	  int sync_pipe[2];
	  pipe(sync_pipe);

    /* real socket */
    int listener;
    struct sockaddr_in saddr;
    socklen_t addrlen;
    int ret;
    int fd;

	  listener = socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_SUCCESS(listener);
    /* fprintf(stderr, "server listen on fd---------- %d\n", listener); */

	  memset(&saddr, 0, sizeof(saddr));
	  saddr.sin_family = AF_INET;
	  saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	  saddr.sin_port = 0;

    EXPECT_SUCCESS(bind(listener, (struct sockaddr*)&saddr, sizeof(saddr)));
    addrlen = sizeof(saddr);
    EXPECT_SUCCESS(getsockname(listener, (struct sockaddr*)&saddr, &addrlen));

    child = fork();
    EXPECT_FALSE(child < 0);
    int status;
	  if (child) {
        /* server */
        EXPECT_SUCCESS(listen(listener, 1));
        fd = accept(listener, NULL, NULL);
        EXPECT_SUCCESS(fd);
        /* fprintf(stderr, "server accept fd---------- %d\n", fd); */

        close(sync_pipe[0]);
        EXPECT_OK(start_server(fd, sync_pipe[1]));

        EXPECT_EQUAL(wait(&status), child);
        EXPECT_EQUAL(status, 0);
    } else {
        /* client */
        fd = socket(AF_INET, SOCK_STREAM, 0);
        EXPECT_SUCCESS(fd);

        sleep(1);
		    EXPECT_SUCCESS(connect(fd, (struct sockaddr*)&saddr, addrlen));

        fprintf(stderr, "client connect fd---------- %d\n", fd);

        close(sync_pipe[1]);
        EXPECT_OK(start_client(fd, sync_pipe[0]));
        exit(0);
    }

    END_TEST();
}
