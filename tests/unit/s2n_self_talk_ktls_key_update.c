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
#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/wait.h>

#define S2N_MODE_COUNT 2
#define S2N_SECRET_TYPE_COUNT 5

pid_t child;
static void terminate(void)
{
	kill(child, SIGTERM);
	exit(1);
}

int s2n_io_pair_init_ktls(struct s2n_test_io_pair *io_pair)
{
    signal(SIGPIPE, SIG_IGN);


    int socket_pair[2];

    POSIX_GUARD(socketpair(AF_UNIX, SOCK_STREAM, 0, socket_pair));

    io_pair->client = socket_pair[0];
    io_pair->server = socket_pair[1];

    return 0;
}

int s2n_fd_set_non_blocking_ktls(int fd) {
    return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

int s2n_io_pair_ktls(struct s2n_test_io_pair *io_pair)
{
    POSIX_GUARD(s2n_io_pair_init_ktls(io_pair));

    POSIX_GUARD(s2n_fd_set_non_blocking_ktls(io_pair->client));
    POSIX_GUARD(s2n_fd_set_non_blocking_ktls(io_pair->server));

    return 0;
}

int mock_client(
        /* int writefd, int readfd, */
        struct s2n_connection *client_conn,
        const char **protocols, int count, const char *expected)
{
    printf("-------- hi child ");
    char buffer[0xffff];
    /* struct s2n_connection *client_conn; */
    /* struct s2n_config *client_config; */
    s2n_blocked_status blocked;
    int result = 0;

    /* Give the server a chance to listen */
    sleep(1);

    /* client_conn = s2n_connection_new(S2N_CLIENT); */
    /* client_config = s2n_config_new(); */
    /* s2n_config_set_protocol_preferences(client_config, protocols, count); */
    /* s2n_config_disable_x509_verification(client_config); */
    /* s2n_connection_set_config(client_conn, client_config); */

    /* s2n_connection_set_read_fd(client_conn, readfd); */
    /* s2n_connection_set_write_fd(client_conn, writefd); */

    result = s2n_negotiate(client_conn, &blocked);
    if (result < 0) {
        result = 1;
    }

/*     const char *got = s2n_get_application_protocol(client_conn); */
/*     if ((got != NULL && expected == NULL) || */
/*         (got == NULL && expected != NULL) || */
/*         (got != NULL && expected != NULL && strcmp(expected, got) != 0)) { */
/*         result = 2; */
/*     } */

/*     for (int i = 1; i < 0xffff; i += 100) { */
/*         for (int j = 0; j < i; j++) { */
/*             buffer[j] = 33; */
/*         } */

/*         s2n_send(client_conn, buffer, i, &blocked); */
/*     } */

    int shutdown_rc= -1;
    if(!result) {
        do {
            shutdown_rc = s2n_shutdown(client_conn, &blocked);
        } while (shutdown_rc != 0);
    }

    s2n_connection_free(client_conn);

    /* Give the server a chance to a void a sigpipe */
    sleep(1);

    s2n_cleanup();

    /* if (result) { */
    /*     terminate(); */
    /* } */

    exit(0);
}

static void ch_handler(int sig)
{
    printf("-------- hi ch_handler ");
	  return;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    signal(SIGPIPE, SIG_IGN);
	  signal(SIGCHLD, ch_handler);

    s2n_blocked_status blocked = 0;
    char send_buffer[0xffff];
    char recv_buffer[0xffff];

    const uint8_t *transport_params = NULL;
    uint16_t transport_params_len = 0;

    /* Setup connections */
    struct s2n_connection *client_conn, *server_conn;
    EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
    EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));

    /* Setup config */
    struct s2n_cert_chain_and_key *chain_and_key;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    struct s2n_config *ktls_config;
    EXPECT_NOT_NULL(ktls_config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(ktls_config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(ktls_config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(ktls_config, chain_and_key));
    /* EXPECT_SUCCESS(s2n_config_ktls_enable(ktls_config)); */
    EXPECT_SUCCESS(s2n_connection_set_config(server_conn, ktls_config));

    struct s2n_config *config;
    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));




    /* real socket */
    int listener;
    struct sockaddr_in saddr;
    socklen_t addrlen;
    int ret;
    int fd;

	  listener = socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_SUCCESS(listener);

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
	  /* if (child < 0) { */
    if (child == 0) {
        /* client */
        fd = socket(AF_INET, SOCK_STREAM, 0);
        EXPECT_SUCCESS(fd);

        sleep(1);
		    EXPECT_SUCCESS(connect(fd, (struct sockaddr*)&saddr, addrlen));

        POSIX_GUARD(s2n_connection_set_fd(client_conn, fd));

        mock_client(client_conn, NULL, 0, NULL);

    } else {
        /* server */
        EXPECT_SUCCESS(listen(listener, 1));
        fd = accept(listener, NULL, NULL);
        POSIX_GUARD(s2n_connection_set_fd(server_conn, fd));
    }


    /* local link */
    /* Create nonblocking pipes */
    /* struct s2n_test_io_pair io_pair; */
    /* EXPECT_SUCCESS(s2n_io_pair_ktls(&io_pair)); */
    /* EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair)); */
    /* EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair)); */

    /* Do handshake */
    /* EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn)); */
    EXPECT_SUCCESS(s2n_negotiate(server_conn, &blocked));

    /* Verify TLS1.3 */
    EXPECT_EQUAL(client_conn->actual_protocol_version, S2N_TLS13);
    EXPECT_EQUAL(server_conn->actual_protocol_version, S2N_TLS13);


    /* KTLS KeyUpdate test */
    /* { */
    /*     const char a = 'a'; */
    /*     const char b = 'b'; */
    /*     const char c = 'c'; */

    /*     send_buffer[0] = a; */
    /*     EXPECT_SUCCESS(s2n_send(client_conn, send_buffer, 1, &blocked)); */
    /*     EXPECT_SUCCESS(s2n_recv(server_conn, recv_buffer, 1, &blocked)); */
    /*     printf("-------- %c %c %c\n", send_buffer[0], a, recv_buffer[0]); */
    /*     EXPECT_TRUE(memcmp(&a, &recv_buffer[0], 1) == 0); */

    /*     /1* -------------------------- client sends *1/ */
    /*     client_conn->key_update_pending = true; */
    /*     EXPECT_SUCCESS(s2n_key_update_send(client_conn, &blocked)); */

    /*     send_buffer[0] = b; */
    /*     EXPECT_SUCCESS(s2n_send(client_conn, send_buffer, 1, &blocked)); */
    /*     EXPECT_SUCCESS(s2n_recv(server_conn, recv_buffer, 1, &blocked)); */
    /*     printf("-------- %c %c %c\n", send_buffer[0], b, recv_buffer[0]); */
    /*     EXPECT_TRUE(memcmp(&b, &recv_buffer[0], 1) == 0); */

    /*     /1* -------------------------- server sends *1/ */
    /*     server_conn->key_update_pending = true; */
    /*     EXPECT_SUCCESS(s2n_key_update_send(server_conn, &blocked)); */

    /*     send_buffer[0] = c; */
    /*     EXPECT_SUCCESS(s2n_send(server_conn, send_buffer, 1, &blocked)); */
    /*     EXPECT_SUCCESS(s2n_recv(client_conn, recv_buffer, 1, &blocked)); */
    /*     printf("-------- %c %c %c\n", send_buffer[0], c, recv_buffer[0]); */
    /*     EXPECT_TRUE(memcmp(&c, &recv_buffer[0], 1) == 0); */

    /* } */
    /* KTLS KeyUpdate test */

		wait(&status);
    EXPECT_EQUAL(waitpid(-1, &status, 0), child);

    EXPECT_SUCCESS(s2n_connection_free(server_conn));
    /* EXPECT_SUCCESS(s2n_io_pair_close(&io_pair)); */
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
    EXPECT_SUCCESS(s2n_config_free(config));

    END_TEST();
}
