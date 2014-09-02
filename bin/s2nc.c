/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <netdb.h>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <errno.h>

#include <s2n.h>

void usage()
{
    fprintf(stderr, "usage: s2nc host [port]\n");
    fprintf(stderr, " host: hostname or IP address to connect to\n");
    fprintf(stderr, " port: port to connect to\n");

    exit(1);
}

extern int echo(struct s2n_connection *conn, int sockfd);

int main(int argc, const char *argv[])
{
    struct addrinfo hints, *ai_list, *ai;
    const char *port = "443";
    int r, sockfd = 0;

    if (argc < 2 || argc > 3) {
        usage();
    }
    if (argc == 3) {
        port = argv[2];
    }

    if (memset(&hints, 0, sizeof(hints)) != &hints) {
        fprintf(stderr, "memset error: %s\n", strerror(errno));
        return -1;
    }

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((r = getaddrinfo(argv[1], port, &hints, &ai_list)) != 0) {
        fprintf(stderr, "error: %s\n", gai_strerror(r));
        return -1;
    }

    int connected = 0;
    for (ai = ai_list; ai != NULL; ai = ai->ai_next) {
        if ((sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1) {
            continue;
        }

        if (connect(sockfd, ai->ai_addr, ai->ai_addrlen) == -1) {
            close(sockfd);
            continue;
        }

        connected = 1;
        /* connect() succeeded */
        break;
    }

    if (connected == 0) {
        fprintf(stderr, "Failed to connect to %s:%s\n", argv[1], port);
        close(sockfd);
        exit(1);
    }

    const char *error;

    if (s2n_init(&error) < 0) {
        fprintf(stderr, "Error running s2n_init(): '%s'\n", error);
    }

    struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT, &error);

    if (conn == NULL) {
        fprintf(stderr, "Error getting new connection: '%s'\n", error);
        exit(1);
    }

    printf("Connected to %s:%s\n", argv[1], port);

    if (s2n_set_server_name(conn, argv[1], &error) < 0) {
        fprintf(stderr, "Error setting server name: '%s'\n", error);
        exit(1);
    }

    if (s2n_connection_set_fd(conn, sockfd, &error) < 0) {
        fprintf(stderr, "Error setting file descriptor: '%s'\n", error);
        exit(1);
    }

    /* See echo.c */
    echo(conn, sockfd);

    if (s2n_connection_free(conn, &error) < 0) {
        fprintf(stderr, "Error freeing connection: '%s'\n", error);
        exit(1);
    }


    return 0;
}
