/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <poll.h>
#include <netdb.h>

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <s2n.h>
#include <error/s2n_errno.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "crypto/s2n_rsa.h"
#include "crypto/s2n_pkey.h"

void print_s2n_error(const char *app_error)
{
    fprintf(stderr, "[%d] %s: '%s' : '%s'\n", getpid(), app_error, s2n_strerror(s2n_errno, "EN"),
            s2n_strerror_debug(s2n_errno, "EN"));
}

int negotiate(struct s2n_connection *conn)
{
    s2n_blocked_status blocked;
    do {
        if (s2n_negotiate(conn, &blocked) < 0) {
            fprintf(stderr, "Failed to negotiate: '%s'. %s\n", s2n_strerror(s2n_errno, "EN"), s2n_strerror_debug(s2n_errno, "EN"));
            fprintf(stderr, "Alert: %d\n", s2n_connection_get_alert(conn));
            S2N_ERROR_PRESERVE_ERRNO();
        }
    } while (blocked);

    /* Now that we've negotiated, print some parameters */
    int client_hello_version;
    int client_protocol_version;
    int server_protocol_version;
    int actual_protocol_version;

    if ((client_hello_version = s2n_connection_get_client_hello_version(conn)) < 0) {
        fprintf(stderr, "Could not get client hello version\n");
        S2N_ERROR(S2N_ERR_CLIENT_HELLO_VERSION);
    }
    if ((client_protocol_version = s2n_connection_get_client_protocol_version(conn)) < 0) {
        fprintf(stderr, "Could not get client protocol version\n");
        S2N_ERROR(S2N_ERR_CLIENT_PROTOCOL_VERSION);
    }
    if ((server_protocol_version = s2n_connection_get_server_protocol_version(conn)) < 0) {
        fprintf(stderr, "Could not get server protocol version\n");
        S2N_ERROR(S2N_ERR_SERVER_PROTOCOL_VERSION);
    }
    if ((actual_protocol_version = s2n_connection_get_actual_protocol_version(conn)) < 0) {
        fprintf(stderr, "Could not get actual protocol version\n");
        S2N_ERROR(S2N_ERR_ACTUAL_PROTOCOL_VERSION);
    }
    printf("CONNECTED:\n");
    printf("Client hello version: %d\n", client_hello_version);
    printf("Client protocol version: %d\n", client_protocol_version);
    printf("Server protocol version: %d\n", server_protocol_version);
    printf("Actual protocol version: %d\n", actual_protocol_version);

    if (s2n_get_server_name(conn)) {
        printf("Server name: %s\n", s2n_get_server_name(conn));
    }

    if (s2n_get_application_protocol(conn)) {
        printf("Application protocol: %s\n", s2n_get_application_protocol(conn));
    }

    printf("Curve: %s\n", s2n_connection_get_curve(conn));
    printf("KEM: %s\n", s2n_connection_get_kem_name(conn));

    uint32_t length;
    const uint8_t *status = s2n_connection_get_ocsp_response(conn, &length);
    if (status && length > 0) {
        fprintf(stderr, "OCSP response received, length %u\n", length);
    }

    printf("Cipher negotiated: %s\n", s2n_connection_get_cipher(conn));
    if (s2n_connection_is_session_resumed(conn)) {
        printf("Resumed session\n");
    }

    return 0;
}

int echo(struct s2n_connection *conn, int sockfd)
{
    struct pollfd readers[2];

    readers[0].fd = sockfd;
    readers[0].events = POLLIN;
    readers[1].fd = STDIN_FILENO;
    readers[1].events = POLLIN;

    /* Act as a simple proxy between stdin and the SSL connection */
    int p;
    s2n_blocked_status blocked;
    do {
        while ((p = poll(readers, 2, -1)) > 0) {
            char buffer[10240];
            int bytes_read, bytes_written;
    
            if (readers[0].revents & POLLIN) {
                do {
                    bytes_read = s2n_recv(conn, buffer, 10240, &blocked);
                    if (bytes_read == 0) {
                        return 0;
                    }
                    if (bytes_read < 0) {
                        fprintf(stderr, "Error reading from connection: '%s' %d\n", s2n_strerror(s2n_errno, "EN"), s2n_connection_get_alert(conn));
                        exit(1);
                    }
                    bytes_written = write(STDOUT_FILENO, buffer, bytes_read);
                    if (bytes_written <= 0) {
                        fprintf(stderr, "Error writing to stdout\n");
                        exit(1);
                    }
                } while (blocked);
            }
            if (readers[1].revents & POLLIN) {
                int bytes_available;
                if (ioctl(STDIN_FILENO, FIONREAD, &bytes_available) < 0) {
                    bytes_available = 1;
                }
                if (bytes_available > sizeof(buffer)) {
                    bytes_available = sizeof(buffer);
                }
    
                /* Read as many bytes as we think we can */
    	    do {
    	        errno = 0;
    		bytes_read = read(STDIN_FILENO, buffer, bytes_available);
    		if(bytes_read < 0 && errno != EINTR){
    		  fprintf(stderr, "Error reading from stdin\n");
    		  exit(1);
    		}
    	    } while (bytes_read < 0);
    
                if (bytes_read == 0) {
                    /* Exit on EOF */
                    return 0;
                }
    
                char *buf_ptr = buffer;
                do {
                    bytes_written = s2n_send(conn, buf_ptr, bytes_available, &blocked);
                    if (bytes_written < 0) {
                        fprintf(stderr, "Error writing to connection: '%s'\n", s2n_strerror(s2n_errno, "EN"));
                        exit(1);
                    }
    
                    bytes_available -= bytes_written;
                    buf_ptr += bytes_written;
                } while (bytes_available || blocked);
            }
            if (readers[1].revents & POLLHUP) {
                /* The stdin pipe hanged up, and we've handled all read from it above */
                return 0;
            }
            if (readers[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                fprintf(stderr, "Error polling from socket: err=%d hup=%d nval=%d\n",
                        (readers[0].revents & POLLERR ) ? 1 : 0,
                        (readers[0].revents & POLLHUP ) ? 1 : 0,
                        (readers[0].revents & POLLNVAL ) ? 1 : 0);
                S2N_ERROR(S2N_ERR_POLLING_FROM_SOCKET);
            }
            if (readers[1].revents & (POLLERR | POLLNVAL)) {
                fprintf(stderr, "Error polling from socket: err=%d nval=%d\n",
                        (readers[1].revents & POLLERR ) ? 1 : 0,
                        (readers[1].revents & POLLNVAL ) ? 1 : 0);
                S2N_ERROR(S2N_ERR_POLLING_FROM_SOCKET);
            }
        }
    } while (p < 0 && errno == EINTR);

    return 0;
}
