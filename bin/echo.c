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
#include "common.h"

#define STDIO_BUFSIZE  10240

void print_s2n_error(const char *app_error)
{
    fprintf(stderr, "[%d] %s: '%s' : '%s'\n", getpid(), app_error, s2n_strerror(s2n_errno, "EN"),
            s2n_strerror_debug(s2n_errno, "EN"));
}

/* Poll the given file descriptor for an event determined by the blocked status */
static int wait_for_event(int fd, s2n_blocked_status blocked)
{
    struct pollfd reader = { .fd = fd, .events = 0 };

    switch (blocked) {
    case S2N_NOT_BLOCKED:
        return S2N_SUCCESS;
    case S2N_BLOCKED_ON_READ:
        reader.events |= POLLIN;
        break;
    case S2N_BLOCKED_ON_WRITE:
        reader.events |= POLLOUT;
        break;
    case S2N_BLOCKED_ON_EARLY_DATA:
    case S2N_BLOCKED_ON_APPLICATION_INPUT:
        /* This case is not encountered by the s2nc/s2nd applications,
         * but is detected for completeness */
        return S2N_SUCCESS;
    }

    if (poll(&reader, 1, -1) < 0) {
        fprintf(stderr, "Failed to poll connection: %s\n", strerror(errno));
        S2N_ERROR_PRESERVE_ERRNO();
    }

    return S2N_SUCCESS;
}

int early_data_recv(struct s2n_connection *conn)
{
    uint32_t max_early_data_size = 0;
    GUARD_RETURN(s2n_connection_get_max_early_data_size(conn, &max_early_data_size), "Error getting max early data size");
    if (max_early_data_size == 0) {
        return S2N_SUCCESS;
    }

    ssize_t total_data_recv = 0;
    ssize_t data_recv = 0;
    bool server_success = 0;
    s2n_blocked_status blocked = 0;
    uint8_t *early_data_received = malloc(max_early_data_size);
    GUARD_EXIT_NULL(early_data_received);

    do {
        server_success = (s2n_recv_early_data(conn, early_data_received + total_data_recv,
                max_early_data_size - total_data_recv, &data_recv, &blocked) >= S2N_SUCCESS);
        total_data_recv += data_recv;
    } while (!server_success);

    if (total_data_recv > 0) {
        fprintf(stdout, "Early Data received: ");
        for (size_t i = 0; i < total_data_recv; i++) {
            fprintf(stdout, "%c", early_data_received[i]);
        }
        fprintf(stdout, "\n");
    }

    free(early_data_received);

    return S2N_SUCCESS;
}

int early_data_send(struct s2n_connection *conn, uint8_t *data, uint32_t len)
{
    s2n_blocked_status blocked = 0;
    ssize_t total_data_sent = 0;
    ssize_t data_sent = 0;
    bool client_success = 0;
    do {
        client_success = (s2n_send_early_data(conn, data + total_data_sent,
                len - total_data_sent, &data_sent, &blocked) >= S2N_SUCCESS);
        total_data_sent += data_sent;
    } while (total_data_sent < len && !client_success);

    return S2N_SUCCESS;
}

int negotiate(struct s2n_connection *conn, int fd)
{
    s2n_blocked_status blocked;
    while (s2n_negotiate(conn, &blocked) != S2N_SUCCESS) {
        if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
            fprintf(stderr, "Failed to negotiate: '%s'. %s\n",
                    s2n_strerror(s2n_errno, "EN"),
                    s2n_strerror_debug(s2n_errno, "EN"));
            fprintf(stderr, "Alert: %d\n",
                    s2n_connection_get_alert(conn));
            S2N_ERROR_PRESERVE_ERRNO();
        }

        if (wait_for_event(fd, blocked) != S2N_SUCCESS) {
            S2N_ERROR_PRESERVE_ERRNO();
        }
    }

    /* Now that we've negotiated, print some parameters */
    int client_hello_version;
    int client_protocol_version;
    int server_protocol_version;
    int actual_protocol_version;

    if ((client_hello_version = s2n_connection_get_client_hello_version(conn)) < 0) {
        fprintf(stderr, "Could not get client hello version\n");
        POSIX_BAIL(S2N_ERR_CLIENT_HELLO_VERSION);
    }
    if ((client_protocol_version = s2n_connection_get_client_protocol_version(conn)) < 0) {
        fprintf(stderr, "Could not get client protocol version\n");
        POSIX_BAIL(S2N_ERR_CLIENT_PROTOCOL_VERSION);
    }
    if ((server_protocol_version = s2n_connection_get_server_protocol_version(conn)) < 0) {
        fprintf(stderr, "Could not get server protocol version\n");
        POSIX_BAIL(S2N_ERR_SERVER_PROTOCOL_VERSION);
    }
    if ((actual_protocol_version = s2n_connection_get_actual_protocol_version(conn)) < 0) {
        fprintf(stderr, "Could not get actual protocol version\n");
        POSIX_BAIL(S2N_ERR_ACTUAL_PROTOCOL_VERSION);
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
    printf("KEM Group: %s\n", s2n_connection_get_kem_group_name(conn));

    uint32_t length;
    const uint8_t *status = s2n_connection_get_ocsp_response(conn, &length);
    if (status && length > 0) {
        fprintf(stderr, "OCSP response received, length %u\n", length);
    }

    printf("Cipher negotiated: %s\n", s2n_connection_get_cipher(conn));

    bool session_resumed = s2n_connection_is_session_resumed(conn);
    if (session_resumed) {
        printf("Resumed session\n");
    }

    uint16_t identity_length = 0;
    GUARD_EXIT(s2n_connection_get_negotiated_psk_identity_length(conn, &identity_length), "Error getting negotiated psk identity length from the connection\n");
    if (identity_length != 0 && !session_resumed) {
        uint8_t *identity = malloc(identity_length);
        GUARD_EXIT_NULL(identity);
        GUARD_EXIT(s2n_connection_get_negotiated_psk_identity(conn, identity, identity_length), "Error getting negotiated psk identity from the connection\n");
        printf("Negotiated PSK identity: %s\n", identity);
        free(identity);
    }

    s2n_early_data_status_t early_data_status = 0;
    GUARD_EXIT(s2n_connection_get_early_data_status(conn, &early_data_status), "Error getting early data status");
    const char *status_str = NULL;
    switch(early_data_status) {
        case S2N_EARLY_DATA_STATUS_OK: status_str = "IN PROGRESS"; break;
        case S2N_EARLY_DATA_STATUS_NOT_REQUESTED: status_str = "NOT REQUESTED"; break;
        case S2N_EARLY_DATA_STATUS_REJECTED: status_str = "REJECTED"; break;
        case S2N_EARLY_DATA_STATUS_END: status_str = "ACCEPTED"; break;
    }
    GUARD_EXIT_NULL(status_str);
    printf("Early Data status: %s\n", status_str);

    printf("s2n is ready\n");
    return 0;
}

int echo(struct s2n_connection *conn, int sockfd, bool *stop_echo)
{
    struct pollfd readers[2];

    readers[0].fd = sockfd;
    readers[0].events = POLLIN;
    readers[1].fd = STDIN_FILENO;
    readers[1].events = POLLIN;

    /* Reset errno so that we can't inherit the errno == EINTR exit condition. */
    errno = 0;

    /* Act as a simple proxy between stdin and the SSL connection */
    int p = 0;
    s2n_blocked_status blocked;
    do {
        /* echo will send and receive Application Data back and forth between
         * client and server, until stop_echo is true. */
        while (!(*stop_echo) && (p = poll(readers, 2, -1)) > 0) {
            char buffer[STDIO_BUFSIZE];
            ssize_t bytes_read = 0;
            ssize_t bytes_written = 0;

            if (readers[0].revents & POLLIN) {
                s2n_errno = S2N_ERR_T_OK;
                bytes_read = s2n_recv(conn, buffer, STDIO_BUFSIZE, &blocked);
                if (bytes_read == 0) {
                    return 0;
                }
                if (bytes_read < 0) {
                    if (s2n_error_get_type(s2n_errno) == S2N_ERR_T_BLOCKED) {
                        /* Wait until poll tells us data is ready */
                        continue;
                    }

                    fprintf(stderr, "Error reading from connection: '%s' %d\n", s2n_strerror(s2n_errno, "EN"), s2n_connection_get_alert(conn));
                    exit(1);
                }

                char *buf_ptr = buffer;
                do {
                    bytes_written = write(STDOUT_FILENO, buf_ptr, bytes_read);
                    if (bytes_written < 0) {
                        fprintf(stderr, "Error writing to stdout\n");
                        exit(1);
                    }

                    bytes_read -= bytes_written;
                    buf_ptr += bytes_written;
                } while (bytes_read > 0);
            }

            if (readers[1].revents & POLLIN) {
                size_t bytes_available = 0;

                if (ioctl(STDIN_FILENO, FIONREAD, &bytes_available) < 0) {
                    bytes_available = 1;
                }

                do {
                    /* We can only read as much data as we have space for. So it may
                     * take a couple loops to empty stdin. */
                    size_t bytes_to_read = bytes_available;
                    if (bytes_available > sizeof(buffer)) {
                        bytes_to_read = sizeof(buffer);
                    }

                    bytes_read = read(STDIN_FILENO, buffer, bytes_to_read);
                    if (bytes_read < 0 && errno != EINTR){
                        fprintf(stderr, "Error reading from stdin\n");
                        exit(1);
                    }
                    if (bytes_read == 0) {
                        fprintf(stderr, "Exiting on stdin EOF\n");
                        return 0;
                    }
                    bytes_available -= bytes_read;

                    /* We may not be able to write all the data we read in one shot, so
                     * keep sending until we have cleared our buffer. */
                    char *buf_ptr = buffer;
                    do {
                        s2n_errno = S2N_ERR_T_OK;
                        bytes_written = s2n_send(conn, buf_ptr, bytes_read, &blocked);
                        if (bytes_written < 0) {
                            if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
                                fprintf(stderr, "Error writing to connection: '%s'\n",
                                        s2n_strerror(s2n_errno, "EN"));
                                exit(1);
                            }

                            if (wait_for_event(sockfd, blocked) != S2N_SUCCESS) {
                                S2N_ERROR_PRESERVE_ERRNO();
                            }
                        } else {
                            // Only modify the counts if we successfully wrote the data
                            bytes_read -= bytes_written;
                            buf_ptr += bytes_written;
                        }
                    } while (bytes_read > 0);

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
                POSIX_BAIL(S2N_ERR_POLLING_FROM_SOCKET);
            }

            if (readers[1].revents & (POLLERR | POLLNVAL)) {
                fprintf(stderr, "Error polling from socket: err=%d nval=%d\n",
                        (readers[1].revents & POLLERR ) ? 1 : 0,
                        (readers[1].revents & POLLNVAL ) ? 1 : 0);
                POSIX_BAIL(S2N_ERR_POLLING_FROM_SOCKET);
            }
        }
    } while (p < 0 && errno == EINTR);

    return 0;
}
