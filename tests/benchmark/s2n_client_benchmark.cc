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

#include <benchmark/benchmark.h>
#include <iostream>

#include <stdlib.h>
#include <string.h>
#include <cstring>

#include <vector>
#define STDIO_BUFSIZE  10240


extern int rc;

extern "C" {
    #define S2N_ECC_EVP_SUPPORTED_CURVES_COUNT 4

    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/ioctl.h>
    #include <sys/param.h>
    #include <poll.h>
    #include <netdb.h>

    #include <stdlib.h>
    #include <signal.h>
    #include <unistd.h>
    #include <string.h>
    #include <stdio.h>
    #include <getopt.h>
    #include <strings.h>
    #include <errno.h>
    #include <fcntl.h>

    #include <s2n.h>
    #include "bin/common.h"
    #include <error/s2n_errno.h>

    #include "tls/s2n_connection.h"
    #include "utils/s2n_safety.h"

    #include "stuffer/s2n_stuffer.h"
    #include "utils/s2n_random.h"
    #define S2N_MAX_ECC_CURVE_NAME_LENGTH 10
}

static const uint8_t hex_inverse[256] = {
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        0,   1,   2,   3,   4,   5,   6,   7,   8,   9, 255, 255, 255, 255, 255, 255,
        255,  10,  11,  12,  13,  14,  15, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255,  10,  11,  12,  13,  14,  15, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
};

struct verify_data {
    const char *trusted_host;
};

void print_s2n_error(const char *app_error)
{
    fprintf(stderr, "[%d] %s: '%s' : '%s'\n", getpid(), app_error, s2n_strerror(s2n_errno, "EN"),
            s2n_strerror_debug(s2n_errno, "EN"));
}

static int wait_for_event(int fd, s2n_blocked_status blocked)
{
    struct pollfd reader = {fd, 0};

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
        //S2N_ERROR_PRESERVE_ERRNO();
    }

    return S2N_SUCCESS;
}

int key_log_callback(void *file, struct s2n_connection *conn, uint8_t *logline, size_t len)
{
    if (fwrite(logline, 1, len, (FILE *)file) != len) {
        return S2N_FAILURE;
    }

    if (fprintf((FILE *)file, "\n") < 0) {
        return S2N_FAILURE;
    }

    return fflush((FILE *)file);
}

int early_data_send(struct s2n_connection *conn, uint8_t *data, uint32_t len)
{
    s2n_blocked_status blocked = (s2n_blocked_status)0;
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


int s2n_str_hex_to_bytes(const unsigned char *hex, uint8_t *out_bytes, uint32_t max_out_bytes_len)
{
    GUARD_EXIT_NULL(hex);
    GUARD_EXIT_NULL(out_bytes);

    uint32_t len_with_spaces = strlen((const char *)hex);
    size_t i = 0, j = 0;
    while (j < len_with_spaces) {
        if (hex[j] == ' ') {
            j++;
            continue;
        }

        uint8_t high_nibble = hex_inverse[hex[j]];
        if (high_nibble == 255) {
            fprintf(stderr, "Invalid HEX encountered\n");
            return S2N_FAILURE;
        }

        uint8_t low_nibble = hex_inverse[hex[j + 1]];
        if (low_nibble == 255) {
            fprintf(stderr, "Invalid HEX encountered\n");
            return S2N_FAILURE;
        }

        if(max_out_bytes_len < i) {
            fprintf(stderr, "Insufficient memory for bytes buffer, try increasing the allocation size\n");
            return S2N_FAILURE;
        }
        out_bytes[i] = high_nibble << 4 | low_nibble;

        i++;
        j+=2;
    }

    return S2N_SUCCESS;
}

static int s2n_get_psk_hmac_alg(s2n_psk_hmac *psk_hmac, char *hmac_str)
{
    GUARD_EXIT_NULL(psk_hmac);
    GUARD_EXIT_NULL(hmac_str);

    if (strcmp(hmac_str, "SHA256") == 0) {
        *psk_hmac = S2N_PSK_HMAC_SHA256;
    } else if (strcmp(hmac_str, "SHA384") == 0) {
        *psk_hmac = S2N_PSK_HMAC_SHA384;
    } else {
        return S2N_FAILURE;
    }
    return S2N_SUCCESS;
}

static int s2n_setup_external_psk(struct s2n_psk **psk, char *params)
{
    GUARD_EXIT_NULL(psk);
    GUARD_EXIT_NULL(params);

    size_t token_idx = 0;
    for (char *token = strtok(params, ","); token != NULL; token = strtok(NULL, ","), token_idx++) {
        switch (token_idx) {
            case 0:
                GUARD_EXIT(s2n_psk_set_identity(*psk, (const uint8_t *)token, strlen(token)),
                           "Error setting psk identity\n");
                break;
            case 1: {
                uint32_t max_secret_len = strlen(token)/2;
                uint8_t *secret = (uint8_t*)malloc(max_secret_len);
                GUARD_EXIT_NULL(secret);
                GUARD_EXIT(s2n_str_hex_to_bytes((const unsigned char *)token, secret, max_secret_len), "Error converting hex-encoded psk secret to bytes\n");
                GUARD_EXIT(s2n_psk_set_secret(*psk, secret, max_secret_len), "Error setting psk secret\n");
                free(secret);
            }
                break;
            case 2: {
                s2n_psk_hmac psk_hmac_alg = (s2n_psk_hmac)0;
                GUARD_EXIT(s2n_get_psk_hmac_alg(&psk_hmac_alg, token), "Invalid psk hmac algorithm\n");
                GUARD_EXIT(s2n_psk_set_hmac(*psk, psk_hmac_alg), "Error setting psk hmac algorithm\n");
            }
                break;
            default:
                break;
        }
    }

    return S2N_SUCCESS;
}

int s2n_setup_external_psk_list(struct s2n_connection *conn, char *psk_optarg_list[S2N_MAX_PSK_LIST_LENGTH], size_t psk_list_len)
{
    GUARD_EXIT_NULL(conn);
    GUARD_EXIT_NULL(psk_optarg_list);

    for (size_t i = 0; i < psk_list_len; i++) {
        struct s2n_psk *psk = s2n_external_psk_new();
        GUARD_EXIT_NULL(psk);
        GUARD_EXIT(s2n_setup_external_psk(&psk, psk_optarg_list[i]), "Error setting external PSK parameters\n");
        GUARD_EXIT(s2n_connection_append_psk(conn, psk), "Error appending psk to the connection\n");
        GUARD_EXIT(s2n_psk_free(&psk), "Error freeing psk\n");
    }
    return S2N_SUCCESS;
}


int echo(struct s2n_connection *conn, int sockfd, bool *stop_echo)
{
    printf("****My Echo****\n");
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

int negotiate(struct s2n_connection *conn, int fd)
{
    printf("**Running my negotiate**\n");
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
    printf("S2N_SUCCESS! Completed negotiation\n");
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
    printf("Handshake: %s\n", s2n_connection_get_handshake_type_name(conn));
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
        uint8_t *identity = (uint8_t*)malloc(identity_length);
        GUARD_EXIT_NULL(identity);
        GUARD_EXIT(s2n_connection_get_negotiated_psk_identity(conn, identity, identity_length), "Error getting negotiated psk identity from the connection\n");
        printf("Negotiated PSK identity: %s\n", identity);
        free(identity);
    }

    s2n_early_data_status_t early_data_status = (s2n_early_data_status_t)0;
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

static uint8_t unsafe_verify_host(const char *host_name, size_t host_name_len, void *data) {
    struct verify_data *verify_data = (struct verify_data *)data;

    if (host_name_len > 2 && host_name[0] == '*' && host_name[1] == '.') {
        const char *suffix = strstr(verify_data->trusted_host, ".");
        return (uint8_t)(strcasecmp(suffix, host_name + 1) == 0);
    }

    if (strcasecmp(host_name, "localhost") == 0 || strcasecmp(host_name, "127.0.0.1") == 0) {
        return (uint8_t) (strcasecmp(verify_data->trusted_host, "localhost") == 0
                          || strcasecmp(verify_data->trusted_host, "127.0.0.1") == 0);
    }

    return (uint8_t) (strcasecmp(host_name, verify_data->trusted_host) == 0);
}

size_t session_state_length = 0;
uint8_t *session_state = NULL;
static int test_session_ticket_cb(struct s2n_connection *conn, void *ctx, struct s2n_session_ticket *ticket)
{
    GUARD_EXIT_NULL(conn);
    GUARD_EXIT_NULL(ticket);

    GUARD_EXIT(s2n_session_ticket_get_data_len(ticket, &session_state_length), "Error getting ticket length ");
    session_state = (uint8_t*)realloc(session_state, session_state_length);
    if(session_state == NULL) {
        print_s2n_error("Error getting new session state");
        exit(1);
    }
    GUARD_EXIT(s2n_session_ticket_get_data(ticket, session_state_length, session_state), "Error getting ticket data");

    bool *session_ticket_recv = (bool *)ctx;
    *session_ticket_recv = 1;

    return S2N_SUCCESS;
}

class TestFixture : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State& state) {
        struct addrinfo hints, *ai_list, *ai;
        int add, sockfd = 0;
        const char *server_name = "localhost";
        const char *host = "localhost";
        const char *port = "8000";
        const char *cipher_prefs = "default";
        s2n_status_request_type type = S2N_STATUS_REQUEST_NONE;
        //struct verify_data unsafe_verify_data;
        const char *alpn_protocols = NULL;
        const char *ca_file = NULL;
        const char *ca_dir = NULL;
        const char *client_cert = NULL;
        const char *client_key = NULL;
        bool client_cert_input = false;
        bool client_key_input = false;
        uint8_t session_ticket = 1;
        uint16_t mfl_value = 0;
        bool session_ticket_recv = 0;
        const char *key_log_path = NULL;
        FILE *key_log_file = NULL;
        int use_corked_io = 0;
        int keyshares_count = 0;
        char keyshares[S2N_ECC_EVP_SUPPORTED_CURVES_COUNT][S2N_MAX_ECC_CURVE_NAME_LENGTH];
        char *psk_optarg_list[S2N_MAX_PSK_LIST_LENGTH];
        size_t psk_list_len = 0;
        char *early_data = NULL;
        uint8_t insecure = 1;
        int echo_input __attribute__((unused)) = 1;


        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        rc = s2n_init();
        assert(rc == 0);

        if ((add = getaddrinfo(host, port, &hints, &ai_list)) != 0) {
            fprintf(stderr, "error: %s\n", gai_strerror(add));
            exit(1);
        }

        int reconnect = 0;
        do {
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
                printf("Connected to s2nd\n");
                break;
            }
            if (connected == 0) {
                fprintf(stderr, "Failed to connect to %s:%s\n", host, port);
                exit(1);
            }

            struct s2n_config *config = s2n_config_new();

            struct verify_data *unsafe_verify_data = (verify_data*)malloc(sizeof(verify_data));;

            if (config == NULL) {
                print_s2n_error("Error getting new config");
                exit(1);
            }

            GUARD_EXIT(s2n_config_set_cipher_preferences(config, cipher_prefs), "Error setting cipher prefs");

            GUARD_EXIT(s2n_config_set_status_request_type(config, type), "OCSP validation is not supported by the linked libCrypto implementation. It cannot be set.");

            if (s2n_config_set_verify_host_callback(config, unsafe_verify_host, unsafe_verify_data) < 0) {
                print_s2n_error("Error setting host name verification function.");
            }

            if (type == S2N_STATUS_REQUEST_OCSP) {
                if(s2n_config_set_check_stapled_ocsp_response(config, 1)) {
                    print_s2n_error("OCSP validation is not supported by the linked libCrypto implementation. It cannot be set.");
                }
            }

            unsafe_verify_data->trusted_host = host;

            if (alpn_protocols) {
                /* Count the number of commas, this tells us how many protocols there
                   are in the list */
                const char *ptr = alpn_protocols;
                int protocol_count = 1;
                while (*ptr) {
                    if (*ptr == ',') {
                        protocol_count++;
                    }
                    ptr++;
                }

                char **protocols = (char**)malloc(sizeof(char *) * protocol_count);
                if (!protocols) {
                    fprintf(stderr, "Error allocating memory\n");
                    exit(1);
                }

                const char *next = alpn_protocols;
                int idx = 0;
                int length = 0;
                ptr = alpn_protocols;
                while (*ptr) {
                    if (*ptr == ',') {
                        protocols[idx] =(char*)malloc(length + 1);
                        if (!protocols[idx]) {
                            fprintf(stderr, "Error allocating memory\n");
                            exit(1);
                        }
                        memcpy(protocols[idx], next, length);
                        protocols[idx][length] = '\0';
                        length = 0;
                        idx++;
                        ptr++;
                        next = ptr;
                    } else {
                        length++;
                        ptr++;
                    }
                }
                if (ptr != next) {
                    protocols[idx] = (char*)malloc(length + 1);
                    if (!protocols[idx]) {
                        fprintf(stderr, "Error allocating memory\n");
                        exit(1);
                    }
                    memcpy(protocols[idx], next, length);
                    protocols[idx][length] = '\0';
                }

                GUARD_EXIT(s2n_config_set_protocol_preferences(config, (const char *const *)protocols, protocol_count), "Failed to set protocol preferences");

                while (protocol_count) {
                    protocol_count--;
                    free(protocols[protocol_count]);
                }
                free(protocols);
            }
            uint8_t mfl_code = 0;
            if (mfl_value > 0) {
                switch(mfl_value) {
                    case 512:
                        mfl_code = S2N_TLS_MAX_FRAG_LEN_512;
                        break;
                    case 1024:
                        mfl_code = S2N_TLS_MAX_FRAG_LEN_1024;
                        break;
                    case 2048:
                        mfl_code = S2N_TLS_MAX_FRAG_LEN_2048;
                        break;
                    case 4096:
                        mfl_code = S2N_TLS_MAX_FRAG_LEN_4096;
                        break;
                    default:
                        fprintf(stderr, "Invalid maximum fragment length value\n");
                        exit(1);
                }
            }

            GUARD_EXIT(s2n_config_send_max_fragment_length(config, (s2n_max_frag_len)mfl_code), "Error setting maximum fragment length");

            if (client_cert_input != client_key_input) {
                print_s2n_error("Client cert/key pair must be given.");
            }

            if (client_cert_input) {
                struct s2n_cert_chain_and_key *chain_and_key = s2n_cert_chain_and_key_new();
                GUARD_EXIT(s2n_cert_chain_and_key_load_pem(chain_and_key, client_cert, client_key), "Error getting certificate/key");
                GUARD_EXIT(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key), "Error setting certificate/key");
            }

            if (ca_file || ca_dir) {
                if (s2n_config_set_verification_ca_location(config, ca_file, ca_dir) < 0) {
                    print_s2n_error("Error setting CA file for trust store.");
                }
            }
            else if (insecure) {
                GUARD_EXIT(s2n_config_disable_x509_verification(config), "Error disabling X.509 validation");
            }

            if (session_ticket) {
                GUARD_EXIT(s2n_config_set_session_tickets_onoff(config, 1), "Error enabling session tickets");
                GUARD_EXIT(s2n_config_set_session_ticket_cb(config, test_session_ticket_cb, &session_ticket_recv), "Error setting session ticket callback");
                session_ticket_recv = 0;
            }

            if (key_log_path) {
                key_log_file = fopen(key_log_path, "a");
                GUARD_EXIT(key_log_file == NULL ? S2N_FAILURE : S2N_SUCCESS, "Failed to open key log file");
                GUARD_EXIT(
                        s2n_config_set_key_log_cb(
                                config,
                                key_log_callback,
                                (void *)key_log_file
                        ),
                        "Failed to set key log callback"
                );
            }

            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);

            if (conn == NULL) {
                print_s2n_error("Error getting new connection");
                exit(1);
            }

            GUARD_EXIT(s2n_connection_set_config(conn, config), "Error setting configuration");

            GUARD_EXIT(s2n_set_server_name(conn, server_name), "Error setting server name");

            GUARD_EXIT(s2n_connection_set_fd(conn, sockfd) , "Error setting file descriptor");

            GUARD_EXIT(s2n_connection_set_client_auth_type(conn, S2N_CERT_AUTH_OPTIONAL), "Error setting ClientAuth optional");

            if (use_corked_io) {
                GUARD_EXIT(s2n_connection_use_corked_io(conn), "Error setting corked io");
            }

            for (size_t i = 0; i < (size_t)keyshares_count; i++) {
                if (keyshares[i]) {
                    GUARD_EXIT(s2n_connection_set_keyshare_by_name_for_testing(conn, keyshares[i]), "Error setting keyshares to generate");
                }
            }

            /* Update session state in connection if exists */
            if (session_state_length > 0) {
                GUARD_EXIT(s2n_connection_set_session(conn, session_state, session_state_length), "Error setting session state in connection");
            }

            GUARD_EXIT(s2n_setup_external_psk_list(conn, psk_optarg_list, psk_list_len), "Error setting external psk list");

            if (early_data) {
                if (!session_ticket) {
                    print_s2n_error("Early data can only be used with session tickets.");
                    exit(1);
                }
                /* Send early data if we have a received a session ticket from the server */
                if (session_state_length) {
                    uint32_t early_data_length = strlen(early_data);
                    GUARD_EXIT(early_data_send(conn, (uint8_t *)early_data, early_data_length), "Error sending early data");
                }
            }

            printf("BEGINNING NEGOTIATION PROCESS\n");
            if (negotiate(conn, sockfd) != 0) {
                /* Error is printed in negotiate */
                //S2N_ERROR_PRESERVE_ERRNO();
                printf("Error in negotiate!\n");
            }

            printf("Connected to %s:%s\n", host, port);

            GUARD_EXIT(s2n_connection_free_handshake(conn), "Error freeing handshake memory after negotiation");

            if (echo_input == 1) {
                bool stop_echo = false;
                fflush(stdout);
                fflush(stderr);
                echo(conn, sockfd, &stop_echo);
            }

            /* The following call can block on receiving a close_notify if we initiate the shutdown or if the */
            /* peer fails to send a close_notify. */
            /* TODO: However, we should expect to receive a close_notify from the peer and shutdown gracefully. */
            /* Please see tracking issue for more detail: https://github.com/aws/s2n-tls/issues/2692 */
            s2n_blocked_status blocked;
            int shutdown_rc = s2n_shutdown(conn, &blocked);
            if (shutdown_rc == -1 && blocked != S2N_BLOCKED_ON_READ) {
                fprintf(stderr, "Unexpected error during shutdown: '%s'\n", s2n_strerror(s2n_errno, "NULL"));
                exit(1);
            }

            GUARD_EXIT(s2n_connection_free(conn), "Error freeing connection");

            GUARD_EXIT(s2n_config_free(config), "Error freeing configuration");

            close(sockfd);

            reconnect--;
        } while (reconnect >= 0);
        printf("Out of reconnect loop\n");
        s2n_result result;

        memset(&r, 0, sizeof(r));
        memset(&entropy, 0, sizeof(entropy));

        pad.resize(state.range(0));
        rc = s2n_blob_init(&r, pad.data(), pad.size());
        assert(rc == 0);


        result  = s2n_get_public_random_data(&r);
        assert(s2n_result_is_ok(result));
        rc = s2n_stuffer_alloc(&entropy, pad.size());
        assert(rc == 0);
        rc = s2n_stuffer_write_bytes(&entropy, pad.data(), pad.size());
        assert(rc == 0);



        printf("***END OF SETUP***\n");
    }

    void TearDown(const ::benchmark::State& state) {
        rc = s2n_cleanup();
        assert(rc == 0);
    }

    std::vector<uint8_t>pad;
    struct s2n_blob r;
    struct s2n_stuffer entropy;
    int rc;

};

BENCHMARK_DEFINE_F(TestFixture, Base64EncodeDecode)(benchmark::State& state) {
    for (auto _ : state) {
        struct s2n_stuffer stuffer = {0};
        struct s2n_stuffer mirror = {0};
        s2n_stuffer_write_base64(&stuffer, &entropy);
        s2n_stuffer_read_base64(&stuffer, &mirror);
    }
}

//BENCHMARK_REGISTER_F(TestFixture, Base64EncodeDecode)->DenseRange(1024, 1024 * 1024, 128 * 1024);
BENCHMARK_REGISTER_F(TestFixture, Base64EncodeDecode)->Arg(1024);

int main(int argc, char** argv) {
    ::benchmark::Initialize(&argc, argv);



    if (::benchmark::ReportUnrecognizedArguments(argc, argv)) return 1;
    ::benchmark::RunSpecifiedBenchmarks();

}



