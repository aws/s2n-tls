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

#include <s2n.h>
#include "common.h"
#include <error/s2n_errno.h>

#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

void usage()
{
    fprintf(stderr, "usage: s2nc [options] host [port]\n");
    fprintf(stderr, " host: hostname or IP address to connect to\n");
    fprintf(stderr, " port: port to connect to\n");
    fprintf(stderr, "\n Options:\n\n");
    fprintf(stderr, "  -a [protocols]\n");
    fprintf(stderr, "  --alpn [protocols]\n");
    fprintf(stderr, "    Sets the application protocols supported by this client, as a comma separated list.\n");
    fprintf(stderr, "  -c [version_string]\n");
    fprintf(stderr, "  --ciphers [version_string]\n");
    fprintf(stderr, "    Set the cipher preference version string. Defaults to \"default\". See USAGE-GUIDE.md\n");
    fprintf(stderr, "  -e\n");
    fprintf(stderr, "  --echo\n");
    fprintf(stderr, "    Listen to stdin after TLS Connection is established and echo it to the Server\n");
    fprintf(stderr, "  -h,--help\n");
    fprintf(stderr, "    Display this message and quit.\n");
    fprintf(stderr, "  -n [server name]\n");
    fprintf(stderr, "  --name [server name]\n");
    fprintf(stderr, "    Sets the SNI server name header for this client.  If not specified, the host value is used.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  -s,--status\n");
    fprintf(stderr, "    Request the OCSP status of the remote server certificate\n");
    fprintf(stderr, "  --mfl\n");
    fprintf(stderr, "    Request maximum fragment length from: 512, 1024, 2048, 4096\n");
    fprintf(stderr, "  -f,--ca-file [file path]\n");
    fprintf(stderr, "    Location of trust store CA file (PEM format). If neither -f or -d are specified. System defaults will be used.\n");
    fprintf(stderr, "  -d,--ca-dir [directory path]\n");
    fprintf(stderr, "    Directory containing hashed trusted certs. If neither -f or -d are specified. System defaults will be used.\n");
    fprintf(stderr, "  -i,--insecure\n");
    fprintf(stderr, "    Turns off certification validation altogether.\n");
    fprintf(stderr, "  -r,--reconnect\n");
    fprintf(stderr, "    Drop and re-make the connection using Session ticket. If session ticket is disabled, then re-make the connection using Session-ID \n");
    fprintf(stderr, "  -T,--no-session-ticket \n");
    fprintf(stderr, "    Disable session ticket for resumption.\n");
    fprintf(stderr, "  -D,--dynamic\n");
    fprintf(stderr, "    Set dynamic record resize threshold\n");
    fprintf(stderr, "  -t,--timeout\n");
    fprintf(stderr, "    Set dynamic record timeout threshold\n");
    fprintf(stderr, "  -C,--corked-io\n");
    fprintf(stderr, "    Turn on corked io\n");
    if (S2N_IN_TEST) {
        fprintf(stderr, "  --tls13\n");
        fprintf(stderr, "    Turn on experimental TLS1.3 support for testing.");
    }
    fprintf(stderr, "\n");
    exit(1);
}

struct verify_data {
    const char *trusted_host;
};

static uint8_t unsafe_verify_host(const char *host_name, size_t host_name_len, void *data) {
    struct verify_data *verify_data = (struct verify_data *)data;

    if (host_name_len > 2 && host_name[0] == '*' && host_name[1] == '.') {
        char *suffix = strstr(verify_data->trusted_host, ".");
        return (uint8_t)(strcasecmp(suffix, host_name + 1) == 0);
    }

    int equals = strcasecmp(host_name, verify_data->trusted_host);
    return (uint8_t)(equals == 0);
}

extern void print_s2n_error(const char *app_error);
extern int echo(struct s2n_connection *conn, int sockfd);
extern int negotiate(struct s2n_connection *conn);

static void setup_s2n_config(struct s2n_config *config, const char *cipher_prefs, s2n_status_request_type type,
    struct verify_data *unsafe_verify_data, const char *host, const char *alpn_protocols, uint16_t mfl_value) {

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

        char **protocols = malloc(sizeof(char *) * protocol_count);
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
                protocols[idx] = malloc(length + 1);
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
            protocols[idx] = malloc(length + 1);
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

    GUARD_EXIT(s2n_config_send_max_fragment_length(config, mfl_code), "Error setting maximum fragment length");
}

int main(int argc, char *const *argv)
{
    struct addrinfo hints, *ai_list, *ai;
    int r, sockfd = 0;
    ssize_t session_state_length = 0;
    uint8_t *session_state = NULL;
    /* Optional args */
    const char *alpn_protocols = NULL;
    const char *server_name = NULL;
    const char *ca_file = NULL;
    const char *ca_dir = NULL;
    uint16_t mfl_value = 0;
    uint8_t insecure = 0;
    int reconnect = 0;
    uint8_t session_ticket = 1;
    s2n_status_request_type type = S2N_STATUS_REQUEST_NONE;
    uint32_t dyn_rec_threshold = 0;
    uint8_t dyn_rec_timeout = 0;
    /* required args */
    const char *cipher_prefs = "default";
    const char *host = NULL;
    struct verify_data unsafe_verify_data;
    const char *port = "443";
    int echo_input = 0;
    int use_corked_io = 0;
    int use_tls13 = 0;

    static struct option long_options[] = {
        {"alpn", required_argument, 0, 'a'},
        {"ciphers", required_argument, 0, 'c'},
        {"echo", required_argument, 0, 'e'},
        {"help", no_argument, 0, 'h'},
        {"name", required_argument, 0, 'n'},
        {"status", no_argument, 0, 's'},
        {"mfl", required_argument, 0, 'm'},
        {"ca-file", required_argument, 0, 'f'},
        {"ca-dir", required_argument, 0, 'd'},
        {"insecure", no_argument, 0, 'i'},
        {"reconnect", no_argument, 0, 'r'},
        {"no-session-ticket", no_argument, 0, 'T'},
        {"dynamic", required_argument, 0, 'D'},
        {"timeout", required_argument, 0, 't'},
        {"corked-io", no_argument, 0, 'C'},
        {"tls13", no_argument, 0, '3'},
    };

    while (1) {
        int option_index = 0;
        int c = getopt_long(argc, argv, "a:c:ehn:sf:d:D:t:irTC", long_options, &option_index);
        if (c == -1) {
            break;
        }
        switch (c) {
        case 'a':
            alpn_protocols = optarg;
            break;
        case 'C':
            use_corked_io = 1;
            break;
        case 'c':
            cipher_prefs = optarg;
            break;
        case 'e':
            echo_input = 1;
            break;
        case 'h':
            usage();
            break;
        case 'n':
            server_name = optarg;
            break;
        case 's':
            type = S2N_STATUS_REQUEST_OCSP;
            break;
        case 'm':
            mfl_value = (uint16_t) atoi(optarg);
            break;
        case 'f':
            ca_file = optarg;
            break;
        case 'd':
            ca_dir = optarg;
            break;
        case 'i':
            insecure = 1;
            break;
        case 'r':
            reconnect = 5;
            break;
        case 'T':
            session_ticket = 0;
            break;
        case 't':
            dyn_rec_timeout = (uint8_t) MIN(255, atoi(optarg));
            break;
        case 'D':
            dyn_rec_threshold = strtoul(optarg, 0, 10);
            if (errno == ERANGE) {
                dyn_rec_threshold = 0;
            }
            break;
        case '3':
            use_tls13 = 1;
            break;
        case '?':
        default:
            usage();
            break;
        }
    }

    if (optind < argc) {
        host = argv[optind++];
    }

    /* cppcheck-suppress duplicateCondition */
    if (optind < argc) {
        port = argv[optind++];
    }

    if (!host) {
        usage();
    }

    if (!server_name) {
        server_name = host;
    }

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        fprintf(stderr, "Error disabling SIGPIPE\n");
        exit(1);
    }

    GUARD_EXIT(s2n_init(), "Error running s2n_init()");

    if ((r = getaddrinfo(host, port, &hints, &ai_list)) != 0) {
        fprintf(stderr, "error: %s\n", gai_strerror(r));
        exit(1);
    }

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
            break;
        }

        if (connected == 0) {
            fprintf(stderr, "Failed to connect to %s:%s\n", host, port);
            exit(1);
        }

        struct s2n_config *config = s2n_config_new();
        setup_s2n_config(config, cipher_prefs, type, &unsafe_verify_data, host, alpn_protocols, mfl_value);

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
        }

        if (use_tls13 && S2N_IN_TEST) {
            GUARD_EXIT(s2n_enable_tls13(), "Error enabling TLS1.3");
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

        /* Update session state in connection if exists */
        if (session_state_length > 0) {
            GUARD_EXIT(s2n_connection_set_session(conn, session_state, session_state_length), "Error setting session state in connection");
        }

        /* See echo.c */
        if (negotiate(conn) != 0)
        {
            /* Error is printed in negotiate */
            S2N_ERROR_PRESERVE_ERRNO();
        }

        printf("Connected to %s:%s\n", host, port);

        /* Save session state from connection if reconnect is enabled */
        if (reconnect > 0) {
            if (!session_ticket && s2n_connection_get_session_id_length(conn) <= 0) {
                printf("Endpoint sent empty session id so cannot resume session\n");
                exit(1);
            }
            free(session_state);
            session_state_length = s2n_connection_get_session_length(conn);
            session_state = calloc(session_state_length, sizeof(uint8_t));
            if (s2n_connection_get_session(conn, session_state, session_state_length) != session_state_length) {
                print_s2n_error("Error getting serialized session state");
                exit(1);
            }
        }

        if (dyn_rec_threshold > 0 && dyn_rec_timeout > 0) {
            s2n_connection_set_dynamic_record_threshold(conn, dyn_rec_threshold, dyn_rec_timeout);
        }

        if (echo_input == 1) {
            echo(conn, sockfd);
        }

        s2n_blocked_status blocked;
        s2n_shutdown(conn, &blocked);

        GUARD_EXIT(s2n_connection_free(conn), "Error freeing connection");

        GUARD_EXIT(s2n_config_free(config), "Error freeing configuration");

        close(sockfd);
        reconnect--;

    } while (reconnect >= 0);

    GUARD_EXIT(s2n_cleanup(), "Error running s2n_cleanup()");

    free(session_state);
    freeaddrinfo(ai_list);
    return 0;
}
