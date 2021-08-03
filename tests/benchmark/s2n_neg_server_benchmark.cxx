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
#include <tests/benchmark/s2n_neg_server_benchmark.h>
#include <benchmark/benchmark.h>
#include <iostream>

#include <stdlib.h>
#include <string.h>
#include <cstring>
#include "string"

#include <vector>
#define STDIO_BUFSIZE  10240


extern "C" {

#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
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
#include <openssl/err.h>
#include <openssl/crypto.h>


#include "tls/s2n_config.h"
#include "tls/s2n_cipher_suites.h"
#include "utils/s2n_safety.h"
#include <error/s2n_errno.h>

#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_random.h"
#include "tests/s2n_test.h"
#include "tests/testlib/s2n_testlib.h"
#include "shared_info.h"
#include "server_info.h"

#define MAX_CERTIFICATES 50
}

static int DEBUG_PRINT = 0;
static int DEBUG_CIPHER = 0;
static unsigned int ITERATIONS = 50;
unsigned int corked = 0;

static struct s2n_cipher_suite *all_suites[] = {
        &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
        &s2n_dhe_rsa_with_aes_256_gcm_sha384,
        &s2n_rsa_with_rc4_128_md5,                      /* 0x00,0x04 */
        &s2n_rsa_with_rc4_128_sha,                      /* 0x00,0x05 */
        &s2n_rsa_with_3des_ede_cbc_sha,                 /* 0x00,0x0A */
        &s2n_dhe_rsa_with_3des_ede_cbc_sha,             /* 0x00,0x16 */
        &s2n_rsa_with_aes_128_cbc_sha,                  /* 0x00,0x2F */
        &s2n_dhe_rsa_with_aes_128_cbc_sha,              /* 0x00,0x33 */
        &s2n_rsa_with_aes_256_cbc_sha,                  /* 0x00,0x35 */
        &s2n_dhe_rsa_with_aes_256_cbc_sha,              /* 0x00,0x39 */
        &s2n_rsa_with_aes_128_cbc_sha256,               /* 0x00,0x3C */
        &s2n_rsa_with_aes_256_cbc_sha256,               /* 0x00,0x3D */
        &s2n_dhe_rsa_with_aes_128_cbc_sha256,           /* 0x00,0x67 */
        &s2n_dhe_rsa_with_aes_256_cbc_sha256,           /* 0x00,0x6B */
        &s2n_rsa_with_aes_128_gcm_sha256,               /* 0x00,0x9C */
        &s2n_rsa_with_aes_256_gcm_sha384,               /* 0x00,0x9D */
        &s2n_dhe_rsa_with_aes_128_gcm_sha256,           /* 0x00,0x9E */
        /* 0x00,0x9F */
        &s2n_ecdhe_rsa_with_rc4_128_sha,                /* 0xC0,0x11 */
        &s2n_ecdhe_rsa_with_3des_ede_cbc_sha,           /* 0xC0,0x12 */
        &s2n_ecdhe_rsa_with_aes_128_cbc_sha,            /* 0xC0,0x13 */
        &s2n_ecdhe_rsa_with_aes_256_cbc_sha,            /* 0xC0,0x14 */

        /* 0xC0,0x27 */
        &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,         /* 0xC0,0x28 */


        &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,         /* 0xC0,0x2F */
        &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,         /* 0xC0,0x30 */
        &s2n_ecdhe_rsa_with_chacha20_poly1305_sha256,   /* 0xCC,0xA8 */

        &s2n_dhe_rsa_with_chacha20_poly1305_sha256,     /* 0xCC,0xAA */
        &s2n_ecdhe_bike_rsa_with_aes_256_gcm_sha384,    /* 0xFF,0x04 */
        &s2n_ecdhe_sike_rsa_with_aes_256_gcm_sha384,    /* 0xFF,0x08 */
        &s2n_ecdhe_kyber_rsa_with_aes_256_gcm_sha384,   /* 0xFF,0x0C */

        &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha,
        &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
        &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
        &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
        &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
        &s2n_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
};


static int my_negotiate(struct s2n_connection *conn, int fd) {
    s2n_blocked_status blocked;
    if (s2n_negotiate(conn, &blocked) != S2N_SUCCESS) {
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


    if (DEBUG_PRINT) {
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
        printf("Server name: %s\n", s2n_get_server_name(conn));
        printf("Application protocol: %s\n", s2n_get_application_protocol(conn));
        printf("Curve: %s\n", s2n_connection_get_curve(conn));
        printf("KEM: %s\n", s2n_connection_get_kem_name(conn));
        printf("KEM Group: %s\n", s2n_connection_get_kem_group_name(conn));
    }

    uint32_t length;
    const uint8_t *status = s2n_connection_get_ocsp_response(conn, &length);
    if (status && length > 0) {
        fprintf(stderr, "OCSP response received, length %u\n", length);
    }

    if (DEBUG_CIPHER) {
        printf("Cipher negotiated: %s\n", s2n_connection_get_cipher(conn));
    }

    bool session_resumed = s2n_connection_is_session_resumed(conn);
    if (session_resumed) {
        printf("Resumed session\n");
    }

    uint16_t identity_length = 0;
    GUARD_EXIT(s2n_connection_get_negotiated_psk_identity_length(conn, &identity_length),
               "Error getting negotiated psk identity length from the connection\n");
    if (identity_length != 0 && !session_resumed) {
        uint8_t *identity = (uint8_t *) malloc(identity_length);
        GUARD_EXIT_NULL(identity);
        GUARD_EXIT(s2n_connection_get_negotiated_psk_identity(conn, identity, identity_length),
                   "Error getting negotiated psk identity from the connection\n");
        if (DEBUG_PRINT) {
            printf("Negotiated PSK identity: %s\n", identity);
        }
        free(identity);
    }

    s2n_early_data_status_t early_data_status = (s2n_early_data_status_t) 0;
    GUARD_EXIT(s2n_connection_get_early_data_status(conn, &early_data_status), "Error getting early data status");
    const char *status_str = NULL;
    switch (early_data_status) {
        case S2N_EARLY_DATA_STATUS_OK:
            status_str = "IN PROGRESS";
            break;
        case S2N_EARLY_DATA_STATUS_NOT_REQUESTED:
            status_str = "NOT REQUESTED";
            break;
        case S2N_EARLY_DATA_STATUS_REJECTED:
            status_str = "REJECTED";
            break;
        case S2N_EARLY_DATA_STATUS_END:
            status_str = "ACCEPTED";
            break;
    }
    GUARD_EXIT_NULL(status_str);

    if (DEBUG_PRINT) {
        printf("s2n is ready\n");
    }
    return 0;
}

static int handle_connection(int fd, struct s2n_config *config, struct conn_settings settings, int suite_num) {
    struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
    if (!conn) {
        print_s2n_error("Error getting new s2n connection");
        S2N_ERROR_PRESERVE_ERRNO();
    }

    if (settings.self_service_blinding) {
        s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING);
    }

    if (settings.mutual_auth) {
        GUARD_RETURN(s2n_config_set_client_auth_type(config, S2N_CERT_AUTH_REQUIRED),
                     "Error setting client auth type");

        if (settings.ca_dir || settings.ca_file) {
            GUARD_RETURN(s2n_config_set_verification_ca_location(config, settings.ca_file, settings.ca_dir),
                         "Error adding verify location");
        }

        if (settings.insecure) {
            GUARD_RETURN(s2n_config_disable_x509_verification(config), "Error disabling X.509 validation");
        }
    }

    GUARD_RETURN(s2n_connection_set_config(conn, config), "Error setting configuration");

    if (settings.prefer_throughput) {
        GUARD_RETURN(s2n_connection_prefer_throughput(conn), "Error setting prefer throughput");
    }

    if (settings.prefer_low_latency) {
        GUARD_RETURN(s2n_connection_prefer_low_latency(conn), "Error setting prefer low latency");
    }

    GUARD_RETURN(s2n_connection_set_fd(conn, fd), "Error setting file descriptor");

    if (settings.use_corked_io) {
        GUARD_RETURN(s2n_connection_use_corked_io(conn), "Error setting corked io");
    }

    GUARD_RETURN(
            s2n_setup_external_psk_list(conn, settings.psk_optarg_list, settings.psk_list_len),
            "Error setting external psk list");

    GUARD_RETURN(early_data_recv(conn), "Error receiving early data");

    if (my_negotiate(conn, fd) != S2N_SUCCESS) {
        if (settings.mutual_auth) {
            if (!s2n_connection_client_cert_used(conn)) {
                print_s2n_error("Error: Mutual Auth was required, but not negotiated");
            }
        }

        S2N_ERROR_PRESERVE_ERRNO();
    }

    GUARD_EXIT(s2n_connection_free_handshake(conn), "Error freeing handshake memory after negotiation");

    s2n_blocked_status blocked;
    s2n_shutdown(conn, &blocked);

    GUARD_RETURN(s2n_connection_wipe(conn), "Error wiping connection");

    GUARD_RETURN(s2n_connection_free(conn), "Error freeing connection");

    return 0;
}


int Server::start_benchmark_server(int argc, char **argv) {
    struct addrinfo hints, *ai;
    int r, sockfd = 0;

    const char *host = "localhost";
    const char *port = "8000";

    if (argc > 1) {
        host = argv[1];
        port = argv[2];
        ITERATIONS = atoi(argv[3]);
        DEBUG_PRINT = atoi(argv[4]);
        DEBUG_CIPHER = atoi(argv[5]);
        corked = atoi(argv[6]);
    }

    const char *session_ticket_key_file_path = NULL;
    const char *cipher_prefs = "test_all_tls12";


    int num_user_certificates = 0;
    int num_user_private_keys = 0;
    const char *certificates[MAX_CERTIFICATES] = {0};
    const char *private_keys[MAX_CERTIFICATES] = {0};

    struct conn_settings conn_settings = {0};


    int parallelize = 0;

    conn_settings.session_ticket = 1;
    conn_settings.session_cache = 0;
    conn_settings.max_conns = -1;
    conn_settings.psk_list_len = 0;

    conn_settings.use_corked_io = corked;

    int max_early_data = 0;

    s2n_init();

    if (conn_settings.prefer_throughput && conn_settings.prefer_low_latency) {
        fprintf(stderr, "prefer-throughput and prefer-low-latency options are mutually exclusive\n");
        exit(1);
    }

    GUARD_EXIT(setvbuf(stdin, NULL, _IONBF, 0), "Error disabling buffering for stdin\n");
    GUARD_EXIT(setvbuf(stdout, NULL, _IONBF, 0), "Error disabling buffering for stdout\n");

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        fprintf(stderr, "Error disabling SIGPIPE\n");
        exit(1);
    }

    GUARD_EXIT(getaddrinfo(host, port, &hints, &ai), "getaddrinfo error\n");
    GUARD_EXIT((sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)), "socket error\n");
    GUARD_EXIT(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &r, sizeof(int)), "setsockopt error");
    GUARD_EXIT(bind(sockfd, ai->ai_addr, ai->ai_addrlen), "bind error");
    GUARD_EXIT(listen(sockfd, 1), "listen error");


    if (DEBUG_PRINT)
        printf("Listening on %s:%s\n", host, port);

    struct s2n_config *config = s2n_config_new();
    if (!config) {
        print_s2n_error("Error getting new s2n config");
        exit(1);
    }

    GUARD_EXIT(s2n_config_set_server_max_early_data_size(config, max_early_data),
               "Error setting max early data");

    GUARD_EXIT(s2n_config_add_dhparams(config, dhparams), "Error adding DH parameters");

    GUARD_EXIT(s2n_config_set_cipher_preferences(config, cipher_prefs), "Error setting cipher prefs");

    GUARD_EXIT(s2n_config_set_cache_store_callback(config, cache_store_callback, session_cache),
               "Error setting cache store callback");

    GUARD_EXIT(s2n_config_set_cache_retrieve_callback(config, cache_retrieve_callback, session_cache),
               "Error setting cache retrieve callback");

    GUARD_EXIT(s2n_config_set_cache_delete_callback(config, cache_delete_callback, session_cache),
               "Error setting cache retrieve callback");

    if (conn_settings.enable_mfl) {
        GUARD_EXIT(s2n_config_accept_max_fragment_length(config),
                   "Error enabling TLS maximum fragment length extension in server");
    }

    if (s2n_config_set_verify_host_callback(config, unsafe_verify_host_fn, NULL)) {
        print_s2n_error("Failure to set hostname verification callback");
        exit(1);
    }

    if (conn_settings.session_ticket) {
        GUARD_EXIT(s2n_config_set_session_tickets_onoff(config, 1), "Error enabling session tickets");
    }

    if (conn_settings.session_cache) {
        GUARD_EXIT(s2n_config_set_session_cache_onoff(config, 1), "Error enabling session cache using id");
    }

    if (conn_settings.session_ticket || conn_settings.session_cache) {
        /* Key initialization */
        uint8_t *st_key;
        uint32_t st_key_length;

        if (session_ticket_key_file_path) {
            int fd = open(session_ticket_key_file_path, O_RDONLY);
            GUARD_EXIT(fd, "Error opening session ticket key file");

            struct stat st;
            GUARD_EXIT(fstat(fd, &st), "Error fstat-ing session ticket key file");

            st_key = (uint8_t *) mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
            st_key_length = st.st_size;

            close(fd);
        } else {
            st_key = default_ticket_key;
            st_key_length = sizeof(default_ticket_key);
        }

        if (s2n_config_add_ticket_crypto_key(config, ticket_key_name, strlen((char *) ticket_key_name), st_key,
                                             st_key_length, 0) != 0) {
            fprintf(stderr, "Error adding ticket key: '%s'\n", s2n_strerror(s2n_errno, "EN"));
            exit(1);
        }
    }
    unsigned int len = sizeof(all_suites) / sizeof(all_suites[0]);
    for (unsigned int j = 0; j < len; ++j) {
        unsigned int suite_num = j;
        unsigned int repeats = 0;
        if (num_user_certificates != num_user_private_keys) {
            fprintf(stderr, "Mismatched certificate(%d) and private key(%d) count!\n", num_user_certificates,
                    num_user_private_keys);
            exit(1);
        }

        unsigned int num_certificates = 0;
        if (num_user_certificates == 0) {
            if (suite_num < 29) {
                certificates[0] = rsa_certificate_chain;
                private_keys[0] = rsa_private_key;
                num_certificates = 1;
            } else {
                certificates[0] = ecdsa_certificate_chain;
                private_keys[0] = ecdsa_private_key;
                num_certificates = 1;
            }
        } else {
            num_certificates = num_user_certificates;
        }

        //Modify cert/key if using ECDSA
        for (unsigned int i = 0; i < num_certificates; i++) {
            struct s2n_cert_chain_and_key *chain_and_key = s2n_cert_chain_and_key_new();
            GUARD_EXIT(s2n_cert_chain_and_key_load_pem(chain_and_key, certificates[i], private_keys[i]),
                       "Error getting certificate/key");

            GUARD_EXIT(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key),
                       "Error setting certificate/key");
        }

        //Complete benchmark for specified number of iterations
        for (repeats = 0; repeats < ITERATIONS; repeats++) {
            int fd;
            bool stop_listen = false;
            while ((!stop_listen) && (fd = accept(sockfd, ai->ai_addr, &ai->ai_addrlen)) > 0) {
                if (!parallelize) {
                    int rc = handle_connection(fd, config, conn_settings, suite_num);
                    stop_listen = true;
                    close(fd);

                    if (rc < 0) {
                        exit(rc);
                    }

                    /* If max_conns was set, then exit after it is reached. Otherwise
                     * unlimited connections are allow, so ignore the variable. */
                    if (conn_settings.max_conns > 0) {
                        if (conn_settings.max_conns-- == 1) {
                            exit(0);
                        }
                    }
                }
            }
        }
    }
    close(sockfd);
    s2n_cleanup();
    return 0;
}
