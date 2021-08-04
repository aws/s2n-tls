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
#include <tests/benchmark/s2n_neg_client_benchmark.h>
#include <benchmark/benchmark.h>
#include <iostream>

#include <stdlib.h>
#include <string.h>
#include <cstring>
#include <string>

#include <vector>
#define STDIO_BUFSIZE  10240

extern "C" {

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
}

//able to be modified when running benchmark
static int DEBUG_PRINT = 0;
static int DEBUG_CIPHER = 0;
static unsigned int ITERATIONS = 50;

extern int rc;

const char *host = "localhost";
const char *port = "8000";
struct addrinfo hints, *ai_list, *ai;
int add, sockfd = 0;
const char *server_name = "localhost";
const char *cipher_prefs = "test_all_tls12";
s2n_status_request_type type = S2N_STATUS_REQUEST_NONE;
int use_corked_io = 0;
char *psk_optarg_list[S2N_MAX_PSK_LIST_LENGTH];
size_t psk_list_len = 0;
uint8_t insecure = 1;

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

#define BENCHMARK_SUCCESS( condition ) __S2N_ENSURE((condition) >= S2N_SUCCESS, state.SkipWithError(#condition ", benchmark did not pass when expected too"))

#define BENCHMARK_FAILURE( condition ) __S2N_ENSURE((condition) < S2N_SUCCESS, state.SkipWithError(#condition ", benchmark did pass when expected not too"))


static unsigned int calls_to_s2n_negotiate = 0;
struct s2n_blob r;
int rc;

static int benchmark_negotiate(struct s2n_connection *conn, int fd, benchmark::State& state)
{
    s2n_blocked_status blocked;
    calls_to_s2n_negotiate += 1;
    int s2n_ret;
    state.ResumeTiming();
    benchmark::DoNotOptimize(s2n_ret = s2n_negotiate(conn, &blocked)); //forces the result to be stored in either memory or a register.
    state.PauseTiming();
    benchmark::ClobberMemory(); //forces the compiler to perform all pending writes to global memory

    if (s2n_ret != S2N_SUCCESS) {
        calls_to_s2n_negotiate += 1;
        if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
            fprintf(stderr, "Failed to negotiate: '%s'. %s\n",
                    s2n_strerror(s2n_errno, "EN"),
                    s2n_strerror_debug(s2n_errno, "EN"));
            fprintf(stderr, "Alert: %d\n",
                    s2n_connection_get_alert(conn));
            printf("Client errno: %s\n", strerror(errno));
            S2N_ERROR_PRESERVE_ERRNO();
        }

        if (wait_for_event(fd, blocked) != S2N_SUCCESS) {
            S2N_ERROR_PRESERVE_ERRNO();
        }

        state.SkipWithError("Negotiate Failed\n");
    }

    bool session_resumed = s2n_connection_is_session_resumed(conn);

    if(DEBUG_PRINT) {
        print_connection_data(conn, session_resumed);
    }

    return 0;
}

static void setup_config() {
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((add = getaddrinfo(host, port, &hints, &ai_list)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(add));
        printf("Error: %d\n", add);
        printf("Errno: %s\n", strerror(errno));
        exit(1);
    }
    return;
}

static void ClientBenchmark(benchmark::State& state) {
    setup_config();
    for (auto _ : state) {
        state.PauseTiming();

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
            if(DEBUG_PRINT) {
                printf("Connected to s2nd\n");
            }
            break;
        }
        if (connected == 0) {
            fprintf(stderr, "Failed to connect to %s:%s\n", host, port);
            printf("Error: %s\n", strerror(errno));
            exit(1);
        }

        struct s2n_config *config = s2n_config_new();

        struct verify_data *unsafe_verify_data = (verify_data*)malloc(sizeof(verify_data));;

        if (config == NULL) {
            print_s2n_error("Error getting new config");
            exit(1);
        }
        if(DEBUG_CIPHER) {
            printf("Cipher preference = %s\n", cipher_prefs);
        }

        struct s2n_cipher_suite *cipher_suites_benchmark[] = {
                all_suites[state.range(0)]
        };

        const struct s2n_cipher_preferences cipher_preferences_benchmark = {
                s2n_array_len(cipher_suites_benchmark),
                cipher_suites_benchmark,
        };

        const struct s2n_security_policy security_policy_benchmark = {
                S2N_SSLv3,
                &cipher_preferences_benchmark,
                &kem_preferences_kms_pq_tls_1_0_2020_07,
                &s2n_signature_preferences_20201021,
                NULL,
                &s2n_ecc_preferences_20201021,
        };

        config->security_policy = &security_policy_benchmark;

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

        uint8_t mfl_code = 0;

        GUARD_EXIT(s2n_config_send_max_fragment_length(config, (s2n_max_frag_len)mfl_code), "Error setting maximum fragment length");


        if (insecure) {
            GUARD_EXIT(s2n_config_disable_x509_verification(config), "Error disabling X.509 validation");
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

        GUARD_EXIT(s2n_setup_external_psk_list(conn, psk_optarg_list, psk_list_len), "Error setting external psk list");

        if (benchmark_negotiate(conn, sockfd, state) != 0) {
            state.SkipWithError("Negotiate Failed\n");
            if(DEBUG_PRINT) {
                printf("Error in negotiate!\n");
            }
        }

        if(DEBUG_PRINT) {
            printf("Connected to %s:%s\n", host, port);
        }

        GUARD_EXIT(s2n_connection_free_handshake(conn), "Error freeing handshake memory after negotiation");

        s2n_blocked_status blocked;
        int shutdown_rc = s2n_shutdown(conn, &blocked);
        if (shutdown_rc == -1 && blocked != S2N_BLOCKED_ON_READ) {
            fprintf(stderr, "Unexpected error during shutdown: '%s'\n", s2n_strerror(s2n_errno, "NULL"));
            exit(1);
        }

        GUARD_EXIT(s2n_connection_free(conn), "Error freeing connection");

        GUARD_EXIT(s2n_config_free(config), "Error freeing configuration");

        free(unsafe_verify_data);

        close(sockfd);
    }

    freeaddrinfo(ai_list);

}

/*
 * Change sizes to 1KB, 10KB, 1MB
 */

int Client::start_benchmark_client(int argc, char** argv) {
    rc = s2n_init();

    while (1) {
        int c = getopt(argc, argv, "c:i:sD");
        if (c == -1) {
            break;
        }

        switch (c) {
            case 0:
                /* getopt_long() returns 0 if an option.flag is non-null (Eg "parallelize") */
                break;
            case 'c':
                use_corked_io = atoi(optarg);
                break;
            case 'i':
                ITERATIONS = atoi(optarg);
                break;
            case 's':
                insecure = 0;
                break;
            case 'D':
                DEBUG_PRINT = 1;
                DEBUG_CIPHER = 1;
                break;
            case '?':
            default:
                fprintf(stdout, "getopt eturned: %d", c);
                break;
        }
    }

    if (optind < argc) {
        host = argv[optind++];
    }

    if (optind < argc) {
        port = argv[optind++];
    }


    unsigned int len = sizeof(all_suites) / sizeof(all_suites[0]);
    unsigned int i;
    for(i = 0; i < len; i++) {
        benchmark::RegisterBenchmark(all_suites[i]->name, ClientBenchmark)->Iterations(ITERATIONS)->Arg(i);
    }//include MB/s
    ::benchmark::Initialize(&argc, argv);

    ::benchmark::RunSpecifiedBenchmarks();
    s2n_cleanup();
    return 0;
}
