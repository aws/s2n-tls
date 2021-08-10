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
static unsigned int ITERATIONS = 50;

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
        &s2n_rsa_with_rc4_128_md5,
        &s2n_rsa_with_rc4_128_sha,
        &s2n_rsa_with_3des_ede_cbc_sha,
        &s2n_dhe_rsa_with_3des_ede_cbc_sha,
        &s2n_rsa_with_aes_128_cbc_sha,
        &s2n_dhe_rsa_with_aes_128_cbc_sha,
        &s2n_rsa_with_aes_256_cbc_sha,
        &s2n_dhe_rsa_with_aes_256_cbc_sha,
        &s2n_rsa_with_aes_128_cbc_sha256,
        &s2n_rsa_with_aes_256_cbc_sha256,
        &s2n_dhe_rsa_with_aes_128_cbc_sha256,
        &s2n_dhe_rsa_with_aes_256_cbc_sha256,
        &s2n_rsa_with_aes_128_gcm_sha256,
        &s2n_rsa_with_aes_256_gcm_sha384,
        &s2n_dhe_rsa_with_aes_128_gcm_sha256,

        &s2n_ecdhe_rsa_with_rc4_128_sha,
        &s2n_ecdhe_rsa_with_3des_ede_cbc_sha,
        &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
        &s2n_ecdhe_rsa_with_aes_256_cbc_sha,

        &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,


        &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
        &s2n_ecdhe_rsa_with_chacha20_poly1305_sha256,

        &s2n_dhe_rsa_with_chacha20_poly1305_sha256,
        &s2n_ecdhe_bike_rsa_with_aes_256_gcm_sha384,
        &s2n_ecdhe_sike_rsa_with_aes_256_gcm_sha384,
        &s2n_ecdhe_kyber_rsa_with_aes_256_gcm_sha384,

        &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha,
        &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
        &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
        &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
        &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
        &s2n_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
};

static int benchmark_negotiate(struct s2n_connection *conn, int fd, benchmark::State& state)
{
    s2n_blocked_status blocked;
    int s2n_ret;
    state.ResumeTiming();
    benchmark::DoNotOptimize(s2n_ret = s2n_negotiate(conn, &blocked)); //forces the result to be stored in either memory or a register.
    state.PauseTiming();
    benchmark::ClobberMemory(); //forces the compiler to perform all pending writes to global memory

    if (s2n_ret != S2N_SUCCESS) {
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

    if(DEBUG_PRINT) {
        print_connection_info(conn);
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

    int connected = 0;
    while(connected == 0) {
        for (ai = ai_list; ai != NULL; ai = ai->ai_next) {
            if ((sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1) {
                continue;
            }

            if (connect(sockfd, ai->ai_addr, ai->ai_addrlen) == -1) {
                close(sockfd);
                continue;
            }

            connected = 1;
            if (DEBUG_PRINT) {
                printf("Connected to s2nd\n");
            }
            break;
        }
    }
    return;
}

static void ClientBenchmark(benchmark::State& state) {

    for (auto _ : state) {
        state.PauseTiming();

        struct s2n_config *config = s2n_config_new();

        struct verify_data *unsafe_verify_data = (verify_data *) malloc(sizeof(verify_data));;

        if (config == NULL) {
            print_s2n_error("Error getting new config");
            exit(1);
        }
        if (DEBUG_PRINT) {
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

        GUARD_EXIT(s2n_config_set_status_request_type(config, type),
                   "OCSP validation is not supported by the linked libCrypto implementation. It cannot be set.");

        if (s2n_config_set_verify_host_callback(config, unsafe_verify_host, unsafe_verify_data) < 0) {
            print_s2n_error("Error setting host name verification function.");
        }

        if (type == S2N_STATUS_REQUEST_OCSP) {
            if (s2n_config_set_check_stapled_ocsp_response(config, 1)) {
                print_s2n_error(
                        "OCSP validation is not supported by the linked libCrypto implementation. It cannot be set.");
            }
        }

        unsafe_verify_data->trusted_host = host;

        uint8_t mfl_code = 0;

        GUARD_EXIT(s2n_config_send_max_fragment_length(config, (s2n_max_frag_len) mfl_code),
                   "Error setting maximum fragment length");


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

        GUARD_EXIT(s2n_connection_set_fd(conn, sockfd), "Error setting file descriptor");

        GUARD_EXIT(s2n_connection_set_client_auth_type(conn, S2N_CERT_AUTH_OPTIONAL),
                   "Error setting ClientAuth optional");

        if (use_corked_io) {
            GUARD_EXIT(s2n_connection_use_corked_io(conn), "Error setting corked io");
        }

        GUARD_EXIT(s2n_setup_external_psk_list(conn, psk_optarg_list, psk_list_len), "Error setting external psk list");

        if (benchmark_negotiate(conn, sockfd, state) != 0) {
            state.SkipWithError("Negotiate Failed\n");
            if (DEBUG_PRINT) {
                printf("Error in negotiate!\n");
            }
        }

        if (DEBUG_PRINT) {
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
    }
    state.SetBytesProcessed(state.iterations() * sizeof(int));
}

int Client::start_benchmark_client(int argc, char** argv) {
    s2n_init();
    char file_prefix[100];

    while (1) {
        int c = getopt(argc, argv, "c:i:o:sD");
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
            case 'o':
                strcpy(file_prefix, optarg);
                break;
            case 's':
                insecure = 1;
                break;
            case 'D':
                DEBUG_PRINT = 1;
                break;
            case '?':
            default:
                fprintf(stdout, "getopt returned: %d", c);
                break;
        }
    }

    if (optind < argc) {
        host = argv[optind++];
    }

    if (optind < argc) {
        port = argv[optind++];
    }

    char **newv = (char**)malloc((argc + 3) * sizeof(*newv));
    memmove(newv, argv, sizeof(*newv) * argc);
    char bench_out[100] = "--benchmark_out=client_";
    strcat(bench_out, file_prefix);
    newv[argc] = bench_out;
    char aggregate[100] = "--benchmark_display_aggregates_only=true";
    newv[argc+1] = aggregate;
    newv[argc+2] = 0;
    argc+=2;
    argv = newv;

    setup_config();
    unsigned int len = sizeof(all_suites) / sizeof(all_suites[0]);
    unsigned int i;
    for(i = 0; i < len; i++) {
        char bench_name[80];
        strcpy(bench_name, "Client: ");
        strcat(bench_name, all_suites[i]->name);

        benchmark::RegisterBenchmark(bench_name, ClientBenchmark)->Repetitions(ITERATIONS)->Iterations(1)->Arg(i);

    }

    ::benchmark::Initialize(&argc, argv);

    ::benchmark::RunSpecifiedBenchmarks();
    free(newv);
    s2n_cleanup();
    close(sockfd);
    freeaddrinfo(ai_list);
    return 0;
}
