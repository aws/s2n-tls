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
#include <tests/benchmark/s2n_negotiate_client_benchmark.h>
#include <tests/benchmark/shared_info.h>
#include <benchmark/benchmark.h>

extern "C" {
#include "bin/common.h"
#include <error/s2n_errno.h>

#include "tls/s2n_connection.h"

#include "stuffer/s2n_stuffer.h"

}


struct addrinfo hints, *ai_list, *ai;
int add, sockfd = 0;
const char *server_name = "localhost";
const char *cipher_prefs = "test_all_tls12";
s2n_status_request_type type = S2N_STATUS_REQUEST_NONE;
char *psk_optarg_list[S2N_MAX_PSK_LIST_LENGTH];
size_t psk_list_len = 0;




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

static void client_benchmark(benchmark::State& state, bool warmup) {
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

    if (benchmark_negotiate(conn, sockfd, state, warmup) != 0) {
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

static void ClientBenchmark(benchmark::State& state) {
    int i;
    for(i = 0; i < WARMUP_ITERS; i++) {
        client_benchmark(state, true);
    }
    int counter = 0;
    for (auto _ : state) {
        counter++;
        if(DEBUG_PRINT){
            printf("Count: %d\n", counter);
        }
        state.PauseTiming();
        client_benchmark(state, false);
    }
}

int Client::start_benchmark_client(int argc, char** argv) {
    s2n_init();
    argument_parse(argc, argv);

    char **newv = (char**)malloc((argc + 4) * sizeof(*newv));
    memmove(newv, argv, sizeof(*newv) * argc);
    char bench_out[100] = "--benchmark_out=client_";
    strcat(bench_out, file_prefix);
    newv[argc] = bench_out;
    char aggregate[100] = "--benchmark_display_aggregates_only=true";
    newv[argc+1] = aggregate;
    newv[argc+2] = bench_format;
    newv[argc+3] = 0;
    argc+=3;
    argv = newv;

    setup_config();
    unsigned int i;
    for(i = 0; i < num_suites; i++) {
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
