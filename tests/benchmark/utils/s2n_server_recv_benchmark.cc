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

#include "tests/benchmark/utils/s2n_server_recv_benchmark.h"
#include "tests/benchmark/utils/shared_info.h"
#include <unistd.h>
#include <stdio.h>
#include <vector>
#include <stdlib.h>
#include <poll.h>

extern "C" {
#include "bin/common.h"
#include "tls/s2n_connection.h"
}

int recv_data(struct s2n_connection *conn, int sockfd2, benchmark::State& state, bool warmup) {
    struct pollfd readers[1];
    readers[0].fd = sockfd2;
    readers[0].events = POLLIN;
    errno = 0;
    int poll_output = 0;
    int number_bytes_sending = state.range(0);
    s2n_blocked_status blocked;
    uint8_t* recieved;
    recieved = (uint8_t*)malloc(number_bytes_sending);

    poll_output = poll(readers, 1, -1);
    int bytes_read = 0;
    do {
        int received_bytes = 0;
        if (!warmup) {
            state.ResumeTiming();
        }
        benchmark::DoNotOptimize(received_bytes = s2n_recv(conn, recieved + bytes_read, number_bytes_sending - bytes_read, &blocked));
        if (!warmup) {
            state.PauseTiming();
        }
        if (received_bytes < 0) {
            fprintf(stderr, "Error reading from connection: '%s' %d\n", s2n_strerror(s2n_errno, "EN"),
                    s2n_connection_get_alert(conn));
            exit(1);
        }
        bytes_read += received_bytes;
    } while (bytes_read < number_bytes_sending);
    free(recieved);
    return 0;
}

static int benchmark_recv_single_suite_server(benchmark::State& state) {
    int connectionfd = state.range(3);
    struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
    size_t warmup_iters = state.range(2);

    if (!conn) {
        print_s2n_error("Error getting new s2n connection");
        exit(1);
    }

    s2n_setup_server_connection(conn, connectionfd, config, conn_settings);

    GUARD_EXIT(benchmark_negotiate(conn, connectionfd, state, true), "Server negotiation failed\n");
    if (conn_settings.mutual_auth) {
        if (!s2n_connection_client_cert_used(conn)) {
            print_s2n_error("Error: Mutual Auth was required, but not negotiated");
            exit(1);
        }
    }

    for (size_t i = 0; i < warmup_iters; i++) {
        recv_data(conn, connectionfd, state, true);
    }
    for (auto _ : state) {
        state.PauseTiming();
        recv_data(conn, connectionfd, state, false);
    }

    s2n_blocked_status blocked;
    int shutdown_rc = s2n_shutdown(conn, &blocked);
    if (shutdown_rc == S2N_FAILURE && blocked != S2N_BLOCKED_ON_READ) {
        fprintf(stderr, "Unexpected error during shutdown: '%s'\n", s2n_strerror(s2n_errno, "NULL"));
        exit(1);
    }

    GUARD_RETURN(s2n_connection_wipe(conn), "Error wiping connection");
    GUARD_RETURN(s2n_connection_free(conn), "Error freeing connection");

    return 0;
}

int start_benchmark_recv_server(int argc, char **argv) {
    const char *cipher_prefs = "test_all_tls12";
    struct addrinfo hints = {};
    struct addrinfo *ai;
    conn_settings = {0};
    int use_corked_io = 0;
    int insecure = 0;
    char bench_format[100] = "--benchmark_out_format=";
    std::string file_prefix;
    std::string gb_options;
    std::vector<int> data_sizes;
    long int warmup_iters = 1;
    size_t iterations = 1;
    size_t repetitions = 1;
    int connectionfd = 0;
    int sockfd = 0;

    argument_parse(argc, argv, use_corked_io, insecure, bench_format, file_prefix, warmup_iters, iterations, repetitions,
                   gb_options, data_sizes);

    if(data_sizes.size() == 0) {
        data_sizes = { 1, 100, 1000, 10000, 100000, 1000000 };
    }

    std::string log_output_name = "server_" + file_prefix;
    FILE* write_log = freopen(log_output_name.c_str(), "w", stdout);

    std::vector<char*> argv_bench(argv, argv + argc);
    argv_bench.push_back(bench_format);
    argv_bench.push_back(nullptr);
    argc = argv_bench.size();

    const char *session_ticket_key_file_path = NULL;

    int setsockopt_value = 1;
    int max_early_data = 0;
    conn_settings.session_ticket = 1;
    conn_settings.session_cache = 0;
    conn_settings.max_conns = -1;
    conn_settings.psk_list_len = 0;
    conn_settings.insecure = insecure;
    conn_settings.use_corked_io = use_corked_io;

    s2n_init();

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        fprintf(stderr, "Error disabling SIGPIPE\n");
        exit(1);
    }

    GUARD_EXIT(getaddrinfo(host, port, &hints, &ai), "getaddrinfo error\n");
    GUARD_EXIT((sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)), "socket error\n");
    GUARD_EXIT(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &setsockopt_value, sizeof(int)), "setsockopt error\n");
    GUARD_EXIT(bind(sockfd, ai->ai_addr, ai->ai_addrlen), "Server bind error\n");
    GUARD_EXIT(listen(sockfd, 1), "listen error\n");

    if (DEBUG_PRINT) {
        printf("Listening on %s:%s\n", host, port);
    }

    config = s2n_config_new();
    if (!config) {
        print_s2n_error("Error getting new s2n config");
        exit(1);
    }

    s2n_set_common_server_config(max_early_data, config, conn_settings, cipher_prefs, session_ticket_key_file_path);

    struct s2n_cert_chain_and_key *chain_and_key_rsa = s2n_cert_chain_and_key_new();
    GUARD_EXIT(s2n_cert_chain_and_key_load_pem(chain_and_key_rsa, rsa_certificate_chain, rsa_private_key),
               "Error loading RSA certificate/key");

    GUARD_EXIT(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key_rsa),
               "Error adding RSA chain and key");

    struct s2n_cert_chain_and_key *chain_and_key_ecdsa = s2n_cert_chain_and_key_new();
    GUARD_EXIT(s2n_cert_chain_and_key_load_pem(chain_and_key_ecdsa, ecdsa_certificate_chain, ecdsa_private_key),
               "Error loading ECDSA certificate/key");

    GUARD_EXIT(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key_ecdsa),
               "Error adding ECDSA chain and key");

    connectionfd = accept(sockfd, ai->ai_addr, &ai->ai_addrlen);
    for (unsigned int suite_num = 0; suite_num < num_suites; ++suite_num) {
        std::string bench_name = std::string("Server: ") + all_suites[ suite_num ]->name;

        for (int current_data_index = 0; current_data_index < (int)data_sizes.size(); current_data_index++) {
            benchmark::RegisterBenchmark(bench_name.c_str(), benchmark_recv_single_suite_server)
                ->ReportAggregatesOnly()
                ->Repetitions(repetitions)
                ->Iterations(iterations)
                ->Args({ data_sizes[current_data_index], suite_num, warmup_iters, connectionfd });
        }
    }

    ::benchmark::Initialize(&argc, argv_bench.data());
    ::benchmark::RunSpecifiedBenchmarks();

    close(connectionfd);
    close(sockfd);
    fclose(write_log);
    s2n_cleanup();
    return 0;
}
