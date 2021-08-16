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
#include <tests/benchmark/utils/s2n_negotiate_server_benchmark.h>
#include <benchmark/benchmark.h>
#include <tests/benchmark/utils/shared_info.h>

extern "C" {

#include "bin/common.h"
#include <error/s2n_errno.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "tls/s2n_config.h"
#include "tls/s2n_cipher_suites.h"

#include "stuffer/s2n_stuffer.h"
#include "tests/s2n_test.h"
#include "tests/testlib/s2n_testlib.h"

#define MAX_CERTIFICATES 50
}

int fd_bench = 0;
struct s2n_config *config_once;
struct conn_settings conn_settings;
struct session_cache_entry session_cache[256];

//rsa_2048_sha384_client_cert.pem - Expires: Jul 8th, 2117
static char rsa_certificate_chain[] =
        "-----BEGIN CERTIFICATE-----"
        "MIIDfTCCAmWgAwIBAgIJAPUg4P1R3ctAMA0GCSqGSIb3DQEBDAUAMF8xCzAJBgNV"
        "BAYTAlVTMQswCQYDVQQIDAJXQTEQMA4GA1UEBwwHU2VhdHRsZTEPMA0GA1UECgwG"
        "QW1hem9uMQwwCgYDVQQLDANzMm4xEjAQBgNVBAMMCWxvY2FsaG9zdDAgFw0xNzA4"
        "MDEyMjQzMzJaGA8yMTE3MDcwODIyNDMzMlowXzELMAkGA1UEBhMCVVMxCzAJBgNV"
        "BAgMAldBMRAwDgYDVQQHDAdTZWF0dGxlMQ8wDQYDVQQKDAZBbWF6b24xDDAKBgNV"
        "BAsMA3MybjESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOC"
        "AQ8AMIIBCgKCAQEA+gyp3fZTLrvWsZ8QxBIoLItRcSveQc4HavylagfNIawpnRbu"
        "39Lu2dzJSDk9so04iPm5+OLVAY8lhH9vPOSyhCL/GxikxkKgCvLWv4c4fVBeWt5Z"
        "S5xgOVsaKUR9oVfhTHLlc6M/gA5NW0Wbh34DZHAFCF9noGGoKKXpnDTyApGBYTHW"
        "XXEcL2sPKF/jU9maGPQzX7joHlHWSx1kiWTne1Gn7NJrmxrYUrn9VjM15bwi94gZ"
        "LE5TsCCoPFIzbzyKattYFJ8xNHERcf/Ss+0VCYCAT2g0GmykjK3znpKPCRSakPfx"
        "Xqfpx0MJLsh9zG1eqkQV+zc4NXursZ61ydBlLQIDAQABozowODALBgNVHQ8EBAMC"
        "BDAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwFAYDVR0RBA0wC4IJMTI3LjAuMC4xMA0G"
        "CSqGSIb3DQEBDAUAA4IBAQBVEGuaKg2pdynqZHiMr67WlbHqAE+9NvT5ouwb81VZ"
        "/UH0hawwRJAQgSa09sUNyp1tGmV7OrLIzVyp0HcpNt4RbASmk9eDwPO/woggGWXD"
        "f0go1LlKPcB/IoMvOmEX8CqqNWncYproXEaHT31hwQRtrT+bfU8MbH76eQ5vC2Fo"
        "RfUfHW6mjc8plw786BdKIg0B5r9rHMTrmFeP/HlDP5fkS4wH5y9hLGqkchBDUtAa"
        "wvXRARKV/xCvZMqcwPY6sqbpZ5surR4GEe9KrgodmtWYCq12TIfmucfkAicFcCQa"
        "fxZRly5wMFwzjqcyM01lzDCqzhxC7nVljCJie8brb2mG"
        "-----END CERTIFICATE-----";

//rsa_2048_sha384_client_key.pem
static char rsa_private_key[] =
        "-----BEGIN PRIVATE KEY-----"
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD6DKnd9lMuu9ax"
        "nxDEEigsi1FxK95Bzgdq/KVqB80hrCmdFu7f0u7Z3MlIOT2yjTiI+bn44tUBjyWE"
        "f2885LKEIv8bGKTGQqAK8ta/hzh9UF5a3llLnGA5WxopRH2hV+FMcuVzoz+ADk1b"
        "RZuHfgNkcAUIX2egYagopemcNPICkYFhMdZdcRwvaw8oX+NT2ZoY9DNfuOgeUdZL"
        "HWSJZOd7Uafs0mubGthSuf1WMzXlvCL3iBksTlOwIKg8UjNvPIpq21gUnzE0cRFx"
        "/9Kz7RUJgIBPaDQabKSMrfOeko8JFJqQ9/Fep+nHQwkuyH3MbV6qRBX7Nzg1e6ux"
        "nrXJ0GUtAgMBAAECggEBAOcHnEtAtEqRsyQZ29vNCuFdN7pg1dHnEmN/WzZETvu1"
        "nh1OexbCRX11yWO5v4+he4LTeUjEDBqMsBVjyNtyUp5T13CprFSiakyzYkdEIKVo"
        "BEXg+pApw5461kkaxxizoa6I2gel5Z3jmQWjorflbiz2cy/xNkWw9TXZVabGJHTJ"
        "OD+C6afzcImpCfdNVPQ2NvZpyNGwxDwimrxbIpowormedFjG0YscdruSAY4R1D/f"
        "Z8iqoUGb22Mlu0vtGT8rb5Gz/VcnzAVjKRmExo4WBCCi7zg6vJ6QwYd9SYgObYJr"
        "JztT3HtQWEk28ip4bNmLgVjDjtAAePEp0e6FwiB8nAECgYEA/jgBHmtx2YGuH6ns"
        "PQEGnOyp2CGCi1lSAcH76pViOBDRnjr1oP1mOFjYqk9OgngF9M3sEnID5dl4FoDr"
        "C12nyV/M9ZRlhy3Vq+5armWIUITFwKNpO1NGXQB9LPYbVA6Mt2Vgntqqc2id9/vA"
        "sgZhdw4Rcjelspx+Gi3+hdlIX6ECgYEA+80uPpzyVpy4BBcYG+IDi07agn7w99LN"
        "vo4/NeFlBPFYGjywaC90Ju0o8CFt8QL0E4tPv8jhWzTqh3FupKbI4R5jLlVzyoHK"
        "cxdJr7WIK4vnXFtJu2tECudHVMGYhY2NkAILXfNyksYThB7/LJkhEK+f9Got8gZK"
        "xXasU6EfSg0CgYBcbNojSCcNUDOROYM1LrFLzlN1y8EdjqzdDLzdLdCW166OW5tA"
        "G8DVTaAAU3MUxjRMK63fiupV37nkXJyX9kXxVc47nudGvWhI6RC5BRsJQyxufDrf"
        "IcicOXhJJ3UKG3wXlVkKiC+eY/PC3BnT37QBx/CZ2Rd6F6FVPVGjMjs44QKBgBSO"
        "LWZDHa1gYc1DrV4pVyy6JTBd+IHinZUeu55EZiC/KvgJWEVJCmxbE+p2cCkqmo41"
        "4y6+0VbGvRaNdgDO9Lsb5fDUXP19Fu/KSOOlKBaV9y8c7Kn2GbniI3qRy0erxJCq"
        "+g6TXxkIPnOcrCwR3BcmnyIuwM1vIg94npy9HHbJAoGBALQa7hybvU+K9QhKJ/UA"
        "Ek0GF+8uYfJtQ27U+lXVXIq85lveXAUZ7S/d5k5WklU6iZTYhljEWnLSpsXReyYi"
        "4UlMKX+zTAsL3a5o7GtM0LbV8ZyecTt9k8xK8T/PdS0/w78KwTO/13OdItuMi0vx"
        "Q00ZFPpn7NMd+V9tAUhofrET"
        "-----END PRIVATE KEY-----";

//ecdsa_p256_pkcs1_cert.pem - Expires: Nov 10th, 2120
static char ecdsa_certificate_chain[] =
        "-----BEGIN CERTIFICATE-----"
        "MIICLDCCAdGgAwIBAgIUPYYEnK24qDzz59IIDcNLc4P2H5swCgYIKoZIzj0EAwIw"
        "XzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMRAwDgYDVQQHDAdTZWF0dGxlMQ8w"
        "DQYDVQQKDAZBbWF6b24xDDAKBgNVBAsMA3MybjESMBAGA1UEAwwJbG9jYWxob3N0"
        "MCAXDTIwMTIwNDA3NDg1NloYDzIxMjAxMTEwMDc0ODU2WjBfMQswCQYDVQQGEwJV"
        "UzELMAkGA1UECAwCV0ExEDAOBgNVBAcMB1NlYXR0bGUxDzANBgNVBAoMBkFtYXpv"
        "bjEMMAoGA1UECwwDczJuMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIB"
        "BggqhkjOPQMBBwNCAARhONnk1k68YnnabiHzf3AvlWwN93SOvdq6v1Grl3YEiGM1"
        "W8WFH7O4cxb+otlVlhhbPzaox4EVthLExJZumx8go2kwZzAdBgNVHQ4EFgQU0ip8"
        "rN6YlbtCUIueCOqfh3/J3KMwHwYDVR0jBBgwFoAU0ip8rN6YlbtCUIueCOqfh3/J"
        "3KMwDwYDVR0TAQH/BAUwAwEB/zAUBgNVHREEDTALggkxMjcuMC4wLjEwCgYIKoZI"
        "zj0EAwIDSQAwRgIhAJwlrxN5SDi2dC17ZPgajqZ8BZyOsNFE+gsobhMBUGN0AiEA"
        "6KFJgyPGBNdQqaczkNyBcutPGqEubuah5Me6faN4qqU="
        "-----END CERTIFICATE-----";

//ecdsa_p384_pkcs1_key.pem
static char ecdsa_private_key[] =
        "-----BEGIN EC PARAMETERS-----"
        "BggqhkjOPQMBBw=="
        "-----END EC PARAMETERS-----"
        "-----BEGIN EC PRIVATE KEY-----"
        "MHcCAQEEIK4AEDQja7MDATqWWu4T0+iMFdSZH4y4+nuVzDX5ao8KoAoGCCqGSM49"
        "AwEHoUQDQgAEYTjZ5NZOvGJ52m4h839wL5VsDfd0jr3aur9Rq5d2BIhjNVvFhR+z"
        "uHMW/qLZVZYYWz82qMeBFbYSxMSWbpsfIA=="
        "-----END EC PRIVATE KEY-----";

static int server_benchmark(benchmark::State& state, bool warmup) {
    int fd = fd_bench;
    struct s2n_config *config = config_once;
    struct conn_settings settings = conn_settings;
    struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
    if (!conn) {
        print_s2n_error("Error getting new s2n connection");
        S2N_ERROR_PRESERVE_ERRNO();
    }

    s2n_setup_server_connection(conn, fd, config, settings);

    if (benchmark_negotiate(conn, fd, state, warmup) != S2N_SUCCESS) {
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

static int ServerBenchmark(benchmark::State& state) {
    int i;
    for(i = 0; i < WARMUP_ITERS; i++) {
        server_benchmark(state, true);
    }
    for(auto _ : state) {
        state.PauseTiming();
        server_benchmark(state, false);
    }
    return 0;
}


int Server::start_benchmark_server(int argc, char **argv) {
    struct addrinfo hints, *ai;
    int r, sockfd= 0;

    conn_settings = {0};
    argument_parse(argc, argv);

    char str[80];
    strcpy(str, "server_");
    strcat(str, file_prefix);
    freopen(str, "w", stdout);

    char **newv = (char**)malloc((argc + 2) * sizeof(*newv));
    memmove(newv, argv, sizeof(*newv) * argc);
    newv[argc] = bench_format;
    newv[argc+1] = 0;
    argc++;
    argv = newv;


    const char *session_ticket_key_file_path = NULL;
    const char *cipher_prefs = "test_all_tls12";

    const char *certificates[MAX_CERTIFICATES] = {0};
    const char *private_keys[MAX_CERTIFICATES] = {0};


    int parallelize = 0;

    conn_settings.session_ticket = 1;
    conn_settings.session_cache = 0;
    conn_settings.max_conns = -1;
    conn_settings.psk_list_len = 0;
    conn_settings.insecure = insecure;

    conn_settings.use_corked_io = use_corked_io;

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
    GUARD_EXIT(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &r, sizeof(int)), "setsockopt error\n");
    GUARD_EXIT(bind(sockfd, ai->ai_addr, ai->ai_addrlen), "bind error");
    GUARD_EXIT(listen(sockfd, 1), "listen error\n");


    if (DEBUG_PRINT) {
        printf("Listening on %s:%s\n", host, port);
    }

    config_once = s2n_config_new();
    if (!config_once) {
        print_s2n_error("Error getting new s2n config");
        exit(1);
    }

    s2n_set_common_server_config(max_early_data, config_once, conn_settings, cipher_prefs, session_ticket_key_file_path);


    certificates[0] = rsa_certificate_chain;
    private_keys[0] = rsa_private_key;
    struct s2n_cert_chain_and_key *chain_and_key_rsa = s2n_cert_chain_and_key_new();
    GUARD_EXIT(s2n_cert_chain_and_key_load_pem(chain_and_key_rsa, certificates[0], private_keys[0]),
               "Error getting certificate/key");

    GUARD_EXIT(s2n_config_add_cert_chain_and_key_to_store(config_once, chain_and_key_rsa),
               "Error setting certificate/key");

    certificates[0] = ecdsa_certificate_chain;
    private_keys[0] = ecdsa_private_key;

    struct s2n_cert_chain_and_key *chain_and_key = s2n_cert_chain_and_key_new();
    GUARD_EXIT(s2n_cert_chain_and_key_load_pem(chain_and_key, certificates[0], private_keys[0]),
               "Error getting certificate/key");

    GUARD_EXIT(s2n_config_add_cert_chain_and_key_to_store(config_once, chain_and_key),
               "Error setting certificate/key");

    bool stop_listen = false;
    while ((!stop_listen) && (fd_bench = accept(sockfd, ai->ai_addr, &ai->ai_addrlen)) > 0) {
        if (!parallelize) {
            for (unsigned int j = 0; j < num_suites; ++j) {
                unsigned int suite_num = j;

                char bench_name[80];
                strcpy(bench_name, "Server: ");
                strcat(bench_name, all_suites[suite_num]->name);

                benchmark::RegisterBenchmark(bench_name, ServerBenchmark)->Repetitions(ITERATIONS)->Iterations(1)->Arg(suite_num);


                /* If max_conns was set, then exit after it is reached. Otherwise
                 * unlimited connections are allow, so ignore the variable. */
                if (conn_settings.max_conns > 0) {
                    if (conn_settings.max_conns-- == 1) {
                        exit(0);
                    }
                }
            }
        }
        stop_listen = true;
    }


    ::benchmark::Initialize(&argc, argv);

    ::benchmark::RunSpecifiedBenchmarks();

    free(newv);
    close(fd_bench);
    close(sockfd);
    s2n_cleanup();
    return 0;
}
