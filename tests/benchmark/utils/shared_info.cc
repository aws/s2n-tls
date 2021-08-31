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

#include "shared_info.h"

extern "C" {
#include "bin/common.h"
}

struct s2n_cipher_suite **all_suites = cipher_preferences_test_all_tls12.suites;
unsigned int num_suites = cipher_preferences_test_all_tls12.count;
const char *host = "localhost";
const char *port = "8000";
char const *pem_dir = "";
int DEBUG_PRINT = 0;
struct s2n_config *config;
struct conn_settings conn_settings;

//rsa_2048_sha384_client_cert.pem - Expires: Jul 8th, 2117
const char *rsa_certificate_chain =
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
const char *rsa_private_key =
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
const char *ecdsa_certificate_chain =
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
const char *ecdsa_private_key =
        "-----BEGIN EC PARAMETERS-----"
        "BggqhkjOPQMBBw=="
        "-----END EC PARAMETERS-----"
        "-----BEGIN EC PRIVATE KEY-----"
        "MHcCAQEEIK4AEDQja7MDATqWWu4T0+iMFdSZH4y4+nuVzDX5ao8KoAoGCCqGSM49"
        "AwEHoUQDQgAEYTjZ5NZOvGJ52m4h839wL5VsDfd0jr3aur9Rq5d2BIhjNVvFhR+z"
        "uHMW/qLZVZYYWz82qMeBFbYSxMSWbpsfIA=="
        "-----END EC PRIVATE KEY-----";

void usage() {
    fprintf(stderr, "usage: s2n_benchmark [options] host port\n");
    fprintf(stderr, " host: hostname or IP address to connect to\n");
    fprintf(stderr, " port: port to connect to\n");
    fprintf(stderr, "\n Options:\n");
    fprintf(stderr, "  -c\n");
    fprintf(stderr, "   sets use_corked_io to true\n");
    fprintf(stderr, "  -i [# of iterations]\n");
    fprintf(stderr, "   sets the number of iterations to run each repetition\n");
    fprintf(stderr, "  -r [# of repetitions]\n");
    fprintf(stderr, "   sets the number of repetitions to run each benchmark\n");
    fprintf(stderr, "  -w [# of warmup iterations]\n");
    fprintf(stderr, "   sets the number of warmup runs for each benchmark\n");
    fprintf(stderr, "  -o [output file name]\n");
    fprintf(stderr, "   sets the name of the output file\n");
    fprintf(stderr, "  -t [json|csv|console]\n");
    fprintf(stderr, "   sets the output format of the output file\n");
    fprintf(stderr, "  -p [file path to pem directory]\n");
    fprintf(stderr, "   if using secure mode, must set pem directory\n");
    fprintf(stderr, "  -g [google benchmark options]\n");
    fprintf(stderr, "   sets the google benchmark options\n");
    fprintf(stderr, "  -d #;#;#\n");
    fprintf(stderr, "   sets the size of the data that should be sent in send/recv benchmarks\n");
    fprintf(stderr, "  -s\n");
    fprintf(stderr, "   run benchmarks in insecure mode\n");
    fprintf(stderr, "  -D\n");
    fprintf(stderr, "   print debug output to terminal\n");
    fprintf(stderr, "\n");
    exit(1);
}

int benchmark_negotiate(struct s2n_connection *conn, int fd, benchmark::State& state, bool warmup) {
    s2n_blocked_status blocked;
    int s2n_ret;
    if (!warmup) {
        state.ResumeTiming();
    }
    benchmark::DoNotOptimize(s2n_ret = s2n_negotiate(conn, &blocked)); //forces the result to be stored in either memory or a register.
    if (!warmup) {
        state.PauseTiming();
    }
    benchmark::ClobberMemory(); //forces the compiler to perform all pending writes to global memory

    if (s2n_ret != S2N_SUCCESS) {
        if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
            fprintf(stderr, "Failed to negotiate: '%s'. %s\n",
                    s2n_strerror(s2n_errno, "EN"),
                    s2n_strerror_debug(s2n_errno, "EN"));
            fprintf(stderr, "Alert: %d\n",
                    s2n_connection_get_alert(conn));
            printf("errno: %s\n", strerror(errno));
            S2N_ERROR_PRESERVE_ERRNO();
        }

        if (wait_for_event(fd, blocked) != S2N_SUCCESS) {
            S2N_ERROR_PRESERVE_ERRNO();
        }

        state.SkipWithError("Negotiate Failed\n");
    }

    if (DEBUG_PRINT) {
        print_connection_info(conn);
    }

    return 0;
}

void argument_parse(int argc, char** argv, int& use_corked_io, int& insecure, char* bench_format,
                    std::string& file_prefix, long int& warmup_iters, size_t& iterations, size_t& repetitions,
                    std::string& gb_options, std::vector<int> &data_sizes) {
    while (1) {
        int c = getopt(argc, argv, "ci:r:w:o:t:p:g:d:sD");
        if (c == -1) {
            break;
        }
        switch (c) {
            case 0:
                /* getopt_long() returns 0 if an option.flag is non-null (Eg "parallelize") */
                break;
            case 'c':
                use_corked_io = 1;
                break;
            case 'i':
                iterations = atoi(optarg);
                break;
            case 'r':
                repetitions = atoi(optarg);
                break;
            case 'w':
                warmup_iters = atoi(optarg);
                break;
            case 'o':
                file_prefix = std::string(optarg);
                break;
            case 't':
                strcat(bench_format, optarg);
                break;
            case 'p':
                pem_dir = optarg;
                break;
            case 'd':
                {
                    std::string s = std::string(optarg);
                    size_t pos = 0;
                    std::string token;
                    while ((pos = s.find(";")) != std::string::npos) {
                        token = s.substr(0, pos);
                        data_sizes.push_back(stoi(token));
                        s.erase(0, pos + 1);
                    }
                    data_sizes.push_back(stoi(s));
                }
                break;
            case 's':
                insecure = 1;
                break;
            case 'D':
                DEBUG_PRINT = 1;
                break;
            case 'g':
                gb_options = std::string(optarg);
                break;
            case '?':
            default:
                fprintf(stdout, "getopt returned: %d", c);
                usage();
                break;
        }
    }

    if (optind < argc) {
        host = argv[optind++];
    }

    if (optind < argc) {
        port = argv[optind++];
    }
}
