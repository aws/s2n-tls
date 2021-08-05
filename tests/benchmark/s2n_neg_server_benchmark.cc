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


static uint8_t ticket_key_name[16] = "2016.07.26.15\0";

static uint8_t default_ticket_key[32] = {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc,
                                         0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b,
                                         0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2,
                                         0xb3, 0xe5 };


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

//dhparams_2048.pem
static char dhparams[] =
        "-----BEGIN DH PARAMETERS-----\n"
        "MIIBCAKCAQEAy1+hVWCfNQoPB+NA733IVOONl8fCumiz9zdRRu1hzVa2yvGseUSq\n"
        "Bbn6k0FQ7yMED6w5XWQKDC0z2m0FI/BPE3AjUfuPzEYGqTDf9zQZ2Lz4oAN90Sud\n"
        "luOoEhYR99cEbCn0T4eBvEf9IUtczXUZ/wj7gzGbGG07dLfT+CmCRJxCjhrosenJ\n"
        "gzucyS7jt1bobgU66JKkgMNm7hJY4/nhR5LWTCzZyzYQh2HM2Vk4K5ZqILpj/n0S\n"
        "5JYTQ2PVhxP+Uu8+hICs/8VvM72DznjPZzufADipjC7CsQ4S6x/ecZluFtbb+ZTv\n"
        "HI5CnYmkAwJ6+FSWGaZQDi8bgerFk9RWwwIBAg==\n"
        "-----END DH PARAMETERS-----\n";

uint8_t unsafe_verify_host_fn(const char *host_name, size_t host_name_len, void *data) {
    return 1;
}

static int benchmark_negotiate(struct s2n_connection *conn, int fd) {
    s2n_blocked_status blocked;
    if (s2n_negotiate(conn, &blocked) != S2N_SUCCESS) {
        if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
            fprintf(stderr, "Failed to negotiate: '%s'. %s\n",
                    s2n_strerror(s2n_errno, "EN"),
                    s2n_strerror_debug(s2n_errno, "EN"));
            fprintf(stderr, "Alert: %d\n",
                    s2n_connection_get_alert(conn));
            printf("Server errno: %s\n", strerror(errno));
            S2N_ERROR_PRESERVE_ERRNO();
        }

        if (wait_for_event(fd, blocked) != S2N_SUCCESS) {
            S2N_ERROR_PRESERVE_ERRNO();
        }
    }

    if(DEBUG_PRINT) {
        print_connection_data(conn);
        psk_early_data(conn);
    }

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

    if (benchmark_negotiate(conn, fd) != S2N_SUCCESS) {
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
    int r, sockfd, fd_bench = 0;

    struct conn_settings conn_settings = {0};
    const char *host = "localhost";
    const char *port = "8000";

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
                corked = atoi(optarg);
                break;
            case 'i':
                ITERATIONS = atoi(optarg);
                break;
            case 's':
                conn_settings.insecure = 0;
                break;
            case 'D':
                DEBUG_PRINT = 1;
                DEBUG_CIPHER = 1;
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

    const char *session_ticket_key_file_path = NULL;
    const char *cipher_prefs = "test_all_tls12";


    int num_user_certificates = 0;
    int num_user_private_keys = 0;
    const char *certificates[MAX_CERTIFICATES] = {0};
    const char *private_keys[MAX_CERTIFICATES] = {0};


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


    if (DEBUG_PRINT) {
        printf("Listening on %s:%s\n", host, port);
    }

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

    bool stop_listen = false;
    while ((!stop_listen) && (fd_bench = accept(sockfd, ai->ai_addr, &ai->ai_addrlen)) > 0) {
        if (!parallelize) {
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
                if (num_user_certificates == 0) {//use auth_method from suites
                    if (all_suites[suite_num]->auth_method == S2N_AUTHENTICATION_RSA) {
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

                for (unsigned int i = 0; i < num_certificates; i++) {
                    struct s2n_cert_chain_and_key *chain_and_key = s2n_cert_chain_and_key_new();
                    GUARD_EXIT(s2n_cert_chain_and_key_load_pem(chain_and_key, certificates[i], private_keys[i]),
                               "Error getting certificate/key");

                    GUARD_EXIT(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key),
                               "Error setting certificate/key");
                }
                int rc;
                for (repeats = 0; repeats < ITERATIONS; repeats++) {
                    rc = handle_connection(fd_bench, config, conn_settings, suite_num);
                }

                stop_listen = true;
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
    close(fd_bench);
    close(sockfd);
    s2n_cleanup();
    return 0;
}
