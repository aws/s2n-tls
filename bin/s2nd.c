/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <netdb.h>

#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <getopt.h>

#include <errno.h>

#include <s2n.h>

static char certificate_chain[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICrTCCAZUCAn7lMA0GCSqGSIb3DQEBCwUAMB4xHDAaBgNVBAMME3MyblRlc3RJ\n"
    "bnRlcm1lZGlhdGUwIBcNMTcwMjEyMDQxMzA5WhgPMjExNzAxMTkwNDEzMDlaMBgx\n"
    "FjAUBgNVBAMMDXMyblRlc3RTZXJ2ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n"
    "ggEKAoIBAQDHZZ9R9bKwS28KgAzNnXHnKeQ/IRqMhcv1OoNpV28TMutajg+Nri42\n"
    "CsdLvQe2gEVSb9WAo81LmaQyy4xMZmVmM2wE2KrgR0Kw9XnL7QNAxZsz5Ai5mEdx\n"
    "JhXI9aPxZ1sHViHteTFgcGXhCxfoQDsgwIbVhK34FCNoB0p4qnj9h6xMmh64CPdY\n"
    "BYFpjxchT9OPnOzi0Q/XyMBuKjc/zjgwbAvrJh+hTuS1qSiXcXFRukJRYmdr0Dws\n"
    "OzfQn1rvDpjOWmJ3CMcZnNKvXow1oq98UPJAE80LcwslybizLN6irQpcEjXiH808\n"
    "OMUD1FB/Ww/KIFpBOr4CeCZCw5AAUcGhAgMBAAEwDQYJKoZIhvcNAQELBQADggEB\n"
    "AD7AKpWe9yVfBmjORAIdt/UFSusUQhliPQDQvrf3AdPFbjrLXu259jSvT6cZxbJM\n"
    "90JOAb9nLtulqWjByoUOUGM9VixdAQNGtFrQ3t5ZGBn+putsd+6Sejb9Z4W01Kks\n"
    "Ih5jG68mpHxVWSpgsExeN1Pu6Q02UqmNOz/6s9+D2/4PeRvdlD+gavo2RrWWjLpz\n"
    "Kd7ayXx7PK2MntojzYzab+RRUW+ecqXL92Me2YLBXleQlnV9AqCwNis19jhUuBzF\n"
    "923g0e8/5SA1EKRFAubrF6FabW87rflR1a8kKlBQmOufX/97SFm9TpTg5/vt/sZn\n"
    "DqaFKO6gnaYSCZxT0LVcsec=\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDKTCCAhGgAwIBAgICGegwDQYJKoZIhvcNAQEFBQAwFjEUMBIGA1UEAwwLczJu\n"
    "VGVzdFJvb3QwIBcNMTcwMjEyMDQxMjAwWhgPMjExNzAxMTkwNDEyMDBaMB4xHDAa\n"
    "BgNVBAMME3MyblRlc3RJbnRlcm1lZGlhdGUwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n"
    "DwAwggEKAoIBAQDH8d/6eRJzSg+mz9y2mmWMzpPtNsiEyXyOZm701ytohyUrZA7Y\n"
    "P3+q0b/96jYYwSUbpZB4FmaWZDZAf5VjWHVpcGwKfHh5h82RXZcBUmyCkFdO5pMj\n"
    "MNutXTwJ3B6RvvKsLScMNpHU1oSQbe2OfXxqPjA8J1DNyAG97xNpQ9m8N+2LQ2Ce\n"
    "RV2743aMjluQWpaSH6O3orjNn/z9rArmLsS+lGzpN4F87z+NYeUUq1lQulWf11S+\n"
    "1jpEJCzKaVsPeQmeSXcu1a41xEEVabGW1ERbfE6yq/uP2QKD1vUxbCqlVzgz92Ky\n"
    "lIWlnK6oMCE8tpQWd11TcEfZNlw7bCjAr/n7AgMBAAGjdzB1MAwGA1UdEwQFMAMB\n"
    "Af8wHQYDVR0OBBYEFKiNxMQOh4aMU0Za7y97D0Wc+tqgMEYGA1UdIwQ/MD2AFBSn\n"
    "L6QRCOpg+LIFK3cubF0tZPOcoRqkGDAWMRQwEgYDVQQDDAtzMm5UZXN0Um9vdIIJ\n"
    "AJB2OQ8SQr0KMA0GCSqGSIb3DQEBBQUAA4IBAQBiW6I16xgQpa4JQnZrPa0a08L/\n"
    "c8lKvJWz6PRejf+xGn9JQU2HRgpsp5osnFuXDZCB/KkkVt1qcbDc/VEJ1tE7GLGr\n"
    "mX+9beZQJj9dS43k5Qt9J9wrVifGGd/0sl+Or0hmoeV/qDJNsq8lHCjnrRZ+iSKt\n"
    "DQ5NdV5z1lc5vOCARK0RyzBk07pHsfn39TCgyrIa+10cS6xrLSJcFC1eqC7sRRsW\n"
    "cOVSt9nJDiKn+DOlEyMPWmwRUZX2rRzAlalDPsS/QzUUU3g+ExrBOACsySwiMKhX\n"
    "aflRFDu7xHWKv9zK5FWysXjwTlKPOrDWcytNu+4NmWtBye/6s+5xyYjWbvdF\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDBDCCAeygAwIBAgIJAJB2OQ8SQr0KMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNV\n"
    "BAMMC3MyblRlc3RSb290MCAXDTE3MDIxMjA0MDk1M1oYDzIxMTcwMTE5MDQwOTUz\n"
    "WjAWMRQwEgYDVQQDDAtzMm5UZXN0Um9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEP\n"
    "ADCCAQoCggEBANgSkebYTJIGo33QWSCKIwx8UXdOxXF9nljyQPQ6dgbuOTGbq4nF\n"
    "eIA0AxMgkt0P8DnGuiJ/yuCvWmNAPy/wdmxPGxHfpDbiHFpbNGh10D7B3k68s51+\n"
    "j4llBp3IymukQVFXQ4mFx3bI7VrSsGG9ZVd/+iMvSsU3yykhLRsgKgpj3RMYcb8C\n"
    "WL3/lzR4F8QNZ9dwy0gifyF60xgC9n7D7kgI0PlDfIUBW68fjvscVhc6xYt1BDeG\n"
    "++zngJpmeC9T7mN37/Nv5mXDCjKOtBGG9iOlriK6RzyPaUMc0n7gA1nB/mMy9GNe\n"
    "lrMvIg44HSaKSdmwIbUVf96+aUegEexhrbsCAwEAAaNTMFEwHQYDVR0OBBYEFBSn\n"
    "L6QRCOpg+LIFK3cubF0tZPOcMB8GA1UdIwQYMBaAFBSnL6QRCOpg+LIFK3cubF0t\n"
    "ZPOcMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBANEFXqBmaVoC\n"
    "gOzPJol8saCkiIBJzgy4WpcY3TVM5z/MkpXd3fj0fR8bnhosmVmlHO6O2relGG+z\n"
    "TtfU9fa7UG9fN+8fFjU59tw57qCJubKcoqJJzAIQCvCCuZ1yGGBkYwyCpKjQrkLX\n"
    "54WNgAxXuPsQDzh4Y2943qk4kwliKEUPbkKnPuCDCxyHvpczXfbIdBcNKQ/WCkhW\n"
    "ma7uqCaZ2sWx89UIR8ZVSpNuXAG+ZxvB1L5SN/8akCajK5z2AdVgAfTAKgsfb7WY\n"
    "q76LCukvaANwJPnbsE0zHV5uYj6fl/V62msSaBlm1iI0glE6uZJAYZqeiEv3+cbF\n"
    "e3r1R9CDhIo=\n"
    "-----END CERTIFICATE-----\n";

static char private_key[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDHZZ9R9bKwS28K\n"
    "gAzNnXHnKeQ/IRqMhcv1OoNpV28TMutajg+Nri42CsdLvQe2gEVSb9WAo81LmaQy\n"
    "y4xMZmVmM2wE2KrgR0Kw9XnL7QNAxZsz5Ai5mEdxJhXI9aPxZ1sHViHteTFgcGXh\n"
    "CxfoQDsgwIbVhK34FCNoB0p4qnj9h6xMmh64CPdYBYFpjxchT9OPnOzi0Q/XyMBu\n"
    "Kjc/zjgwbAvrJh+hTuS1qSiXcXFRukJRYmdr0DwsOzfQn1rvDpjOWmJ3CMcZnNKv\n"
    "Xow1oq98UPJAE80LcwslybizLN6irQpcEjXiH808OMUD1FB/Ww/KIFpBOr4CeCZC\n"
    "w5AAUcGhAgMBAAECggEBAL0n52Ld/TyG4vkIDp1EHhjYQcGtir0B9EFX1/An1KRW\n"
    "6rQGDjUupoH36aYs1dNIjfqtQtH9EjUEtKLHO/oCLXEtmOxkCn4mu9qZlIhi+HIK\n"
    "w7gPPEOsdSGeqo3wkSziCpXEHP1lufSty8gYOP7HaBAi9AY8DrlHiWsXd4tO1OZU\n"
    "kOc4t6/bKOywtylcoJ7Na5eGsDT+f6bjQgHK7e4ianh79pfhfTYQJOwGiFY4deGF\n"
    "4zOdR/V7w0l9FMeTLwiV5vsXPP9o5+rEwVH8K0wzD40uc7Crt8DdMRl8eXMrojoD\n"
    "iIRNZgSepDrnrzh4bkthZQAMkHnE1t+eSjt7+HktFwECgYEA5Sd64HM1lWtOzaGQ\n"
    "S+w0E18M0VXjdO1nbGbezV4mgT1u7PsA3PYZVQKJ72PhGNUqD+GuTh4E9Y/VYEz3\n"
    "uHBp6buhMAz8zboTNJQ0X5CFwSaNTaCa6UWucDRnImVxPxo+PPIZDgJ3PamlilDP\n"
    "n4rndFgHFae41C0OUjb8hxQ96bECgYEA3sGyviyA1AFnAVmE2ENJD11VT/tvdznf\n"
    "Tgl9VEaYKv1jYgxwENvupZOCOjLsHalaKGQp7peawhlWxBSMOIsyx0XSp/mvHXUt\n"
    "Y7kAX+zL0FY1fCZZYBuCtMQkT8kp+8Uz1LtTl0gK/HqMgCB0iVf4BqXF8MZV1tuF\n"
    "+jOJc3mDYvECgYEAizj+TamRb5N/kC1NpuL+DJreBb0B8YNfJ5wkV2+RQ0oYv8AM\n"
    "GTMn1t8xAJGVK+ouoPGDXhCdALh/cf+xLYyWvJvzZWcunKslifdVDo6WxO/wP66J\n"
    "D5r3TVJ5KoupTyZZk9ue30UePwd3/N32Fr9kuenVfBGnmLk7DzY7HLJunzECgYAj\n"
    "UYTcoEPA2YQSc7Ybb/eqhvra1pvixHtCbUDA1vyTfF+AkUZHdgeNmyi/v4kuXsab\n"
    "tt3rJYB1G/1k03k0EeX4MHrpBS6dthF/STrk+q+KFdEfIRl0oogDz0GOoO+WKrtA\n"
    "FH95cgPD6k5SllLD3/3EWA5dUaUUjvPcKsW1WGPbkQKBgBwinJcEwAVtXOI8d3sw\n"
    "WnJr36PE1DWH5BO03pWQ06VdkNUwaq1X8U4c6+TNIX9avsFGn/ibUarb1jGIBf8j\n"
    "0+YkUFp5po+y4k+x0G56hz5o2bGLj9hSTdrux9G0TpoBlbcmqFTATP8QRg5+oke9\n"
    "po46kGuM+jAQB9Htg+ydwA6X\n"
    "-----END PRIVATE KEY-----\n";

static char dhparams[] =
    "-----BEGIN DH PARAMETERS-----\n"
    "MIIBCAKCAQEAy1+hVWCfNQoPB+NA733IVOONl8fCumiz9zdRRu1hzVa2yvGseUSq\n"
    "Bbn6k0FQ7yMED6w5XWQKDC0z2m0FI/BPE3AjUfuPzEYGqTDf9zQZ2Lz4oAN90Sud\n"
    "luOoEhYR99cEbCn0T4eBvEf9IUtczXUZ/wj7gzGbGG07dLfT+CmCRJxCjhrosenJ\n"
    "gzucyS7jt1bobgU66JKkgMNm7hJY4/nhR5LWTCzZyzYQh2HM2Vk4K5ZqILpj/n0S\n"
    "5JYTQ2PVhxP+Uu8+hICs/8VvM72DznjPZzufADipjC7CsQ4S6x/ecZluFtbb+ZTv\n" "HI5CnYmkAwJ6+FSWGaZQDi8bgerFk9RWwwIBAg==\n" "-----END DH PARAMETERS-----\n";

#define MAX_KEY_LEN 32
#define MAX_VAL_LEN 255

struct session_cache_entry {
    uint8_t key[MAX_KEY_LEN];
    uint8_t key_len;
    uint8_t value[MAX_VAL_LEN];
    uint8_t value_len;
};

struct session_cache_entry session_cache[256];

int cache_store(void *ctx, uint64_t ttl, const void *key, uint64_t key_size, const void *value, uint64_t value_size)
{
    struct session_cache_entry *cache = ctx;

    if (key_size == 0 || key_size > MAX_KEY_LEN) {
        return -1;
    }
    if (value_size == 0 || value_size > MAX_VAL_LEN) {
        return -1;
    }

    uint8_t index = ((const uint8_t *)key)[0];

    memcpy(cache[index].key, key, key_size);
    memcpy(cache[index].value, value, value_size);

    cache[index].key_len = key_size;
    cache[index].value_len = value_size;

    return 0;
}

int cache_retrieve(void *ctx, const void *key, uint64_t key_size, void *value, uint64_t * value_size)
{
    struct session_cache_entry *cache = ctx;

    if (key_size == 0 || key_size > MAX_KEY_LEN) {
        return -1;
    }

    uint8_t index = ((const uint8_t *)key)[0];

    if (cache[index].key_len != key_size) {
        return -1;
    }

    if (memcmp(cache[index].key, key, key_size)) {
        return -1;
    }

    if (*value_size < cache[index].value_len) {
        return -1;
    }

    *value_size = cache[index].value_len;
    memcpy(value, cache[index].value, cache[index].value_len);

    printf("Resumed session ");
    for (int i = 0; i < key_size; i++) {
        printf("%02x", ((const uint8_t *)key)[i]);
    }
    printf("\n");

    return 0;
}

int cache_delete(void *ctx, const void *key, uint64_t key_size)
{
    struct session_cache_entry *cache = ctx;

    if (key_size == 0 || key_size > MAX_KEY_LEN) {
        return -1;
    }

    uint8_t index = ((const uint8_t *)key)[0];

    if (cache[index].key_len != key_size) {
        return -1;
    }

    if (memcmp(cache[index].key, key, key_size)) {
        return -1;
    }

    cache[index].key_len = 0;
    cache[index].value_len = 0;

    return 0;
}


extern int echo(struct s2n_connection *conn, int sockfd);
extern int negotiate(struct s2n_connection *conn);

void usage()
{
    fprintf(stderr, "usage: s2nd [options] host port\n");
    fprintf(stderr, " host: hostname or IP address to listen on\n");
    fprintf(stderr, " port: port to listen on\n");
    fprintf(stderr, "\n Options:\n\n");
    fprintf(stderr, "  -c [version_string]\n");
    fprintf(stderr, "  --ciphers [version_string]\n");
    fprintf(stderr, "    Set the cipher preference version string. Defaults to \"default\". See USAGE-GUIDE.md\n");
    fprintf(stderr, "  -n\n");
    fprintf(stderr, "  --negotiate\n");
    fprintf(stderr, "    Only perform tls handshake and then shutdown the connection\n");
    fprintf(stderr, "  --prefer-low-latency\n");
    fprintf(stderr, "    Prefer low latency by clamping maximum outgoing record size at 1500.");
    fprintf(stderr, "  --prefer-throughput\n");
    fprintf(stderr, "    Prefer throughput by raising maximum outgoing record size to 16k");
    fprintf(stderr, "  -h,--help\n");
    fprintf(stderr, "    Display this message and quit.\n");

    exit(1);
}

int main(int argc, char *const *argv)
{
    struct addrinfo hints, *ai;
    int r, sockfd = 0;

    /* required args */
    const char *host = NULL;
    const char *port = NULL;

    const char *cipher_prefs = "default";
    int only_negotiate = 0;
    int prefer_throughput = 0;
    int prefer_low_latency = 0;

    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"ciphers", required_argument, 0, 'c'},
        {"negotiate", no_argument, 0, 'n'},
        {"prefer-low-latency", no_argument, 0, 'l'},
        {"prefer-throughput", no_argument, 0, 'p'},
        /* Per getopt(3) the last element of the array has to be filled with all zeros */
        { 0 },
    };
    while (1) {
        int option_index = 0;
        int c = getopt_long(argc, argv, "c:hn", long_options, &option_index);
        if (c == -1) {
            break;
        }
        switch (c) {
        case 'c':
            cipher_prefs = optarg;
            break;
        case 'h':
            usage();
            break;
        case 'n':
            only_negotiate = 1;
            break;
        case 'l':
            prefer_low_latency = 1;
            break;
        case 'p':
            prefer_throughput = 1;
            break;
        case '?':
        default:
            usage();
            break;
        }
    }

    if (prefer_throughput && prefer_low_latency) {
        fprintf(stderr, "prefer-throughput and prefer-low-latency options are mutually exclusive\n");
        exit(1);
    }

    if (optind < argc) {
        host = argv[optind++];
    }
    if (optind < argc) {
        port = argv[optind++];
    }

    if (!host || !port) {
        usage();
    }

    if (setvbuf(stdin, NULL, _IONBF, 0) < 0) {
        fprintf(stderr, "Error disabling buffering for stdin\n");
        exit(1);
    }

    if (setvbuf(stdout, NULL, _IONBF, 0) < 0) {
        fprintf(stderr, "Error disabling buffering for stdout\n");
        exit(1);
    }

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        fprintf(stderr, "Error disabling SIGPIPE\n");
        exit(1);
    }

    if ((r = getaddrinfo(host, port, &hints, &ai)) < 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(r));
        exit(1);
    }

    if ((sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1) {
        fprintf(stderr, "socket error: %s\n", strerror(errno));
        exit(1);
    }

    r = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &r, sizeof(int)) < 0) {
        fprintf(stderr, "setsockopt error: %s\n", strerror(errno));
        exit(1);
    }

    if (bind(sockfd, ai->ai_addr, ai->ai_addrlen) < 0) {
        fprintf(stderr, "bind error: %s\n", strerror(errno));
        exit(1);
    }

    if (listen(sockfd, 1) == -1) {
        fprintf(stderr, "listen error: %s\n", strerror(errno));
        exit(1);
    }

    if (s2n_init() < 0) {
        fprintf(stderr, "Error running s2n_init(): '%s'\n", s2n_strerror(s2n_errno, "EN"));
    }

    printf("Listening on %s:%s\n", host, port);

    struct s2n_config *config = s2n_config_new();
    if (!config) {
        fprintf(stderr, "Error getting new s2n config: '%s'\n", s2n_strerror(s2n_errno, "EN"));
        exit(1);
    }

    if (s2n_config_add_cert_chain_and_key(config, certificate_chain, private_key) < 0) {
        fprintf(stderr, "Error getting certificate/key: '%s'\n", s2n_strerror(s2n_errno, "EN"));
        exit(1);
    }

    if (s2n_config_add_dhparams(config, dhparams) < 0) {
        fprintf(stderr, "Error adding DH parameters: '%s'\n", s2n_strerror(s2n_errno, "EN"));
        exit(1);
    }

    if (s2n_config_set_cipher_preferences(config, cipher_prefs) < 0) {
        fprintf(stderr, "Error setting cipher prefs: '%s'\n", s2n_strerror(s2n_errno, "EN"));
        exit(1);
    }

    if (s2n_config_set_cache_store_callback(config, cache_store, session_cache) < 0) {
        fprintf(stderr, "Error setting cache store callback: '%s'\n", s2n_strerror(s2n_errno, "EN"));
        exit(1);
    }

    if (s2n_config_set_cache_retrieve_callback(config, cache_retrieve, session_cache) < 0) {
        fprintf(stderr, "Error setting cache retrieve callback: '%s'\n", s2n_strerror(s2n_errno, "EN"));
        exit(1);
    }

    if (s2n_config_set_cache_delete_callback(config, cache_delete, session_cache) < 0) {
        fprintf(stderr, "Error setting cache retrieve callback: '%s'\n", s2n_strerror(s2n_errno, "EN"));
        exit(1);
    }

    struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
    if (!conn) {
        fprintf(stderr, "Error getting new s2n connection: '%s'\n", s2n_strerror(s2n_errno, "EN"));
        exit(1);
    }

    if (s2n_connection_set_config(conn, config) < 0) {
        fprintf(stderr, "Error setting configuration: '%s'\n", s2n_strerror(s2n_errno, "EN"));
        exit(1);
    }

    if (prefer_throughput && s2n_connection_prefer_throughput(conn) < 0) {
        fprintf(stderr, "Error setting prefer throughput: '%s'\n", s2n_strerror(s2n_errno, "EN"));
        exit(1);
    }

    if (prefer_low_latency && s2n_connection_prefer_low_latency(conn) < 0) {
        fprintf(stderr, "Error setting prefer low latency: '%s'\n", s2n_strerror(s2n_errno, "EN"));
        exit(1);
    }

    int fd;
    while ((fd = accept(sockfd, ai->ai_addr, &ai->ai_addrlen)) > 0) {
        if (s2n_connection_set_fd(conn, fd) < 0) {
            fprintf(stderr, "Error setting file descriptor: '%s'\n", s2n_strerror(s2n_errno, "EN"));
            exit(1);
        }

        negotiate(conn);

        if (!only_negotiate) {
            echo(conn, fd);
        }

        s2n_blocked_status blocked;
        s2n_shutdown(conn, &blocked);

        close(fd);

        if (s2n_connection_wipe(conn) < 0) {
            fprintf(stderr, "Error wiping connection: '%s'\n", s2n_strerror(s2n_errno, "EN"));
            exit(1);
        }
    }

    if (s2n_connection_free(conn) < 0) {
        fprintf(stderr, "Error freeing connection: '%s'\n", s2n_strerror(s2n_errno, "EN"));
        exit(1);
    }

    if (s2n_cleanup() < 0) {
        fprintf(stderr, "Error running s2n_cleanup(): '%s'\n", s2n_strerror(s2n_errno, "EN"));
    }

    return 0;
}
