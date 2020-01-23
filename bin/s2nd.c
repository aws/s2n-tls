/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <poll.h>
#include <netdb.h>

#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <getopt.h>

#include <errno.h>

#include <error/s2n_errno.h>

#include <openssl/crypto.h>
#include <openssl/err.h>

#include <s2n.h>
#include "common.h"

#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

#define MAX_CERTIFICATES 50

static char default_certificate_chain[] =
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

static char default_private_key[] =
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
    "5JYTQ2PVhxP+Uu8+hICs/8VvM72DznjPZzufADipjC7CsQ4S6x/ecZluFtbb+ZTv\n"
    "HI5CnYmkAwJ6+FSWGaZQDi8bgerFk9RWwwIBAg==\n"
    "-----END DH PARAMETERS-----\n";

uint8_t ticket_key_name[16] = "2016.07.26.15\0";

uint8_t default_ticket_key[32] = {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc,
                                  0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b,
                                  0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2,
                                  0xb3, 0xe5 };

#define MAX_KEY_LEN 32
#define MAX_VAL_LEN 255

struct session_cache_entry {
    uint8_t key[MAX_KEY_LEN];
    uint8_t key_len;
    uint8_t value[MAX_VAL_LEN];
    uint8_t value_len;
};

struct session_cache_entry session_cache[256];

int cache_store_callback(struct s2n_connection *conn, void *ctx, uint64_t ttl, const void *key, uint64_t key_size, const void *value, uint64_t value_size)
{
    struct session_cache_entry *cache = ctx;

    S2N_ERROR_IF(key_size == 0 || key_size > MAX_KEY_LEN, S2N_ERR_INVALID_ARGUMENT);
    S2N_ERROR_IF(value_size == 0 || value_size > MAX_VAL_LEN, S2N_ERR_INVALID_ARGUMENT);

    uint8_t index = ((const uint8_t *)key)[0];

    memcpy(cache[index].key, key, key_size);
    memcpy(cache[index].value, value, value_size);

    cache[index].key_len = key_size;
    cache[index].value_len = value_size;

    return 0;
}

int cache_retrieve_callback(struct s2n_connection *conn, void *ctx, const void *key, uint64_t key_size, void *value, uint64_t * value_size)
{
    struct session_cache_entry *cache = ctx;

    S2N_ERROR_IF(key_size == 0 || key_size > MAX_KEY_LEN, S2N_ERR_INVALID_ARGUMENT);

    uint8_t index = ((const uint8_t *)key)[0];

    S2N_ERROR_IF(cache[index].key_len != key_size, S2N_ERR_INVALID_ARGUMENT);
    S2N_ERROR_IF(memcmp(cache[index].key, key, key_size), S2N_ERR_INVALID_ARGUMENT);
    S2N_ERROR_IF(*value_size < cache[index].value_len, S2N_ERR_INVALID_ARGUMENT);

    *value_size = cache[index].value_len;
    memcpy(value, cache[index].value, cache[index].value_len);

    for (int i = 0; i < key_size; i++) {
        printf("%02x", ((const uint8_t *)key)[i]);
    }
    printf("\n");

    return 0;
}

int cache_delete_callback(struct s2n_connection *conn, void *ctx, const void *key, uint64_t key_size)
{
    struct session_cache_entry *cache = ctx;

    S2N_ERROR_IF(key_size == 0 || key_size > MAX_KEY_LEN, S2N_ERR_INVALID_ARGUMENT);

    uint8_t index = ((const uint8_t *)key)[0];

    S2N_ERROR_IF(cache[index].key_len != key_size, S2N_ERR_INVALID_ARGUMENT);
    S2N_ERROR_IF(memcmp(cache[index].key, key, key_size), S2N_ERR_INVALID_ARGUMENT);

    cache[index].key_len = 0;
    cache[index].value_len = 0;

    return 0;
}

/*
 * Since this is a server, and the mechanism for hostname verification is not defined for this use-case,
 * allow any hostname through. If you are writing something with mutual auth and you have a scheme for verifying
 * the client (e.g. a reverse DNS lookup), you would plug that in here.
 */
static uint8_t unsafe_verify_host_fn(const char *host_name, size_t host_name_len, void *data)
{
    return 1;
}

extern void print_s2n_error(const char *app_error);
extern int echo(struct s2n_connection *conn, int sockfd);
extern int negotiate(struct s2n_connection *conn);

/* Caller is expected to free the memory returned. */
static char *load_file_to_cstring(const char *path)
{
    FILE *pem_file = fopen(path, "rb");
    if (!pem_file) {
       fprintf(stderr, "Failed to open file %s: '%s'\n", path, strerror(errno));
       return NULL;
    }

    /* Make sure we can fit the pem into the output buffer */
    if (fseek(pem_file, 0, SEEK_END) < 0) {
        fprintf(stderr, "Failed calling fseek: '%s'\n", strerror(errno));
        fclose(pem_file);
        return NULL;
    }

    const long int pem_file_size = ftell(pem_file);
    if (pem_file_size < 0) {
        fprintf(stderr, "Failed calling ftell: '%s'\n", strerror(errno));
        fclose(pem_file);
        return NULL;
    }

    rewind(pem_file);

    char *pem_out = malloc(pem_file_size + 1);
    if (pem_out == NULL) {
        fprintf(stderr, "Failed allocating memory\n");
        fclose(pem_file);
        return NULL;
    }

    if (fread(pem_out, sizeof(char), pem_file_size, pem_file) < pem_file_size) {
        fprintf(stderr, "Failed reading file: '%s'\n", strerror(errno));
        free(pem_out);
        fclose(pem_file);
        return NULL;
    }

    pem_out[pem_file_size] = '\0';
    fclose(pem_file);

    return pem_out;
}

void usage()
{
    fprintf(stderr, "usage: s2nd [options] host port\n");
    fprintf(stderr, " host: hostname or IP address to listen on\n");
    fprintf(stderr, " port: port to listen on\n");
    fprintf(stderr, "\n Options:\n\n");
    fprintf(stderr, "  -c [version_string]\n");
    fprintf(stderr, "  --ciphers [version_string]\n");
    fprintf(stderr, "    Set the cipher preference version string. Defaults to \"default\". See USAGE-GUIDE.md\n");
    fprintf(stderr, "  --enter-fips-mode\n");
    fprintf(stderr, "    Enter libcrypto's FIPS mode. The linked version of OpenSSL must be built with the FIPS module.\n");
    fprintf(stderr, "  --cert\n");
    fprintf(stderr, "    Path to a PEM encoded certificate [chain]. Option can be repeated to load multiple certs.\n");
    fprintf(stderr, "  --key\n");
    fprintf(stderr, "    Path to a PEM encoded private key that matches cert. Option can be repeated to load multiple certs.\n");
    fprintf(stderr, "  -m\n");
    fprintf(stderr, "  --mutualAuth\n");
    fprintf(stderr, "    Request a Client Certificate. Any RSA Certificate will be accepted.\n");
    fprintf(stderr, "  -n\n");
    fprintf(stderr, "  --negotiate\n");
    fprintf(stderr, "    Only perform tls handshake and then shutdown the connection\n");
    fprintf(stderr, "  --parallelize\n");
    fprintf(stderr, "    Create a new Connection handler thread for each new connection. Useful for tests with lots of connections.\n");
    fprintf(stderr, "    Warning: this option isn't compatible with TLS Resumption, since each thread gets its own Session cache.\n");
    fprintf(stderr, "  --prefer-low-latency\n");
    fprintf(stderr, "    Prefer low latency by clamping maximum outgoing record size at 1500.\n");
    fprintf(stderr, "  --prefer-throughput\n");
    fprintf(stderr, "    Prefer throughput by raising maximum outgoing record size to 16k\n");
    fprintf(stderr, "  --enable-mfl\n");
    fprintf(stderr, "    Accept client's TLS maximum fragment length extension request\n");
    fprintf(stderr, "  --ocsp\n");
    fprintf(stderr, "    Path to a DER formatted OCSP response for stapling\n");
    fprintf(stderr, "  -s\n");
    fprintf(stderr, "  --self-service-blinding\n");
    fprintf(stderr, "    Don't introduce 10-30 second delays on TLS Handshake errors. \n");
    fprintf(stderr, "    Warning: this should only be used for testing since skipping blinding may allow timing side channels.\n");
    fprintf(stderr, "  -t,--ca-file [file path]\n");
    fprintf(stderr, "    Location of trust store CA file (PEM format). If neither -t or -d are specified. System defaults will be used.");
    fprintf(stderr, "    This option is only used if mutual auth is enabled.\n");
    fprintf(stderr, "  -d,--ca-dir [directory path]\n");
    fprintf(stderr, "    Directory containing hashed trusted certs. If neither -t or -d are specified. System defaults will be used.");
    fprintf(stderr, "    This option is only used if mutual auth is enabled.\n");
    fprintf(stderr, "  -i,--insecure\n");
    fprintf(stderr, "    Turns off certification validation altogether.\n");
    fprintf(stderr, "  --stk-file\n");
    fprintf(stderr, "    Location of key file used for encryption and decryption of session ticket.\n");
    fprintf(stderr, "  -T,--no-session-ticket\n");
    fprintf(stderr, "    Disable session ticket for resumption.\n");
    fprintf(stderr, "  -C,--corked-io\n");
    fprintf(stderr, "    Turn on corked io\n");
    if (S2N_IN_TEST) {
        fprintf(stderr, "  --tls13\n");
        fprintf(stderr, "    Turn on experimental TLS1.3 support for testing.");
    }
    fprintf(stderr, "  -h,--help\n");
    fprintf(stderr, "    Display this message and quit.\n");

    exit(1);
}


struct conn_settings {
    int mutual_auth;
    int self_service_blinding;
    int only_negotiate;
    int prefer_throughput;
    int prefer_low_latency;
    int enable_mfl;
    int session_ticket;
    const char *ca_dir;
    const char *ca_file;
    int insecure;
    int use_corked_io;
};

int handle_connection(int fd, struct s2n_config *config, struct conn_settings settings)
{
    struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
    if (!conn) {
        print_s2n_error("Error getting new s2n connection");
        S2N_ERROR_PRESERVE_ERRNO();
    }

    if (settings.self_service_blinding) {
        s2n_connection_set_blinding(conn, S2N_SELF_SERVICE_BLINDING);
    }

    if (settings.mutual_auth) {
        GUARD_RETURN(s2n_config_set_client_auth_type(config, S2N_CERT_AUTH_REQUIRED), "Error setting client auth type");

        if (settings.ca_dir || settings.ca_file) {
            GUARD_RETURN(s2n_config_set_verification_ca_location(config, settings.ca_file, settings.ca_dir), "Error adding verify location");
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

    negotiate(conn);

    if (settings.mutual_auth) {
        if (!s2n_connection_client_cert_used(conn)) {
            print_s2n_error("Error: Mutual Auth was required, but not negotiated");
            S2N_ERROR_PRESERVE_ERRNO();
        }
    }

    if (!settings.only_negotiate) {
        echo(conn, fd);
    }

    s2n_blocked_status blocked;
    s2n_shutdown(conn, &blocked);

    GUARD_RETURN(s2n_connection_wipe(conn), "Error wiping connection");

    GUARD_RETURN(s2n_connection_free(conn), "Error freeing connection");

    return 0;
}

int main(int argc, char *const *argv)
{
    struct addrinfo hints, *ai;
    int r, sockfd = 0;

    /* required args */
    const char *host = NULL;
    const char *port = NULL;

    const char *ocsp_response_file_path = NULL;
    const char *session_ticket_key_file_path = NULL;
    const char *cipher_prefs = "default";

    /* The certificates provided by the user. If there are none provided, we will use the hardcoded default cert.
     * The associated private key for each cert will be at the same index in private_keys. If the user mixes up the
     * order of --cert --key for a given cert/key pair, s2n will fail to load the cert and s2nd will exit.
     */
    int num_user_certificates = 0;
    int num_user_private_keys = 0;
    const char *certificates[MAX_CERTIFICATES] = { 0 };
    const char *private_keys[MAX_CERTIFICATES] = { 0 };

    struct conn_settings conn_settings = { 0 };
    int fips_mode = 0;
    int parallelize = 0;
    int use_tls13 = 0;
    conn_settings.session_ticket = 1;

    struct option long_options[] = {
        {"ciphers", required_argument, NULL, 'c'},
        {"enable-mfl", no_argument, NULL, 'e'},
        {"enter-fips-mode", no_argument, NULL, 'f'},
        {"help", no_argument, NULL, 'h'},
        {"key", required_argument, NULL, 'k'},
        {"prefer-low-latency", no_argument, NULL, 'l'},
        {"mutualAuth", no_argument, NULL, 'm'},
        {"negotiate", no_argument, NULL, 'n'},
        {"ocsp", required_argument, NULL, 'o'},
        {"parallelize", no_argument, &parallelize, 1},
        {"prefer-throughput", no_argument, NULL, 'p'},
        {"cert", required_argument, NULL, 'r'},
        {"self-service-blinding", no_argument, NULL, 's'},
        {"ca-dir", required_argument, 0, 'd'},
        {"ca-file", required_argument, 0, 't'},
        {"insecure", no_argument, 0, 'i'},
        {"stk-file", required_argument, 0, 'a'},
        {"no-session-ticket", no_argument, 0, 'T'},
        {"corked-io", no_argument, 0, 'C'},
        {"tls13", no_argument, 0, '3'},
        /* Per getopt(3) the last element of the array has to be filled with all zeros */
        { 0 },
    };
    while (1) {
        int option_index = 0;
        int c = getopt_long(argc, argv, "c:hmnst:d:iTC", long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 0:
            /* getopt_long() returns 0 if an option.flag is non-null (Eg "parallelize") */
            break;
        case 'C':
            conn_settings.use_corked_io = 1;
            break;
        case 'c':
            cipher_prefs = optarg;
            break;
        case 'e':
            conn_settings.enable_mfl = 1;
            break;
        case 'f':
            fips_mode = 1;
            break;
        case 'h':
            usage();
            break;
        case 'k':
            if (num_user_private_keys == MAX_CERTIFICATES) {
                fprintf(stderr, "Cannot support more than %d certificates!\n", MAX_CERTIFICATES);
                exit(1);
            }
            private_keys[num_user_private_keys] = load_file_to_cstring(optarg);
            num_user_private_keys++;
            break;
        case 'l':
            conn_settings.prefer_low_latency = 1;
            break;
        case 'm':
            conn_settings.mutual_auth = 1;
            break;
        case 'n':
            conn_settings.only_negotiate = 1;
            break;
        case 'o':
            ocsp_response_file_path = optarg;
            break;
        case 'p':
            conn_settings.prefer_throughput = 1;
            break;
        case 'r':
            if (num_user_certificates == MAX_CERTIFICATES) {
                fprintf(stderr, "Cannot support more than %d certificates!\n", MAX_CERTIFICATES);
                exit(1);
            }
            certificates[num_user_certificates] = load_file_to_cstring(optarg);
            num_user_certificates++;
            break;
        case 's':
            conn_settings.self_service_blinding = 1;
            break;
        case 'd':
            conn_settings.ca_dir = optarg;
            break;
        case 't':
            conn_settings.ca_file = optarg;
            break;
        case 'i':
            conn_settings.insecure = 1;
            break;
        case 'a':
            session_ticket_key_file_path = optarg;
            break;
        case 'T':
            conn_settings.session_ticket = 0;
            break;
        case '3':
            use_tls13 = 1;
            break;
        case '?':
        default:
            fprintf(stdout, "getopt_long returned: %d", c);
            usage();
            break;
        }
    }

    if (conn_settings.prefer_throughput && conn_settings.prefer_low_latency) {
        fprintf(stderr, "prefer-throughput and prefer-low-latency options are mutually exclusive\n");
        exit(1);
    }

    if (optind < argc) {
        host = argv[optind++];
    }

    /* cppcheck-suppress duplicateCondition */
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

    if (fips_mode) {
#ifdef OPENSSL_FIPS
        if (FIPS_mode_set(1) == 0) {
            unsigned long fips_rc = ERR_get_error();
            char ssl_error_buf[256]; /* Openssl claims you need no more than 120 bytes for error strings */
            fprintf(stderr, "s2nd failed to enter FIPS mode with RC: %lu; String: %s\n", fips_rc, ERR_error_string(fips_rc, ssl_error_buf));
            exit(1);
        }
        printf("s2nd entered FIPS mode\n");
#else
        fprintf(stderr, "Error entering FIPS mode. s2nd is not linked with a FIPS-capable libcrypto.\n");
        exit(1);
#endif
    }

    if (use_tls13 && S2N_IN_TEST) {
        GUARD_EXIT(s2n_enable_tls13(), "Error enabling TLS1.3");
    }

    GUARD_EXIT(s2n_init(), "Error running s2n_init()");

    printf("Listening on %s:%s\n", host, port);

    struct s2n_config *config = s2n_config_new();
    if (!config) {
        print_s2n_error("Error getting new s2n config");
        exit(1);
    }

    if (num_user_certificates != num_user_private_keys) {
        fprintf(stderr, "Mismatched certificate(%d) and private key(%d) count!\n", num_user_certificates, num_user_private_keys);
        exit(1);
    }

    int num_certificates = 0;
    if (num_user_certificates == 0) {
        certificates[0] = default_certificate_chain;
        private_keys[0] = default_private_key;
        num_certificates = 1;
    } else {
        num_certificates = num_user_certificates;
    }

    for (int i = 0; i < num_certificates; i++) {
        struct s2n_cert_chain_and_key *chain_and_key = s2n_cert_chain_and_key_new();
        GUARD_EXIT(s2n_cert_chain_and_key_load_pem(chain_and_key, certificates[i], private_keys[i]), "Error getting certificate/key");

        GUARD_EXIT(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key), "Error setting certificate/key");
    }

    if (ocsp_response_file_path) {
        int fd = open(ocsp_response_file_path, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "Error opening OCSP response file: '%s'\n", strerror(errno));
            exit(1);
        }

        struct stat st = {0};
        if (fstat(fd, &st) < 0) {
            fprintf(stderr, "Error fstat-ing OCSP response file: '%s'\n", strerror(errno));
            exit(1);
        }

        uint8_t *ocsp_response = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (s2n_config_set_extension_data(config, S2N_EXTENSION_OCSP_STAPLING, ocsp_response, st.st_size) < 0) {
            fprintf(stderr, "Error adding ocsp response: '%s'\n", s2n_strerror(s2n_errno, "EN"));
            exit(1);
        }

        close(fd);
    }

    GUARD_EXIT(s2n_config_add_dhparams(config, dhparams), "Error adding DH parameters");

    GUARD_EXIT(s2n_config_set_cipher_preferences(config, cipher_prefs),"Error setting cipher prefs");

    GUARD_EXIT(s2n_config_set_cache_store_callback(config, cache_store_callback, session_cache), "Error setting cache store callback");

    GUARD_EXIT(s2n_config_set_cache_retrieve_callback(config, cache_retrieve_callback, session_cache), "Error setting cache retrieve callback");

    GUARD_EXIT(s2n_config_set_cache_delete_callback(config, cache_delete_callback, session_cache), "Error setting cache retrieve callback");

    if (conn_settings.enable_mfl) {
        GUARD_EXIT(s2n_config_accept_max_fragment_length(config), "Error enabling TLS maximum fragment length extension in server");
    }

    if (s2n_config_set_verify_host_callback(config, unsafe_verify_host_fn, NULL)) {
        print_s2n_error("Failure to set hostname verification callback");
        exit(1);
    }

    if (conn_settings.session_ticket) {
        GUARD_EXIT(s2n_config_set_session_tickets_onoff(config, 1), "Error enabling session tickets");

        /* Key initialization */
        uint8_t *st_key;
        uint32_t st_key_length;

        if (session_ticket_key_file_path) {
            int fd = open(session_ticket_key_file_path, O_RDONLY);
            GUARD_EXIT(fd, "Error opening session ticket key file");

            struct stat st;
            GUARD_EXIT(fstat(fd, &st), "Error fstat-ing session ticket key file");

            st_key = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
            S2N_ERROR_IF(st_key == MAP_FAILED, S2N_ERR_MMAP);

            st_key_length = st.st_size;

            close(fd);
        } else {
            st_key = default_ticket_key;
            st_key_length = sizeof(default_ticket_key);
        }

        if (s2n_config_add_ticket_crypto_key(config, ticket_key_name, strlen((char *) ticket_key_name), st_key, st_key_length, 0) != 0) {
            fprintf(stderr, "Error adding ticket key: '%s'\n", s2n_strerror(s2n_errno, "EN"));
            exit(1);
        }
    }

    if (parallelize) {
        struct sigaction sa;

        sa.sa_handler = SIG_IGN;
        sa.sa_flags = SA_NOCLDWAIT;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGCHLD, &sa, NULL);
    }

    int fd;
    while ((fd = accept(sockfd, ai->ai_addr, &ai->ai_addrlen)) > 0) {

        if (!parallelize) {
            int rc = handle_connection(fd, config, conn_settings);
            close(fd);
            if (rc < 0) {
                exit(rc);
            }
        } else {
            /* Fork Process, one for the Acceptor (parent), and another for the Handler (child). */
            pid_t child_pid = fork();

            if (child_pid == 0) {
                /* This is the Child Handler Thread. We should handle the connection, then exit. */
                int rc = handle_connection(fd, config, conn_settings);
                close(fd);
                _exit(rc);
            } else if (child_pid == -1) {
                close(fd);
                print_s2n_error("Error calling fork(). Acceptor unable to start handler.");
                exit(1);
            } else {
                /* This is the parent Acceptor Thread, continue listening for new connections */
                close(fd);
                continue;
            }
        }

    }

    GUARD_EXIT(s2n_cleanup(),  "Error running s2n_cleanup()");

    return 0;
}
