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

#include "common.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "api/s2n.h"
#include "error/s2n_errno.h"
#include "utils/s2n_safety.h"
uint8_t ticket_key_name[16] = "2016.07.26.15\0";

uint8_t default_ticket_key[32] = { 0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc,
    0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b,
    0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2,
    0xb3, 0xe5 };

struct session_cache_entry session_cache[256];

static char dhparams[] =
        "-----BEGIN DH PARAMETERS-----\n"
        "MIIBCAKCAQEAy1+hVWCfNQoPB+NA733IVOONl8fCumiz9zdRRu1hzVa2yvGseUSq\n"
        "Bbn6k0FQ7yMED6w5XWQKDC0z2m0FI/BPE3AjUfuPzEYGqTDf9zQZ2Lz4oAN90Sud\n"
        "luOoEhYR99cEbCn0T4eBvEf9IUtczXUZ/wj7gzGbGG07dLfT+CmCRJxCjhrosenJ\n"
        "gzucyS7jt1bobgU66JKkgMNm7hJY4/nhR5LWTCzZyzYQh2HM2Vk4K5ZqILpj/n0S\n"
        "5JYTQ2PVhxP+Uu8+hICs/8VvM72DznjPZzufADipjC7CsQ4S6x/ecZluFtbb+ZTv\n"
        "HI5CnYmkAwJ6+FSWGaZQDi8bgerFk9RWwwIBAg==\n"
        "-----END DH PARAMETERS-----\n";

/*
 * Since this is a server, and the mechanism for hostname verification is not defined for this use-case,
 * allow any hostname through. If you are writing something with mutual auth and you have a scheme for verifying
 * the client (e.g. a reverse DNS lookup), you would plug that in here.
 */
static uint8_t unsafe_verify_host_fn(const char *host_name, size_t host_name_len, void *data)
{
    return 1;
}

int write_array_to_file(const char *path, uint8_t *data, size_t length)
{
    GUARD_EXIT_NULL(path);
    GUARD_EXIT_NULL(data);

    FILE *file = fopen(path, "wb");
    if (!file) {
        return S2N_FAILURE;
    }

    if (fwrite(data, sizeof(char), length, file) != length) {
        fclose(file);
        return S2N_FAILURE;
    }
    fclose(file);

    return S2N_SUCCESS;
}

int get_file_size(const char *path, size_t *length)
{
    GUARD_EXIT_NULL(path);
    GUARD_EXIT_NULL(length);

    FILE *file = fopen(path, "rb");
    if (!file) {
        return S2N_FAILURE;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return S2N_FAILURE;
    }

    long file_length = ftell(file);
    if (file_length < 0) {
        fclose(file);
        return S2N_FAILURE;
    }

    *length = file_length;
    fclose(file);
    return S2N_SUCCESS;
}

int load_file_to_array(const char *path, uint8_t *data, size_t max_length)
{
    GUARD_EXIT_NULL(path);
    GUARD_EXIT_NULL(data);

    size_t file_size = 0;
    if (get_file_size(path, &file_size) < 0 || file_size > max_length) {
        return S2N_FAILURE;
    }

    FILE *file = fopen(path, "rb");
    if (!file) {
        return S2N_FAILURE;
    }

    if (fread(data, sizeof(char), file_size, file) < file_size) {
        fclose(file);
        return S2N_FAILURE;
    }

    fclose(file);
    return S2N_SUCCESS;
}

char *load_file_to_cstring(const char *path)
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

    const ssize_t pem_file_size = ftell(pem_file);
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

    if (fread(pem_out, sizeof(char), pem_file_size, pem_file) < (size_t) pem_file_size) {
        fprintf(stderr, "Failed reading file: '%s'\n", strerror(errno));
        free(pem_out);
        fclose(pem_file);
        return NULL;
    }

    pem_out[pem_file_size] = '\0';
    fclose(pem_file);

    return pem_out;
}

int key_log_callback(void *file, struct s2n_connection *conn, uint8_t *logline, size_t len)
{
    if (fwrite(logline, 1, len, (FILE *) file) != len) {
        return S2N_FAILURE;
    }

    if (fprintf((FILE *) file, "\n") < 0) {
        return S2N_FAILURE;
    }

    return fflush((FILE *) file);
}

/* An inverse map from an ascii value to a hexadecimal nibble value
 * accounts for all possible char values, where 255 is invalid value */
static const uint8_t hex_inverse[256] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255, 255, 255, 255,
    255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 10, 11, 12, 13, 14, 15, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
};

int s2n_str_hex_to_bytes(const unsigned char *hex, uint8_t *out_bytes, uint32_t max_out_bytes_len)
{
    GUARD_EXIT_NULL(hex);
    GUARD_EXIT_NULL(out_bytes);

    uint32_t len_with_spaces = strlen((const char *) hex);
    size_t i = 0, j = 0;
    while (j < len_with_spaces) {
        if (hex[j] == ' ') {
            j++;
            continue;
        }

        uint8_t high_nibble = hex_inverse[hex[j]];
        if (high_nibble == 255) {
            fprintf(stderr, "Invalid HEX encountered\n");
            return S2N_FAILURE;
        }

        uint8_t low_nibble = hex_inverse[hex[j + 1]];
        if (low_nibble == 255) {
            fprintf(stderr, "Invalid HEX encountered\n");
            return S2N_FAILURE;
        }

        if (max_out_bytes_len < i) {
            fprintf(stderr, "Insufficient memory for bytes buffer, try increasing the allocation size\n");
            return S2N_FAILURE;
        }
        out_bytes[i] = high_nibble << 4 | low_nibble;

        i++;
        j += 2;
    }

    return S2N_SUCCESS;
}

static int s2n_get_psk_hmac_alg(s2n_psk_hmac *psk_hmac, char *hmac_str)
{
    GUARD_EXIT_NULL(psk_hmac);
    GUARD_EXIT_NULL(hmac_str);

    if (strcmp(hmac_str, "SHA256") == 0) {
        *psk_hmac = S2N_PSK_HMAC_SHA256;
    } else if (strcmp(hmac_str, "SHA384") == 0) {
        *psk_hmac = S2N_PSK_HMAC_SHA384;
    } else {
        return S2N_FAILURE;
    }
    return S2N_SUCCESS;
}

static int s2n_setup_external_psk(struct s2n_psk **psk, char *params)
{
    GUARD_EXIT_NULL(psk);
    GUARD_EXIT_NULL(params);

    /* duplicate params as strtok will modify the input string */
    char *params_dup = malloc(strlen(params) + 1);
    GUARD_EXIT_NULL(params_dup);
    strcpy(params_dup, params);

    size_t token_idx = 0;
    for (char *token = strtok(params_dup, ","); token != NULL; token = strtok(NULL, ","), token_idx++) {
        switch (token_idx) {
            case 0:
                GUARD_EXIT(s2n_psk_set_identity(*psk, (const uint8_t *) token, strlen(token)),
                        "Error setting psk identity\n");
                break;
            case 1: {
                uint32_t max_secret_len = strlen(token) / 2;
                uint8_t *secret = malloc(max_secret_len);
                GUARD_EXIT_NULL(secret);
                GUARD_EXIT(s2n_str_hex_to_bytes((const unsigned char *) token, secret, max_secret_len), "Error converting hex-encoded psk secret to bytes\n");
                GUARD_EXIT(s2n_psk_set_secret(*psk, secret, max_secret_len), "Error setting psk secret\n");
                free(secret);
            } break;
            case 2: {
                s2n_psk_hmac psk_hmac_alg = 0;
                GUARD_EXIT(s2n_get_psk_hmac_alg(&psk_hmac_alg, token), "Invalid psk hmac algorithm\n");
                GUARD_EXIT(s2n_psk_set_hmac(*psk, psk_hmac_alg), "Error setting psk hmac algorithm\n");
            } break;
            default:
                break;
        }
    }

    free(params_dup);
    return S2N_SUCCESS;
}

int s2n_setup_external_psk_list(struct s2n_connection *conn, char *psk_optarg_list[S2N_MAX_PSK_LIST_LENGTH], size_t psk_list_len)
{
    GUARD_EXIT_NULL(conn);
    GUARD_EXIT_NULL(psk_optarg_list);

    for (size_t i = 0; i < psk_list_len; i++) {
        struct s2n_psk *psk = s2n_external_psk_new();
        GUARD_EXIT_NULL(psk);
        GUARD_EXIT(s2n_setup_external_psk(&psk, psk_optarg_list[i]), "Error setting external PSK parameters\n");
        GUARD_EXIT(s2n_connection_append_psk(conn, psk), "Error appending psk to the connection\n");
        GUARD_EXIT(s2n_psk_free(&psk), "Error freeing psk\n");
    }
    return S2N_SUCCESS;
}

int s2n_set_common_server_config(int max_early_data, struct s2n_config *config, struct conn_settings conn_settings, const char *cipher_prefs, const char *session_ticket_key_file_path)
{
    GUARD_EXIT(s2n_config_set_server_max_early_data_size(config, max_early_data), "Error setting max early data");

    GUARD_EXIT(s2n_config_add_dhparams(config, dhparams), "Error adding DH parameters");

    GUARD_EXIT(s2n_config_set_cipher_preferences(config, cipher_prefs), "Error setting cipher prefs");

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
    }

    if (conn_settings.session_cache) {
        GUARD_EXIT(s2n_config_set_session_cache_onoff(config, 1), "Error enabling session cache using id");
    }

    if (conn_settings.session_ticket || conn_settings.session_cache) {
        /* Key initialization */
        uint8_t *st_key = NULL;
        uint32_t st_key_length = 0;

        if (session_ticket_key_file_path) {
            int fd = open(session_ticket_key_file_path, O_RDONLY);
            GUARD_EXIT(fd, "Error opening session ticket key file");

            struct stat st;
            GUARD_EXIT(fstat(fd, &st), "Error fstat-ing session ticket key file");

            st_key = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
            POSIX_ENSURE(st_key != MAP_FAILED, S2N_ERR_MMAP);

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
    return 0;
}

int s2n_setup_server_connection(struct s2n_connection *conn, int fd, struct s2n_config *config, struct conn_settings settings)
{
    if (settings.deserialize_in) {
        GUARD_RETURN(s2n_connection_deserialize_in(conn, settings.deserialize_in), "Failed to deserialize file");
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

    GUARD_RETURN(
            s2n_setup_external_psk_list(conn, settings.psk_optarg_list, settings.psk_list_len),
            "Error setting external psk list");

    GUARD_RETURN(early_data_recv(conn), "Error receiving early data");
    return 0;
}

int cache_store_callback(struct s2n_connection *conn, void *ctx, uint64_t ttl, const void *key, uint64_t key_size, const void *value, uint64_t value_size)
{
    struct session_cache_entry *cache = ctx;

    POSIX_ENSURE_INCLUSIVE_RANGE(1, key_size, MAX_KEY_LEN);
    POSIX_ENSURE_INCLUSIVE_RANGE(1, value_size, MAX_VAL_LEN);

    uint8_t idx = ((const uint8_t *) key)[0];

    memmove(cache[idx].key, key, key_size);
    memmove(cache[idx].value, value, value_size);

    cache[idx].key_len = key_size;
    cache[idx].value_len = value_size;

    return 0;
}

int cache_retrieve_callback(struct s2n_connection *conn, void *ctx, const void *key, uint64_t key_size, void *value, uint64_t *value_size)
{
    struct session_cache_entry *cache = ctx;

    POSIX_ENSURE_INCLUSIVE_RANGE(1, key_size, MAX_KEY_LEN);

    uint8_t idx = ((const uint8_t *) key)[0];

    POSIX_ENSURE(cache[idx].key_len == key_size, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(memcmp(cache[idx].key, key, key_size) == 0, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(*value_size >= cache[idx].value_len, S2N_ERR_INVALID_ARGUMENT);

    *value_size = cache[idx].value_len;
    memmove(value, cache[idx].value, cache[idx].value_len);

    for (uint64_t i = 0; i < key_size; i++) {
        printf("%02x", ((const uint8_t *) key)[i]);
    }
    printf("\n");

    return 0;
}

int cache_delete_callback(struct s2n_connection *conn, void *ctx, const void *key, uint64_t key_size)
{
    struct session_cache_entry *cache = ctx;

    POSIX_ENSURE_INCLUSIVE_RANGE(1, key_size, MAX_KEY_LEN);

    uint8_t idx = ((const uint8_t *) key)[0];

    if (cache[idx].key_len != 0) {
        POSIX_ENSURE(cache[idx].key_len == key_size, S2N_ERR_INVALID_ARGUMENT);
        POSIX_ENSURE(memcmp(cache[idx].key, key, key_size) == 0, S2N_ERR_INVALID_ARGUMENT);
    }

    cache[idx].key_len = 0;
    cache[idx].value_len = 0;

    return 0;
}

uint8_t unsafe_verify_host(const char *host_name, size_t host_name_len, void *data)
{
    struct verify_data *verify_data = (struct verify_data *) data;

    if (host_name_len > 2 && host_name[0] == '*' && host_name[1] == '.') {
        char *suffix = strstr(verify_data->trusted_host, ".");
        return (uint8_t) (strcasecmp(suffix, host_name + 1) == 0);
    }

    if (strcasecmp(host_name, "localhost") == 0 || strcasecmp(host_name, "127.0.0.1") == 0) {
        return (uint8_t) (strcasecmp(verify_data->trusted_host, "localhost") == 0
                || strcasecmp(verify_data->trusted_host, "127.0.0.1") == 0);
    }

    return (uint8_t) (strcasecmp(host_name, verify_data->trusted_host) == 0);
}

int wait_for_shutdown(struct s2n_connection *conn, int fd)
{
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    while (s2n_shutdown(conn, &blocked) != S2N_SUCCESS) {
        int errno_val = errno;
        switch (s2n_error_get_type(s2n_errno)) {
            case S2N_ERR_T_BLOCKED:
                GUARD_RETURN(wait_for_event(fd, blocked), "Error polling IO for shutdown");
                break;
            case S2N_ERR_T_CLOSED:
                /* We can't control the behavior of our peer. If the peer indicates end-of-stream
                 * without sending a close_notify, don't treat it as an error, but print a warning.
                 *
                 * This is common in our integration tests both because OpenSSL s_server
                 * never sends a close_notify (see https://github.com/openssl/openssl/issues/1806)
                 * and because we tend to kill processes rather than waiting for a graceful shutdown.
                 */
                fprintf(stdout, "Connection closed by peer\n");
                return S2N_SUCCESS;
            case S2N_ERR_T_IO:
                /* Again, we can't control the behavior of our peer, so just print a warning.
                 * Killing a process can result in its peer receiving a ECONNRESET.
                 */
                if (errno_val == ECONNRESET) {
                    fprintf(stdout, "Connection reset by peer\n");
                    return S2N_SUCCESS;
                }
                /* Otherwise, IO errors are fatal and should be investigated */
                fprintf(stderr, "Unexpected IO error during shutdown: %s\n", strerror(errno_val));
                return S2N_FAILURE;
            default:
                return S2N_FAILURE;
        }
    }
    return S2N_SUCCESS;
}

int s2n_connection_serialize_out(struct s2n_connection *conn, const char *file_path)
{
    uint32_t serialize_length = 0;
    GUARD_RETURN(s2n_connection_serialization_length(conn, &serialize_length), "Failed to get serialized connection length");
    uint8_t *mem = malloc(serialize_length);
    GUARD_RETURN_NULL(mem);
    GUARD_RETURN(s2n_connection_serialize(conn, mem, serialize_length), "Failed to get serialized connection");
    GUARD_RETURN(write_array_to_file(file_path, mem, serialize_length), "Failed to write serialized connection to file");
    free(mem);

    return 0;
}

int s2n_connection_deserialize_in(struct s2n_connection *conn, const char *file_path)
{
    size_t deserialize_length = 0;
    GUARD_RETURN(get_file_size(file_path, &deserialize_length), "Failed to read deserialize-in file size");
    ENSURE_RETURN(deserialize_length <= UINT32_MAX, "deserialize-in file size is too large");
    uint8_t *mem = malloc(deserialize_length);
    GUARD_RETURN_NULL(mem);
    GUARD_RETURN(load_file_to_array(file_path, mem, deserialize_length), "Failed to read deserialize-in file");
    GUARD_RETURN(s2n_connection_deserialize(conn, mem, (uint32_t) deserialize_length), "Failed to deserialize connection");
    free(mem);

    return 0;
}
