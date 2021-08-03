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

static int cache_store_callback(struct s2n_connection *conn, void *ctx, uint64_t ttl, const void *key, uint64_t key_size,
                                const void *value, uint64_t value_size) {
    struct session_cache_entry *cache = (session_cache_entry *) ctx;
    POSIX_ENSURE_INCLUSIVE_RANGE(1, key_size, MAX_KEY_LEN);
    POSIX_ENSURE_INCLUSIVE_RANGE(1, value_size, MAX_VAL_LEN);

    uint8_t idx = ((const uint8_t *) key)[0];

    memcpy(cache[idx].key, key, key_size);
    memcpy(cache[idx].value, value, value_size);

    cache[idx].key_len = key_size;
    cache[idx].value_len = value_size;

    return 0;
}

static int cache_retrieve_callback(struct s2n_connection *conn, void *ctx, const void *key, uint64_t key_size, void *value,
                                   uint64_t *value_size) {
    struct session_cache_entry *cache = (session_cache_entry *) ctx;

    POSIX_ENSURE_INCLUSIVE_RANGE(1, key_size, MAX_KEY_LEN);

    uint8_t idx = ((const uint8_t *) key)[0];

    POSIX_ENSURE(cache[idx].key_len == key_size, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(memcmp(cache[idx].key, key, key_size) == 0, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(*value_size >= cache[idx].value_len, S2N_ERR_INVALID_ARGUMENT);

    *value_size = cache[idx].value_len;
    memcpy(value, cache[idx].value, cache[idx].value_len);

    for (uint64_t i = 0; i < key_size; i++) {
        printf("%02x", ((const uint8_t *) key)[i]);
    }
    printf("\n");

    return 0;
}

static int cache_delete_callback(struct s2n_connection *conn, void *ctx, const void *key, uint64_t key_size) {
    struct session_cache_entry *cache = (session_cache_entry *) ctx;

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

static uint8_t unsafe_verify_host_fn(const char *host_name, size_t host_name_len, void *data) {
    return 1;
}


struct conn_settings {
    unsigned mutual_auth: 1;
    unsigned self_service_blinding: 1;
    unsigned only_negotiate: 1;
    unsigned prefer_throughput: 1;
    unsigned prefer_low_latency: 1;
    unsigned enable_mfl: 1;
    unsigned session_ticket: 1;
    unsigned session_cache: 1;
    unsigned insecure: 1;
    unsigned use_corked_io: 1;
    unsigned https_server: 1;
    uint32_t https_bench;
    int max_conns;
    const char *ca_dir;
    const char *ca_file;
    char *psk_optarg_list[S2N_MAX_PSK_LIST_LENGTH];
    size_t psk_list_len;
};