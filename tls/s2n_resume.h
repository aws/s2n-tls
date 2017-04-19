/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#pragma once

#include "utils/s2n_blob.h"

#include "stuffer/s2n_stuffer.h"

#define S2N_SERIALIZED_FORMAT_VERSION   1
#define S2N_STATE_LIFETIME_IN_NANOS     21600000000
#define S2N_STATE_SIZE_IN_BYTES         (1 + 8 + 1 + S2N_TLS_CIPHER_SUITE_LEN + S2N_TLS_SECRET_LEN)
#define S2N_TLS_SESSION_CACHE_TTL       (6 * 60 * 60)
#define S2N_TICKET_KEY_NAME_LEN         16
#define S2N_TICKET_AAD_IMPLICIT_LEN     12
#define S2N_TICKET_AAD_LEN              (S2N_TICKET_AAD_IMPLICIT_LEN + S2N_TICKET_KEY_NAME_LEN)
#define S2N_AES256_KEY_LEN              32
#define S2N_TICKET_SIZE_IN_BYTES        (S2N_TICKET_KEY_NAME_LEN + S2N_TLS_GCM_IV_LEN + S2N_STATE_SIZE_IN_BYTES + S2N_TLS_GCM_TAG_LEN)

struct s2n_connection;
struct s2n_config;

struct s2n_ticket_key {
    unsigned char key_name[S2N_TICKET_KEY_NAME_LEN]; /* name = "YYYY.MM.DD.HH\0" */
    uint8_t aes_key[S2N_AES256_KEY_LEN];
    uint8_t implicit_aad[S2N_TICKET_AAD_IMPLICIT_LEN];
    uint64_t expiration_in_nanos;
};

extern int s2n_encrypt_session_ticket(struct s2n_connection *conn, struct s2n_stuffer *to);
extern int s2n_decrypt_session_ticket(struct s2n_connection *conn, struct s2n_stuffer *from);
extern int s2n_verify_unique_ticket_key(struct s2n_config *config, uint8_t *hash);

extern int s2n_is_caching_enabled(struct s2n_config *config);
extern int s2n_resume_from_cache(struct s2n_connection *conn);
extern int s2n_store_to_cache(struct s2n_connection *conn);
