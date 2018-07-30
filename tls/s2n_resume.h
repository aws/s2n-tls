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

#include "tls/s2n_connection.h"

#include "utils/s2n_blob.h"

#define S2N_SERIALIZED_FORMAT_VERSION   1
#define S2N_STATE_LIFETIME_IN_NANOS     21600000000
#define S2N_STATE_SIZE_IN_BYTES         (1 + 8 + 1 + S2N_TLS_CIPHER_SUITE_LEN + S2N_TLS_SECRET_LEN)
#define S2N_TLS_SESSION_CACHE_TTL       (6 * 60 * 60)

typedef enum {
	S2N_STATE_WITH_SESSION_ID = 0,
	S2N_STATE_WITH_SESSION_TICKET
} s2n_client_tls_session_state_format;

extern int s2n_allowed_to_cache_connection(struct s2n_connection *conn);
extern int s2n_resume_from_cache(struct s2n_connection *conn);
extern int s2n_store_to_cache(struct s2n_connection *conn);
