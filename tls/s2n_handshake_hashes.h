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

#pragma once

#include "api/s2n.h"

#include "crypto/s2n_hash.h"

struct s2n_handshake_hashes {
    struct s2n_hash_state md5;
    struct s2n_hash_state sha1;
    struct s2n_hash_state sha224;
    struct s2n_hash_state sha256;
    struct s2n_hash_state sha384;
    struct s2n_hash_state sha512;
    struct s2n_hash_state md5_sha1;

    /* TLS1.3 does not always use a hash immediately.
     * We save copies of some states for later use in the key schedule.
     */
    struct s2n_hash_state server_hello_copy;
    struct s2n_hash_state server_finished_copy;

    /* To avoid allocating memory for hash objects, we reuse one temporary hash object.
     * Do NOT rely on this hash state maintaining its value outside of the current context.
     */
    struct s2n_hash_state hash_workspace;
};

S2N_RESULT s2n_handshake_hashes_new(struct s2n_handshake_hashes **hashes);
S2N_RESULT s2n_handshake_hashes_wipe(struct s2n_handshake_hashes *hashes);
S2N_CLEANUP_RESULT s2n_handshake_hashes_free(struct s2n_handshake_hashes **hashes);
