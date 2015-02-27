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

#pragma once

#include <stdint.h>
#include <s2n.h>

#include "tls/s2n_crypto.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_hash.h"

struct s2n_handshake {
    struct s2n_stuffer io;
    uint32_t bytes_remaining;

    struct s2n_hash_state client_md5;
    struct s2n_hash_state client_sha1;
    struct s2n_hash_state client_sha256;
    struct s2n_hash_state server_md5;
    struct s2n_hash_state server_sha1;
    struct s2n_hash_state server_sha256;

    uint8_t server_finished[S2N_SSL_FINISHED_LEN];
    uint8_t client_finished[S2N_SSL_FINISHED_LEN];

    /* We use this state machine to track where we are in the 
     * handshake. We can only progress forwards in the list
     * of states, if the other end of a connections attempts to
     * go backwards, we'll abort. Though it's ok to skip some
     * (e.g. CLIENT_CERT*). 
     */
    enum handshake_state {
        CLIENT_HELLO,
        SERVER_HELLO,
        SERVER_CERT,
        SERVER_CERT_STATUS,
        SERVER_KEY,
        SERVER_CERT_REQ,
        SERVER_HELLO_DONE,
        CLIENT_CERT,
        CLIENT_KEY,
        CLIENT_CERT_VERIFY,
        CLIENT_CHANGE_CIPHER_SPEC,
        CLIENT_FINISHED,
        SERVER_CHANGE_CIPHER_SPEC,
        SERVER_FINISHED,
        HANDSHAKE_OVER
    } state, next_state;

    /* Set to 1 if the RSA verificiation failed */
    uint8_t rsa_failed;
};
