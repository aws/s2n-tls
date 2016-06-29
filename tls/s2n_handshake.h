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

/* This is the list of message types that we support */
typedef enum {
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
    APPLICATION_DATA
} message_type_t;

struct s2n_handshake {
    struct s2n_stuffer io;

    struct s2n_hash_state md5;
    struct s2n_hash_state sha1;
    struct s2n_hash_state sha256;
    struct s2n_hash_state sha384;

    uint8_t server_finished[S2N_SSL_FINISHED_LEN];
    uint8_t client_finished[S2N_SSL_FINISHED_LEN];

    enum {
        /* Dummy handshake that we always start out with */
        INITIAL, 

        /* A Full handshake with forward secrecy */
        FULL_WITH_PFS,

        /* A full handshake with forward secrecy and an OCSP response */
        FULL_WITH_PFS_WITH_STATUS,

        /* A full handshake with no forward secrecy */
        FULL_NO_PFS,

        /* A full handshake with no forward secrecy, but with an OCSP response */
        FULL_NO_PFS_WITH_STATUS,

        /* A resumption handshake */
        RESUME
    } handshake_type;

    /* Which handshake message number are we processing */
    int message_number;

    /* Set to 1 if the RSA verificiation failed */
    uint8_t rsa_failed;
};

extern int s2n_conn_set_handshake_type(struct s2n_connection *conn);
