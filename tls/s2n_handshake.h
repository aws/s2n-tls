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
    SERVER_NEW_SESSION_TICKET,
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
    struct s2n_hash_state sha224;
    struct s2n_hash_state sha256;
    struct s2n_hash_state sha384;
    struct s2n_hash_state sha512;
    struct s2n_hash_state md5_sha1;

    /* Used for SSLv3 PRF */
    struct s2n_hash_state sslv3_md5_copy;
    struct s2n_hash_state sslv3_sha1_copy;
    /*Used for TLS PRF */
    struct s2n_hash_state tls_hash_copy;

    uint8_t server_finished[S2N_SSL_FINISHED_LEN];
    uint8_t client_finished[S2N_SSL_FINISHED_LEN];


    /* Handshake type is a bitset, with the following
       bit positions */
    int handshake_type;

/* Has the handshake been negotiated yet? */
#define INITIAL                     0x00
#define NEGOTIATED                  0x01

/* Handshake is a full handshake  */
#define FULL_HANDSHAKE              0x02
#define IS_FULL_HANDSHAKE( type )   ( (type) & FULL_HANDSHAKE )
#define IS_RESUMPTION_HANDSHAKE( type ) ( !IS_FULL_HANDSHAKE( (type) ) )

/* Handshake uses perfect forward secrecy */
#define PERFECT_FORWARD_SECRECY     0x04

/* Handshake needs OCSP status message */
#define OCSP_STATUS                 0x08

/* Handshake should request a Client Certificate */
#define CLIENT_AUTH                 0x10

/* Session Resumption via session-tickets */
#define WITH_SESSION_TICKET         0x20

    /* Which handshake message number are we processing */
    int message_number;

    /* Set to 1 if the RSA verification failed */
    uint8_t rsa_failed;
};

extern int s2n_conn_set_handshake_type(struct s2n_connection *conn);
extern int s2n_handshake_get_hash_state(struct s2n_connection *conn, s2n_hash_algorithm hash_alg, struct s2n_hash_state *hash_state);
