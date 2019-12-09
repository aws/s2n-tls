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

#pragma once

#include <stdint.h>
#include <s2n.h>

#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_crypto.h"
#include "tls/s2n_signature_algorithms.h"
#include "tls/s2n_tls_parameters.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_hash.h"

/* This is the list of message types that we support */
typedef enum {
    CLIENT_HELLO=0,
    SERVER_SESSION_LOOKUP,
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

    /* TLS1.3 message types. Defined: https://tools.ietf.org/html/rfc8446#appendix-B.3 */
    ENCRYPTED_EXTENSIONS,
    SERVER_CERT_VERIFY,

    APPLICATION_DATA,
} message_type_t;

struct s2n_handshake_parameters {
    /* Signature/hash algorithm pairs offered by the client in the signature_algorithms extension */
    struct s2n_sig_scheme_list client_sig_hash_algs;

    /* Signature/hash algorithm pairs offered by the server in the certificate request */
    struct s2n_sig_scheme_list server_sig_hash_algs;

    /* The cert chain we will send the peer. */
    struct s2n_cert_chain_and_key *our_chain_and_key;

    /* The subset of certificates that match the server_name presented in the ClientHello.
     * In the case of multiple certificates matching a server_name, s2n will prefer certificates
     * in FIFO order based on calls to s2n_config_add_cert_chain_and_key_to_store
     *
     * Note that in addition to domain matching, the key type for the certificate must also be
     * suitable for a negotiation in order to be selected. The set of matching certs here are indexed
     * by s2n_authentication_method.
     *
     * Example:
     *    - Assume certA is added to s2n_config via s2n_config_add_cert_chain_and_key_to_store
     *    - Next certB is added.
     *    - if certA matches www.foo.com and certB matches www.foo.com, s2n will prefer certA
     *
     * Note that in addition to domain matching, the key type for the certificate must also be
     * suitable for a negotiation in order to be selected.
     *
     * Example:
     *    - Assume certA and certB match server_name www.foo.com
     *    - certA is ECDSA and certB is RSA.
     *    - Client only supports RSA ciphers
     *    - certB will be selected.
     */
    struct s2n_cert_chain_and_key *exact_sni_matches[S2N_AUTHENTICATION_METHOD_SENTINEL];
    struct s2n_cert_chain_and_key *wc_sni_matches[S2N_AUTHENTICATION_METHOD_SENTINEL];
    uint8_t exact_sni_match_exists;
    uint8_t wc_sni_match_exists;
};

struct s2n_handshake {
    struct s2n_stuffer io;

    struct s2n_hash_state md5;
    struct s2n_hash_state sha1;
    struct s2n_hash_state sha224;
    struct s2n_hash_state sha256;
    struct s2n_hash_state sha384;
    struct s2n_hash_state sha512;
    struct s2n_hash_state md5_sha1;

    /* A copy of the handshake messages hash used to validate the CertificateVerify message */
    struct s2n_hash_state ccv_hash_copy;

    /* Used for SSLv3, TLS 1.0, and TLS 1.1 PRFs */
    struct s2n_hash_state prf_md5_hash_copy;
    struct s2n_hash_state prf_sha1_hash_copy;
    /*Used for TLS 1.2 PRF */
    struct s2n_hash_state prf_tls12_hash_copy;

    /* Hash algorithms required for this handshake. The set of required hashes can be reduced as session parameters are
     * negotiated, i.e. cipher suite and protocol version.
     */
    uint8_t required_hash_algs[S2N_HASH_SENTINEL];

    uint8_t server_finished[S2N_TLS_SECRET_LEN];
    uint8_t client_finished[S2N_TLS_SECRET_LEN];

    /* Handshake type is a bitset, with the following
       bit positions */
    uint32_t handshake_type;

/* Has the handshake been negotiated yet? */
#define INITIAL                     0x00
#define NEGOTIATED                  0x01
#define IS_NEGOTIATED( type ) ( (type) & NEGOTIATED )

/* Handshake is a full handshake  */
#define FULL_HANDSHAKE              0x02
#define IS_FULL_HANDSHAKE( type )   ( (type) & FULL_HANDSHAKE )
#define IS_RESUMPTION_HANDSHAKE( type ) ( !IS_FULL_HANDSHAKE( (type) ) && IS_NEGOTIATED ( (type) ) )

/* Handshake uses perfect forward secrecy */
#define TLS12_PERFECT_FORWARD_SECRECY 0x04

/* Handshake needs OCSP status message */
#define OCSP_STATUS                 0x08
#define IS_OCSP_STAPLED( type ) ( (type) & OCSP_STATUS )

/* Handshake should request a Client Certificate */
#define CLIENT_AUTH                 0x10

/* Handshake requested a Client Certificate but did not get one */
#define NO_CLIENT_CERT              0x40

/* Session Resumption via session-tickets */
#define WITH_SESSION_TICKET         0x20
#define IS_ISSUING_NEW_SESSION_TICKET( type )   ( (type) & WITH_SESSION_TICKET )

    /* Which handshake message number are we processing */
    int message_number;

    /* Set to 1 if the RSA verification failed */
    uint8_t rsa_failed;
};

extern message_type_t s2n_conn_get_current_message_type(struct s2n_connection *conn);
extern int s2n_conn_set_handshake_type(struct s2n_connection *conn);
extern int s2n_conn_set_handshake_no_client_cert(struct s2n_connection *conn);
extern int s2n_handshake_require_all_hashes(struct s2n_handshake *handshake);
extern uint8_t s2n_handshake_is_hash_required(struct s2n_handshake *handshake, s2n_hash_algorithm hash_alg);
extern int s2n_conn_update_required_handshake_hashes(struct s2n_connection *conn);
extern int s2n_handshake_get_hash_state(struct s2n_connection *conn, s2n_hash_algorithm hash_alg, struct s2n_hash_state *hash_state);
extern int s2n_conn_find_name_matching_certs(struct s2n_connection *conn);
extern int s2n_create_wildcard_hostname(struct s2n_stuffer *hostname, struct s2n_stuffer *output);
