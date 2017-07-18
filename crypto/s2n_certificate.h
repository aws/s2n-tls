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

#include "crypto/s2n_rsa.h"
#include "stuffer/s2n_stuffer.h"

#define S2N_MAX_SERVER_NAME 256

struct s2n_cert_chain {
    struct s2n_blob cert;
    struct s2n_cert_chain *next;
};

struct s2n_cert_chain_and_key {
    uint32_t chain_size;
    struct s2n_cert_chain *head;
    struct s2n_rsa_private_key private_key;
    struct s2n_blob ocsp_status;
    struct s2n_blob sct_list;
    char server_name[S2N_MAX_SERVER_NAME];
};

/* RFC's that define below values:
 *  - https://tools.ietf.org/html/rfc5246#section-7.4.4
 *  - https://tools.ietf.org/search/rfc4492#section-5.5
 */
typedef enum {
    S2N_CERT_TYPE_RSA_SIGN = 1,
    S2N_CERT_TYPE_DSS_SIGN = 2,
    S2N_CERT_TYPE_RSA_FIXED_DH = 3,
    S2N_CERT_TYPE_DSS_FIXED_DH = 4,
    S2N_CERT_TYPE_RSA_EPHEMERAL_DH_RESERVED = 5,
    S2N_CERT_TYPE_DSS_EPHEMERAL_DH_RESERVED = 6,
    S2N_CERT_TYPE_FORTEZZA_DMS_RESERVED = 20,
    S2N_CERT_TYPE_ECDSA_SIGN = 64,
    S2N_CERT_TYPE_RSA_FIXED_ECDH = 65,
    S2N_CERT_TYPE_ECDSA_FIXED_ECDH = 66,
} s2n_cert_type;

struct s2n_cert_public_key {
    s2n_cert_type cert_type;
    union {
        struct s2n_rsa_public_key rsa;
        /* TODO: Support other Public Key Types (Eg ECDSA) */
    } public_key;
};

typedef enum { S2N_CERT_AUTH_NONE, S2N_CERT_AUTH_REQUIRED } s2n_cert_auth_type;

/* Verifies the Certificate Chain of trust and places the leaf Certificate's Public Key in the public_key_out parameter.
*
* Does not perform any hostname validation, which is still needed in order to completely validate a Certificate.
*
* @param cert_chain_in The DER formatted full chain of certificates recieved
* @param public_key_out The public key that should be updated with the key extracted from the certificate
* @param context A pointer to any caller defined context data
*
* @return The function should return 0 if Certificate is trusted and public key extraction was successful, and less than
*         0 if the Certificate is untrusted, or there was some other error.
*/
typedef int verify_cert_trust_chain(uint8_t *cert_chain_in, uint32_t cert_chain_len, struct s2n_cert_public_key *public_key_out, void *context);

int s2n_send_cert_chain(struct s2n_stuffer *out, struct s2n_cert_chain_and_key *chain);
int s2n_cert_public_key_set_cert_type(struct s2n_cert_public_key *cert_pub_key, s2n_cert_type cert_type);
int s2n_cert_public_key_get_rsa(struct s2n_cert_public_key *cert_pub_key, struct s2n_rsa_public_key **rsa);
int s2n_cert_public_key_set_rsa(struct s2n_cert_public_key *cert_pub_key, struct s2n_rsa_public_key rsa);
