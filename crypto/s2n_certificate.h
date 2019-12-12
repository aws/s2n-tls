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

#include <openssl/x509.h>

#include <s2n.h>
#include "crypto/s2n_pkey.h"
#include "stuffer/s2n_stuffer.h"

struct s2n_cert {
    s2n_pkey_type pkey_type;
    s2n_cert_public_key public_key;
    struct s2n_blob raw;
    struct s2n_cert *next;
};

struct s2n_cert_chain {
    uint32_t chain_size;
    struct s2n_cert *head;
};

struct s2n_cert_chain_and_key {
    struct s2n_cert_chain *cert_chain;
    s2n_cert_private_key *private_key;
    struct s2n_blob ocsp_status;
    struct s2n_blob sct_list;
    /* DNS type SubjectAlternative names from the leaf certificate to match
     * with the server_name extension. We ignore non-DNS SANs here since the
     * server_name extension only supports DNS.
     */
    struct s2n_array *san_names;
    /* CommonName values from the leaf certificate's Subject to match with the
     * server_name extension. Decoded as UTF8.
     */
    struct s2n_array *cn_names;
    /* Application defined data related to this cert. */
    void *context;
};

typedef enum {
    S2N_AUTHENTICATION_RSA = 0,
    S2N_AUTHENTICATION_ECDSA,
    S2N_AUTHENTICATION_RSA_PSS,
    S2N_AUTHENTICATION_METHOD_SENTINEL
} s2n_authentication_method;

/* Used by TLS 1.3 CipherSuites (Eg TLS_AES_128_GCM_SHA256 "0x1301") where the Auth method will be specified by the
 * SignatureScheme Extension, not the CipherSuite. */
#define S2N_AUTHENTICATION_METHOD_TLS13     S2N_AUTHENTICATION_METHOD_SENTINEL

struct auth_method_to_cert_value {
    struct s2n_cert_chain_and_key *certs[S2N_AUTHENTICATION_METHOD_SENTINEL];
};

int s2n_cert_chain_and_key_set_ocsp_data(struct s2n_cert_chain_and_key *chain_and_key, const uint8_t *data, uint32_t length);
int s2n_cert_chain_and_key_set_sct_list(struct s2n_cert_chain_and_key *chain_and_key, const uint8_t *data, uint32_t length);
/* Exposed for fuzzing */
int s2n_cert_chain_and_key_load_cns(struct s2n_cert_chain_and_key *chain_and_key, X509 *x509_cert);
int s2n_cert_chain_and_key_load_sans(struct s2n_cert_chain_and_key *chain_and_key, X509 *x509_cert);
int s2n_cert_chain_and_key_matches_dns_name(const struct s2n_cert_chain_and_key *chain_and_key, const struct s2n_blob *dns_name);

int s2n_cert_public_key_set_rsa_from_openssl(s2n_cert_public_key *cert_pub_key, RSA *rsa);
int s2n_cert_set_cert_type(struct s2n_cert *cert, s2n_pkey_type pkey_type);
int s2n_send_cert_chain(struct s2n_stuffer *out, struct s2n_cert_chain *chain, uint8_t actual_protocol_version);
int s2n_send_empty_cert_chain(struct s2n_stuffer *out);
int s2n_create_cert_chain_from_stuffer(struct s2n_cert_chain *cert_chain_out, struct s2n_stuffer *chain_in_stuffer);
int s2n_cert_chain_and_key_set_cert_chain(struct s2n_cert_chain_and_key *cert_and_key, const char *cert_chain_pem);
int s2n_cert_chain_and_key_set_private_key(struct s2n_cert_chain_and_key *cert_and_key, const char *private_key_pem);

s2n_authentication_method s2n_cert_chain_and_key_get_auth_method(struct s2n_cert_chain_and_key *chain_and_key);

