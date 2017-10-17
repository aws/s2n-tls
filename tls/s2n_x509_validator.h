/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <openssl/x509v3.h>


typedef uint8_t (*verify_host) (const char *host_name, size_t host_name_len, void *data);
struct s2n_connection;

typedef enum s2n_x509_validation_step {
    S2N_X509_NOT_STARTED = 0,
    S2N_X509_CERT_BASIC_VERIFIED = 1,
    S2N_X509_CERT_HOST_VERIFIED = 2,
    S2N_X509_CERT_STAPLED_OCSP_RESPONSE_VERIFIED = 3,
    S2N_X509_VALIDATED = 4,
    S2N_X509_VALIDATION_FAILED = -1
} s2n_x509_validation_step;

struct s2n_x509_trust_store {
    X509_STORE *trust_store;
};

struct s2n_x509_validator {
    struct s2n_x509_trust_store *trust_store;
    STACK_OF(X509) *cert_chain;

    s2n_x509_validation_step current_step;
    uint8_t validate_certificates;
    verify_host verify_host_fn;
    void *validation_ctx;
};

void s2n_x509_trust_store_init(struct s2n_x509_trust_store *store);
uint8_t s2n_x509_trust_store_has_certs(struct s2n_x509_trust_store *store);
int s2n_x509_trust_store_from_ca_file(struct s2n_x509_trust_store *store, const char *ca_file);
void s2n_x509_trust_store_cleanup(struct s2n_x509_trust_store *store);

int s2n_x509_validator_init_no_checks(struct s2n_x509_validator *validator);
int s2n_x509_validator_init(struct s2n_x509_validator *validator, struct s2n_x509_trust_store *trust_store, verify_host verify_host_fn, void *verify_ctx);
void s2n_x509_validator_cleanup(struct s2n_x509_validator *validator);

s2n_cert_validation_code s2n_x509_validator_validate_cert_chain(struct s2n_x509_validator *validator, uint8_t *cert_chain_in,
                                            uint32_t cert_chain_len,
                                            struct s2n_cert_public_key *public_key_out);

s2n_cert_validation_code s2n_x509_validator_validate_cert_stapled_ocsp_response(struct s2n_x509_validator *validator, const uint8_t *ocsp_response, size_t size);



