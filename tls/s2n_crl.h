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
#include "utils/s2n_result.h"

#include <openssl/x509v3.h>

struct s2n_x509_validator;

struct s2n_crl {
    X509_CRL *crl;
};

typedef enum {
    AWAITING_RESPONSE,
    FINISHED
} crl_lookup_callback_status;

struct s2n_crl_lookup {
    crl_lookup_callback_status status;
    X509 *cert;
    uint16_t cert_idx;
    struct s2n_crl *crl;
};

typedef int (*s2n_crl_lookup_callback) (struct s2n_crl_lookup *lookup, void *context);

/* TODO: APIs are part of an unfinished CRL validation feature and are temporarily hidden
 * https://github.com/aws/s2n-tls/issues/3499 */
struct s2n_crl *s2n_crl_new(void);
int s2n_crl_load_pem(struct s2n_crl *crl, uint8_t *pem, size_t len);
int s2n_crl_free(struct s2n_crl **crl);
int s2n_crl_get_issuer_hash(struct s2n_crl *crl, uint64_t *hash);
int s2n_crl_lookup_get_cert_issuer_hash(struct s2n_crl_lookup *lookup, uint64_t *hash);
int s2n_crl_lookup_accept(struct s2n_crl_lookup *lookup, struct s2n_crl *crl);
int s2n_crl_lookup_reject(struct s2n_crl_lookup *lookup);

S2N_RESULT s2n_crl_handle_lookup_callback_result(struct s2n_x509_validator *validator);
S2N_RESULT s2n_crl_invoke_lookup_callbacks(struct s2n_connection *conn, struct s2n_x509_validator *validator);
S2N_RESULT s2n_crl_get_crls_from_lookup_list(struct s2n_x509_validator *validator, STACK_OF(X509_CRL) *crl_stack);
