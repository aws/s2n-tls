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

#include <openssl/x509v3.h>

struct s2n_crl {
    X509_CRL *crl;
};

/* TODO: APIs are part of an unfinished CRL validation feature and are temporarily hidden
 * https://github.com/aws/s2n-tls/issues/3499 */
struct s2n_crl *s2n_crl_new(void);
int s2n_crl_load_pem(struct s2n_crl *crl, uint8_t *pem, size_t len);
int s2n_crl_free(struct s2n_crl **crl);
int s2n_crl_get_issuer_hash(struct s2n_crl *crl, uint64_t *hash);
