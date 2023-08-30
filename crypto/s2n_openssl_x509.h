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

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <stdint.h>

#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"

DEFINE_POINTER_CLEANUP_FUNC(X509 *, X509_free);

S2N_CLEANUP_RESULT s2n_openssl_x509_stack_pop_free(STACK_OF(X509) **cert_chain);

S2N_CLEANUP_RESULT s2n_openssl_asn1_time_free_pointer(ASN1_GENERALIZEDTIME **time);

S2N_RESULT s2n_openssl_x509_parse(struct s2n_blob *cert_asn1_der, X509 **cert, uint32_t *cert_len);
S2N_RESULT s2n_openssl_x509_validate_length(struct s2n_blob *cert_asn1_der, uint32_t cert_len);
