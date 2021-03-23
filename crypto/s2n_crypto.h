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

#include <stdint.h>

#include <openssl/aes.h>
#include <openssl/rc4.h>
#include <openssl/des.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>

/* OPENSSL_free is defined within <openssl/crypto.h> for OpenSSL Libcrypto
 * and within <openssl/mem.h> for AWS_LC */
#include <openssl/crypto.h>
#if defined(OPENSSL_IS_AWSLC)
#include <openssl/mem.h>
#endif

#include "api/s2n.h"

int s2n_openssl_free(uint8_t** data);
