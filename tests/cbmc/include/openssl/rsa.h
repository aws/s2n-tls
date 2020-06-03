/*
 * Changes to OpenSSL version 1.1.1.
 * Copyright Amazon.com, Inc. All Rights Reserved.
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
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

#define RSA_PKCS1_PADDING 1
#define RSA_SSLV23_PADDING 2
#define RSA_NO_PADDING 3
#define RSA_PKCS1_OAEP_PADDING 4
#define RSA_X931_PADDING 5
/* EVP_PKEY_ only */
#define RSA_PKCS1_PSS_PADDING 6
