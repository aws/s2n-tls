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

#include "crypto/s2n_certificate.h"
#include "utils/s2n_blob.h"

/*
 * Verifies the Certificate Chain and places the Certificate's Public Key in the public_key_out parameter.
 * @param cert_chain The full chain of certificates recieved
 * @param public_key Where to store the public key extracted from the certificate
 * @param context A pointer to any caller defined context data
 *
 * @return The function should return 0 if Certificate is trusted and public key extraction was successful, and less than
 *         0 if the Certificate is untrusted, or there was some other error.
 */
typedef int verify_cert_chain(struct s2n_blob *cert_chain, struct s2n_cert_public_key *public_key, void *context);

