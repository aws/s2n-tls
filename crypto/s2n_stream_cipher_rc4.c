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

#include <openssl/rc4.h>

#include "crypto/s2n_cipher.h"

#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

int s2n_stream_cipher_rc4_endecrypt(struct s2n_session_key *key, struct s2n_blob *in, struct s2n_blob *out, const char **err)
{
    gte_check(out->size, in->size);
    RC4(&key->native_format.rc4, out->size, in->data, out->data);
    return 0;
}

int s2n_stream_cipher_rc4_get_key(struct s2n_session_key *key, struct s2n_blob *in, const char **err)
{
    eq_check(in->size, 16);
    RC4_set_key(&key->native_format.rc4, in->size, in->data);
    return 0;
}

struct s2n_cipher s2n_rc4 = {
    .type = S2N_STREAM,
    .key_material_size = 16,
    .io.stream = {
                  .decrypt = s2n_stream_cipher_rc4_endecrypt,
                  .encrypt = s2n_stream_cipher_rc4_endecrypt},
    .get_decryption_key = s2n_stream_cipher_rc4_get_key,
    .get_encryption_key = s2n_stream_cipher_rc4_get_key
};
