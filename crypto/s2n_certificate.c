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

#include <s2n.h>

#include "crypto/s2n_certificate.h"
#include "utils/s2n_safety.h"

int s2n_cert_public_key_set_rsa_from_openssl(s2n_cert_public_key *public_key, RSA *openssl_rsa)
{
    notnull_check(openssl_rsa);
    notnull_check(public_key);
    public_key->key.rsa_key.rsa = openssl_rsa;

    return 0;
}

int s2n_cert_set_cert_type(struct s2n_cert *cert, s2n_cert_type cert_type)
{
    notnull_check(cert);
    cert->cert_type = cert_type;
    s2n_pkey_setup_for_type(&cert->public_key, cert_type);
    return 0;
}

int s2n_send_cert_chain(struct s2n_stuffer *out, struct s2n_cert_chain *chain)
{
    notnull_check(out);
    notnull_check(chain);
    GUARD(s2n_stuffer_write_uint24(out, chain->chain_size));

    struct s2n_cert *cur_cert = chain->head;
    while (cur_cert) {
        notnull_check(cur_cert); 
        GUARD(s2n_stuffer_write_uint24(out, cur_cert->raw.size));
        GUARD(s2n_stuffer_write_bytes(out, cur_cert->raw.data, cur_cert->raw.size));
        cur_cert = cur_cert->next;
    }

    return 0;
}

int s2n_send_empty_cert_chain(struct s2n_stuffer *out) {
    notnull_check(out);
    GUARD(s2n_stuffer_write_uint24(out, 0));
    return 0;
}
