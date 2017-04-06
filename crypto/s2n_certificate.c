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

int s2n_cert_public_key_set_cert_type(struct s2n_cert_public_key *cert_pub_key, s2n_cert_type cert_type)
{
    notnull_check(cert_pub_key);
    cert_pub_key->cert_type = cert_type;

    return 0;
}

int s2n_cert_public_key_get_rsa(struct s2n_cert_public_key *cert_pub_key, struct s2n_rsa_public_key **rsa)
{
    notnull_check(cert_pub_key);
    notnull_check(rsa);
    *rsa = &cert_pub_key->public_key.rsa;

    return 0;
}

int s2n_send_cert_chain(struct s2n_stuffer *out, struct s2n_cert_chain_and_key *chain)
{
    notnull_check(out);
    notnull_check(chain);
    GUARD(s2n_stuffer_write_uint24(out, chain->chain_size));

    struct s2n_cert_chain *head = chain->head;
    while (head) {
        notnull_check(head);
        GUARD(s2n_stuffer_write_uint24(out, head->cert.size));
        GUARD(s2n_stuffer_write_bytes(out, head->cert.data, head->cert.size));
        head = head->next;
    }

    return 0;
}
