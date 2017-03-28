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

#include "stuffer/s2n_stuffer.h"
#include "error/s2n_errno.h"
#include "tls/s2n_client_cert_preferences.h"
#include "utils/s2n_safety.h"

int s2n_recv_client_cert_preferences(struct s2n_stuffer *in, s2n_cert_type *chosen_cert_type_out)
{
    uint8_t cert_types_len;
    GUARD(s2n_stuffer_read_uint8(in, &cert_types_len));
    GUARD(s2n_choose_preferred_client_cert_type(in, cert_types_len, chosen_cert_type_out));

    return 0;
}

int s2n_choose_preferred_client_cert_type(struct s2n_stuffer *in, int num_certs, s2n_cert_type *chosen_cert_type_out)
{
    uint8_t *their_cert_type_pref_list = s2n_stuffer_raw_read(in, num_certs);
    notnull_check(their_cert_type_pref_list);

    for (int our_cert_pref_idx = 0; our_cert_pref_idx < sizeof(s2n_cert_type_preference_list); our_cert_pref_idx++) {
        for (int their_cert_idx = 0; their_cert_idx < num_certs; their_cert_idx++) {
            if(their_cert_type_pref_list[their_cert_idx] == s2n_cert_type_preference_list[our_cert_pref_idx]){
                *chosen_cert_type_out = s2n_cert_type_preference_list[our_cert_pref_idx];
                return 0;
            }
        }
    }

    S2N_ERROR(S2N_ERR_CERT_TYPE_UNSUPPORTED);
}
