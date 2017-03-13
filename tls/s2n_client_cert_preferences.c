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

int s2n_recv_client_cert_preferences(struct s2n_stuffer *in, s2n_cert_type *chosen_cert_type)
{
    uint8_t cert_types_len;
    uint8_t *cert_types;

    GUARD(s2n_stuffer_read_uint8(in, &cert_types_len));
    cert_types = s2n_stuffer_raw_read(in, cert_types_len);
    notnull_check(cert_types);

    GUARD(s2n_choose_preferred_client_cert_type(in, cert_types_len, cert_types, chosen_cert_type));

    return 0;
}

int s2n_choose_preferred_client_cert_type(struct s2n_stuffer *in, int certs_available, uint8_t *cert_types,
        s2n_cert_type *chosen_cert_type)
{
    s2n_cert_type best_cert_type;
    int found_valid_cert = 0;
    int certs_read = 0;
    int curr_best_cert_type_index = sizeof(s2n_cert_type_preference_list) - 1;

    /* Current Best starts out high, at the size of the preferred cert_type. We
     * always search backwards from chosen, so can only move to an algorithm
     * with a higher preference.
     */
    while(certs_read < certs_available){
        for (int i = curr_best_cert_type_index; i >= 0; i--) {
            s2n_cert_type curr_cert_type = cert_types[i];
            certs_read++;
            if (s2n_cert_type_preference_list[i] != curr_cert_type) {
                continue;
            }

            found_valid_cert = 1;
            curr_best_cert_type_index = i;
            best_cert_type = curr_cert_type;

            if (i == 0) {
                break;
            }
        }
    }

    if (found_valid_cert) {
        *chosen_cert_type = best_cert_type;
        return 0;
    }

    S2N_ERROR(S2N_ERR_CERT_TYPE_UNSUPPORTED);
}
