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
#include "testlib/s2n_testlib.h"

S2N_RESULT s2n_resumption_test_ticket_key_setup(struct s2n_config *config)
{
    /**
     *= https://www.rfc-editor.org/rfc/rfc5869#appendix-A.1
     *# PRK  = 0x077709362c2e32df0ddc3f0dc47bba63
     *#        90b6c73bb50f9c3122ec844ad7c2b3e5 (32 octets)
     **/
    S2N_RESULT_BLOB_FROM_HEX(ticket_key,
            "077709362c2e32df0ddc3f0dc47bba63"
            "90b6c73bb50f9c3122ec844ad7c2b3e5");

    /* Set up encryption key */
    uint64_t current_time = 0;
    uint8_t ticket_key_name[16] = "2016.07.26.15\0";

    RESULT_GUARD_POSIX(s2n_config_set_session_tickets_onoff(config, true));
    RESULT_GUARD_POSIX(config->wall_clock(config->sys_clock_ctx, &current_time));
    RESULT_GUARD_POSIX(s2n_config_add_ticket_crypto_key(config, ticket_key_name, strlen((char *) ticket_key_name),
            ticket_key.data, ticket_key.size, current_time / ONE_SEC_IN_NANOS));
    return S2N_RESULT_OK;
}
