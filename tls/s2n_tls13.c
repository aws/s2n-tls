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

#include "api/s2n.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13.h"
#include "utils/s2n_safety.h"

int s2n_is_tls13_enabled()
{
    return s2n_highest_protocol_version == S2N_TLS13;
}

int s2n_enable_tls13()
{
    S2N_ERROR_IF(!S2N_IN_TEST, S2N_ERR_NOT_IN_UNIT_TEST);
    s2n_highest_protocol_version = S2N_TLS13;
    return 0;
}

int s2n_disable_tls13()
{
    s2n_highest_protocol_version = S2N_TLS12;
    return 0;
}

/* Returns whether a uint16 iana value is a valid TLS 1.3 cipher suite */
bool s2n_is_valid_tls13_cipher(const uint8_t version[2]) {
    /* Valid TLS 1.3 Ciphers are
     * 0x1301, 0x1302, 0x1303, 0x1304, 0x1305.
     * (https://tools.ietf.org/html/rfc8446#appendix-B.4)
     */
    return version[0] == 0x13 && version[1] >= 0x01 && version[1] <= 0x05;
}
