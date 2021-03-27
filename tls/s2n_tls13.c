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
#include "crypto/s2n_rsa_signing.h"

bool s2n_use_default_tls13_config_flag = false;

bool s2n_use_default_tls13_config()
{
    return s2n_use_default_tls13_config_flag;
}

/* Allow TLS1.3 to be negotiated, and use the default TLS1.3 security policy.
 * This is NOT the default behavior, and this method is deprecated.
 *
 * Please consider using the default behavior and configuring
 * TLS1.2/TLS1.3 via explicit security policy instead.
 */
int s2n_enable_tls13()
{
    s2n_highest_protocol_version = S2N_TLS13;
    s2n_use_default_tls13_config_flag = true;
    return S2N_SUCCESS;
}

/* Do NOT allow TLS1.3 to be negotiated, regardless of security policy.
 * This is NOT the default behavior, and this method is deprecated.
 *
 * Please consider using the default behavior and configuring
 * TLS1.2/TLS1.3 via explicit security policy instead.
 */
int s2n_disable_tls13()
{
    POSIX_ENSURE(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    s2n_highest_protocol_version = S2N_TLS12;
    s2n_use_default_tls13_config_flag = false;
    return S2N_SUCCESS;
}

/* Reset S2N to the default protocol version behavior.
 *
 * This method is intended for use in existing unit tests when the APIs
 * to enable/disable TLS1.3 have already been called.
 */
int s2n_reset_tls13()
{
    POSIX_ENSURE(s2n_in_unit_test(), S2N_ERR_NOT_IN_UNIT_TEST);
    s2n_highest_protocol_version = S2N_TLS13;
    s2n_use_default_tls13_config_flag = false;
    return S2N_SUCCESS;
}

/* Returns whether a uint16 iana value is a valid TLS 1.3 cipher suite */
bool s2n_is_valid_tls13_cipher(const uint8_t version[2]) {
    /* Valid TLS 1.3 Ciphers are
     * 0x1301, 0x1302, 0x1303, 0x1304, 0x1305.
     * (https://tools.ietf.org/html/rfc8446#appendix-B.4)
     */
    return version[0] == 0x13 && version[1] >= 0x01 && version[1] <= 0x05;
}

/* Use middlebox compatibility mode for TLS1.3 by default.
 * For now, only disable it when QUIC support is enabled.
 */
bool s2n_is_middlebox_compat_enabled(struct s2n_connection *conn)
{
    return s2n_connection_get_protocol_version(conn) >= S2N_TLS13
            && conn && conn->config && !conn->config->quic_enabled;
}
