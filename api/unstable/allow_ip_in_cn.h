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

#pragma once

#include <s2n.h>

/**
 * @file allow_ip_in_cn.h
 *
 * The following API allows certificates with an IP address in the CN field and no SAN extension
 * to be accepted during hostname validation. This should only be used as a temporary workaround
 * while certificates are being re-issued with proper iPAddress SAN entries.
 */

/**
 * Allows IP addresses in the Common Name (CN) field to be used for hostname validation.
 *
 * By default, s2n-tls rejects certificates that contain an IP address in the CN field when no
 * Subject Alternative Name (SAN) extension is present. This is in accordance with RFC 6125
 * section 6.4.4, which states that the CN fallback only applies to fully qualified DNS domain
 * names, and section 6.2.1, which requires IP reference identities to match only iPAddress SAN
 * entries.
 *
 * Some legacy PKIs issue certificates with IP addresses in the CN field and no iPAddress SAN
 * entry. `s2n_config_allow_ip_in_cn()` may be called to temporarily allow these certificates
 * to pass hostname validation while re-issuing certs with proper iPAddress SAN entries.
 *
 * @param config The associated connection config.
 * @returns S2N_SUCCESS on success, S2N_FAILURE on failure.
 */
S2N_API extern int s2n_config_allow_ip_in_cn(struct s2n_config *config);
