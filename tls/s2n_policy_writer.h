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

struct s2n_security_policy;

/**
 * Output format types for verbose policy output.
 */
typedef enum {
    /**
     * Produces structured output with the following sections:
     * - min version: <minimum_protocol_version>
     * - rules:
     *   - <rule_name>: <yes|no>
     * - cipher suites:
     *   - <cipher_suite_name>
     * - signature schemes:
     *   - <signature_scheme_name>
     * - curves:
     *   - <curve_name>
     * - certificate signature schemes: (if present)
     *   - <cert_signature_scheme_name>
     * - certificate keys: (if present)
     *   - <certificate_key_name>
     * - pq: (if present)
     *   - revision: <pq_hybrid_draft_revision>
     *   - kems: (if present)
     *     -- <kem_name>
     *   - kem groups:
     *     -- <kem_group_name>
     */
    S2N_POLICY_FORMAT_DEBUG_V1 = 1,
} s2n_policy_format;

/**
 * Retrieves the length of the buffer needed for s2n_security_policy_write_bytes().
 * This function should be used to allocate enough memory for the policy output buffer before calling
 * s2n_security_policy_write_bytes().
 *
 * @note The size of the policy output depends on the specific policy configuration.
 * Do not expect the size to always remain the same across different policies.
 *
 * @param policy The security policy to get the buffer size for
 * @param format The output format to use
 * @param length Output parameter where the required buffer length will be written
 * @returns S2N_SUCCESS on success, S2N_FAILURE on failure
 */
int s2n_security_policy_write_length(const struct s2n_security_policy *policy,
        s2n_policy_format format, uint32_t *length);

/**
 * Writes output of a security policy to a user-provided buffer in the specified format.
 * 
 * @param policy The security policy to output
 * @param format The output format to use
 * @param buffer The buffer to write to
 * @param buffer_length The size of the buffer
 * @param output_size Output variable to be set to the actual number of bytes written to `buffer`
 *                    This value is only meaningful when the function returns S2N_SUCCESS
 * @returns S2N_SUCCESS on success, S2N_FAILURE on failure (e.g., if buffer is too small)
 */
int s2n_security_policy_write_bytes(const struct s2n_security_policy *policy,
        s2n_policy_format format, uint8_t *buffer, uint32_t buffer_length, uint32_t *output_size);

/**
 * Writes output of a security policy to a file descriptor in the specified format.
 * 
 * @param policy The security policy to output
 * @param format The output format to use  
 * @param fd The file descriptor to write to (e.g., STDOUT_FILENO or an open file)
 * @param output_size Output variable to be set to the actual number of bytes written to the file descriptor
 *                    This value is only meaningful when the function returns S2N_SUCCESS
 * @returns S2N_SUCCESS on success, S2N_FAILURE on failure
 */
int s2n_security_policy_write_fd(const struct s2n_security_policy *policy,
        s2n_policy_format format, int fd, uint32_t *output_size);
