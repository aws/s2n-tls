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
 * @file custom_x509_extensions.h
 *
 * The following API enables applications to configure custom x509 critical extensions unknown to s2n-tls.
 * s2n-tls will ignore these extensions during certificate validation. Applications MUST validate their 
 * custom critical extensions in the cert validation callback or after the handshake.
 */

/**
 * Specify some unknown critical extensions to be ignored during certificate validation.
 * 
 * By default, s2n-tls will reject received certificates with unknown critical extensions. Calling 
 * s2n_config_set_custom_x509_extensions will allow s2n-tls to trust the given extension_oids.
 * This allows applications to provide their own validation for certificate extensions unknown to s2n-tls.
 * 
 * Invoking this API will override any custom extensions previously set on the config.
 * 
 * Libcrypto Requirement: AWS-LC >= 1.51.0
 * 
 * # Safety
 * 
 * RFC 5280 indicates that certificate extensions are to be marked critical when validators MUST
 * understand the extension in order to safely determine the certificate's validity. As such, s2n-tls
 * assumes that this validation is performed by the application. Applications MUST implement this
 * validation for all provided certificate extensions outside of s2n-tls. The `s2n_cert_validation_callback`
 * can be used for this purpose.
 *
 * @param config The configuration object being updated
 * @param extension_oids The list of custom critical oids
 * @param extension_oid_count The length of the array `extension_oids`
 * @returns S2N_SUCCESS on success. S2N_FAILURE on failure
 */
S2N_API extern int s2n_config_set_custom_x509_extensions(struct s2n_config *config, const char *const *extension_oids, uint32_t extension_oid_count);
