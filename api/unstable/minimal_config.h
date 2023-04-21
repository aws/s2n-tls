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
 * Creates a new s2n_config object with minimal default options.
 *
 * This API is similar to `s2n_config_new`, except that the returned config is created without
 * loading system certificates into the trust store. To add system certificates to this config,
 * call `s2n_config_load_system_certs`.
 *
 * The returned config should be freed with `s2n_config_free` after it's no longer in use by any
 * connections.
 *
 * @returns A new s2n_config object
 */
S2N_API struct s2n_config* s2n_config_new_minimal(void);

/**
 * Loads system certificates into the trust store.
 *
 * Operating systems typically install a set of default system certificates used by TLS clients to
 * verify the authenticity of public TLS servers. If s2n-tls is operating as a client connecting to
 * such a server, applications can add these system certificates to the config's trust store.
 *
 * This API is intended to be used on certificates created with `s2n_config_new_minimal`, which
 * does not load system certificates into the config's trust store by default.
 *
 * @note This API will error if called on a config that has already loaded system certificates
 * into its trust store, which includes all configs created with `s2n_config_new`.
 * @param config The configuration object being updated
 * @returns S2N_SUCCESS on success. S2N_FAILURE on failure
 */
S2N_API int s2n_config_load_system_certs(struct s2n_config* config);
