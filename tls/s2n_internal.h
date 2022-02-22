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

#include "api/s2n.h"

/*
 * Internal APIs used for exploring experimental APIs.
 *
 * These APIs change the behavior of S2N in potentially dangerous ways and should only be
 * used for testing purposes. All Internal APIs are subject to change without notice.
 */


/*
 * Return a pointer to the config set on the connection.
 *
 * This function will return a pointer to the config set by `s2n_connection_set_config`.
 * It will return NULL prior to `s2n_connection_set_config` being called and a config
 * being set by the application.
 *
 * Caution: A config can be associated with multiple connections and should not be
 * modified after it has been built. Doing so is undefined behavior.
 *
 * WARNING: this method is still considered experimental and will not always report
 * the correct alert description. It may be used for testing and logging, but
 * not relied on for production logic.
 */

S2N_API
extern struct s2n_config *s2n_internal_connection_get_config(struct s2n_connection *conn);
