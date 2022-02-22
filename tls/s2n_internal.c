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

#include "tls/s2n_internal.h"

#include "tls/s2n_connection.h"

/*
 * Internal APIs used for exploring experimental APIs.
 *
 * These APIs change the behavior of S2N in potentially dangerous ways and should only be
 * used for testing purposes. All Internal APIs are subject to change without notice.
 */


/*
 * Return a pointer to the config set on the connection.
 */
struct s2n_config *s2n_internal_connection_get_config(struct s2n_connection *conn) {
    if (s2n_fetch_default_config() == conn->config) {
        return NULL;
    }

    return conn->config;
}

