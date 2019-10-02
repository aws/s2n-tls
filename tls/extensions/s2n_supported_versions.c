/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <sys/param.h>
#include <stdint.h>

#include "tls/extensions/s2n_supported_versions.h"
#include "tls/s2n_cipher_preferences.h"

#include "utils/s2n_safety.h"

int s2n_connection_get_minimum_supported_version(struct s2n_connection *conn, uint8_t *min_version) 
{
    const struct s2n_cipher_preferences *cipher_preferences;
    GUARD(s2n_connection_get_cipher_preferences(conn, &cipher_preferences));
    *min_version = cipher_preferences->minimum_protocol_version;

    return 0;
}
