/*
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <stdint.h>
#include <string.h>

#include "utils/s2n_blob.h"

struct s2n_client_hello_parsed_extension {
	uint16_t extension_type;
	struct s2n_blob extension;
};

extern int s2n_client_hello_get_parsed_extension(struct s2n_array *parsed_extensions, s2n_tls_extension_type extension_type,
        struct s2n_client_hello_parsed_extension *parsed_extension);
extern void s2n_register_extension(uint16_t ext_type);
