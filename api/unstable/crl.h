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

struct s2n_crl_lookup;

typedef int (*s2n_crl_lookup_callback) (struct s2n_crl_lookup *lookup, void *context);

S2N_API
int s2n_config_set_crl_lookup_cb(struct s2n_config *config, s2n_crl_lookup_callback callback, void *context);
