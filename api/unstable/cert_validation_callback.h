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

struct s2n_cert_validation_info;

typedef int (*s2n_cert_validation_callback)(struct s2n_connection *conn, struct s2n_cert_validation_info *info,
        void *context);

S2N_API extern int s2n_config_set_cert_validation_cb(struct s2n_config *config,
        s2n_cert_validation_callback cert_validation_cb, void *context);

S2N_API extern int s2n_cert_validation_accept(struct s2n_cert_validation_info *info);
S2N_API extern int s2n_cert_validation_reject(struct s2n_cert_validation_info *info);
