#!/bin/bash
# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

./.travis/zero_init_struct_helper.sh s2n_blob {0}
./.travis/zero_init_struct_helper.sh s2n_stuffer {{0}}
./.travis/zero_init_struct_helper.sh s2n_config {0}
./.travis/zero_init_struct_helper.sh s2n_pkey {{{0}}}
./.travis/zero_init_struct_helper.sh s2n_session_key {0}
./.travis/zero_init_struct_helper.sh s2n_connection_prf_handles {{{{0}}}}
./.travis/zero_init_struct_helper.sh s2n_connection_hash_handles {{{0}}}
./.travis/zero_init_struct_helper.sh s2n_connection_hmac_handles {{{{0}}}}
./.travis/zero_init_struct_helper.sh s2n_client_hello_parsed_extension {0}
./.travis/zero_init_struct_helper.sh s2n_hash_state {0}
./.travis/zero_init_struct_helper.sh s2n_dh_params {0}
./.travis/zero_init_struct_helper.sh s2n_map {0}
./.travis/zero_init_struct_helper.sh timespec {0}
./.travis/zero_init_struct_helper.sh tm {0}
./.travis/zero_init_struct_helper.sh stat {0}