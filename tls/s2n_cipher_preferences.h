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

#include "tls/s2n_cipher_suites.h"

struct s2n_cipher_preferences {
    uint8_t count;
    struct s2n_cipher_suite **suites;
    int minimum_protocol_version;
};

extern const struct s2n_cipher_preferences cipher_preferences_20140601;
extern const struct s2n_cipher_preferences cipher_preferences_20141001;
extern const struct s2n_cipher_preferences cipher_preferences_20150202;
extern const struct s2n_cipher_preferences cipher_preferences_20150214;
extern const struct s2n_cipher_preferences cipher_preferences_20150306;
extern const struct s2n_cipher_preferences cipher_preferences_20160411;
extern const struct s2n_cipher_preferences cipher_preferences_20160804;
extern const struct s2n_cipher_preferences cipher_preferences_20160824;
extern const struct s2n_cipher_preferences cipher_preferences_20170210;
extern const struct s2n_cipher_preferences cipher_preferences_20170328;
extern const struct s2n_cipher_preferences cipher_preferences_20170405;
extern const struct s2n_cipher_preferences cipher_preferences_20170718;
extern const struct s2n_cipher_preferences cipher_preferences_test_all;
extern const struct s2n_cipher_preferences cipher_preferences_test_all_fips;

extern int s2n_config_set_cipher_preferences(struct s2n_config *config, const char *version);
