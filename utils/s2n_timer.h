/*
 * Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

struct s2n_timer {
    uint64_t time;
};

extern int s2n_timer_start(struct s2n_config *config, struct s2n_timer *timer);
extern int s2n_timer_elapsed(struct s2n_config *config, struct s2n_timer *timer, uint64_t * nanoseconds);
extern int s2n_timer_reset(struct s2n_config *config, struct s2n_timer *timer, uint64_t * nanoseconds);
