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

#include <stdint.h>
#include <time.h>

#include "utils/s2n_result.h"

struct parser_args {
    uint8_t offset_negative;
    uint8_t local_time_assumed;
    uint8_t current_digit;
    long offset_hours;
    long offset_minutes;
    struct tm time;
};

/**
 * Converts an asn1 formatted time string to ticks since epoch in nanoseconds.
 * ticks is an output parameter. Returns 0 on success and -1 on failure.
 */
S2N_RESULT s2n_asn1_time_to_nano_since_epoch_ticks(const char *asn1_time, uint32_t len, uint64_t *ticks);

