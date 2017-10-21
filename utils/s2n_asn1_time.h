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

/**
 * Converts an asn1 formatted time string to ticks since epoch in nanoseconds.
 * ticks is an output parameter. Returns 0 on success and -1 on failure.
 */
int s2n_asn1_time_to_nano_since_epoch_ticks(const char *asn1_time, uint32_t len, uint64_t *ticks);

