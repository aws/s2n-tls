/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "utils/s2n_blob.h"

#include <stdint.h>

int s2n_mem_init(void);
int s2n_mem_cleanup(void);
int s2n_alloc(struct s2n_blob *b, uint32_t size);
int s2n_realloc(struct s2n_blob *b, uint32_t size);
int s2n_free(struct s2n_blob *b);
int s2n_free_object(uint8_t **p_data, uint32_t size);
int s2n_dup(struct s2n_blob *from, struct s2n_blob *to);
