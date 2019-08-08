/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <string.h>

#include "crypto/s2n_hash.h"

#include "utils/s2n_blob.h"

struct s2n_map;

extern struct s2n_map *s2n_map_new();
extern struct s2n_map *s2n_map_new_with_initial_capacity(uint32_t capacity);
extern int s2n_map_add(struct s2n_map *map, struct s2n_blob *key, struct s2n_blob *value);
extern int s2n_map_put(struct s2n_map *map, struct s2n_blob *key, struct s2n_blob *value);
extern int s2n_map_complete(struct s2n_map *map);
extern int s2n_map_unlock(struct s2n_map *map);
extern int s2n_map_lookup(struct s2n_map *map, struct s2n_blob *key, struct s2n_blob *value);
extern int s2n_map_free(struct s2n_map *map);
