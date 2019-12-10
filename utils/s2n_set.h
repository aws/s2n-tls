/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include "utils/s2n_array.h"

struct s2n_set {
  struct s2n_array *data;
  int (*comparator)(const void*, const void*);
};

extern struct s2n_set *s2n_set_new(size_t element_size, int (*comparator)(const void*, const void*));
extern int s2n_set_add(struct s2n_set *set, void *element);
extern void *s2n_set_get(struct s2n_set *set, uint32_t index);
extern int s2n_set_remove(struct s2n_set *set, uint32_t index);
extern int s2n_set_free_p(struct s2n_set **pset);
extern int s2n_set_free(struct s2n_set *set);
extern int s2n_set_size(struct s2n_set *set);
