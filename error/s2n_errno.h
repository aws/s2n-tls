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

#include <s2n.h>

#define S2N_DEBUG_STR_LEN 128
extern __thread const char *s2n_debug_str;

#define TO_STRING(s) #s
#define STRING_(s) TO_STRING(s)
#define STRING__LINE__ STRING_(__LINE__)

#define _S2N_ERROR( x )     s2n_debug_str = "Error encountered in " __FILE__ " line " STRING__LINE__ ; s2n_errno = ( x )
#define S2N_ERROR( x )      _S2N_ERROR( ( x ) ); return -1
#define S2N_ERROR_PTR( x )  _S2N_ERROR( ( x ) ); return NULL
