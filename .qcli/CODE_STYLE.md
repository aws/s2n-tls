# s2n-tls Code Style Guide

This document outlines the coding conventions and style guidelines for the s2n-tls project.

## Formatting

s2n-tls uses clang-format to enforce consistent code formatting for C. The configuration is defined in the `.clang-format` file at the root of the repository.

To format your code:
```bash
./codebuild/bin/clang_format_changed_files.sh
```

## Language Standard

- s2n-tls is written in C99
- Avoid using C++ features or extensions

## General Style Rules

### Indentation and Spacing
- Use 4 spaces for indentation, never tabs
- Line width of 120 characters is acceptable
- No trailing whitespace
- One empty line at the end of each file

### Braces and Control Structures
- Always include curly braces for control structures, even for single-line blocks
- Opening brace on the same line for control structures
- Opening brace on a new line for function definitions
- Always include a default case in switch statements

```c
if (condition) {
    // Single line still gets braces
}

static int function_name(int parameter)
{
    // Function body
}
```

### Function Design
- Functions should be small and focused (no more than a page or two)
- Functions should have clear input and output parameters
- Follow the "pure function" approach where possible
- Avoid deep nesting of control structures

### Variables and Types
- Use explicitly sized primitives where possible (e.g., uint8_t, uint32_t)
- Use unsigned ints for sizes (following TLS/SSL conventions)
- Declare variables closest to their first point of use
- Initialize variables at declaration when possible
- Structures exposed to application authors must be opaque

### Error Handling
- Always check return values
- Use the GUARD macro for error handling to maintain linear control flow
- Use BAIL macro to surface errors to applications
- Minimize the use of else clauses; favor linear control flow

```c
GUARD(s2n_function_that_might_fail());
// Continue with normal execution
```

### Comments
- Use C-style comments (`/* */`) and avoid C++ comments (`//`)
- Comments should explain *why* code exists, not *what* it does
- Variable and function names should be self-explanatory
- Include references to RFCs or context when necessary
- Every source file must include the Apache Software License 2.0 and copyright notice

```c
/*
 * This function implements the XYZ algorithm from RFC 1234.
 * It's needed because...
 */
```

## Memory Handling

- Use s2n_blob structures to track memory regions
- Use s2n_stuffer structures for buffer manipulation
- Avoid C string functions and standard buffer manipulation patterns
- Follow the stuffer lifecycle guidelines when using raw pointers

## Naming Conventions

- Use snake_case for function and variable names
- Use UPPER_CASE for macros and constants
- Prefix public functions with `s2n_`
- Use descriptive names that indicate purpose

## Header Files

- Include guards should use the pattern: `S2N_[PATH]_[FILE]_H`
- Order includes as: system headers, then library headers, then local headers
- Minimize what is exposed in public headers

## Example

```c
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

#include <stdint.h>

#include "utils/s2n_safety.h"
#include "tls/s2n_connection.h"

S2N_RESULT s2n_example_function(struct s2n_connection *conn, uint32_t value)
{
    GUARD_AS_RESULT(s2n_connection_check_io_status(conn, S2N_IO_WRITABLE));
    
    /* 
     * This calculation is needed to comply with section X.Y of RFC 1234,
     * which requires values to be adjusted based on the connection state.
     */
    uint32_t adjusted_value = value;
    if (conn->mode == S2N_CLIENT) {
        adjusted_value += 1;
    }
    
    GUARD_AS_RESULT(s2n_connection_write_value(conn, adjusted_value));
    
    return S2N_RESULT_OK;
}
```
