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

#include "s2n_test.h"

#include "utils/s2n_blob.h"

#include <s2n.h>

int raises_error()
{
  S2N_ERROR(S2N_ERR_INVALID_ARGUMENT);
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_stack_traces_enabled_set(true));
    struct s2n_stacktrace trace;
    /* If nothing has errored yet, we have no stacktrace */
    EXPECT_SUCCESS(s2n_get_stacktrace(&trace));
    EXPECT_NULL(trace.trace);
    EXPECT_EQUAL(trace.trace_size, 0);

    /* Raise an error, and see that it generates a stacktrace */
    EXPECT_FAILURE(raises_error());
    EXPECT_SUCCESS(s2n_get_stacktrace(&trace));
    EXPECT_NOT_NULL(trace.trace);
    EXPECT_NOT_EQUAL(trace.trace_size, 0);

    /* Test printing the stacktrace. */
    FILE *stream = fopen("/dev/null","w");
    EXPECT_SUCCESS(s2n_print_stacktrace(stream));
    fclose(stream);

    /* Free the stacktrace to avoid memory leaks */
    EXPECT_SUCCESS(s2n_free_stacktrace());
    END_TEST();
}
