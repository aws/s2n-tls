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

#include <stdio.h>
#include <string.h>

#include "api/s2n.h"
#include "crypto/s2n_certificate.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "utils/s2n_safety.h"

struct wildcardify_test_case {
    const char *hostname;
    const char *output;
};

struct wildcardify_test_case wildcardify_test_cases[] = {
    { .hostname = "foo.bar.com", .output = "*.bar.com" },
    { .hostname = "localhost", .output = NULL },
    { .hostname = "one.com", .output = "*.com" },
    { .hostname = "foo*.bar*.com*", .output = "*.bar*.com*" },
    { .hostname = "foo.bar.com.", .output = "*.bar.com." },
    { .hostname = "*.a.c", .output = "*.a.c" },
    { .hostname = "*", .output = NULL },
    { .hostname = "foo.", .output = "*." },
};

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    const int num_wildcardify_tests = s2n_array_len(wildcardify_test_cases);
    for (size_t i = 0; i < num_wildcardify_tests; i++) {
        const char *hostname = wildcardify_test_cases[i].hostname;
        struct s2n_blob hostname_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&hostname_blob, (uint8_t *) (uintptr_t) hostname, strlen(hostname)));
        uint8_t output[S2N_MAX_SERVER_NAME] = { 0 };
        struct s2n_blob output_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&output_blob, (uint8_t *) (uintptr_t) output, sizeof(output)));
        struct s2n_stuffer hostname_stuffer = { 0 };
        struct s2n_stuffer output_stuffer = { 0 };
        EXPECT_SUCCESS(s2n_stuffer_init(&hostname_stuffer, &hostname_blob));
        EXPECT_SUCCESS(s2n_stuffer_skip_write(&hostname_stuffer, hostname_blob.size));
        EXPECT_SUCCESS(s2n_stuffer_init(&output_stuffer, &output_blob));
        EXPECT_SUCCESS(s2n_create_wildcard_hostname(&hostname_stuffer, &output_stuffer));

        /* Make sure the wildcard generated matches the output we expect. */
        const uint32_t wildcard_len = s2n_stuffer_data_available(&output_stuffer);
        const char *expected_output = wildcardify_test_cases[i].output;
        if (wildcard_len > 0) {
            EXPECT_EQUAL(wildcard_len, strlen(expected_output));
            EXPECT_SUCCESS(memcmp(output, expected_output, wildcard_len));
        } else {
            EXPECT_EQUAL(expected_output, NULL);
        }
    }

    END_TEST();
}
