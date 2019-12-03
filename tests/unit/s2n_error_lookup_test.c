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

#include <s2n.h>

#include "testlib/s2n_testlib.h"

#include "error/s2n_errno.h"

int main(void)
{
    BEGIN_TEST();

    /* First, test that we can find error message for all defined errors */
    for (int err = S2N_ERR_T_OK_START; err < S2N_ERR_T_OK_END; err++) {
        EXPECT_NOT_EQUAL(strcmp(s2n_strerror_name(err), "Internal s2n error"), 0);
        EXPECT_NOT_EQUAL(strcmp(s2n_strerror(err, "EN"), "Internal s2n error"), 0);
    }
    for (int err = S2N_ERR_T_IO_START; err < S2N_ERR_T_IO_END; err++) {
        EXPECT_NOT_EQUAL(strcmp(s2n_strerror_name(err), "Internal s2n error"), 0);
        EXPECT_NOT_EQUAL(strcmp(s2n_strerror(err, "EN"), "Internal s2n error"), 0);
    }
    for (int err = S2N_ERR_T_CLOSED_START; err < S2N_ERR_T_CLOSED_END; err++) {
        EXPECT_NOT_EQUAL(strcmp(s2n_strerror_name(err), "Internal s2n error"), 0);
        EXPECT_NOT_EQUAL(strcmp(s2n_strerror(err, "EN"), "Internal s2n error"), 0);
    }
    for (int err = S2N_ERR_T_BLOCKED_START; err < S2N_ERR_T_BLOCKED_END; err++) {
        EXPECT_NOT_EQUAL(strcmp(s2n_strerror_name(err), "Internal s2n error"), 0);
        EXPECT_NOT_EQUAL(strcmp(s2n_strerror(err, "EN"), "Internal s2n error"), 0);
    }
    for (int err = S2N_ERR_T_ALERT_START; err < S2N_ERR_T_ALERT_END; err++) {
        EXPECT_NOT_EQUAL(strcmp(s2n_strerror_name(err), "Internal s2n error"), 0);
        EXPECT_NOT_EQUAL(strcmp(s2n_strerror(err, "EN"), "Internal s2n error"), 0);
    }
    for (int err = S2N_ERR_T_PROTO_START; err < S2N_ERR_T_PROTO_END; err++) {
        EXPECT_NOT_EQUAL(strcmp(s2n_strerror_name(err), "Internal s2n error"), 0);
        EXPECT_NOT_EQUAL(strcmp(s2n_strerror(err, "EN"), "Internal s2n error"), 0);
    }
    for (int err = S2N_ERR_T_INTERNAL_START; err < S2N_ERR_T_INTERNAL_END; err++) {
        EXPECT_NOT_EQUAL(strcmp(s2n_strerror_name(err), "Internal s2n error"), 0);
        EXPECT_NOT_EQUAL(strcmp(s2n_strerror(err, "EN"), "Internal s2n error"), 0);
    }
    for (int err = S2N_ERR_T_USAGE_START; err < S2N_ERR_T_USAGE_END; err++) {
        EXPECT_NOT_EQUAL(strcmp(s2n_strerror_name(err), "Internal s2n error"), 0);
        EXPECT_NOT_EQUAL(strcmp(s2n_strerror(err, "EN"), "Internal s2n error"), 0);
    }

    /* Next, test that we get an error wen try to search for non-existing errors for each type */
    EXPECT_EQUAL(strcmp(s2n_strerror_name(S2N_ERR_T_OK_END), "Internal s2n error"), 0);
    EXPECT_EQUAL(strcmp(s2n_strerror(S2N_ERR_T_OK_END, "EN"), "Internal s2n error"), 0);

    EXPECT_EQUAL(strcmp(s2n_strerror_name(S2N_ERR_T_IO_END), "Internal s2n error"), 0);
    EXPECT_EQUAL(strcmp(s2n_strerror(S2N_ERR_T_IO_END, "EN"), "Internal s2n error"), 0);

    EXPECT_EQUAL(strcmp(s2n_strerror_name(S2N_ERR_T_CLOSED_END), "Internal s2n error"), 0);
    EXPECT_EQUAL(strcmp(s2n_strerror(S2N_ERR_T_CLOSED_END, "EN"), "Internal s2n error"), 0);

    EXPECT_EQUAL(strcmp(s2n_strerror_name(S2N_ERR_T_BLOCKED_END), "Internal s2n error"), 0);
    EXPECT_EQUAL(strcmp(s2n_strerror(S2N_ERR_T_BLOCKED_END, "EN"), "Internal s2n error"), 0);

    EXPECT_EQUAL(strcmp(s2n_strerror_name(S2N_ERR_T_ALERT_END), "Internal s2n error"), 0);
    EXPECT_EQUAL(strcmp(s2n_strerror(S2N_ERR_T_ALERT_END, "EN"), "Internal s2n error"), 0);

    EXPECT_EQUAL(strcmp(s2n_strerror_name(S2N_ERR_T_PROTO_END), "Internal s2n error"), 0);
    EXPECT_EQUAL(strcmp(s2n_strerror(S2N_ERR_T_PROTO_END, "EN"), "Internal s2n error"), 0);

    EXPECT_EQUAL(strcmp(s2n_strerror_name(S2N_ERR_T_INTERNAL_END), "Internal s2n error"), 0);
    EXPECT_EQUAL(strcmp(s2n_strerror(S2N_ERR_T_INTERNAL_END, "EN"), "Internal s2n error"), 0);

    EXPECT_EQUAL(strcmp(s2n_strerror_name(S2N_ERR_T_USAGE_END), "Internal s2n error"), 0);
    EXPECT_EQUAL(strcmp(s2n_strerror(S2N_ERR_T_USAGE_END, "EN"), "Internal s2n error"), 0);

    /* And ensure that we get an error in non-existing classes of errors */
    EXPECT_EQUAL(strcmp(s2n_strerror_name((S2N_ERR_T_USAGE + 1) << S2N_ERR_NUM_VALUE_BITS), "Internal s2n error"), 0);
    EXPECT_EQUAL(strcmp(s2n_strerror((S2N_ERR_T_USAGE + 1) << S2N_ERR_NUM_VALUE_BITS, "EN"), "Internal s2n error"), 0);

    /* Test that lookup works even after s2n_cleanup */
    EXPECT_SUCCESS(s2n_cleanup());

    EXPECT_EQUAL(strcmp(s2n_strerror_name(S2N_ERR_OK), "S2N_ERR_OK"), 0);
    EXPECT_EQUAL(strcmp(s2n_strerror(S2N_ERR_OK, "EN"), "no error"), 0);

    END_TEST();
}
