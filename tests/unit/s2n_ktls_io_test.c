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

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_ktls.h"

S2N_RESULT s2n_ktls_set_control_data(struct msghdr *msg, char *buf, size_t buf_size,
        int cmsg_type, uint8_t record_type);
S2N_RESULT s2n_ktls_get_control_data(struct msghdr *msg, int cmsg_type, uint8_t *record_type);

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test s2n_ktls_set_control_data and s2n_ktls_get_control_data */
    {
        /* Test: Safety */
        {
            struct msghdr msg = { 0 };
            char buf[100] = { 0 };
            EXPECT_ERROR_WITH_ERRNO(s2n_ktls_set_control_data(NULL, buf, sizeof(buf), 0, 0),
                    S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_ktls_set_control_data(&msg, NULL, sizeof(buf), 0, 0),
                    S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_ktls_set_control_data(&msg, buf, 0, 0, 0),
                    S2N_ERR_NULL);

            uint8_t record_type = 0;
            EXPECT_ERROR_WITH_ERRNO(s2n_ktls_get_control_data(NULL, 0, &record_type),
                    S2N_ERR_NULL);
            EXPECT_ERROR_WITH_ERRNO(s2n_ktls_get_control_data(&msg, 0, NULL),
                    S2N_ERR_NULL);
        };

        /* Test: s2n_ktls_set_control_data msg is parseable by s2n_ktls_get_control_data */
        {
            const uint8_t set_record_type = 5;
            struct msghdr msg = { 0 };
            const int cmsg_type = 11;
            char buf[100] = { 0 };
            EXPECT_OK(s2n_ktls_set_control_data(&msg, buf, sizeof(buf), cmsg_type, set_record_type));

            uint8_t get_record_type = 0;
            EXPECT_OK(s2n_ktls_get_control_data(&msg, cmsg_type, &get_record_type));

            EXPECT_EQUAL(set_record_type, get_record_type);
        };

        /* Test: s2n_ktls_get_control_data fails with unexpected cmsg_type */
        {
            const uint8_t set_record_type = 5;
            struct msghdr msg = { 0 };
            const int cmsg_type = 11;
            char buf[100] = { 0 };
            EXPECT_OK(s2n_ktls_set_control_data(&msg, buf, sizeof(buf), cmsg_type, set_record_type));

            const int bad_cmsg_type = 99;
            uint8_t get_record_type = 0;
            EXPECT_ERROR_WITH_ERRNO(s2n_ktls_get_control_data(&msg, bad_cmsg_type, &get_record_type),
                    S2N_ERR_KTLS_BAD_CMSG);
        };
    };

    END_TEST();
}
