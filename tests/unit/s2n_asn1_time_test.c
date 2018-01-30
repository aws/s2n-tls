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

#include "s2n_test.h"
#include "utils/s2n_asn1_time.h"

#include <stdlib.h>
#include <time.h>

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* October 20, 2017 3:09:11 PM GMT-07:00 */
    uint64_t expected_ns = 1508539878000000000;

    /* test GMT date parses without the millis*/
    {
        const char *time_str = "20171020225118Z";
        uint64_t timestamp = 0;
        EXPECT_SUCCESS(s2n_asn1_time_to_nano_since_epoch_ticks(time_str, strlen(time_str), &timestamp));
        EXPECT_EQUAL(expected_ns, timestamp);
    }

    /* test GMT date parses */
    {
        const char *time_str = "20171020225118.999Z";
        uint64_t timestamp = 0;
        EXPECT_SUCCESS(s2n_asn1_time_to_nano_since_epoch_ticks(time_str, strlen(time_str), &timestamp));
        EXPECT_EQUAL(expected_ns, timestamp);
    }

    /* test zero offset date parses */
    {
        const char *time_str = "20171020225118.999+0000";
        uint64_t timestamp = 0;
        EXPECT_SUCCESS(s2n_asn1_time_to_nano_since_epoch_ticks(time_str, strlen(time_str), &timestamp));
        EXPECT_EQUAL(expected_ns, timestamp);
    }

    /* test 1:15 west offset date parses */
    {
        const char *time_str = "20171020213618.999-0115";
        uint64_t timestamp = 0;
        EXPECT_SUCCESS(s2n_asn1_time_to_nano_since_epoch_ticks(time_str, strlen(time_str), &timestamp));
        EXPECT_EQUAL(expected_ns, timestamp);
    }

    /* test 1:15 east offset date parses */
    {
        const char *time_str = "20171021000618.999+0115";
        uint64_t timestamp = 0;
        EXPECT_SUCCESS(s2n_asn1_time_to_nano_since_epoch_ticks(time_str, strlen(time_str), &timestamp));
        EXPECT_EQUAL(expected_ns, timestamp);
    }

    /* test invalid date fails */
    {
        const char *time_str = "201710210";
        uint64_t timestamp = 0;
        int err_code = s2n_asn1_time_to_nano_since_epoch_ticks(time_str, strlen(time_str), &timestamp);
        EXPECT_NOT_EQUAL(0, err_code);
    }

    /* test invalid tz character fails. */
    {
        const char *time_str = "20171020225118.999q";
        uint64_t timestamp = 0;
        int err_code = s2n_asn1_time_to_nano_since_epoch_ticks(time_str, strlen(time_str), &timestamp);
        EXPECT_NOT_EQUAL(0, err_code);
    }

    /* test invalid month fails. */
    {
        const char *time_str = "20171320225118.999Z";
        uint64_t timestamp = 0;
        int err_code = s2n_asn1_time_to_nano_since_epoch_ticks(time_str, strlen(time_str), &timestamp);
        EXPECT_NOT_EQUAL(0, err_code);
    }

    /* test invalid day fails. */
    {
        const char *time_str = "20171032225118.999Z";
        uint64_t timestamp = 0;
        int err_code = s2n_asn1_time_to_nano_since_epoch_ticks(time_str, strlen(time_str), &timestamp);
        EXPECT_NOT_EQUAL(0, err_code);
    }

    /* test invalid hour fails. */
    {
        const char *time_str = "20171020255118.999Z";
        uint64_t timestamp = 0;
        int err_code = s2n_asn1_time_to_nano_since_epoch_ticks(time_str, strlen(time_str), &timestamp);
        EXPECT_NOT_EQUAL(0, err_code);
    }

    /* test invalid minute fails. */
    {
        const char *time_str = "20171020226118.999Z";
        uint64_t timestamp = 0;
        int err_code = s2n_asn1_time_to_nano_since_epoch_ticks(time_str, strlen(time_str), &timestamp);
        EXPECT_NOT_EQUAL(0, err_code);
    }

    /* test invalid second fails. */
    {
        const char *time_str = "20171020225161.999Z";
        uint64_t timestamp = 0;
        int err_code = s2n_asn1_time_to_nano_since_epoch_ticks(time_str, strlen(time_str), &timestamp);
        EXPECT_NOT_EQUAL(0, err_code);
    }

    /* test empty fails */
    {
        const char *time_str = "";
        uint64_t timestamp = 0;
        int err_code = s2n_asn1_time_to_nano_since_epoch_ticks(time_str, strlen(time_str), &timestamp);
        EXPECT_NOT_EQUAL(0, err_code);
    }

    /* now run a test where we are certain UTC is not the timezone used, but make sure it still converts.
     * Also note, the moment timezones come into play, so does daylight savings time. So there are two tests here, across the timezone boundaries.*/
    {
        char *tz = getenv("TZ");
        setenv("TZ", "US/Pacific", 1);
        tzset();
        const char *dst_time_str = "20171020225118.999Z";
        uint64_t timestamp = 0;
        EXPECT_SUCCESS(s2n_asn1_time_to_nano_since_epoch_ticks(dst_time_str, strlen(dst_time_str), &timestamp));
        EXPECT_EQUAL(expected_ns, timestamp);

        uint64_t non_dst_stamp = 1510610608000000000;
        const char *non_dst_str = "20171113220328.999Z";
        timestamp = 0;
        EXPECT_SUCCESS(s2n_asn1_time_to_nano_since_epoch_ticks(non_dst_str, strlen(non_dst_str), &timestamp));
        EXPECT_EQUAL(non_dst_stamp, timestamp);
        if(tz) {
            setenv("TZ", tz, 1);
        }
        tzset();
    }

    /* make sure a leap-year date works */
    {
        const char *leap_yr = "20200229220328.999Z";
        uint64_t leap_yr_stamp = 1583013808000000000;
        uint64_t timestamp = 0;
        EXPECT_SUCCESS(s2n_asn1_time_to_nano_since_epoch_ticks(leap_yr, strlen(leap_yr), &timestamp));
        EXPECT_EQUAL(leap_yr_stamp, timestamp);
    }

    /* make sure a leap-year date on a non-leap year works */
    {
        const char *non_leap_yr = "20170229220328.999Z";
        uint64_t non_leap_yr_stamp = 1488405808000000000;
        uint64_t timestamp = 0;
        EXPECT_SUCCESS(s2n_asn1_time_to_nano_since_epoch_ticks(non_leap_yr, strlen(non_leap_yr), &timestamp));
        EXPECT_EQUAL(non_leap_yr_stamp, timestamp);
    }

    /* test non digit character fails */
    {
        const char *time_str = "2017102B225118.999Z";
        uint64_t timestamp = 0;
        int err_code = s2n_asn1_time_to_nano_since_epoch_ticks(time_str, strlen(time_str), &timestamp);
        EXPECT_NOT_EQUAL(0, err_code);
    }
    END_TEST();
}
