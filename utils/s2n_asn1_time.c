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

#include "utils/s2n_asn1_time.h"
#include "s2n_safety.h"

#include <time.h>
#include <ctype.h>

typedef enum parser_state {
    ON_YEAR_DIGIT_1 = 0,
    ON_YEAR_DIGIT_2,
    ON_YEAR_DIGIT_3,
    ON_YEAR_DIGIT_4,
    ON_MONTH_DIGIT_1,
    ON_MONTH_DIGIT_2,
    ON_DAY_DIGIT_1,
    ON_DAY_DIGIT_2,
    ON_HOUR_DIGIT_1,
    ON_HOUR_DIGIT_2,
    ON_MINUTE_DIGIT_1,
    ON_MINUTE_DIGIT_2,
    ON_SECOND_DIGIT_1,
    ON_SECOND_DIGIT_2,
    ON_SUBSECOND,
    ON_TIMEZONE,
    ON_OFFSET_HOURS_DIGIT_1,
    ON_OFFSET_HOURS_DIGIT_2,
    ON_OFFSET_MINUTES_DIGIT_1,
    ON_OFFSET_MINUTES_DIGIT_2,
    FINISHED,
    PARSE_ERROR
} parser_state;

static inline long get_gmt_offset(struct tm *time) {

#if defined(__USE_BSD)
    return time->tm_gmtoff;
#else
    return time->__tm_gmtoff;
#endif
}

static inline long get_current_timezone_offset(void) {
    struct tm time_ptr;
    time_t raw_time;
    time(&raw_time);
    localtime_r(&raw_time, &time_ptr);
    return get_gmt_offset(&time_ptr);
}

int s2n_asn1_time_to_nano_since_epoch_ticks(const char *asn1_time, uint32_t len, uint64_t *ticks) {

    //figure out if we are on something other than UTC since timegm is not supported everywhere.
    long gmt_offset_current = get_current_timezone_offset();

    uint32_t str_len = len;
    parser_state state = ON_YEAR_DIGIT_1;

    struct tm time = {.tm_hour = 0, .tm_isdst = -1, .tm_mday = 0, .tm_min = 0, .tm_mon = 0,
            .tm_sec = 0, .tm_wday = 0, .tm_yday = 0, .tm_year = 0,
    };

    uint32_t current_pos = 0;
    uint8_t offset_negative = 0;
    uint8_t local_time_assumed = 1;
    uint8_t current_digit = 0;
    long offset_hours = 0;
    long offset_minutes = 0;

    //this is just a standard state machine for ASN1 date format... nothing special.
    //just do a character at a time and change the state per character encountered.
    //when finished the above time structure should be filled in along with some
    //crazy timezone info we'll need shortly afterwards.
    while (state < FINISHED && current_pos < str_len) {
        char current_char = asn1_time[current_pos];
        switch (state) {
            case ON_YEAR_DIGIT_1:
                char_to_digit(current_char, current_digit);
                time.tm_year = current_digit;
                state = ON_YEAR_DIGIT_2;
                current_pos++;
                break;
            case ON_YEAR_DIGIT_2:
                char_to_digit(current_char, current_digit);
                time.tm_year = time.tm_year * 10 + current_digit;
                state = ON_YEAR_DIGIT_3;
                current_pos++;
                break;
            case ON_YEAR_DIGIT_3:
                char_to_digit(current_char, current_digit);
                time.tm_year = time.tm_year * 10 + current_digit;
                state = ON_YEAR_DIGIT_4;
                current_pos++;
                break;
            case ON_YEAR_DIGIT_4:
                char_to_digit(current_char, current_digit);
                time.tm_year = time.tm_year * 10 + current_digit;
                time.tm_year -= 1900;
                state = ON_MONTH_DIGIT_1;
                current_pos++;
                break;
            case ON_MONTH_DIGIT_1:
                char_to_digit(current_char, current_digit);
                time.tm_mon = current_digit;
                current_pos++;
                state = ON_MONTH_DIGIT_2;
                break;
            case ON_MONTH_DIGIT_2:
                char_to_digit(current_char, current_digit);
                time.tm_mon = time.tm_mon * 10 + current_digit;
                time.tm_mon -= 1;
                current_pos++;
                state = ON_DAY_DIGIT_1;
                break;
            case ON_DAY_DIGIT_1:
                char_to_digit(current_char, current_digit);
                time.tm_mday = current_digit;
                current_pos++;
                state = ON_DAY_DIGIT_2;
                break;
            case ON_DAY_DIGIT_2:
                char_to_digit(current_char, current_digit);
                time.tm_mday = time.tm_mday * 10 + current_digit;
                current_pos++;
                state = ON_HOUR_DIGIT_1;
                break;
            case ON_HOUR_DIGIT_1:
                char_to_digit(current_char, current_digit);
                time.tm_hour = current_digit;
                current_pos++;
                state = ON_HOUR_DIGIT_2;
                break;
            case ON_HOUR_DIGIT_2:
                char_to_digit(current_char, current_digit);
                time.tm_hour = time.tm_hour * 10 + current_digit;
                current_pos++;
                state = ON_MINUTE_DIGIT_1;
                break;
            case ON_MINUTE_DIGIT_1:
                char_to_digit(current_char, current_digit);
                time.tm_min = current_digit;
                current_pos++;
                state = ON_MINUTE_DIGIT_2;
                break;
            case ON_MINUTE_DIGIT_2:
                char_to_digit(current_char, current_digit);
                time.tm_min = time.tm_min * 10 + current_digit;
                current_pos++;
                state = ON_SECOND_DIGIT_1;
                break;
            case ON_SECOND_DIGIT_1:
                char_to_digit(current_char, current_digit);
                time.tm_sec = current_digit;
                current_pos++;
                state = ON_SECOND_DIGIT_2;
                break;
            case ON_SECOND_DIGIT_2:
                char_to_digit(current_char, current_digit);
                time.tm_sec = time.tm_sec * 10 + current_digit;
                current_pos++;
                state = ON_SUBSECOND;
                break;
            case ON_SUBSECOND:
                if (current_char == '.' || isdigit(current_char)) {
                    current_pos++;
                } else {
                    state = ON_TIMEZONE;
                }
                break;
            case ON_TIMEZONE:
                if (current_char == 'Z' || current_char == 'z') {
                    local_time_assumed = 0;
                    state = FINISHED;
                } else if (current_char == '-') {
                    local_time_assumed = 0;
                    offset_negative = 1;
                    state = ON_OFFSET_HOURS_DIGIT_1;
                } else if (current_char == '+') {
                    local_time_assumed = 0;
                    offset_negative = 0;
                    state = ON_OFFSET_HOURS_DIGIT_1;
                }

                current_pos++;
                break;
            case ON_OFFSET_HOURS_DIGIT_1:
                char_to_digit(current_char, current_digit);
                offset_hours = current_digit;
                current_pos++;
                state = ON_OFFSET_HOURS_DIGIT_2;
                break;
            case ON_OFFSET_HOURS_DIGIT_2:
                char_to_digit(current_char, current_digit);
                offset_hours = offset_hours * 10 + current_digit;
                current_pos++;
                state = ON_OFFSET_MINUTES_DIGIT_1;
                break;
            case ON_OFFSET_MINUTES_DIGIT_1:
                char_to_digit(current_char, current_digit);
                offset_minutes = current_digit;
                current_pos++;
                state = ON_OFFSET_MINUTES_DIGIT_2;
                char_to_digit(current_char, current_digit);
                break;
            case ON_OFFSET_MINUTES_DIGIT_2:
                char_to_digit(current_char, current_digit);
                offset_minutes = offset_minutes * 10 + current_digit;
                current_pos++;
                state = FINISHED;
                break;
            default:
                state = PARSE_ERROR;
                break;
        }
    }

    if (state > ON_TIMEZONE && state < PARSE_ERROR) {
        time_t clock_data = 0;
        //ASN1 + and - is in format HHMM. We need to convert it to seconds for the adjustment
        long gmt_offset = (offset_hours * 3600) + (offset_minutes * 60);

        if (offset_negative) {
            gmt_offset = 0 - gmt_offset;
        }

        //if we detected UTC is being used (please always use UTC), we need to add the detected timezone on the local
        //machine back to the offset.
        if (!local_time_assumed) {
            gmt_offset -= gmt_offset_current;
        }

        clock_data = mktime(&time);

        //convert to nanoseconds and add the timezone offset.
        if (clock_data > 0) {
            *ticks = ((uint64_t) clock_data - gmt_offset) * 1000000000;
            return 0;
        }
    }

    return -1;
}
