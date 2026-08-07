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

/* Validity-time parsing equivalence — for all generated
 * UTCTime/GeneralizedTime encodings, the hardened parser accepts exactly the
 * RFC 5280-conformant encodings and agrees with libcrypto's ASN1_TIME
 * interpretation on accepted values; non-conformant encodings are rejected.
 *
 * 
 *
 * Generator: time-string generator (conformant and violating).
 * Minimum 100 iterations. */

#include "crypto/s2n_openssl_x509.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_cert_parse.h"

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    #include <openssl/asn1.h>
    #include <openssl/bytestring.h>
    #include <openssl/x509.h>
    #include <stdint.h>
    #include <string.h>
    #include <time.h>

    /* Number of property-test iterations per category. */
    #define PROPERTY_TEST_ITERATIONS 100

/* Simple xorshift32 PRNG for reproducible test sequences. */
static uint32_t s2n_test_xorshift32(uint32_t *state)
{
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

/* Generate a random value in [lo, hi] inclusive using the PRNG. */
static uint32_t s2n_test_rand_range(uint32_t *state, uint32_t lo, uint32_t hi)
{
    return lo + (s2n_test_xorshift32(state) % (hi - lo + 1));
}

/* Days in each month (non-leap year). */
static const uint8_t s2n_test_days_in_month[] = {
    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

static bool s2n_test_is_leap_year(uint32_t year)
{
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

static uint8_t s2n_test_max_day(uint32_t year, uint32_t month)
{
    uint8_t d = s2n_test_days_in_month[month - 1];
    if (month == 2 && s2n_test_is_leap_year(year)) {
        d = 29;
    }
    return d;
}

/* Build a DER TLV for a conformant time encoding.
 * For UTCTime: tag 0x17, length 13, contents "YYMMDDHHMMSSZ"
 * For GeneralizedTime: tag 0x18, length 15, contents "YYYYMMDDHHMMSSZ"
 * Writes into `buf` (must be at least 17 bytes) and sets blob to reference it.
 * Returns the total TLV size. */
static size_t s2n_test_build_time_tlv(uint8_t *buf, bool is_utc,
        uint32_t year, uint32_t month, uint32_t day,
        uint32_t hour, uint32_t minute, uint32_t second)
{
    size_t offset = 0;
    if (is_utc) {
        buf[offset++] = 0x17; /* UTCTime tag */
        buf[offset++] = 13;   /* length */
        uint32_t yy = year % 100;
        buf[offset++] = (uint8_t) ('0' + yy / 10);
        buf[offset++] = (uint8_t) ('0' + yy % 10);
    } else {
        buf[offset++] = 0x18; /* GeneralizedTime tag */
        buf[offset++] = 15;   /* length */
        buf[offset++] = (uint8_t) ('0' + year / 1000);
        buf[offset++] = (uint8_t) ('0' + (year / 100) % 10);
        buf[offset++] = (uint8_t) ('0' + (year / 10) % 10);
        buf[offset++] = (uint8_t) ('0' + year % 10);
    }
    buf[offset++] = (uint8_t) ('0' + month / 10);
    buf[offset++] = (uint8_t) ('0' + month % 10);
    buf[offset++] = (uint8_t) ('0' + day / 10);
    buf[offset++] = (uint8_t) ('0' + day % 10);
    buf[offset++] = (uint8_t) ('0' + hour / 10);
    buf[offset++] = (uint8_t) ('0' + hour % 10);
    buf[offset++] = (uint8_t) ('0' + minute / 10);
    buf[offset++] = (uint8_t) ('0' + minute % 10);
    buf[offset++] = (uint8_t) ('0' + second / 10);
    buf[offset++] = (uint8_t) ('0' + second % 10);
    buf[offset++] = 'Z';
    return offset;
}

/* Cross-check a conformant time encoding against libcrypto's ASN1_TIME.
 * Constructs an ASN1_TIME from the time string, converts to struct tm,
 * then to posix seconds, and compares with s2n_cert_parse_time's result. */
static S2N_RESULT s2n_test_crosscheck_time(const uint8_t *tlv_buf, size_t tlv_len,
        uint64_t s2n_seconds)
{
    /* The TLV is tag + length + contents. Extract the contents string
     * for ASN1_TIME_set_string (needs NUL-terminated copy). */
    RESULT_ENSURE(tlv_len >= 2, S2N_ERR_SAFETY);
    uint8_t tag = tlv_buf[0];
    size_t content_len = tlv_buf[1];
    RESULT_ENSURE(content_len + 2 == tlv_len, S2N_ERR_SAFETY);

    /* NUL-terminated copy of the time string contents. */
    char time_str[16] = { 0 };
    RESULT_ENSURE(content_len < sizeof(time_str), S2N_ERR_SAFETY);
    memcpy(time_str, &tlv_buf[2], content_len);
    time_str[content_len] = '\0';

    /* Build an ASN1_TIME and set it from our generated string. */
    ASN1_TIME *asn1_time = ASN1_TIME_new();
    RESULT_ENSURE_REF(asn1_time);

    /* ASN1_TIME_set_string populates the ASN1_TIME from the text. */
    int set_ok = ASN1_TIME_set_string(asn1_time, time_str);
    if (set_ok != 1) {
        /* libcrypto couldn't parse it — unexpected for our conformant
         * encodings. */
        ASN1_TIME_free(asn1_time);
        RESULT_BAIL(S2N_ERR_SAFETY);
    }

    /* Override the type to match (UTCTime=23, GeneralizedTime=24). */
    if (tag == 0x17) {
        asn1_time->type = V_ASN1_UTCTIME;
    } else {
        asn1_time->type = V_ASN1_GENERALIZEDTIME;
    }

    /* ASN1_TIME_to_time_t is used instead of ASN1_TIME_to_tm +
     * OPENSSL_tm_to_posix because it exists on every aws-lc branch the CBS
     * builds support (awslc-fips-2022 predates the other two). */
    time_t posix_seconds = 0;
    int posix_ok = ASN1_TIME_to_time_t(asn1_time, &posix_seconds);
    ASN1_TIME_free(asn1_time);
    RESULT_ENSURE(posix_ok == 1, S2N_ERR_SAFETY);

    /* Pre-epoch times are saturated to 0 by s2n_cert_parse_time. */
    uint64_t expected = (posix_seconds < 0) ? 0 : (uint64_t) posix_seconds;
    RESULT_ENSURE(s2n_seconds == expected, S2N_ERR_SAFETY);

    return S2N_RESULT_OK;
}

/* Non-conformant encoding violation types. */
typedef enum {
    VIOLATION_MISSING_Z = 0,
    VIOLATION_OFFSET_SUFFIX,
    VIOLATION_FRACTIONAL_SECONDS,
    VIOLATION_NON_DIGIT,
    VIOLATION_WRONG_LENGTH_SHORT,
    VIOLATION_WRONG_LENGTH_LONG,
    VIOLATION_OUT_OF_RANGE_MONTH,
    VIOLATION_OUT_OF_RANGE_DAY,
    VIOLATION_OUT_OF_RANGE_HOUR,
    VIOLATION_OUT_OF_RANGE_MINUTE,
    VIOLATION_OUT_OF_RANGE_SECOND,
    VIOLATION_BAD_TAG,
    VIOLATION_COUNT,
} s2n_test_violation_type;

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

int main(int argc, char **argv)
{
    BEGIN_TEST();

#if S2N_LIBCRYPTO_SUPPORTS_CBS

    /* PART 1: Conformant time encodings — generate random valid times,
     * verify s2n_cert_parse_time accepts them, and cross-check against
     * libcrypto's ASN1_TIME interpretation. */
    {
        uint32_t prng_state = 0xDEADBEEF; /* fixed seed for reproducibility */

        for (uint32_t iter = 0; iter < PROPERTY_TEST_ITERATIONS; iter++) {
            /* Pick UTCTime or GeneralizedTime. */
            bool is_utc = (s2n_test_xorshift32(&prng_state) % 2) == 0;

            uint32_t year = 0;
            if (is_utc) {
                /* UTCTime: generate only post-epoch years for the cross-check.
                 * YY 70-99 maps to 1970-1999; YY 00-49 maps to 2000-2049.
                 * Pre-epoch saturation is tested separately in Part 3. */
                uint32_t yy = s2n_test_rand_range(&prng_state, 0, 99);
                year = (yy < 50) ? 2000 + yy : 1900 + yy;
                /* Skip pre-epoch years for the libcrypto cross-check. */
                if (year < 1970) {
                    year = 2000 + (year % 50);
                }
            } else {
                /* GeneralizedTime: full 4-digit year. Keep in range for posix
                 * cross-check (1970-2099 stays in range for
                 * OPENSSL_tm_to_posix). */
                year = s2n_test_rand_range(&prng_state, 1970, 2099);
            }

            uint32_t month = s2n_test_rand_range(&prng_state, 1, 12);
            uint32_t max_d = s2n_test_max_day(year, month);
            uint32_t day = s2n_test_rand_range(&prng_state, 1, max_d);
            uint32_t hour = s2n_test_rand_range(&prng_state, 0, 23);
            uint32_t minute = s2n_test_rand_range(&prng_state, 0, 59);
            uint32_t second = s2n_test_rand_range(&prng_state, 0, 59);

            uint8_t tlv_buf[17] = { 0 };
            size_t tlv_len = s2n_test_build_time_tlv(tlv_buf, is_utc,
                    year, month, day, hour, minute, second);

            struct s2n_blob time_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&time_blob, tlv_buf, (uint32_t) tlv_len));

            /* s2n_cert_parse_time must accept this conformant encoding. */
            uint64_t s2n_seconds = 0;
            EXPECT_OK(s2n_cert_parse_time(&time_blob, &s2n_seconds));

            /* Cross-check against libcrypto. */
            EXPECT_OK(s2n_test_crosscheck_time(tlv_buf, tlv_len, s2n_seconds));
        }
    }

    /* PART 2: Non-conformant time encodings — generate violations of various
     * kinds and verify s2n_cert_parse_time rejects them all with
     * S2N_ERR_CERT_INVALID. */
    {
        uint32_t prng_state = 0xCAFEBABE; /* different seed */

        for (uint32_t iter = 0; iter < PROPERTY_TEST_ITERATIONS; iter++) {
            s2n_test_violation_type violation = (s2n_test_violation_type) (iter % VIOLATION_COUNT);

            /* Start from a conformant base encoding. */
            bool is_utc = (s2n_test_xorshift32(&prng_state) % 2) == 0;
            uint32_t year = is_utc ? s2n_test_rand_range(&prng_state, 1970, 2049) : s2n_test_rand_range(&prng_state, 1970, 2099);
            /* For UTCTime, store the 2-digit year representation. */
            uint32_t utc_year = year;
            if (is_utc) {
                /* Ensure the year fits UTCTime range properly. */
                if (year >= 2000) {
                    utc_year = year; /* YY < 50 maps to 20YY */
                } else {
                    utc_year = year; /* YY >= 50 maps to 19YY */
                }
            }
            uint32_t month = s2n_test_rand_range(&prng_state, 1, 12);
            uint32_t max_d = s2n_test_max_day(year, month);
            uint32_t day = s2n_test_rand_range(&prng_state, 1, max_d);
            uint32_t hour = s2n_test_rand_range(&prng_state, 0, 23);
            uint32_t minute = s2n_test_rand_range(&prng_state, 0, 59);
            uint32_t second = s2n_test_rand_range(&prng_state, 0, 59);

            /* Build the base conformant TLV, then apply the violation. */
            uint8_t tlv_buf[32] = { 0 };
            size_t tlv_len = s2n_test_build_time_tlv(tlv_buf, is_utc,
                    utc_year, month, day, hour, minute, second);

            /* Apply the violation to create a non-conformant encoding. */
            uint8_t bad_buf[32] = { 0 };
            memcpy(bad_buf, tlv_buf, tlv_len);
            size_t bad_len = tlv_len;

            switch (violation) {
                case VIOLATION_MISSING_Z:
                    /* Remove the trailing 'Z' by shortening content by 1. */
                    bad_len -= 1;
                    bad_buf[1] -= 1; /* adjust length byte */
                    break;

                case VIOLATION_OFFSET_SUFFIX:
                    /* Replace 'Z' with '+0000' offset (need more space). */
                    bad_buf[bad_len - 1] = '+';
                    bad_buf[bad_len] = '0';
                    bad_buf[bad_len + 1] = '0';
                    bad_buf[bad_len + 2] = '0';
                    bad_buf[bad_len + 3] = '0';
                    bad_len += 4;
                    bad_buf[1] += 4; /* adjust length */
                    break;

                case VIOLATION_FRACTIONAL_SECONDS:
                    /* Insert ".123" before the Z (increase length). */
                    memmove(&bad_buf[bad_len - 1 + 4], &bad_buf[bad_len - 1], 1);
                    bad_buf[bad_len - 1] = '.';
                    bad_buf[bad_len] = '1';
                    bad_buf[bad_len + 1] = '2';
                    bad_buf[bad_len + 2] = '3';
                    bad_len += 4;
                    bad_buf[1] += 4; /* adjust length */
                    break;

                case VIOLATION_NON_DIGIT: {
                    /* Replace a random digit with a non-digit character. */
                    uint32_t digit_pos = 2 + (s2n_test_xorshift32(&prng_state) % (uint32_t) (bad_len - 3));
                    /* Make sure we're targeting a digit position, not the Z. */
                    if (digit_pos >= bad_len - 1) {
                        digit_pos = 2;
                    }
                    bad_buf[digit_pos] = 'X';
                    break;
                }

                case VIOLATION_WRONG_LENGTH_SHORT:
                    /* Set length to content_len - 2 (too short). */
                    bad_buf[1] = (uint8_t) (bad_buf[1] - 2);
                    bad_len -= 2;
                    break;

                case VIOLATION_WRONG_LENGTH_LONG:
                    /* Set length to content_len + 2 (too long). Append garbage. */
                    bad_buf[1] = (uint8_t) (bad_buf[1] + 2);
                    bad_buf[bad_len] = 0x00;
                    bad_buf[bad_len + 1] = 0x00;
                    bad_len += 2;
                    break;

                case VIOLATION_OUT_OF_RANGE_MONTH: {
                    /* Set month to 13 or 00. */
                    size_t month_offset = is_utc ? 4 : 6;
                    bad_buf[month_offset] = '1';
                    bad_buf[month_offset + 1] = '3';
                    break;
                }

                case VIOLATION_OUT_OF_RANGE_DAY: {
                    /* Set day to 32. */
                    size_t day_offset = is_utc ? 6 : 8;
                    bad_buf[day_offset] = '3';
                    bad_buf[day_offset + 1] = '2';
                    break;
                }

                case VIOLATION_OUT_OF_RANGE_HOUR: {
                    /* Set hour to 24. */
                    size_t hour_offset = is_utc ? 8 : 10;
                    bad_buf[hour_offset] = '2';
                    bad_buf[hour_offset + 1] = '4';
                    break;
                }

                case VIOLATION_OUT_OF_RANGE_MINUTE: {
                    /* Set minute to 60. */
                    size_t minute_offset = is_utc ? 10 : 12;
                    bad_buf[minute_offset] = '6';
                    bad_buf[minute_offset + 1] = '0';
                    break;
                }

                case VIOLATION_OUT_OF_RANGE_SECOND: {
                    /* Set second to 60 (leap second; rejected per RFC 5280). */
                    size_t second_offset = is_utc ? 12 : 14;
                    bad_buf[second_offset] = '6';
                    bad_buf[second_offset + 1] = '0';
                    break;
                }

                case VIOLATION_BAD_TAG: {
                    /* Use an invalid tag (not UTCTime or GeneralizedTime). */
                    bad_buf[0] = 0x16; /* IA5String tag */
                    break;
                }

                default:
                    break;
            }

            struct s2n_blob bad_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&bad_blob, bad_buf, (uint32_t) bad_len));

            /* s2n_cert_parse_time must reject this non-conformant encoding. */
            uint64_t dummy_seconds = 0;
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_cert_parse_time(&bad_blob, &dummy_seconds),
                    S2N_ERR_CERT_INVALID);
        }
    }

    /* PART 3: Additional conformant edge cases — pre-epoch UTCTime values
     * (years 1950-1969 via UTCTime) should succeed and saturate to 0. */
    {
        uint32_t prng_state = 0x12345678;

        for (uint32_t iter = 0; iter < 20; iter++) {
            /* UTCTime YY in 50-69 maps to 1950-1969 (pre-epoch). */
            uint32_t yy = s2n_test_rand_range(&prng_state, 50, 69);
            uint32_t year = 1900 + yy;
            uint32_t month = s2n_test_rand_range(&prng_state, 1, 12);
            uint32_t max_d = s2n_test_max_day(year, month);
            uint32_t day = s2n_test_rand_range(&prng_state, 1, max_d);
            uint32_t hour = s2n_test_rand_range(&prng_state, 0, 23);
            uint32_t minute = s2n_test_rand_range(&prng_state, 0, 59);
            uint32_t second = s2n_test_rand_range(&prng_state, 0, 59);

            uint8_t tlv_buf[17] = { 0 };
            size_t tlv_len = s2n_test_build_time_tlv(tlv_buf, true,
                    year, month, day, hour, minute, second);

            struct s2n_blob time_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&time_blob, tlv_buf, (uint32_t) tlv_len));

            uint64_t s2n_seconds = 42; /* non-zero to verify saturation */
            EXPECT_OK(s2n_cert_parse_time(&time_blob, &s2n_seconds));
            /* Pre-epoch values saturate to 0. */
            EXPECT_EQUAL(s2n_seconds, 0);
        }
    }

    /* PART 4: Conformant GeneralizedTime with years < 1970 — these should
     * succeed and saturate to 0 as well. */
    {
        uint32_t prng_state = 0xABCDEF01;

        for (uint32_t iter = 0; iter < 10; iter++) {
            uint32_t year = s2n_test_rand_range(&prng_state, 1900, 1969);
            uint32_t month = s2n_test_rand_range(&prng_state, 1, 12);
            uint32_t max_d = s2n_test_max_day(year, month);
            uint32_t day = s2n_test_rand_range(&prng_state, 1, max_d);
            uint32_t hour = s2n_test_rand_range(&prng_state, 0, 23);
            uint32_t minute = s2n_test_rand_range(&prng_state, 0, 59);
            uint32_t second = s2n_test_rand_range(&prng_state, 0, 59);

            uint8_t tlv_buf[17] = { 0 };
            size_t tlv_len = s2n_test_build_time_tlv(tlv_buf, false,
                    year, month, day, hour, minute, second);

            struct s2n_blob time_blob = { 0 };
            EXPECT_SUCCESS(s2n_blob_init(&time_blob, tlv_buf, (uint32_t) tlv_len));

            uint64_t s2n_seconds = 42;
            EXPECT_OK(s2n_cert_parse_time(&time_blob, &s2n_seconds));
            EXPECT_EQUAL(s2n_seconds, 0);
        }
    }

    /* PART 5: Feb 29 on leap years must be accepted; Feb 29 on non-leap
     * years must be rejected. */
    {
        /* 2024 is a leap year: Feb 29 should succeed. */
        uint8_t tlv_buf[17] = { 0 };
        size_t tlv_len = s2n_test_build_time_tlv(tlv_buf, false,
                2024, 2, 29, 12, 0, 0);
        struct s2n_blob time_blob = { 0 };
        EXPECT_SUCCESS(s2n_blob_init(&time_blob, tlv_buf, (uint32_t) tlv_len));
        uint64_t seconds = 0;
        EXPECT_OK(s2n_cert_parse_time(&time_blob, &seconds));
        EXPECT_TRUE(seconds > 0);

        /* 2023 is not a leap year: Feb 29 should be rejected. */
        tlv_len = s2n_test_build_time_tlv(tlv_buf, false,
                2023, 2, 29, 12, 0, 0);
        EXPECT_SUCCESS(s2n_blob_init(&time_blob, tlv_buf, (uint32_t) tlv_len));
        EXPECT_ERROR_WITH_ERRNO(
                s2n_cert_parse_time(&time_blob, &seconds),
                S2N_ERR_CERT_INVALID);

        /* 2000 is a leap year (div by 400): Feb 29 should succeed. */
        tlv_len = s2n_test_build_time_tlv(tlv_buf, false,
                2000, 2, 29, 12, 0, 0);
        EXPECT_SUCCESS(s2n_blob_init(&time_blob, tlv_buf, (uint32_t) tlv_len));
        EXPECT_OK(s2n_cert_parse_time(&time_blob, &seconds));
        EXPECT_TRUE(seconds > 0);

        /* 1900 is NOT a leap year (div by 100 but not 400): Feb 29 rejected. */
        tlv_len = s2n_test_build_time_tlv(tlv_buf, false,
                1900, 2, 29, 12, 0, 0);
        EXPECT_SUCCESS(s2n_blob_init(&time_blob, tlv_buf, (uint32_t) tlv_len));
        EXPECT_ERROR_WITH_ERRNO(
                s2n_cert_parse_time(&time_blob, &seconds),
                S2N_ERR_CERT_INVALID);

        /* UTCTime: YY=00 maps to 2000 (leap year): Feb 29 should succeed. */
        tlv_len = s2n_test_build_time_tlv(tlv_buf, true,
                2000, 2, 29, 12, 0, 0);
        EXPECT_SUCCESS(s2n_blob_init(&time_blob, tlv_buf, (uint32_t) tlv_len));
        EXPECT_OK(s2n_cert_parse_time(&time_blob, &seconds));
        EXPECT_TRUE(seconds > 0);
    }

#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

    END_TEST();
}
