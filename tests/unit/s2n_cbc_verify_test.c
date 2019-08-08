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

#include "s2n_test.h"

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

#include <s2n.h>

#include "testlib/s2n_testlib.h"

#include "tls/s2n_cipher_suites.h"
#include "stuffer/s2n_stuffer.h"
#include "crypto/s2n_cipher.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"
#include "crypto/s2n_hmac.h"
#include "tls/s2n_record.h"
#include "tls/s2n_prf.h"

/*
 * disable everything in this file if the compiler target isn't Intel x86 or x86_64. There's inline asm
 * that can't really be replaced with an analog for other architectures.
 */
#if defined(__x86_64__) || defined(__i386__)
/* qsort() u64s numerically */
static int u64cmp (const void * left, const void * right)
{
   if (*(const uint64_t *)left > *(const uint64_t *)right) return 1;
   if (*(const uint64_t *)left < *(const uint64_t *)right) return -1;
   return 0;
}

/* Generate summary statistics from a list of u64s */
static void summarize(uint64_t *list, int n, uint64_t *count, uint64_t *avg, uint64_t *median, uint64_t *stddev, uint64_t *variance)
{
    qsort(list, n, sizeof(uint64_t), u64cmp);

    uint64_t p25 = list[ n / 4 ];
    uint64_t p50 = list[ n / 2 ];
    uint64_t p75 = list[ n - (n / 4)];
    uint64_t iqr = p75 - p25;

    /* Use the standard interquartile range rule for outlier detection */
    int64_t low = p25 - (iqr * 1.5);
    if (iqr > p25) {
        low = 0;
    }

    *avg = low;
        
    int64_t hi = p75 + (iqr * 1.5);
    /* Ignore overflow as we have plenty of room at the top */

    *count = 0;
    uint64_t sum = 0;
    uint64_t sum_squares = 0;
    uint64_t min = 0xFFFFFFFF;
    uint64_t max = 0;
    
    for (int i = 0; i < n; i++) {
        int64_t value = list[ i ];

        if (value < low || value > hi) {
            continue;
        }

        (*count)++;

        sum += value;
        sum_squares += value * value;

        if (value < min) {
            min = value; 
        }
        if (value > max) {
            max = value;
        }
    }

    *variance = sum_squares - (sum * sum);
    *median = p50;

    if (*count == 0) {
        *avg = 0;
    }
    else {
        *avg = sum / *count;
    }

    if (*count <= 1) {
        *stddev = 0;
    }
    else {
        *stddev = sqrt((*count * *variance) / (*count * (*count - 1)));
    }
}

inline static uint64_t rdtsc(){
    unsigned int bot, top;
    __asm__ __volatile__ ("rdtsc" : "=a" (bot), "=d" (top));
    return ((uint64_t) top << 32) | bot;
}
#endif /* defined(__x86_64__) || defined(__i386__) */

int main(int argc, char **argv)
{
    BEGIN_TEST();
/*
 * disable everything in this test if the compiler target isn't Intel x86 or x86_64. There's inline asm
 * that can't really be replaced with an analog for other architectures.
 */
#if defined(__x86_64__) || defined(__i386__)
    struct s2n_connection *conn;
    uint8_t mac_key[] = "sample mac key";
    uint8_t fragment[S2N_SMALL_FRAGMENT_LENGTH];
    uint8_t random_data[S2N_SMALL_FRAGMENT_LENGTH];
    struct s2n_hmac_state check_mac, record_mac;
    struct s2n_blob r = {.data = random_data, .size = sizeof(random_data)};


    /* Valgrind affects execution timing, making this test unreliable */
    if (getenv("S2N_VALGRIND") != NULL) {
        END_TEST();
    }

    EXPECT_SUCCESS(s2n_hmac_new(&check_mac));
    EXPECT_SUCCESS(s2n_hmac_new(&record_mac));

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));
    EXPECT_SUCCESS(s2n_get_urandom_data(&r));

    /* Emulate TLS1.2 */
    conn->actual_protocol_version = S2N_TLS12;

    /* Try every 16 bytes to simulate block alignments */
    for (int i = 288; i < S2N_SMALL_FRAGMENT_LENGTH; i += 16) {

        EXPECT_SUCCESS(s2n_hmac_init(&record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));

        memcpy(fragment, random_data, i - 20 - 1);
        EXPECT_SUCCESS(s2n_hmac_update(&record_mac, fragment, i - 20 - 1));
        EXPECT_SUCCESS(s2n_hmac_digest(&record_mac, fragment + (i - 20 - 1), 20));

        /* Start out with zero byte padding */
        fragment[i - 1] = 0;
        struct s2n_blob decrypted = { .data = fragment, .size = i};

        uint64_t timings[10001];
        for (int t = 0; t < 10001; t++) {
            EXPECT_SUCCESS(s2n_hmac_init(&check_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));

            uint64_t before = rdtsc();
            EXPECT_SUCCESS(s2n_verify_cbc(conn, &check_mac, &decrypted));
            uint64_t after = rdtsc();

            timings[ t ] = (after - before);
        }

        uint64_t good_median, good_avg, good_stddev, good_variance, good_count;
        summarize(timings, 10001, &good_count, &good_avg, &good_median, &good_stddev, &good_variance);

        for (int t = 0; t < 10001; t++) {
            EXPECT_SUCCESS(s2n_hmac_init(&check_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));

            uint64_t before = rdtsc();
            EXPECT_SUCCESS(s2n_verify_cbc(conn, &check_mac, &decrypted));
            uint64_t after = rdtsc();

            timings[ t ] = (after - before);
        }

        summarize(timings, 10001, &good_count, &good_avg, &good_median, &good_stddev, &good_variance);

        /* Set up a record so that the MAC fails */
        EXPECT_SUCCESS(s2n_hmac_init(&record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));

        /* Set up 254 bytes of padding */
        for (int j = 1; j < 256; j++) {
            fragment[i - j] = 254;
        }

        memcpy(fragment, random_data, i - 20 - 255);
        EXPECT_SUCCESS(s2n_hmac_update(&record_mac, fragment, i - 20 - 255));
        EXPECT_SUCCESS(s2n_hmac_digest(&record_mac, fragment + (i - 20 - 255), 20));

        /* Verify that the record would pass: the MAC and padding are ok */
        EXPECT_SUCCESS(s2n_hmac_init(&check_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
        EXPECT_SUCCESS(s2n_verify_cbc(conn, &check_mac, &decrypted));

        /* Corrupt a HMAC byte */
        fragment[i - 256]++;

        for (int t = 0; t < 10001; t++) {
            EXPECT_SUCCESS(s2n_hmac_init(&check_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));

            uint64_t before = rdtsc();
            EXPECT_FAILURE(s2n_verify_cbc(conn, &check_mac, &decrypted));
            uint64_t after = rdtsc();

            timings[ t ] = (after - before);
        }
        
        uint64_t mac_median, mac_avg, mac_stddev, mac_variance, mac_count;
        summarize(timings, 10001, &mac_count, &mac_avg, &mac_median, &mac_stddev, &mac_variance);

        /* Use a simple 3 sigma test for the median distance from the good */
        int64_t lo = good_median - (3 * good_stddev);
        int64_t hi = good_median + (3 * good_stddev);

        if ((int64_t) mac_median < lo || (int64_t) mac_median > hi) {
            printf("\n\nRecord size: %d\nGood Median: %" PRIu64 " (Avg: %" PRIu64 " Stddev: %" PRIu64 ")\n"
                   "Bad Median: %" PRIu64 " (Avg: %" PRIu64 " Stddev: %" PRIu64 ")\n\n", 
                    i, good_median, good_avg, good_stddev, mac_median, mac_avg, mac_stddev);
            FAIL();
        }

        /* Set up the record so that the HMAC passes, and the padding fails */
        EXPECT_SUCCESS(s2n_hmac_init(&record_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));

        /* Set up 15 bytes of padding */
        for (int j = 1; j < 17; j++) {
            fragment[i - j] = 15;
        }

        memcpy(fragment, random_data, i - 20 - 16);
        EXPECT_SUCCESS(s2n_hmac_update(&record_mac, fragment, i - 20 - 16));
        EXPECT_SUCCESS(s2n_hmac_digest(&record_mac, fragment + (i - 20 - 16), 20));

        /* Verify that the record would pass: the MAC and padding are ok */
        EXPECT_SUCCESS(s2n_hmac_init(&check_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));
        EXPECT_SUCCESS(s2n_verify_cbc(conn, &check_mac, &decrypted));

        /* Now corrupt a padding byte */
        fragment[i - 10]++;

        for (int t = 0; t < 10001; t++) {
            EXPECT_SUCCESS(s2n_hmac_init(&check_mac, S2N_HMAC_SHA1, mac_key, sizeof(mac_key)));

            uint64_t before = rdtsc();
            EXPECT_FAILURE(s2n_verify_cbc(conn, &check_mac, &decrypted));
            uint64_t after = rdtsc();

            timings[ t ] = (after - before);
        }
        
        uint64_t pad_median, pad_avg, pad_stddev, pad_variance, pad_count;
        summarize(timings, 10001, &pad_count, &pad_avg, &pad_median, &pad_stddev, &pad_variance);

        /* Use a simple 3 sigma test for the median from the good */
        lo = good_median - (good_stddev);
        hi = good_median + (good_stddev);

        if ((int64_t) pad_median < lo || (int64_t) pad_median > hi) {
            printf("\n\nRecord size: %d\nGood Median: %" PRIu64 " (Avg: %" PRIu64 " Stddev: %" PRIu64 ")\n"
                   "Bad Median: %" PRIu64 " (Avg: %" PRIu64 " Stddev: %" PRIu64 ")\n\n", 
                    i, good_median, good_avg, good_stddev, pad_median, pad_avg, pad_stddev);
            FAIL();
        }
 
        /* Use a more sensitive 0.5 sigma test for the MAC error from the padding error. This is the
         * the difference that attackers can exploit.
         */
        lo = mac_median - (mac_stddev / 2);
        hi = mac_median + (mac_stddev / 2);

        if ((int64_t) pad_median < lo || (int64_t) pad_median > hi) {
            printf("\n\nRecord size: %d\nMAC Median: %" PRIu64 " (Avg: %" PRIu64 " Stddev: %" PRIu64 ")\n"
                   "PAD Median: %" PRIu64 " (Avg: %" PRIu64 " Stddev: %" PRIu64 ")\n\n", 
                    i, mac_median, mac_avg, mac_stddev, pad_median, pad_avg, pad_stddev);
            FAIL();
        }
    }

    EXPECT_SUCCESS(s2n_hmac_free(&check_mac));
    EXPECT_SUCCESS(s2n_hmac_free(&record_mac));
    EXPECT_SUCCESS(s2n_connection_free(conn));

#endif /* defined(__x86_64__) || defined(__i386__) */
    END_TEST();
}
