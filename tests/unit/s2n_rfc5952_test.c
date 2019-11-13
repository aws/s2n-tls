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

#include <arpa/inet.h>

#include "utils/s2n_rfc5952.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    uint8_t ipv4[4];
    uint8_t ipv6[16];

    uint8_t ipv4_buf[ sizeof("255.255.255.255") ];
    uint8_t ipv6_buf[ sizeof("1111:2222:3333:4444:5555:6666:7777:8888") ];

    struct s2n_blob ipv4_blob = { .data = ipv4_buf, .size = sizeof(ipv4_buf) };
    struct s2n_blob ipv6_blob = { .data = ipv6_buf, .size = sizeof(ipv6_buf) };

    EXPECT_SUCCESS(inet_pton(AF_INET, "111.222.111.111", ipv4));
    EXPECT_SUCCESS(s2n_inet_ntop(AF_INET, ipv4, &ipv4_blob));
    EXPECT_EQUAL(strcmp("111.222.111.111", (char *) ipv4_buf), 0);

    EXPECT_SUCCESS(inet_pton(AF_INET, "0.0.0.0", ipv4));
    EXPECT_SUCCESS(s2n_inet_ntop(AF_INET, ipv4, &ipv4_blob));
    EXPECT_EQUAL(strcmp("0.0.0.0", (char *) ipv4_buf), 0);

    EXPECT_SUCCESS(inet_pton(AF_INET, "100.104.123.1", ipv4));
    EXPECT_SUCCESS(s2n_inet_ntop(AF_INET, ipv4, &ipv4_blob));
    EXPECT_EQUAL(strcmp("100.104.123.1", (char *) ipv4_buf), 0);

    EXPECT_SUCCESS(inet_pton(AF_INET, "255.255.255.255", ipv4));
    EXPECT_SUCCESS(s2n_inet_ntop(AF_INET, ipv4, &ipv4_blob));
    EXPECT_EQUAL(strcmp("255.255.255.255", (char *) ipv4_buf), 0);

    EXPECT_SUCCESS(inet_pton(AF_INET6, "2001:db8:0:0:0:0:2:1", ipv6));
    EXPECT_SUCCESS(s2n_inet_ntop(AF_INET6, ipv6, &ipv6_blob));
    EXPECT_EQUAL(strcmp("2001:db8::2:1", (char *) ipv6_buf), 0);

    EXPECT_SUCCESS(inet_pton(AF_INET6, "2001:db8::1", ipv6));
    EXPECT_SUCCESS(s2n_inet_ntop(AF_INET6, ipv6, &ipv6_blob));
    EXPECT_EQUAL(strcmp("2001:db8::1", (char *) ipv6_buf), 0);

    EXPECT_SUCCESS(inet_pton(AF_INET6, "2001:db8:0:1:1:1:1:1", ipv6));
    EXPECT_SUCCESS(s2n_inet_ntop(AF_INET6, ipv6, &ipv6_blob));
    EXPECT_EQUAL(strcmp("2001:db8:0:1:1:1:1:1", (char *) ipv6_buf), 0);

    EXPECT_SUCCESS(inet_pton(AF_INET6, "2001:db8::1:0:0:1", ipv6));
    EXPECT_SUCCESS(s2n_inet_ntop(AF_INET6, ipv6, &ipv6_blob));
    EXPECT_EQUAL(strcmp("2001:db8::1:0:0:1", (char *) ipv6_buf), 0);

    EXPECT_SUCCESS(inet_pton(AF_INET6, "0:0:0:0:0:0:0:1", ipv6));
    EXPECT_SUCCESS(s2n_inet_ntop(AF_INET6, ipv6, &ipv6_blob));
    EXPECT_EQUAL(strcmp("::1", (char *) ipv6_buf), 0);

    EXPECT_SUCCESS(inet_pton(AF_INET6, "0:0:0:0:0:0:0:0", ipv6));
    EXPECT_SUCCESS(s2n_inet_ntop(AF_INET6, ipv6, &ipv6_blob));
    EXPECT_EQUAL(strcmp("::", (char *) ipv6_buf), 0);

    /* Prevents build failure on Mac */
    #ifndef AF_BLUETOOTH
        #define AF_BLUETOOTH 31
    #endif

    EXPECT_FAILURE_WITH_ERRNO(s2n_inet_ntop(AF_BLUETOOTH, ipv6, &ipv6_blob), S2N_ERR_INVALID_ARGUMENT);
    END_TEST();
}

