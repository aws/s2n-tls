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
#include "utils/s2n_str.h"

#define BUF_SIZE 10

int main(int argc, char **argv)
{
    char buf[BUF_SIZE];

    BEGIN_TEST();

    char *p = buf;
    char *last = buf + BUF_SIZE;
    const char *hello = "Hello";
    const char *world = " World!";
    const char *expect_result = "Hello Wor";
    const char *hi = " Hi!";
    const char *hello_hi = "Hello Hi!";

    p = s2n_strcpy(p, last, hello);
    EXPECT_TRUE(0 == strcmp(buf, hello));

    /* buf = last, string does not change */
    p = s2n_strcpy(p, p, hello);
    EXPECT_TRUE(0 == strcmp(buf, hello));

    /* buf > last, string does not change */
    p = s2n_strcpy(p, buf, hello);
    EXPECT_TRUE(0 == strcmp(buf, hello));

    /* last - buf - 1 <= length of src string, output string length is truncated to buf size - 1 */
    p = s2n_strcpy(p, last, world);
    EXPECT_TRUE(0 == strcmp(buf, expect_result));

    /* NULL src, a NULL terminator should be added */
    p = buf;
    p = s2n_strcpy(p, last, NULL);
    EXPECT_EQUAL(*p, '\0');

    p = s2n_strcpy(p, last, hello);
    EXPECT_TRUE(0 == strcmp(buf, hello));

    /* buf + 1 = last, a NULL terminator should be added */
    *p = 'a';
    p = s2n_strcpy(p, p + 1, hello);
    EXPECT_TRUE(0 == strcmp(buf, hello));

    /* Normal case, string just fit buf size */
    p = s2n_strcpy(p, last, hi);
    EXPECT_TRUE(0 == strcmp(buf, hello_hi));

    /* Writing to the end buf does not change the string */
    p = s2n_strcpy(p, last, "s2n");
    EXPECT_TRUE(0 == strcmp(buf, hello_hi));

    END_TEST();
}
