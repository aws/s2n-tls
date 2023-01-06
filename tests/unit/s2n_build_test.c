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
#include <stdlib.h>

#include "s2n_test.h"


extern char **environ;

int main(int argc, char **argv)
{
    BEGIN_TEST();

    (void) argc, (void) argv;
    printf("s2n_build_test:\nPrinting Environment Variables:\n");
    for (char **env = environ; *env != 0; env++)
    {
        // printf("%s\n", *env);
        (void) env;
    }

    const char *s2n_build_preset = getenv("S2N_BUILD_PRESET");
    EXPECT_NOT_NULL(s2n_build_preset);
    const char *s2n_libcrypto = getenv("S2N_LIBCRYPTO");
    EXPECT_NOT_NULL(s2n_build_preset);

    #define MATCHES(x) strcmp(s2n_build_preset, x) == 0
    #define CHK_LC(x) EXPECT_EQUAL(strcmp(s2n_libcrypto, x), 0)
    /* Verify that the environment  */
    if (MATCHES("awslc_gcc4-8")
            || MATCHES("awslc_gcc9")) {
        CHK_LC("awslc");
    } else if (MATCHES("awslc-fips_gcc4-8")
            || MATCHES("awslc-fips_gcc9")) {
        CHK_LC("awslc-fips");
    } else if (MATCHES("libressl_gcc6")
            || MATCHES("libressl_gcc9")) {
        CHK_LC("libressl");
    } else if (MATCHES("boringssl")) {
        CHK_LC("boringssl");
    } else if (MATCHES("openssl-1-0-2")) {
        CHK_LC("openssl-1.0.2");
    } else if (MATCHES("openssl-1.0.2-fips")) {
        CHK_LC("openssl-1.0.2-fips");
    } else if (MATCHES("openssl-1.1.1_gcc4-8")
            || MATCHES("openssl-1.1.1_gcc6")
            || MATCHES("openssl-1.1.1_gcc6_softcrypto")
            || MATCHES("openssl-1.1.1_gcc9")) {
        CHK_LC("openssl-1.1.1");
    } else if (MATCHES("openssl-3.0")) {
        CHK_LC("openssl-3.0");
    }

    FILE *fp;
    char buffer[1035];

    /* Open the command for reading. */
    /* TODO get the location of a binary (s2nd would work for instance) */
    fp = popen("which s2nc", "r");
    if (fp == NULL) {
        printf("Failed to run command\n" );
        exit(1);
    }

    /* Read the output a line at a time - output it. */
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        printf("%s", buffer);
    }

    /* close */
    pclose(fp);

    return 0;

    END_TEST();
    return 0;
}
