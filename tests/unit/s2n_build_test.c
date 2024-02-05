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
#define _GNU_SOURCE
#include <ctype.h>
#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/s2n_openssl.h"
#include "s2n_test.h"

int tokenize_s2n_libcrypto(char *s2n_libcrypto, char **name, char **version)
{
    if (name == NULL || version == NULL || s2n_libcrypto == NULL) {
        return S2N_FAILURE;
    }

    *name = strtok(s2n_libcrypto, "-");
    if (*name == NULL) {
        return S2N_FAILURE;
    }

    char *remaining = strtok(NULL, "");

    *version = NULL;
    if (remaining != NULL && isdigit(remaining[0])) {
        *version = strtok(remaining, "_-");
    }

    return S2N_SUCCESS;
}

int main()
{
    BEGIN_TEST();

    const char *s2n_libcrypto = getenv("S2N_LIBCRYPTO");

    /* S2N_LIBCRYPTO and S2N_BUILD_PRESET should be consistent, but only
       if S2N_BUILD_PRESET is set.  */
    {
        const char *s2n_build_preset = getenv("S2N_BUILD_PRESET");
        if (s2n_build_preset != NULL) {
            EXPECT_NOT_NULL(s2n_libcrypto);
            EXPECT_NOT_NULL(strstr(s2n_build_preset, s2n_libcrypto));
        }
    };

    if (s2n_libcrypto == NULL || s2n_libcrypto[0] == '\0') {
        END_TEST();
        return 0;
    }

    if (strcmp(s2n_libcrypto, "default") == 0) {
        END_TEST();
    }

    char s2n_libcrypto_copy[100] = { 0 };
    strncpy(s2n_libcrypto_copy, s2n_libcrypto, 99);
    char *name = NULL;
    char *version = NULL;
    EXPECT_SUCCESS(tokenize_s2n_libcrypto(s2n_libcrypto_copy, &name, &version));

    /* Check libcrypto name matches the intent of the CI.  */
    {
        if (strstr(name, "awslc") != NULL) {
            /* Early versions of awslc's SSLeay_version return an inaccurate value left over
	     * after its fork from BoringSSL.  */
            EXPECT_TRUE(s2n_libcrypto_is_awslc());
        } else {
            /* Any other library should have the name of the library (modulo case) in its version string.  */
            const char *ssleay_version_text = SSLeay_version(SSLEAY_VERSION);
            EXPECT_NOT_NULL(strcasestr(ssleay_version_text, name));
        }
    };

    /* Check libcrypto version matches the intent of the CI.  */
    {
        if (version != NULL) {
            const char *ssleay_version_text = SSLeay_version(SSLEAY_VERSION);
            EXPECT_NOT_NULL(strstr(ssleay_version_text, version));
        }
    };

    END_TEST();
    return 0;
}
