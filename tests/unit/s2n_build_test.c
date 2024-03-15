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

#define MAX_LIBCRYPTO_NAME_LEN 100

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

S2N_RESULT s2n_test_lowercase_copy(const char *input, char *destination, size_t max_len)
{
    RESULT_ENSURE_REF(input);
    RESULT_ENSURE_REF(destination);

    for (size_t i = 0; i < strlen(input); i++) {
        RESULT_ENSURE_LT(i, max_len);
        destination[i] = tolower(input[i]);
    }

    return S2N_RESULT_OK;
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

    /* Ensure that FIPS mode is enabled when linked to AWS-LC-FIPS, and disabled when linked to AWS-LC */
    if (strstr(s2n_libcrypto, "awslc") != NULL) {
        s2n_fips_mode fips_mode = S2N_FIPS_MODE_DISABLED;
        EXPECT_SUCCESS(s2n_get_fips_mode(&fips_mode));

        if (strstr(s2n_libcrypto, "fips") != NULL) {
            EXPECT_EQUAL(fips_mode, S2N_FIPS_MODE_ENABLED);
        } else {
            EXPECT_EQUAL(fips_mode, S2N_FIPS_MODE_DISABLED);
        }
    }

    char s2n_libcrypto_copy[MAX_LIBCRYPTO_NAME_LEN] = { 0 };
    EXPECT_TRUE(strlen(s2n_libcrypto) < MAX_LIBCRYPTO_NAME_LEN);
    EXPECT_OK(s2n_test_lowercase_copy(s2n_libcrypto, &s2n_libcrypto_copy[0], s2n_array_len(s2n_libcrypto_copy)));
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
            char ssleay_version_text[MAX_LIBCRYPTO_NAME_LEN] = { 0 };
            EXPECT_OK(s2n_test_lowercase_copy(SSLeay_version(SSLEAY_VERSION), &ssleay_version_text[0], MAX_LIBCRYPTO_NAME_LEN));
            EXPECT_NOT_NULL(strstr(ssleay_version_text, name));
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
