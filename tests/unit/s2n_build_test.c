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

#include "s2n_test.h"

struct libcrypto_info {
    char *name;
    int major_version;
    int minor_version;
    int patch_version;
};

int number_from_version(char *version)
{
    if (version == NULL) {
        return -1;
    }
    if (version[0] == '0') {
        return 0;
    }
    int version_number = atoi(version);
    /* atoi returns 0 on error */
    if (version_number == 0) {
        return -1;
    } else {
        return version_number;
    }
}

int convert_version_number_to_string(struct libcrypto_info *libcrypto_info, char *version_string_out)
{
    /* Format major minor and patch version in a normalized version string (e.x. "1.1.1", "3.0", "3")
     * If there is no major version, return -1 and leave version_string_out untouched. */
    if (libcrypto_info->major_version == -1) {
        return -1;
    }

    if (libcrypto_info->major_version >= 0
            && libcrypto_info->minor_version >= 0
            && libcrypto_info->patch_version >= 0) {
        sprintf(version_string_out, "%d.%d.%d", libcrypto_info->major_version, libcrypto_info->minor_version, libcrypto_info->patch_version);
    } else if (libcrypto_info->major_version >= 0
            && libcrypto_info->minor_version >= 0) {
        sprintf(version_string_out, "%d.%d", libcrypto_info->major_version, libcrypto_info->minor_version);
    } else if (libcrypto_info->major_version >= 0) {
        sprintf(version_string_out, "%d", libcrypto_info->major_version);
    }

    return 0;
}

int extract_libcrypto_info_from_s2n_libcrypto(char *s2n_libcrypto_name, struct libcrypto_info *libcrypto_info)
{
    if (libcrypto_info == NULL || s2n_libcrypto_name == NULL || strlen(s2n_libcrypto_name) == 0) {
        return -1;
    }

    libcrypto_info->name = NULL;
    libcrypto_info->major_version = -1;
    libcrypto_info->minor_version = -1;
    libcrypto_info->patch_version = -1;

    libcrypto_info->name = strtok(s2n_libcrypto_name, "-");
    char *rest = strtok(NULL, "");

    if (rest != NULL && isdigit(rest[0])) {
        char *version_number_text = strtok(rest, ".");
        libcrypto_info->major_version = number_from_version(version_number_text);
        version_number_text = strtok(NULL, ".");
        libcrypto_info->minor_version = number_from_version(version_number_text);
        version_number_text = strtok(NULL, ".");
        libcrypto_info->patch_version = number_from_version(version_number_text);
    }

    return 0;
}

int main()
{
    BEGIN_TEST();

    const char *s2n_libcrypto = getenv("S2N_LIBCRYPTO");

    /* S2N_LIBCRYPTO and S2N_BUILD_PRESET should be consistent.  */
    {
        const char *s2n_build_preset = getenv("S2N_BUILD_PRESET");
        if (s2n_build_preset != NULL) {
            EXPECT_NOT_NULL(s2n_libcrypto);
            EXPECT_NOT_NULL(strstr(s2n_build_preset, s2n_libcrypto));
        }
    };

    if (s2n_libcrypto == NULL || s2n_libcrypto[0] != '\0') {
        END_TEST();
        return 0;
    }

    struct libcrypto_info s2n_libcrypto_info = { 0 };
    char s2n_libcrypto_copy[100] = { 0 };
    strncpy(s2n_libcrypto_copy, s2n_libcrypto, 99);
    EXPECT_NOT_EQUAL(extract_libcrypto_info_from_s2n_libcrypto(s2n_libcrypto_copy, &s2n_libcrypto_info), -1);

    /* Check libcrypto name matches the intent of the CI.  */
    {
        if (strstr(s2n_libcrypto_info.name, "awslc") != NULL) {
/* Special case awslc since it is a fork of BoringSSL and therefore the version returned by SSLeay_version
 * is inaccurate in early releases of awslc.
 */
#ifndef OPENSSL_IS_AWSLC
            FAIL_MSG("CI intended AWS-LC, but LIBCRYPTO isn't AWS-LC. ");
#endif
        } else {
            /* Any other library should have the name of the library (modulo case) in its version string.  */
            const char *ssleay_version_text = SSLeay_version(SSLEAY_VERSION);
            EXPECT_NOT_NULL(strcasestr(ssleay_version_text, s2n_libcrypto_info.name));
        }
    };

    /* Check libcrypto version matches the intent of the CI.  */
    {
        char intent_version[20] = { 0 };
        if (convert_version_number_to_string(&s2n_libcrypto_info, intent_version) != -1) {
            const char *ssleay_version_text = SSLeay_version(SSLEAY_VERSION);
            EXPECT_NOT_NULL(strstr(ssleay_version_text, intent_version));
        }
    };

    END_TEST();
    return 0;
}
