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
    bool is_fips;
};

void init_libcrypto_info(struct libcrypto_info *libcrypto_info)
{
    if (libcrypto_info != NULL) {
        libcrypto_info->name = NULL;
        libcrypto_info->major_version = -1;
        libcrypto_info->minor_version = -1;
        libcrypto_info->patch_version = -1;
        libcrypto_info->is_fips = false;
    }
}

int number_from_version(char *version)
{
    if (version == NULL) {
        return -1;
    }
    if (version[0] == '0') {
        return 0;
    }
    int i = atoi(version);
    /* atoi returns 0 on error */
    if (i == 0) {
        return -1;
    } else {
        return i;
    }
}

int convert_version_number_to_string(struct libcrypto_info *libcrypto_info, char *version_string_out)
{
    /* Format major minor and patch version in a normalized version string (e.x. "1.1.1", "3.0", "3", "")
     * If there is no major version, return -1 and leave version_string_out untouched. */
    if (libcrypto_info->major_version != -1) {
        sprintf(version_string_out, "%d", libcrypto_info->major_version);
        version_string_out = &version_string_out[1];
    } else {
        return -1;
    }
    if (libcrypto_info->minor_version != -1) {
        sprintf(version_string_out, ".%d", libcrypto_info->minor_version);
        version_string_out = &version_string_out[2];
    }
    if (libcrypto_info->patch_version != -1) {
        sprintf(version_string_out, ".%d", libcrypto_info->patch_version);
    }
    return 0;
}

int extract_libcrypto_info_from_s2n_libcrypto(char *s2n_libcrypto_name, struct libcrypto_info *libcrypto_info)
{
    if (libcrypto_info == NULL || s2n_libcrypto_name == NULL || strlen(s2n_libcrypto_name) == 0) {
        return -1;
    }
    libcrypto_info->name = strtok(s2n_libcrypto_name, "-");
    char *rest = strtok(NULL, "");

    if (rest != NULL && isdigit(rest[0])) {
        char *saved = strtok(rest, ".-");
        libcrypto_info->major_version = number_from_version(saved);
        if (libcrypto_info->major_version != -1) {
            saved = strtok(NULL, ".-");
            libcrypto_info->minor_version = number_from_version(saved);
        }
        if (libcrypto_info->minor_version != -1) {
            saved = strtok(NULL, ".-");
            libcrypto_info->patch_version = number_from_version(saved);
        }
        if (libcrypto_info->patch_version != -1) {
            rest = strtok(NULL, "");
        } else {
            rest = saved;
        }
    }

    if (rest != NULL) {
        libcrypto_info->is_fips = (strstr(rest, "fips") != NULL);
    }
    return 0;
}

int extract_libcrypto_info_from_s2n_build_preset(char *s2n_build_preset_copy, struct libcrypto_info *libcrypto_info)
{
    if (libcrypto_info == NULL || strlen(s2n_build_preset_copy) == 0) {
        return -1;
    }
    libcrypto_info->name = strtok(s2n_build_preset_copy, "-_");
    char *rest = strtok(NULL, "");
    if (rest != NULL && isdigit(rest[0])) {
        libcrypto_info->major_version = number_from_version(strtok(rest, ".-"));
        if (libcrypto_info->major_version != -1) {
            libcrypto_info->minor_version = number_from_version(strtok(NULL, ".-"));
        }
        if (libcrypto_info->minor_version != -1) {
            libcrypto_info->patch_version = number_from_version(strtok(NULL, "-_"));
        }
        rest = strtok(NULL, "");
    }

    if (rest != NULL) {
        libcrypto_info->is_fips = (strstr(rest, "fips") != NULL);
    }
    return 0;
}

int main()
{
    /* Ensure the libcrypto we build with, link against and intend to use are all the same.  */
    BEGIN_TEST(); /* s2n_init, called by BEGIN_TEST, checks that the build and link libcrypto are identical.  */

    /* Without these variables there is no particular intended version of libcrypto, and thus nothing to check.  */
    const char *s2n_build_preset = getenv("S2N_BUILD_PRESET");
    const char *s2n_libcrypto = getenv("S2N_LIBCRYPTO");
    if (s2n_build_preset == NULL && s2n_libcrypto == NULL) {
        END_TEST();
        return 0;
    }

    /* Parse the info out of environment variables.  */
    struct libcrypto_info s2n_build_preset_info = { 0 };
    init_libcrypto_info(&s2n_build_preset_info);
    char s2n_build_preset_copy[100] = { 0 };
    int s2n_build_preset_parsed = -1;
    if (s2n_build_preset != NULL && s2n_build_preset[0] != '\0') {
        strcpy(s2n_build_preset_copy, s2n_build_preset);
        s2n_build_preset_parsed = extract_libcrypto_info_from_s2n_build_preset(s2n_build_preset_copy, &s2n_build_preset_info);
    }

    struct libcrypto_info s2n_libcrypto_info = { 0 };
    init_libcrypto_info(&s2n_libcrypto_info);
    char s2n_libcrypto_copy[100] = { 0 };
    int s2n_libcrypto_parsed = -1;
    if (s2n_libcrypto != NULL && s2n_libcrypto[0] != '\0') {
        strcpy(s2n_libcrypto_copy, s2n_libcrypto);
        s2n_libcrypto_parsed = extract_libcrypto_info_from_s2n_libcrypto(s2n_libcrypto_copy, &s2n_libcrypto_info);
    }

    if (s2n_libcrypto_parsed == -1 && s2n_build_preset_parsed == -1) {
        /* Neither intent parsed.  */
        END_TEST();
        return 0;
    }

    /* If S2N_BUILD_PRESET and S2N_LIBCRYPTO don't match the intent of the CI is inconsistent.  */
    if (s2n_libcrypto_parsed != -1 && s2n_build_preset_parsed != -1) {
        /* Check that intents, if both declared, match.  */
        EXPECT_STRING_EQUAL(s2n_libcrypto_info.name, s2n_build_preset_info.name);
        EXPECT_EQUAL(s2n_libcrypto_info.major_version, s2n_build_preset_info.major_version);
        EXPECT_EQUAL(s2n_libcrypto_info.minor_version, s2n_build_preset_info.minor_version);
        EXPECT_EQUAL(s2n_libcrypto_info.patch_version, s2n_build_preset_info.patch_version);
        EXPECT_EQUAL(s2n_libcrypto_info.is_fips, s2n_build_preset_info.is_fips);
    }

    /* The intent of the CI is defined and consistent.  */
    struct libcrypto_info *s2n_libcrypto_intent = NULL;
    if (s2n_libcrypto_parsed != -1) {
        s2n_libcrypto_intent = &s2n_libcrypto_info;
    } else if (s2n_build_preset_parsed != -1) {
        s2n_libcrypto_intent = &s2n_build_preset_info;
    } else {
        FAIL_MSG("Sanity check -- this should be unreachable");
    }

    /* Check libcrypto name matches the intent of the CI.  */
    {
        if (strcmp(s2n_libcrypto_intent->name, "awslc") == 0) {
/* Special case awslc since it is a fork of BoringSSL and therefore the version returned by SSLeay_version
 * is inaccurate in early releases of awslc.
 */
#ifndef OPENSSL_IS_AWSLC
            FAIL_MSG("CI intended AWS-LC, but LIBCRYPTO isn't AWS-LC. ");
#endif
        } else {
            /* Any other library should have the name of the library (modulo case) in its version string.  */
            const char *ssleay_version_text = SSLeay_version(SSLEAY_VERSION);
            EXPECT_NOT_NULL(strcasestr(ssleay_version_text, s2n_libcrypto_intent->name));
        }
    };

    /* Check libcrypto version matches the intent of the CI.  */
    {
        char intent_version[20] = { 0 };
        if (convert_version_number_to_string(s2n_libcrypto_intent, intent_version) != -1) {
            const char *ssleay_version_text = SSLeay_version(SSLEAY_VERSION);
            EXPECT_NOT_NULL(strstr(ssleay_version_text, intent_version));
        }
    };

    END_TEST();
    return 0;
}
