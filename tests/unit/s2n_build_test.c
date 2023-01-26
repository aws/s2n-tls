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
#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "s2n_test.h"

struct libcrypto_info {
    char *name;
    int major_version;
    int minor_version;
    int patch_version;
    bool is_fips;
};

void init_libcrypto_info(struct libcrypto_info *li) {
    if (li != NULL) {
        li->name = NULL;
        li->major_version = -1;
        li->minor_version = -1;
        li->patch_version = -1;
        li->is_fips = false;
    }
}

void print_libcrypto_info(struct libcrypto_info *li) {
    if (li == NULL) {
        printf("(null)");
        return;
    }
    printf("struct libcrypto_info {\n");
    printf("	name = %s\n", li->name);
    printf("	major_version = %d\n", li->major_version);
    printf("	minor_version = %d\n", li->minor_version);
    printf("	patch_version = %d\n", li->patch_version);
    printf("	is_fips = %d\n", li->is_fips);
    printf("}\n");
}

int number_from_version(char *version) {
    if (version == NULL) return -1;
    if (version[0] == '0') return 0;
    int i = atoi(version);
    if (i == 0) {
        // atoi error
        return -1;
    } else {
        return i;
    }
}

int convert_version_number_to_string(struct libcrypto_info *li, char *version_string_out) {
    /* Format major minor and patch version in a normalized version string (e.x. "1.1.1", "3.0", "3", "") */
    /* If there is no major version, return -1 and leave version_string_out untouched. */
    if (li->major_version != -1) {
        sprintf(version_string_out, "%d", li->major_version);
        version_string_out = &version_string_out[1];
    } else {
        return -1;
    }
    if (li->minor_version != -1) {
        sprintf(version_string_out, ".%d", li->minor_version);
        version_string_out = &version_string_out[2];
    }
    if (li->patch_version != -1) {
        sprintf(version_string_out, ".%d", li->patch_version);
    }
    return 0;
}

int extract_libcrypto_info_from_s2n_libcrypto(char *s2n_libcrypto_copy, struct libcrypto_info *li) {
    if (li == NULL) return -1;
    if (strlen(s2n_libcrypto_copy) == 0) return -1;
    li->name = strtok(s2n_libcrypto_copy, "-");
    char *rest = strtok(NULL, "");
    printf("rest = %s\n", rest);

    if (rest != NULL && isdigit(rest[0])) {
        // This is a version number
        char *saved = NULL;
        li->major_version = number_from_version(strtok(rest, ".-"));
        if (li->major_version != -1) {
            saved = strtok(NULL, ".-");
            li->minor_version = number_from_version(saved);
        }
        if (li->minor_version != -1) {
            saved = strtok(NULL, ".-");
            li->patch_version = number_from_version(saved);
        }
        if (li->patch_version != -1) {
            rest = strtok(NULL, "");
        } else {
            rest = saved;
        }
    }

    if (rest != NULL) {
        li->is_fips = (strstr(rest, "fips") != NULL);
    }
    return 0;
}

int extract_libcrypto_info_from_s2n_build_preset(char *s2n_build_preset_copy, struct libcrypto_info *li) {
    if (li == NULL) return -1;
    if (strlen(s2n_build_preset_copy) == 0) return -1;
    li->name = strtok(s2n_build_preset_copy, "-_");
    char *rest = strtok(NULL, "");
    if (rest != NULL && isdigit(rest[0])) {
        // This is a version number
        li->major_version = number_from_version(strtok(rest, ".-"));
        if (li->major_version != -1) {
            li->minor_version = number_from_version(strtok(NULL, ".-"));
        }
        if (li->minor_version != -1) {
            li->patch_version = number_from_version(strtok(NULL, "-_"));
        }
        rest = strtok(NULL, "");
    }

    if (rest != NULL) {
        li->is_fips = (strstr(rest, "fips") != NULL);
    }
    return 0;
}


int main()
{
    /* There are three different specifications of libcrypto which must be in sync.
     *  1 The #include headers (-I) (checked with macros, e.g. OPENSSL_VERSION_TEXT and OPENSSL_IS_AWSLC)
     *  2 The (dynamically) linked library (-L) (checked by calling function e.g. SSLeay_version)
     *  3 The intent of the CI (declared by environment variables S2N_BUILD_PRESET and S2N_LIBCYPTO)
     * BEGIN_TEST calls s2n_init which checks that (1) and (2) match.
     */
    BEGIN_TEST();
    /* The rest of the test checks that (3) matches (1) or (2). */

    /* If both S2N_BUILD_PRESET and S2N_LIBCRYPTO are not defined, we aren't in a CI, end the test. */
    const char *s2n_build_preset = getenv("S2N_BUILD_PRESET");
    const char *s2n_libcrypto = getenv("S2N_LIBCRYPTO");
    if (s2n_build_preset == NULL && s2n_libcrypto == NULL) {
        /* No intent declared. */
        FAIL_MSG("TODO: remove - DEBUGGING CI neither declared\n");
        END_TEST();
        return 0;
    }

    /* Parse the info out of environment variables.  */
    struct libcrypto_info s2n_build_preset_info = { 0 };
    init_libcrypto_info(&s2n_build_preset_info);
    char s2n_build_preset_copy[100] = { 0 };
    strcpy(s2n_build_preset_copy, s2n_build_preset);
    int s2n_build_preset_parsed = extract_libcrypto_info_from_s2n_build_preset(s2n_build_preset_copy, &s2n_build_preset_info);

    struct libcrypto_info s2n_libcrypto_info = { 0 };
    init_libcrypto_info(&s2n_libcrypto_info);
    char s2n_libcrypto_copy[100] = { 0 };
    strcpy(s2n_libcrypto_copy, s2n_libcrypto);
    int s2n_libcrypto_parsed = extract_libcrypto_info_from_s2n_libcrypto(s2n_libcrypto_copy, &s2n_libcrypto_info);

    printf("S2N_BUILD_PRESET == %s\n", s2n_build_preset);
    print_libcrypto_info(&s2n_build_preset_info);
    printf("S2N_LIBCRYPTO == %s\n", s2n_libcrypto);
    print_libcrypto_info(&s2n_libcrypto_info);

    if (s2n_libcrypto_parsed == -1 && s2n_build_preset_parsed == -1) {
        /* Neither intent parsed.  */
        FAIL_MSG("TODO: remove - DEBUGGING CI both failed to parse\n");
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
            /* aws lc version strings have a storied history:
             *     Originally a fork from BoringSSL, OPENSSL_VERSION_TEXT was defined to be "OpenSSL 1.1.1 (compatible; BoringSSL)".
             *     AWC-LC commit 8f184f5d69604cc4645bafec47c2d6d9929cb50f on 4/11/22 modified it to be  "OpenSSL 1.1.1 (compatible; AWL-LC)"
             * Unfortunately in both cases we can't do a straight forward comparison against "awslc".
             * We can however rely on the macro OPENSSL_IS_AWSLC.  */
#ifndef OPENSSL_IS_AWSLC
            FAIL_MSG("CI intended AWS-LC, but LIBCRYPTO isn't AWS-LC. ");
#endif
        } else {
            /* Any other library should have the name of the library (modulo case) in its version string.  */
            printf("SSLeay_version(SSLEAY_VERSION) == %s\n", SSLeay_version(SSLEAY_VERSION));
            printf("s2n_libcrypto_intent->name     == %s\n", s2n_libcrypto_intent->name);
            EXPECT_NOT_NULL(strcasestr(SSLeay_version(SSLEAY_VERSION), s2n_libcrypto_intent->name));
        }
    };

    /* Check libcrypto version matches the intent of the CI.  */
    {
        char intent_version[20] = { 0 };
        if (convert_version_number_to_string(s2n_libcrypto_intent, intent_version) != -1) {
            printf("SSLeay_version(SSLEAY_VERSION) == %s\n", SSLeay_version(SSLEAY_VERSION));
            printf("intent_version                 == %s\n", intent_version);
            EXPECT_NOT_NULL(strstr(SSLeay_version(SSLEAY_VERSION), intent_version));
        }
    };

    END_TEST();
    return 0;
}
