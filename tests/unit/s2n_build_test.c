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
#include <stdio.h>
#include <stdlib.h>

#include <openssl/opensslv.h>
#include <openssl/crypto.h>

#include <string.h>

#include "s2n_test.h"


extern char **environ;

int main(int argc, char **argv)
{
   (void) argc, (void) argv;
   BEGIN_TEST();

   /*
    * In the case that libcrypto is dynamicly linked there is a chance that the
    * build version and the linked version don't match. OPENSSL_VERSION_TEXT is
    * a macro defined in openssl/crypto.h and should be returned from OpenSSL_version.
    * In the event that we are dynamicly linked to the wrong libcrypto the function,
    * call will return a diffrent version text than the one we used at a source level.
    *
    * If libcrypto is staticly linked, this is sure to be true.
    */
   if (NULL == strcasestr(OPENSSL_VERSION_TEXT, SSLeay_version(SSLEAY_VERSION))) {
       printf("\nOPENSSL_VERSION_TEXT ==           |%s|\n", OPENSSL_VERSION_TEXT);
       printf("SSLeay_version(SSLEAY_VERSION) == |%s|\n", SSLeay_version(SSLEAY_VERSION));
   }
   EXPECT_NOT_NULL(strcasestr(OPENSSL_VERSION_TEXT, SSLeay_version(SSLEAY_VERSION)));

   /*
    * The build configurations in CI are defined by S2N_BUILD_PRESET.
    *
    */
   const char *s2n_build_preset = getenv("S2N_BUILD_PRESET");
   if (s2n_build_preset == NULL) {
       /* Apparently we aren't in CI. */
       END_TEST();
   }

   /* CMake generated Makefiles can select a default LIBCRYPTO,
    * lets make sure that didn't happen. */
   const char *s2n_libcrypto = getenv("S2N_LIBCRYPTO");
   EXPECT_NOT_NULL(s2n_build_preset);

#define CONTAINS(x) strcasestr(s2n_build_preset, x) != NULL
#define CHK_LC(x) EXPECT_EQUAL(strcmp(s2n_libcrypto, x), 0)
   /* Verify that the environment  */
   if (CONTAINS("awslc")) {
       if (CONTAINS("fips")) {
           CHK_LC("awslc-fips");
       } else {
           CHK_LC("awslc");
       }
   } else if (CONTAINS("libressl")) {
       CHK_LC("libressl");
   } else if (CONTAINS("boringssl")) {
       CHK_LC("boringssl");
   } else if (CONTAINS("openssl")) {
       if (CONTAINS("fips")) {
           if (CONTAINS("1-0-2") || CONTAINS("1.0.2")) {
               CHK_LC("openssl-1.0.2-fips");
           } else if (CONTAINS("1.1.1") || CONTAINS("1-1-1")) {
               CHK_LC("openssl-1.1.1-fips");
           } else if (CONTAINS("3-0") || CONTAINS("3.0")) {
               CHK_LC("openssl-3.0-fips");
           }
       } else {
           if (CONTAINS("1-0-2") || CONTAINS("1.0.2")) {
               CHK_LC("openssl-1.0.2");
           } else if (CONTAINS("1.1.1") || CONTAINS("1-1-1")) {
               CHK_LC("openssl-1.1.1");
           } else if (CONTAINS("3-0") || CONTAINS("3.0")) {
               CHK_LC("openssl-3.0");
           }
       }
   } else {
       printf("\nTest didn't handle this combination of variables\n");
       printf("S2N_BUILD_PRESET == %s\n", s2n_build_preset);
       printf("S2N_LIBCRYPTO    == %s\n", s2n_libcrypto);
       EXPECT_TRUE(0);
   }

   /* Now that we can rely on the value of S2N_LIBCRYPTO lets check that it matches the version
    * that libcrypto reports. */
   const char *openssl_version = SSLeay_version(SSLEAY_VERSION);
   char s2n_libcrypto_copy[31] = { 0 };
   strncpy(s2n_libcrypto_copy, s2n_libcrypto, 30);
   char *token = strtok(s2n_libcrypto_copy, "-");
   /* The name of the library should be included (AWS, BoringSSL, LibreSSL, OpenSSL, ect) */
   if (NULL == strcasestr(openssl_version, token)) {
       printf("SSLeay_version(SSLEAY_VERSION) == %s\n", openssl_version);
       printf("token == %s\n", token);
       printf("s2n_libcrypto == %s\n", s2n_libcrypto);
   }
   EXPECT_NOT_NULL(strcasestr(openssl_version, token));
   /* The version number, if present should also be there. */
   strtok(NULL, "-");
   if (token != NULL) {
       EXPECT_NOT_NULL(strcasestr(openssl_version, token));
   }

   END_TEST();
   return 0;
}