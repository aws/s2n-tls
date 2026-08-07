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

/* Target Functions: s2n_ocsp_response_parse */

#include <stdint.h>

#include "api/s2n.h"
#include "tests/s2n_test.h"
#include "tls/s2n_cert_revocation.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"

int s2n_fuzz_test(const uint8_t *buf, size_t len)
{
#if S2N_LIBCRYPTO_SUPPORTS_CBS
    /* Feed the entire fuzz input as one DER OCSPResponse. Parse failures are
     * expected and harmless; the goal is to prove the strict-DER CBS walk over
     * the OCSPResponse / BasicOCSPResponse / ResponseData / SingleResponse
     * structure never reads out of bounds (validated under ASan/UBSan). */
    struct s2n_blob ocsp_der = { 0 };
    POSIX_GUARD(s2n_blob_init(&ocsp_der, (uint8_t *) (uintptr_t) buf, len));

    struct s2n_ocsp_response_view view = { 0 };
    /* s2n_ocsp_response_parse walks the full structure and captures every span
     * used by s2n_ocsp_validate, so parsing alone exercises the entire byte
     * walk. Full validation needs a validated leaf/issuer pair which arbitrary
     * fuzz input cannot supply. */
    s2n_result_ignore(s2n_ocsp_response_parse(&view, &ocsp_der));
#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

    return S2N_SUCCESS;
}

S2N_FUZZ_TARGET(NULL, s2n_fuzz_test, NULL)
