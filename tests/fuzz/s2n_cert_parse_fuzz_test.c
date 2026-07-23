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

/* Target Functions: s2n_cert_span_view_parse s2n_cert_chain_spans_parse */

#include <stdint.h>

#include "api/s2n.h"
#include "tests/s2n_test.h"
#include "tls/s2n_cert_parse.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"

int s2n_fuzz_test(const uint8_t *buf, size_t len)
{
#if S2N_LIBCRYPTO_SUPPORTS_CBS
    /* Exercise single-certificate parsing: treat the entire fuzz input as one
     * DER Certificate TLV. Parse failures are expected and harmless. */
    {
        struct s2n_blob cert_der = { 0 };
        POSIX_GUARD(s2n_blob_init(&cert_der, (uint8_t *) (uintptr_t) buf, len));

        struct s2n_cert_span_view view = { 0 };
        /* Parse failures are expected on arbitrary input; swallow the result. */
        s2n_result_ignore(s2n_cert_span_view_parse(&view, &cert_der));
    }

    /* Exercise chain-level parsing: treat the entire fuzz input as a
     * concatenation of back-to-back DER Certificate TLVs. */
    {
        struct s2n_blob wire_chain = { 0 };
        POSIX_GUARD(s2n_blob_init(&wire_chain, (uint8_t *) (uintptr_t) buf, len));

        struct s2n_cert_chain_spans chain = { 0 };
        /* Parse failures are expected on arbitrary input; swallow the result. */
        s2n_result_ignore(s2n_cert_chain_spans_parse(&chain, &wire_chain, 7 /* default max chain depth */));
    }
#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

    return S2N_SUCCESS;
}

S2N_FUZZ_TARGET(NULL, s2n_fuzz_test, NULL)
