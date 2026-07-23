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

/* Target Functions: s2n_crl_view_parse s2n_crl_check_times s2n_crl_check_serial */

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
    /* Feed the entire fuzz input as one DER CertificateList. Parse failures are
     * expected and harmless; the goal is to prove the strict-DER CBS walk never
     * reads out of bounds (validated under ASan/UBSan). */
    struct s2n_blob crl_der = { 0 };
    POSIX_GUARD(s2n_blob_init(&crl_der, (uint8_t *) (uintptr_t) buf, len));

    struct s2n_crl_view view = { 0 };
    if (s2n_result_is_ok(s2n_crl_view_parse(&view, &crl_der))) {
        /* Only exercise the time/serial scans when the parse succeeded so the
         * spans they read are known-in-bounds sub-ranges of the input. */
        s2n_result_ignore(s2n_crl_check_times(&view, 1600000000));

        /* Scan revokedCertificates for an arbitrary serial derived from the
         * input, exercising the bounded linear walk. */
        uint8_t serial_bytes[] = { 0x01, 0x02, 0x03, 0x04 };
        struct s2n_blob serial = { 0 };
        POSIX_GUARD(s2n_blob_init(&serial, serial_bytes, sizeof(serial_bytes)));
        s2n_result_ignore(s2n_crl_check_serial(&view, &serial));

        /* Also scan for the issuer's leading bytes if available, to reach
         * matching entries in seeded corpus CRLs. */
        if (view.issuer.size >= 1) {
            struct s2n_blob serial2 = { 0 };
            POSIX_GUARD(s2n_blob_init(&serial2, view.issuer.data,
                    view.issuer.size < 8 ? view.issuer.size : 8));
            s2n_result_ignore(s2n_crl_check_serial(&view, &serial2));
        }
    }
#endif /* S2N_LIBCRYPTO_SUPPORTS_CBS */

    return S2N_SUCCESS;
}

S2N_FUZZ_TARGET(NULL, s2n_fuzz_test, NULL)
