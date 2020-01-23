/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "s2n_test.h"

#include "tls/s2n_tls.h"
#include "error/s2n_errno.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_retry_send(NULL), S2N_ERR_UNIMPLEMENTED);
    EXPECT_FAILURE_WITH_ERRNO(s2n_server_hello_retry_recv(NULL), S2N_ERR_UNIMPLEMENTED);

    END_TEST();
}
