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

/* MacOS and BSD have completely different signatures for sendfile,
 * and sendfile is provided by different headers.
 * Test ONLY for the Linux version.
 */

#include <sys/sendfile.h>

int main()
{
    int out_fd = 0, in_fd = 0;
    off_t offset = 0;
    size_t count = 0;
    ssize_t result = sendfile(out_fd, in_fd, &offset, count);
    return 0;
}
