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

#include <string.h>

#include "error/s2n_errno.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"
#include <openssl/evp.h>

bool s2n_is_base64_char(unsigned char c)
{
    /* use bitwise operations to minimize branching */
    uint8_t is_upper = (c >= 'A') & (c <= 'Z');
    uint8_t is_lower = (c >= 'a') & (c <= 'z');
    uint8_t is_digit = (c >= '0') & (c <= '9');
    uint8_t is_plus = c == '+';
    uint8_t is_slash = c == '/';
    uint8_t is_equals = c == '=';
    
    return is_upper | is_lower | is_digit | is_plus | is_slash | is_equals;
}

int s2n_stuffer_read_base64(struct s2n_stuffer *stuffer, struct s2n_stuffer *out)
{
    POSIX_PRECONDITION(s2n_stuffer_validate(stuffer));
    POSIX_PRECONDITION(s2n_stuffer_validate(out));

    int base64_data_size = s2n_stuffer_data_available(stuffer) / 4 * 4;
    int binary_output_size = base64_data_size / 4 * 3;

    POSIX_GUARD(s2n_stuffer_skip_read(stuffer, base64_data_size));
    const uint8_t *start_of_base64_data = stuffer->blob.data + stuffer->read_cursor - base64_data_size;
    
    POSIX_GUARD(s2n_stuffer_skip_write(out, binary_output_size));
    uint8_t *start_of_binary_output = out->blob.data + out->write_cursor - binary_output_size;

    int res = EVP_DecodeBlock(start_of_binary_output, start_of_base64_data, base64_data_size);
    POSIX_ENSURE(res > 0, S2N_ERR_INVALID_BASE64);

    /* > The output will be padded with 0 bits if necessary to ensure that the 
     * > output is always 3 bytes for every 4 input bytes. This function will 
     * > return the length of the data decoded or -1 on error.
     * https://docs.openssl.org/1.1.1/man3/EVP_EncodeInit/
     * FFFF -> 0x14 0x51 0x45
     * FFF= -> 0x14 0x51 0x00
     * FF== -> 0x14 0x00 0x00
     * F=== -> INVALID
     */
    for (int i = 1; i <= 2; i++) {
        if (stuffer->blob.data[stuffer->read_cursor - i] == '=') {
            out->write_cursor -= 1;
        }
    }
    
    return S2N_SUCCESS;
}

int s2n_stuffer_write_base64(struct s2n_stuffer *stuffer, struct s2n_stuffer *in)
{
    POSIX_PRECONDITION(s2n_stuffer_validate(stuffer));
    POSIX_PRECONDITION(s2n_stuffer_validate(in));

    int binary_data_size = s2n_stuffer_data_available(in);
    int base64_output_size = binary_data_size / 3 * 4;
    /* we will need to add a final padded block */
    if (binary_data_size % 3 != 0) {
        base64_output_size += 4;
    }
    /* Null terminator is added */
    base64_output_size += 1;

    POSIX_GUARD(s2n_stuffer_skip_read(in, binary_data_size));
    const uint8_t *start_of_binary_data = in->blob.data + in->read_cursor - binary_data_size;
    
    POSIX_GUARD(s2n_stuffer_skip_write(stuffer, base64_output_size));
    uint8_t *start_of_base64_output = stuffer->blob.data + stuffer->write_cursor - base64_output_size;

    /* > The length of the data generated without the NUL terminator is returned from the function. */
    int res = EVP_EncodeBlock(start_of_base64_output, start_of_binary_data, binary_data_size);
    POSIX_ENSURE(res == base64_output_size - 1, S2N_ERR_INVALID_BASE64);
    stuffer->write_cursor -= 1;

    return S2N_SUCCESS;
}

