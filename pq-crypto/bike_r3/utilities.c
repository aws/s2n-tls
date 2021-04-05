/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#include <inttypes.h>

#include "utilities.h"

#define BITS_IN_QWORD 64ULL
#define BITS_IN_BYTE  8ULL

uint64_t r_bits_vector_weight(IN const r_t *in)
{
  uint64_t acc = 0;
  for(size_t i = 0; i < (R_BYTES - 1); i++) {
    acc += __builtin_popcount(in->raw[i]);
  }

  acc += __builtin_popcount(in->raw[R_BYTES - 1] & LAST_R_BYTE_MASK);
  return acc;
}

#if defined(VERBOSE)
// Print a new line only if we prints in qw blocks
_INLINE_ void print_newline(IN const uint64_t qw_pos)
{
#  if !defined(NO_NEWLINE)
  if((qw_pos % 4) == 3) {
    printf("\n    ");
  }
#  endif
}

// Prints a QW in LE/BE in win/linux format
_INLINE_ void print_uint64(IN const uint64_t val)
{
  // If printing in BE is required, swap the order of the bytes.
#  if defined(PRINT_IN_BE)
  uint64_t tmp = bswap_64(val);
#  else
  uint64_t tmp = val;
#  endif

  printf("%.16" PRIx64, tmp);

#  if !defined(NO_SPACE)
  printf(" ");
#  endif
}

// Last block requires special handling: we should zero-mask all the bits
// above the desired number.
// Endian - 0 - BE, 1 - LE
// Return 1 if the last block was printed; else return 0.
_INLINE_ uint8_t print_last_block(IN const uint8_t *last_bytes,
                                  IN const uint32_t bits_num,
                                  IN const uint32_t endien)
{
  // Floor of bits/64 the reminder is in the next QW
  const uint32_t qw_num = bits_num / BITS_IN_QWORD;

  // How many bits to pad with zero
  const uint32_t rem_bits = bits_num - (BITS_IN_QWORD * qw_num);

  // We read byte by byte and not the whole QW, in order to avoid reading a bad
  // memory address
  const uint32_t bytes_num =
    ((rem_bits % 8) == 0) ? rem_bits / BITS_IN_BYTE : 1 + rem_bits / BITS_IN_BYTE;

  // Must be signed for the LE loop
  int i;

  if(0 == rem_bits) {
    return 0;
  }

  // Mask unneeded bits
  const uint8_t last_byte = (rem_bits % 8 == 0)
                              ? last_bytes[bytes_num - 1]
                              : last_bytes[bytes_num - 1] & MASK(rem_bits % 8);
  // BE
  if(0 == endien) {
    for(i = 0; (uint32_t)i < (bytes_num - 1); i++) {
      printf("%.2x", last_bytes[i]);
    }

    printf("%.2x", last_byte);

    for(i++; (uint32_t)i < sizeof(uint64_t); i++) {
      printf("__");
    }
  } else {
    for(i = sizeof(uint64_t) - 1; (uint32_t)i >= bytes_num; i--) {
      printf("__");
    }

    printf("%.2x", last_byte);

    for(i--; i >= 0; i--) {
      printf("%.2x", last_bytes[i]);
    }
  }

#  if !defined(NO_SPACE)
  printf(" ");
#  endif

  return 1;
}

void print_LE(IN const uint64_t *in, IN const uint32_t bits_num)
{
  const uint32_t qw_num = bits_num / BITS_IN_QWORD;

  // Print the MSB QW
  uint32_t qw_pos = print_last_block((const uint8_t *)&in[qw_num], bits_num, 1);

  // Print every 8 bytes separated by a space (if required)
  for(int i = ((int)qw_num) - 1; i >= 0; i--, qw_pos++) {
    print_uint64(in[i]);
    print_newline(qw_pos);
  }

  printf("\n");
}

void print_BE(IN const uint64_t *in, IN const uint32_t bits_num)
{
  const uint32_t qw_num = bits_num / BITS_IN_QWORD;

  // Print every 16 numbers separately
  for(uint32_t i = 0; i < qw_num; ++i) {
    print_uint64(in[i]);
    print_newline(i);
  }

  // Print the MSB QW
  print_last_block((const uint8_t *)&in[qw_num], bits_num, 0);

  printf("\n");
}

#endif // VERBOSE
