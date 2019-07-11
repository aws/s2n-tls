/***************************************************************************
* Additional implementation of "BIKE: Bit Flipping Key Encapsulation". 
* Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Written by Nir Drucker and Shay Gueron
* AWS Cryptographic Algorithms Group
* (ndrucker@amazon.com, gueron@amazon.com)
*
* The license is detailed in the file LICENSE.txt, and applies to this file.
* ***************************************************************************/

#pragma once

#include <stdlib.h>
#include "types.h"

#define NUM_OF_BLOCKS_IN_MB 4ULL

#define SLICE_REM           111ULL
#define MAX_MB_SLICES       8ULL
#define HASH_BLOCK_SIZE     128ULL

typedef sha384_hash_t sha_hash_t;
