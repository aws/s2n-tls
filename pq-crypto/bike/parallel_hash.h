/******************************************************************************
 * BIKE -- Bit Flipping Key Encapsulation
 *
 * Copyright (c) 2017 Nir Drucker, Shay Gueron, Rafael Misoczki, Tobias Oder, Tim Gueneysu
 * (drucker.nir@gmail.com, shay.gueron@gmail.com, rafael.misoczki@intel.com, tobias.oder@rub.de, tim.gueneysu@rub.de)
 *
 * Permission to use this code for BIKE is granted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * * The names of the contributors may not be used to endorse or promote
 *   products derived from this software without specific prior written
 *   permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ""AS IS"" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS CORPORATION OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#ifndef __PARALLEL_HASH_H_INCLUDED__
#define __PARALLEL_HASH_H_INCLUDED__

#include "types.h"

#define SHA384_HASH_SIZE   48ULL
#define SHA384_HASH_QWORDS (SHA384_HASH_SIZE/8)

typedef struct sha384_hash_s
{
    union
    {
        uint8_t  raw[SHA384_HASH_SIZE];
        uint64_t qwords[SHA384_HASH_QWORDS];
    } u;
} sha384_hash_t;

//The parallel_hash algorithm uses the technique described in
// 1) S. Gueron, V. Krasnov. Simultaneous Hashing of Multiple Messages.
//    Journal of Information Security 3:319-325 (2012).
// 2) S. Gueron. A j-Lanes Tree Hashing Mode and j-Lanes SHA-256.
//    Journal of Information Security 4:7-11 (2013).
// See also:
// 3) S. Gueron. Parallelized Hashing via j-Lanes and j-Pointers Tree Modes,
//    with Applications to SHA-256.
//    Journal of Information Security 5:91-113 (2014).
//
// It is designed to convert the serial hashing to a parallelizeable process.
void parallel_hash(OUT sha384_hash_t* out_hash,
        IN const uint8_t* m,
        IN const uint32_t la);

#endif //__AES_CTR_REF_H_INCLUDED__

