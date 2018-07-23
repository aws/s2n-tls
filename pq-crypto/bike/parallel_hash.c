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

#include "parallel_hash.h"
#include "utilities.h"
#include "openssl/sha.h"
#include "string.h"
#include "stdio.h"

#define SLICE_REM       111ULL
#define PH_SLICES_NUM   8ULL
#define HASH_BLOCK_SIZE 128ULL
#define MAX_REM_LEN     (PH_SLICES_NUM * HASH_BLOCK_SIZE)

#pragma pack(push, 1)

//The below struct is a concatenation of eight slices and Y.
typedef struct yx_s
{
    union {
        struct {
            sha384_hash_t x[PH_SLICES_NUM];
            //We define MAX_REM_LEN and not lrem to be compatible with the standard of C.
            uint8_t y[MAX_REM_LEN];
        } v;
        uint8_t raw[(PH_SLICES_NUM * sizeof(sha384_hash_t)) + MAX_REM_LEN];
    } u;
} yx_t;

#pragma pack(pop)

_INLINE_ uint64_t compute_slice_len(IN uint64_t la)
{
    //alpha is the number of full blocks.
    const uint64_t alpha = (((la / PH_SLICES_NUM) - SLICE_REM) / HASH_BLOCK_SIZE);
    return ((alpha * HASH_BLOCK_SIZE) + SLICE_REM);
}

void parallel_hash(OUT sha384_hash_t* out_hash,
                   IN const uint8_t* m,
                   IN const uint32_t la)
{
    DMSG("    Enter parallel_hash.\n");

    //Calculating how many bytes will go to "parallel" hashing
    //and how many will remind as a tail for later on.
    const uint32_t ls = compute_slice_len(la);
    const uint32_t lrem = (uint32_t)(la - (ls * PH_SLICES_NUM));
    yx_t yx = {0};

#ifdef WIN32
    DMSG("    Len=%u splits into %I64u logical streams (A1..A8) of length %u bytes. ",  la, PH_SLICES_NUM, ls);
    DMSG("Append the logically remaining buffer (Y) of %u - %I64u*%u = %u bytes\n\n", la, PH_SLICES_NUM, ls, lrem);
#else
    DMSG("    Len=%u splits into %llu logical streams (A1..A8) of length %u bytes. ",  la, PH_SLICES_NUM, ls);
    DMSG("Append the logically remaining buffer (Y) of %u - %llu*%u = %u bytes\n\n", la, PH_SLICES_NUM, ls, lrem);
#endif

    EDMSG("    The (original) buffer is:\n    "); print((uint64_t*)m, la*8); DMSG("\n");
    EDMSG("    The 8 SHA digests:\n");

    //Hash each block (X[i]).
    for(uint32_t i = 0; i < PH_SLICES_NUM; i++)
    {
        SHA384(&m[i * ls], ls, yx.u.v.x[i].u.raw);
        EDMSG("X[%u]:", i); print((uint64_t*)yx.u.v.x[i].u.raw, sizeof(yx.u.v.x[i])*8);
    }

    //Copy the reminder (Y).
    memcpy(yx.u.v.y, &m[PH_SLICES_NUM * ls], lrem);

    //Compute the final hash (on YX).
    SHA384(yx.u.raw, sizeof(yx), out_hash->u.raw);

    EDMSG("\nY:  "); print((uint64_t*)yx.u.v.y, lrem*8);

    DMSG("    Exit parallel_hash.\n");
}

