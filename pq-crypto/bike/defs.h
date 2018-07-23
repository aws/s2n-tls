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

#ifndef __DEFS_H_INCLUDED__
#define __DEFS_H_INCLUDED__

////////////////////////////////////////////
//         BIKE main parameters
///////////////////////////////////////////

// BIKE shared-secret size:
#define ELL_K_BITS  256ULL
#define ELL_K_SIZE (ELL_K_BITS/8)


////////////////////////////////////////////
// Implicit Parameters (do NOT edit below)
///////////////////////////////////////////

// BIKE-1 and BIKE-2 parameters:
#ifndef BIKE3
// 128-bits of post-quantum security parameters:
#ifdef PARAM128
#define R_BITS 32749ULL
#define DV     137ULL
#define T1     264ULL
#define VAR_TH_FCT(x) (17.489 + 0.0043536 * (x))
#define DELTA_BIT_FLIPPING 10
#define S_BIT_FLIPPING 12000
#else
// 96-bits of post-quantum security parameters:
#ifdef PARAM96
//    #define R_BITS 21893ULL
#define R_BITS 19853ULL
#define DV     103ULL
#define T1     199ULL
#define VAR_TH_FCT(x) (15.932 + 0.0052936 * (x))
#define DELTA_BIT_FLIPPING 8
#define S_BIT_FLIPPING 7000
#else
// 64-bits of post-quantum security parameters:
#ifdef PARAM64
#define R_BITS 10163ULL
#define DV     71ULL
#define T1     134ULL
#define VAR_TH_FCT(x) (13.530 + 0.0069721 * (x))
#define DELTA_BIT_FLIPPING 10
#define S_BIT_FLIPPING 3000
#endif
#endif
#endif

// BIKE-3 parameters:
#else
// 128-bits of post-quantum security parameters:
#ifdef PARAM128
#define R_BITS 36131ULL
#define DV     133ULL
#define T1     300ULL
#define VAR_TH_FCT(x) (17.061 + 0.0038459 * (x))
#define DELTA_BIT_FLIPPING 10
#define S_BIT_FLIPPING 12000
#else
// 96-bits of post-quantum security parameters:
#ifdef PARAM96
#define R_BITS 21683ULL
#define DV     99ULL
#define T1     226ULL
#define VAR_TH_FCT(x) (15.561 + 0.0046692 * (x))
#define DELTA_BIT_FLIPPING 10
#define S_BIT_FLIPPING 7000
#else
// 64-bits of post-quantum security parameters:
#ifdef PARAM64
#define R_BITS 11027ULL
#define DV     67ULL
#define T1     154ULL
#define VAR_TH_FCT(x) (13.209 + 0.0060515 * (x))
#define DELTA_BIT_FLIPPING 10
#define S_BIT_FLIPPING 3000
#endif
#endif
#endif
#endif

// Divide by the divider and round up to next integer:
#define DIVIDE_AND_CEIL(x, divider)  ((x/divider) + (x % divider == 0 ? 0 : 1ULL))
// Round the size to the nearest byte.
// SIZE suffix, is the number of bytes (uint8_t).
#define N_BITS   (R_BITS*2)
#define R_SIZE   DIVIDE_AND_CEIL(R_BITS, 8ULL)
#define N_SIZE   DIVIDE_AND_CEIL(N_BITS, 8ULL)
#define R_DQWORDS DIVIDE_AND_CEIL(R_SIZE, 16ULL)
#define MAX_J_SIZE 10*T1

#define UNUSED(x) (void)(x)

////////////////////////////////////////////
//             Debug
///////////////////////////////////////////

#ifndef VERBOSE 
#define VERBOSE 0
#endif

#if (VERBOSE == 3)
#define MSG(...)     { printf(__VA_ARGS__); }
#define DMSG(...)    MSG(__VA_ARGS__)
#define EDMSG(...)   MSG(__VA_ARGS__)
#define SEDMSG(...)  MSG(__VA_ARGS__)
#elif (VERBOSE == 2)
#define MSG(...)     { printf(__VA_ARGS__); }
#define DMSG(...)    MSG(__VA_ARGS__)
#define EDMSG(...)   MSG(__VA_ARGS__)
#define SEDMSG(...)
#elif (VERBOSE == 1)
#define MSG(...)     { printf(__VA_ARGS__); }
#define DMSG(...)    MSG(__VA_ARGS__)
#define EDMSG(...)
#define SEDMSG(...)
#else
#define MSG(...)     { printf(__VA_ARGS__); }
#define DMSG(...)
#define EDMSG(...)
#define SEDMSG(...)
#endif

////////////////////////////////////////////
//              Printing
///////////////////////////////////////////

// Show timer results in cycles.
//#define RDTSC

//#define PRINT_IN_BE
//#define NO_SPACE
//#define NO_NEWLINE

////////////////////////////////////////////
//              Testing
///////////////////////////////////////////
#define NUM_OF_CODE_TESTS       1ULL
#define NUM_OF_ENCRYPTION_TESTS 1ULL

#endif //__TYPES_H_INCLUDED__

