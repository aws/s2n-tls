/******************************************************************************
 * BIKE -- Bit Flipping Key Encapsulation
 *
 * Copyright (c) 2017 Nir Drucker, Shay Gueron, Rafael Misoczki, Tobias Oder, Tim Gueneysu
 * (drucker.nir@gmail.com, shay.gueron@gmail.com, rafael.misoczki@intel.com, tobias.oder@rub.de, tim.gueneysu@rub.de)
 *
 * This decoder is the decoder used by CAKE. But with the thresholds used by BIKE's decoder.
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

#include "decode.h"
#include "utilities.h"

#include "sampling.h"
#include "aes_ctr_prf.h"

#include <stdio.h>
#include <string.h>
#include <math.h>

// count number of 1's in tmp:
uint32_t getHammingWeight(const uint8_t tmp[R_BITS], const uint32_t length)
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < length; i++)
    {
        count+=tmp[i];
    }

    return count;
}

uint32_t get_predefined_threshold_var(const uint8_t s[R_BITS])
{
    // compute syndrome weight:
    uint32_t syndromeWeight = getHammingWeight(s, R_BITS);

    // set threshold according to syndrome weight:
    uint32_t threshold = ceil(VAR_TH_FCT(syndromeWeight));

    DMSG("    Thresold: %d\n", threshold);
    return threshold;
}

static void recompute_syndrome(uint8_t s[R_BITS],
                               const uint32_t numPositions,
                               const uint32_t positions[N_BITS],
                               const uint32_t h0_compact[DV],
                               const uint32_t h1_compact[DV])
{
    for (uint32_t i = 0; i < numPositions; i++)
    {
        uint32_t pos = positions[i];
        if (pos < R_BITS)
        {
            for (uint32_t j = 0; j < DV; j++)
            {
                if (h0_compact[j] <= pos) 
                {
                    s[pos - h0_compact[j]] ^= 1;
                }
                else 
                {
                    s[R_BITS - h0_compact[j] +  pos] ^= 1;
                }
            }
        }
        else
        {
            pos = pos - R_BITS;
            for (uint32_t j = 0; j < DV; j++)
            {
                if (h1_compact[j] <= pos)
                    s[pos - h1_compact[j]] ^= 1;
                else
                    s[R_BITS - h1_compact[j] + pos] ^= 1;
            }
        }
    }
}

void compute_counter_of_unsat(uint8_t unsat_counter[N_BITS],
        const uint8_t s[R_BITS],
        const uint32_t h0_compact[DV],
        const uint32_t h1_compact[DV])
{
    uint8_t unsat_counter2[N_BITS*2] = {0};
    uint32_t h1_compact2[DV] = {0};

    for (uint32_t i = 0; i < DV; i++)
    {
        h1_compact2[i] = N_BITS + h1_compact[i];
    }

    for (uint32_t i = 0; i < R_BITS; i++)
    {
        if (!s[i])
        {
            continue; 
        }

        for (uint32_t j = 0; j < DV; j++)
        {
            unsat_counter2[h0_compact[j] + i]++;
            unsat_counter2[h1_compact2[j] + i]++;
        }
    }

    for (uint32_t i = 0; i < R_BITS; i++)
    {
        unsat_counter[i] = unsat_counter2[i] + unsat_counter2[R_BITS+i];
        unsat_counter[R_BITS+i] = \
                unsat_counter2[N_BITS+i] + unsat_counter2[N_BITS+R_BITS+i];
    }
}

int decode(uint8_t e[R_BITS*2],
           uint8_t s_original[R_BITS],
           uint32_t h0_compact[DV],
           uint32_t h1_compact[DV],
           uint32_t u)
{
    int code_ret = -1;

    int delta = MAX_DELTA;
    uint8_t s[R_BITS] = {0};
    memcpy(s, s_original, R_BITS);

    int iter = 0;
    while (delta >= 0)
    {
        for (; iter < MAX_IT; iter++)
        {
            DMSG("    delta: %d\n", delta);
            DMSG("    Iteration: %d\n", iter);
            DMSG("    Weight of e: %d\n", getHammingWeight(e, N_BITS));
            DMSG("    Weight of syndrome: %d\n", getHammingWeights(s, R_BITS));
            
            // count the number of unsatisfied parity-checks:
            uint8_t unsat_counter[N_BITS] = {0};
            compute_counter_of_unsat(unsat_counter, s, h0_compact, h1_compact);

            // defining the threshold:
            int threshold = get_predefined_threshold_var(s);
            DMSG("    Threshold type: %d value: %d\n", THRESHOLD_TECHNIQUE, threshold);

            // we call black positions the positions involved in more than "threshold" unsatisfied parity-checks:
            uint32_t numBlackPositions = 0;
            uint32_t blackPositions[N_BITS] = {0}; // TODO: the size of blackPositions vector can be much smaller
    
            // we call gray positions the positions involved in more than (threashold - delta) unsat. parity-checks:
            uint32_t numGrayPositions = 0;
            uint32_t grayPositions[N_BITS] = {0}; // TODO: the size of grayPositions vector can be much smaller
            
            // Decoding Step I: flipping all black positions:
            for (uint64_t i = 0; i < N_BITS; i++)
            {
                if (unsat_counter[i] >= threshold)
                {
                    blackPositions[numBlackPositions++] = i;
                    uint32_t posError = i;
                    if (i != 0 && i != R_BITS)
                    {
                        // the position in e is adjusted because syndrome is transposed
                        posError = (i > R_BITS) ? ((N_BITS - i)+R_BITS) : (R_BITS - i); 
                    }
                    e[posError] ^= 1; 
    
                    DMSG("      flipping black position: %d\n", posError);
    
                } else if(unsat_counter[i] > threshold - delta) {
                    grayPositions[numGrayPositions++] = i;
                }
            }
    
            // Decoding Step I: recompute syndrome:
            recompute_syndrome(s, numBlackPositions, blackPositions, h0_compact, h1_compact);
    
            // Decoding Step I: check if syndrome is 0 (successful decoding):
            if (getHammingWeight(s, R_BITS) <= u)
            {
                code_ret = 0;
                DMSG("    Weight of syndrome: 0\n");
                break;
            }
    
            // recompute counter of unsat. parity checks:
            compute_counter_of_unsat(unsat_counter, s, h0_compact, h1_compact);
    
            // Decoding Step II: Unflip positions that still have high number of unsatisfied parity-checks associated:  
            uint32_t positionsToUnflip[N_BITS] = {0}; // TODO: the size of positionsToUnflip vector can be much smaller
            uint32_t numUnflippedPositions = 0;
            
            for (uint32_t i = 0; i < numBlackPositions; i++)
            {
                uint32_t pos = blackPositions[i];
                if (unsat_counter[pos] > (DV+1)/2)
                {
                    positionsToUnflip[numUnflippedPositions++] = pos;
                    uint32_t posError  = pos;
                    if (pos != 0 && pos != R_BITS)
                    {
                        // the position in e is adjusted because syndrome is transposed
                        posError = (pos > R_BITS) ? ((N_BITS - pos)+R_BITS) : (R_BITS - pos); 
                    }
                    e[posError] ^= 1; 
                    //MSG("      unflipping black position: %d\n", posError);
                }
            }

            // Decoding Step II: recompute syndrome:
            recompute_syndrome(s, numUnflippedPositions, positionsToUnflip, h0_compact, h1_compact);

            // Decoding Step II: check if syndrome is 0 (successful decoding):
            if (getHammingWeight(s, R_BITS) <= u)
            {
                code_ret = 0;
                DMSG("    Weight of syndrome: 0\n");
                break;
            }

            // recomputing counter of unsat. parity checks:
            compute_counter_of_unsat(unsat_counter, s, h0_compact, h1_compact);

            // Decoding Step III: Flip all gray positions associated to high number of unsatisfied parity-checks: 
            uint32_t grayPositionsToFlip[N_BITS] = {0}; // TODO: the size of grayPositionsToFlip vector can be much smaller
            uint32_t numGrayPositionsToFlip = 0;

            for (uint32_t i = 0; i < numGrayPositions; i++)
            {
                uint32_t pos = grayPositions[i];
                if (unsat_counter[pos] > (DV+1)/2)
                {
                    grayPositionsToFlip[numGrayPositionsToFlip++] = pos;
                    uint32_t posError  = pos;
                    if (pos != 0 && pos != R_BITS)
                    {
                        // the position in e is adjusted because syndrome is transposed
                        posError = (pos > R_BITS) ? ((N_BITS - pos)+R_BITS) : (R_BITS - pos); 
                    }
                    e[posError] ^= 1; 
                    //MSG("      flipping gray position: %d\n", posError);
                }
            }

            // Decoding Step III: recompute syndrome:
            recompute_syndrome(s, numGrayPositionsToFlip, grayPositionsToFlip, h0_compact, h1_compact);

            // Decoding Step III: check if syndrome is 0 (successful decoding):
            if (getHammingWeight(s, R_BITS) <= u)
            {
                code_ret = 0;
                DMSG("    Weight of syndrome: 0\n");
                break;
            }
        }
        if (getHammingWeight(s, R_BITS) <= u) {
            break;
        } else {
            delta--;
            iter = 0;
            
            for (uint64_t i = 0; i < N_BITS; i++)
            {
                e[i] = 0; 
            }
            memcpy(s, s_original, R_BITS);
       }
    }

    return code_ret;
}
