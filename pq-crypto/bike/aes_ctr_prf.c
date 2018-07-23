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
#include "aes_ctr_prf.h"
#include "string.h"
#include "stdio.h"
#include "utilities.h"

status_t init_aes_ctr_prf_state(OUT aes_ctr_prf_state_t* s,
        IN const uint32_t maxInvokations,
        IN const seed_t* seed)
{
    if (maxInvokations == 0)
    {
        return E_AES_CTR_PRF_INIT_FAIL;
    }

    //Set the Key schedule (from seed).
    if (AES_set_encrypt_key(seed->u.raw, AES256_KEY_BITS, &s->key) != 0)
    {
        return E_AES_SET_KEY_FAIL;
    }

    //Initialize buffer and counter
    s->ctr.u.qwords[0] = 0;
    s->ctr.u.qwords[1] = 0;

    AES_encrypt(s->ctr.u.bytes, s->buffer.u.bytes, &s->key);
    s->ctr.u.qwords[0]++;

    s->pos = 0;
    s->rem_invokations = (maxInvokations - 1);

    SEDMSG("    Init aes_prf_ctr state:\n");
    SEDMSG("      s.pos = %d\n", s->pos); 
    SEDMSG("      s.rem_invokations = %u\n", s->rem_invokations); 
    SEDMSG("      s.buffer = "); //print(s->buffer.qwords, sizeof(s->buffer)*8);
    SEDMSG("      s.ctr = 0x"); //print(s->ctr.qwords, sizeof(s->ctr)*8);

    return SUCCESS;
}

_INLINE_ status_t perform_aes(OUT uint8_t* ct, IN OUT aes_ctr_prf_state_t* s)
{
    if(s->rem_invokations == 0)
    {
        return E_AES_OVER_USED;
    }

    AES_encrypt(s->ctr.u.bytes, ct, &s->key);
    s->ctr.u.qwords[0]++;
    s->rem_invokations--;

    return SUCCESS;
}

status_t aes_ctr_prf(OUT uint8_t* a,
        IN aes_ctr_prf_state_t* s,
        IN const uint32_t len)
{
    status_t res = SUCCESS;

    //When Len i smaller then whats left in the buffer 
    //No need in additional AES.
    if ((len + s->pos) <= AES256_BLOCK_SIZE)
    {
        memcpy(a, &s->buffer.u.bytes[s->pos], len);
        s->pos += len;

        return res;
    }

    //if s.pos != AES256_BLOCK_SIZE then copy whats left in the buffer.
    //else copy zero bytes.
    uint32_t idx = AES256_BLOCK_SIZE - s->pos;
    memcpy(a, &s->buffer.u.bytes[s->pos], idx);

    //Init s.pos;
    s->pos = 0;

    //Copy full AES blocks.
    while((len - (idx - 1)) >= AES256_BLOCK_SIZE)
    {
        res = perform_aes(&a[idx], s);                    CHECK_STATUS(res);
        idx += AES256_BLOCK_SIZE;
    }

    res = perform_aes(s->buffer.u.bytes, s);                CHECK_STATUS(res);

    //Copy the tail.
    s->pos = len - idx;
    memcpy(&a[idx], s->buffer.u.bytes, s->pos);

    EXIT:
    return res;
}

