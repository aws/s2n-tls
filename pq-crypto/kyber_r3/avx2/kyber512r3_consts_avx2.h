#pragma once

#include "kyber512r3_align_avx2.h"
#include "kyber512r3_cdecl_avx2.h"


typedef ALIGNED_INT16(640) qdata_t;
extern const qdata_t kyber512_qdata_avx2;

