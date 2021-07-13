#pragma once

#include "kyber512r3_params.h"
#include <stdint.h>

#define _16XQ            0
#define _16XQINV        16
#define _16XV           32
#define _16XFLO         48
#define _16XFHI         64
#define _16XMONTSQLO    80
#define _16XMONTSQHI    96
#define _16XMASK       112
#define _REVIDXB       128
#define _REVIDXD       144
#define _ZETAS_EXP     160
#define	_16XSHIFT      624


#define qdata S2N_KYBER_512_R3_NAMESPACE(qdata)
extern const int16_t qdata[];
