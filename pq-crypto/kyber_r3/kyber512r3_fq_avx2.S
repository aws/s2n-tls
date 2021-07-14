#include "kyber512r3_cdecl_avx2.h"

//#include "kyber512r3_consts_avx2.h"
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
#define    _16XSHIFT      624

//.include "fq.inc"
.macro red16 r,rs=0,x=12
vpmulhw         %ymm1,%ymm\r,%ymm\x
.if \rs
vpmulhrsw    %ymm\rs,%ymm\x,%ymm\x
.else
vpsraw          $10,%ymm\x,%ymm\x
.endif
vpmullw         %ymm0,%ymm\x,%ymm\x
vpsubw          %ymm\x,%ymm\r,%ymm\r
.endm

.macro csubq r,x=12
vpsubw        %ymm0,%ymm\r,%ymm\r
vpsraw        $15,%ymm\r,%ymm\x
vpand        %ymm0,%ymm\x,%ymm\x
vpaddw        %ymm\x,%ymm\r,%ymm\r
#vpcmpgtw    %ymm0,%ymm\r,%ymm\x
#vpand        %ymm0,%ymm\x,%ymm\x
#vpsubw        %ymm\x,%ymm\r,%ymm\r
.endm

.macro caddq r,x=12
vpsraw        $15,%ymm\r,%ymm\x
vpand        %ymm0,%ymm\x,%ymm\x
vpaddw        %ymm\x,%ymm\r,%ymm\r
.endm

.macro fqmulprecomp al,ah,b,x=12
vpmullw        %ymm\al,%ymm\b,%ymm\x
vpmulhw        %ymm\ah,%ymm\b,%ymm\b
vpmulhw        %ymm0,%ymm\x,%ymm\x
vpsubw        %ymm\x,%ymm\b,%ymm\b
.endm



.text
reduce128_avx:
#load
vmovdqa		(%rdi),%ymm2
vmovdqa		32(%rdi),%ymm3
vmovdqa		64(%rdi),%ymm4
vmovdqa		96(%rdi),%ymm5
vmovdqa		128(%rdi),%ymm6
vmovdqa		160(%rdi),%ymm7
vmovdqa		192(%rdi),%ymm8
vmovdqa		224(%rdi),%ymm9

red16		2,x=10
red16		3,x=11
red16		4,x=12
red16		5,x=13
red16		6,x=14
red16		7,x=15
red16		8,x=10
red16		9,x=11

#store
vmovdqa		%ymm2,(%rdi)
vmovdqa		%ymm3,32(%rdi)
vmovdqa		%ymm4,64(%rdi)
vmovdqa		%ymm5,96(%rdi)
vmovdqa		%ymm6,128(%rdi)
vmovdqa		%ymm7,160(%rdi)
vmovdqa		%ymm8,192(%rdi)
vmovdqa		%ymm9,224(%rdi)

ret

.global cdecl(s2n_kyber_512_r3_reduce_avx2_asm)
.global _cdecl(s2n_kyber_512_r3_reduce_avx2_asm)
cdecl(s2n_kyber_512_r3_reduce_avx2_asm):
_cdecl(s2n_kyber_512_r3_reduce_avx2_asm):
#consts
vmovdqa		_16XQ*2(%rsi),%ymm0
vmovdqa		_16XV*2(%rsi),%ymm1
call		reduce128_avx
add		$256,%rdi
call		reduce128_avx
ret

csubq128_avx:
#load
vmovdqa		(%rdi),%ymm1
vmovdqa		32(%rdi),%ymm2
vmovdqa		64(%rdi),%ymm3
vmovdqa		96(%rdi),%ymm4
vmovdqa		128(%rdi),%ymm5
vmovdqa		160(%rdi),%ymm6
vmovdqa		192(%rdi),%ymm7
vmovdqa		224(%rdi),%ymm8

csubq		1,9
csubq		2,10
csubq		3,11
csubq		4,12
csubq		5,13
csubq		6,14
csubq		7,15
csubq		8,9

#store
vmovdqa		%ymm1,(%rdi)
vmovdqa		%ymm2,32(%rdi)
vmovdqa		%ymm3,64(%rdi)
vmovdqa		%ymm4,96(%rdi)
vmovdqa		%ymm5,128(%rdi)
vmovdqa		%ymm6,160(%rdi)
vmovdqa		%ymm7,192(%rdi)
vmovdqa		%ymm8,224(%rdi)

ret

.global cdecl(s2n_kyber_512_r3_csubq_avx2_asm)
.global _cdecl(s2n_kyber_512_r3_csubq_avx2_asm)
cdecl(s2n_kyber_512_r3_csubq_avx2_asm):
_cdecl(s2n_kyber_512_r3_csubq_avx2_asm):
#consts
vmovdqa		_16XQ*2(%rsi),%ymm0
call		csubq128_avx
add		$256,%rdi
call		csubq128_avx
ret

tomont128_avx:
#load
vmovdqa		(%rdi),%ymm3
vmovdqa		32(%rdi),%ymm4
vmovdqa		64(%rdi),%ymm5
vmovdqa		96(%rdi),%ymm6
vmovdqa		128(%rdi),%ymm7
vmovdqa		160(%rdi),%ymm8
vmovdqa		192(%rdi),%ymm9
vmovdqa		224(%rdi),%ymm10

fqmulprecomp	1,2,3,11
fqmulprecomp	1,2,4,12
fqmulprecomp	1,2,5,13
fqmulprecomp	1,2,6,14
fqmulprecomp	1,2,7,15
fqmulprecomp	1,2,8,11
fqmulprecomp	1,2,9,12
fqmulprecomp	1,2,10,13

#store
vmovdqa		%ymm3,(%rdi)
vmovdqa		%ymm4,32(%rdi)
vmovdqa		%ymm5,64(%rdi)
vmovdqa		%ymm6,96(%rdi)
vmovdqa		%ymm7,128(%rdi)
vmovdqa		%ymm8,160(%rdi)
vmovdqa		%ymm9,192(%rdi)
vmovdqa		%ymm10,224(%rdi)

ret

.global cdecl(s2n_kyber_512_r3_tomont_avx2_asm)
.global _cdecl(s2n_kyber_512_r3_tomont_avx2_asm)
cdecl(s2n_kyber_512_r3_tomont_avx2_asm):
_cdecl(s2n_kyber_512_r3_tomont_avx2_asm):
#consts
vmovdqa		_16XQ*2(%rsi),%ymm0
vmovdqa		_16XMONTSQLO*2(%rsi),%ymm1
vmovdqa		_16XMONTSQHI*2(%rsi),%ymm2
call		tomont128_avx
add		$256,%rdi
call		tomont128_avx
ret
