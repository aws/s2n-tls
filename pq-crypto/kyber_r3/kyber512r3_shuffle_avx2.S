#include "kyber512r3_consts_avx2.h"

// The small macros (.inc files) are combined with .S files directly
/*****.include "fq.inc"*****/
/***************************/
.macro red16 r,rs=0,x=12
vpmulhw     %ymm1,%ymm\r,%ymm\x
.if \rs
vpmulhrsw   %ymm\rs,%ymm\x,%ymm\x
.else
vpsraw      $10,%ymm\x,%ymm\x
.endif
vpmullw     %ymm0,%ymm\x,%ymm\x
vpsubw      %ymm\x,%ymm\r,%ymm\r
.endm

.macro csubq r,x=12
vpsubw      %ymm0,%ymm\r,%ymm\r
vpsraw      $15,%ymm\r,%ymm\x
vpand       %ymm0,%ymm\x,%ymm\x
vpaddw      %ymm\x,%ymm\r,%ymm\r
.endm

.macro caddq r,x=12
vpsraw      $15,%ymm\r,%ymm\x
vpand       %ymm0,%ymm\x,%ymm\x
vpaddw      %ymm\x,%ymm\r,%ymm\r
.endm

.macro fqmulprecomp al,ah,b,x=12
vpmullw     %ymm\al,%ymm\b,%ymm\x
vpmulhw     %ymm\ah,%ymm\b,%ymm\b
vpmulhw     %ymm0,%ymm\x,%ymm\x
vpsubw      %ymm\x,%ymm\b,%ymm\b
.endm
/***************************/

/*****.include "shuffle.inc"*****/
/********************************/
.macro shuffle8 r0,r1,r2,r3
vperm2i128  $0x20,%ymm\r1,%ymm\r0,%ymm\r2
vperm2i128  $0x31,%ymm\r1,%ymm\r0,%ymm\r3
.endm

.macro shuffle4 r0,r1,r2,r3
vpunpcklqdq %ymm\r1,%ymm\r0,%ymm\r2
vpunpckhqdq %ymm\r1,%ymm\r0,%ymm\r3
.endm

.macro shuffle2 r0,r1,r2,r3
#vpsllq     $32,%ymm\r1,%ymm\r2
vmovsldup   %ymm\r1,%ymm\r2
vpblendd    $0xAA,%ymm\r2,%ymm\r0,%ymm\r2
vpsrlq      $32,%ymm\r0,%ymm\r0
#vmovshdup  %ymm\r0,%ymm\r0
vpblendd    $0xAA,%ymm\r1,%ymm\r0,%ymm\r3
.endm

.macro shuffle1 r0,r1,r2,r3
vpslld      $16,%ymm\r1,%ymm\r2
vpblendw    $0xAA,%ymm\r2,%ymm\r0,%ymm\r2
vpsrld      $16,%ymm\r0,%ymm\r0
vpblendw    $0xAA,%ymm\r1,%ymm\r0,%ymm\r3
.endm
/********************************/

.text
nttunpack128_avx:
#load
vmovdqa     (%rdi),%ymm4
vmovdqa     32(%rdi),%ymm5
vmovdqa     64(%rdi),%ymm6
vmovdqa     96(%rdi),%ymm7
vmovdqa     128(%rdi),%ymm8
vmovdqa     160(%rdi),%ymm9
vmovdqa     192(%rdi),%ymm10
vmovdqa     224(%rdi),%ymm11

shuffle8    4,8,3,8
shuffle8    5,9,4,9
shuffle8    6,10,5,10
shuffle8    7,11,6,11

shuffle4    3,5,7,5
shuffle4    8,10,3,10
shuffle4    4,6,8,6
shuffle4    9,11,4,11

shuffle2    7,8,9,8
shuffle2    5,6,7,6
shuffle2    3,4,5,4
shuffle2    10,11,3,11

shuffle1    9,5,10,5
shuffle1    8,4,9,4
shuffle1    7,3,8,3
shuffle1    6,11,7,11

#store
vmovdqa     %ymm10,(%rdi)
vmovdqa     %ymm5,32(%rdi)
vmovdqa     %ymm9,64(%rdi)
vmovdqa     %ymm4,96(%rdi)
vmovdqa     %ymm8,128(%rdi)
vmovdqa     %ymm3,160(%rdi)
vmovdqa     %ymm7,192(%rdi)
vmovdqa     %ymm11,224(%rdi)

ret

.global cdecl(nttunpack_avx2_asm)
cdecl(nttunpack_avx2_asm):
call        nttunpack128_avx
add         $256,%rdi
call        nttunpack128_avx
ret

ntttobytes128_avx:
#load
vmovdqa     (%rsi),%ymm5
vmovdqa     32(%rsi),%ymm6
vmovdqa     64(%rsi),%ymm7
vmovdqa     96(%rsi),%ymm8
vmovdqa     128(%rsi),%ymm9
vmovdqa     160(%rsi),%ymm10
vmovdqa     192(%rsi),%ymm11
vmovdqa     224(%rsi),%ymm12

#csubq
csubq       5,13
csubq       6,13
csubq       7,13
csubq       8,13
csubq       9,13
csubq       10,13
csubq       11,13
csubq       12,13

#bitpack
vpsllw      $12,%ymm6,%ymm4
vpor        %ymm4,%ymm5,%ymm4

vpsrlw      $4,%ymm6,%ymm5
vpsllw      $8,%ymm7,%ymm6
vpor        %ymm5,%ymm6,%ymm5

vpsrlw      $8,%ymm7,%ymm6
vpsllw      $4,%ymm8,%ymm7
vpor        %ymm6,%ymm7,%ymm6

vpsllw      $12,%ymm10,%ymm7
vpor        %ymm7,%ymm9,%ymm7

vpsrlw      $4,%ymm10,%ymm8
vpsllw      $8,%ymm11,%ymm9
vpor        %ymm8,%ymm9,%ymm8

vpsrlw      $8,%ymm11,%ymm9
vpsllw      $4,%ymm12,%ymm10
vpor        %ymm9,%ymm10,%ymm9

shuffle1    4,5,3,5
shuffle1    6,7,4,7
shuffle1    8,9,6,9

shuffle2    3,4,8,4
shuffle2    6,5,3,5
shuffle2    7,9,6,9

shuffle4    8,3,7,3
shuffle4    6,4,8,4
shuffle4    5,9,6,9

shuffle8    7,8,5,8
shuffle8    6,3,7,3
shuffle8    4,9,6,9

#store
vmovdqu     %ymm5,(%rdi)
vmovdqu     %ymm7,32(%rdi)
vmovdqu     %ymm6,64(%rdi)
vmovdqu     %ymm8,96(%rdi)
vmovdqu     %ymm3,128(%rdi)
vmovdqu     %ymm9,160(%rdi)

ret

.global cdecl(ntttobytes_avx2_asm)
cdecl(ntttobytes_avx2_asm):
#consts
vmovdqa     _16XQ*2(%rdx),%ymm0
call        ntttobytes128_avx
add         $256,%rsi
add         $192,%rdi
call        ntttobytes128_avx
ret

nttfrombytes128_avx:
#load
vmovdqu     (%rsi),%ymm4
vmovdqu     32(%rsi),%ymm5
vmovdqu     64(%rsi),%ymm6
vmovdqu     96(%rsi),%ymm7
vmovdqu     128(%rsi),%ymm8
vmovdqu     160(%rsi),%ymm9

shuffle8    4,7,3,7
shuffle8    5,8,4,8
shuffle8    6,9,5,9

shuffle4    3,8,6,8
shuffle4    7,5,3,5
shuffle4    4,9,7,9

shuffle2    6,5,4,5
shuffle2    8,7,6,7
shuffle2    3,9,8,9

shuffle1    4,7,10,7
shuffle1    5,8,4,8
shuffle1    6,9,5,9

#bitunpack
vpsrlw      $12,%ymm10,%ymm11
vpsllw      $4,%ymm7,%ymm12
vpor        %ymm11,%ymm12,%ymm11
vpand       %ymm0,%ymm10,%ymm10
vpand       %ymm0,%ymm11,%ymm11

vpsrlw      $8,%ymm7,%ymm12
vpsllw      $8,%ymm4,%ymm13
vpor        %ymm12,%ymm13,%ymm12
vpand       %ymm0,%ymm12,%ymm12

vpsrlw      $4,%ymm4,%ymm13
vpand       %ymm0,%ymm13,%ymm13

vpsrlw      $12,%ymm8,%ymm14
vpsllw      $4,%ymm5,%ymm15
vpor        %ymm14,%ymm15,%ymm14
vpand       %ymm0,%ymm8,%ymm8
vpand       %ymm0,%ymm14,%ymm14

vpsrlw      $8,%ymm5,%ymm15
vpsllw      $8,%ymm9,%ymm1
vpor        %ymm15,%ymm1,%ymm15
vpand       %ymm0,%ymm15,%ymm15

vpsrlw      $4,%ymm9,%ymm1
vpand       %ymm0,%ymm1,%ymm1

#store
vmovdqa     %ymm10,(%rdi)
vmovdqa     %ymm11,32(%rdi)
vmovdqa     %ymm12,64(%rdi)
vmovdqa     %ymm13,96(%rdi)
vmovdqa     %ymm8,128(%rdi)
vmovdqa     %ymm14,160(%rdi)
vmovdqa     %ymm15,192(%rdi)
vmovdqa     %ymm1,224(%rdi)

ret

.global cdecl(nttfrombytes_avx2_asm)
cdecl(nttfrombytes_avx2_asm):
#consts
vmovdqa     _16XMASK*2(%rdx),%ymm0
call        nttfrombytes128_avx
add         $256,%rdi
add         $192,%rsi
call        nttfrombytes128_avx
ret
