//*******************************************************************************************
// Supersingular Isogeny Key Encapsulation Library
//
// Abstract: field arithmetic in x64 assembly for P434 on Linux
//*******************************************************************************************

/* Requires bmi2 instruction set for mulx. adx instructions are optional, but preferred. */
.intel_syntax noprefix

#define S2N_SIKE_P434_R3_NAMESPACE(s) s2n_sike_p434_r3_##s

// Registers that are used for parameter passing:
#define reg_p1  rdi
#define reg_p2  rsi
#define reg_p3  rdx

// Define addition instructions
#ifdef S2N_ADX

#define ADD1    adox
#define ADC1    adox
#define ADD2    adcx
#define ADC2    adcx

#else

#define ADD1    add
#define ADC1    adc
#define ADD2    add
#define ADC2    adc

#endif

#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif

.text

#define asm_p434 S2N_SIKE_P434_R3_NAMESPACE(asm_p434)
.align 32
.type   asm_p434, @object
.size   asm_p434, 56
asm_p434:
.quad   -1
.quad   -1
.quad   -1
.quad   -161717841442111489
.quad   8918917783347572387
.quad   7853257225132122198
.quad   620258357900100


#define asm_p434x2 S2N_SIKE_P434_R3_NAMESPACE(asm_p434x2)
.align 32
.type   asm_p434x2, @object
.size   asm_p434x2, 56
asm_p434x2:
.quad   -2
.quad   -1
.quad   -1
.quad   -323435682884222977
.quad   -608908507014406841
.quad   -2740229623445307220
.quad   1240516715800200


#define asm_p434x4 S2N_SIKE_P434_R3_NAMESPACE(asm_p434x4)
.align 32
.type   asm_p434x4, @object
.size   asm_p434x4, 56
asm_p434x4:
.quad   -4
.quad   -1
.quad   -1
.quad   -646871365768445953
.quad   -1217817014028813681
.quad   -5480459246890614439
.quad   2481033431600401


#define asm_p434p1 S2N_SIKE_P434_R3_NAMESPACE(asm_p434p1)
.align 32
.type   asm_p434p1, @object
.size   asm_p434p1, 56
asm_p434p1:
.quad   0
.quad   0
.quad   0
.quad   -161717841442111488
.quad   8918917783347572387
.quad   7853257225132122198
.quad   620258357900100

//***********************************************************************
//  Field addition
//  Operation: c [reg_p3] = a [reg_p1] + b [reg_p2]
//***********************************************************************
#define fpadd434_asm S2N_SIKE_P434_R3_NAMESPACE(fpadd434_asm)
.global fpadd434_asm
fpadd434_asm:
  push   r12
  push   r13
  push   r14
  push   r15
  push   rbx
  push   rbp
  
  xor    rax, rax
  mov    r8, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  mov    r12, [reg_p1+32]
  mov    r13, [reg_p1+40]
  mov    r14, [reg_p1+48]
  add    r8, [reg_p2] 
  adc    r9, [reg_p2+8] 
  adc    r10, [reg_p2+16] 
  adc    r11, [reg_p2+24] 
  adc    r12, [reg_p2+32] 
  adc    r13, [reg_p2+40] 
  adc    r14, [reg_p2+48]

  mov    rbx, [rip+asm_p434x2]
  sub    r8, rbx
  mov    rcx, [rip+asm_p434x2+8]
  sbb    r9, rcx
  sbb    r10, rcx
  mov    rdi, [rip+asm_p434x2+24]
  sbb    r11, rdi
  mov    rsi, [rip+asm_p434x2+32]
  sbb    r12, rsi
  mov    rbp, [rip+asm_p434x2+40]
  sbb    r13, rbp
  mov    r15, [rip+asm_p434x2+48]
  sbb    r14, r15
  sbb    rax, 0
  
  and    rbx, rax
  and    rcx, rax
  and    rdi, rax
  and    rsi, rax
  and    rbp, rax
  and    r15, rax
  
  add    r8, rbx  
  adc    r9, rcx  
  adc    r10, rcx  
  adc    r11, rdi 
  adc    r12, rsi 
  adc    r13, rbp   
  adc    r14, r15
  mov    [reg_p3], r8
  mov    [reg_p3+8], r9 
  mov    [reg_p3+16], r10 
  mov    [reg_p3+24], r11
  mov    [reg_p3+32], r12 
  mov    [reg_p3+40], r13 
  mov    [reg_p3+48], r14
  
  pop    rbp
  pop    rbx
  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret

//***********************************************************************
//  Field subtraction
//  Operation: c [reg_p3] = a [reg_p1] - b [reg_p2]
//***********************************************************************
#define fpsub434_asm S2N_SIKE_P434_R3_NAMESPACE(fpsub434_asm)
.global fpsub434_asm
fpsub434_asm:
  push   r12
  push   r13
  push   r14
  
  xor    rax, rax
  mov    r8, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  mov    r12, [reg_p1+32]
  mov    r13, [reg_p1+40]
  mov    r14, [reg_p1+48]
  sub    r8, [reg_p2] 
  sbb    r9, [reg_p2+8] 
  sbb    r10, [reg_p2+16] 
  sbb    r11, [reg_p2+24] 
  sbb    r12, [reg_p2+32] 
  sbb    r13, [reg_p2+40] 
  sbb    r14, [reg_p2+48]
  sbb    rax, 0
  
  mov    rcx, [rip+asm_p434x2]
  mov    rdi, [rip+asm_p434x2+8]
  mov    rsi, [rip+asm_p434x2+24]
  and    rcx, rax
  and    rdi, rax
  and    rsi, rax  
  add    r8, rcx  
  adc    r9, rdi  
  adc    r10, rdi  
  adc    r11, rsi 
  mov    [reg_p3], r8
  mov    [reg_p3+8], r9 
  mov    [reg_p3+16], r10 
  mov    [reg_p3+24], r11 
  setc   cl  

  mov    r8, [rip+asm_p434x2+32]
  mov    rdi, [rip+asm_p434x2+40]
  mov    rsi, [rip+asm_p434x2+48]
  and    r8, rax
  and    rdi, rax
  and    rsi, rax  
  bt     rcx, 0  
  adc    r12, r8 
  adc    r13, rdi   
  adc    r14, rsi
  mov    [reg_p3+32], r12 
  mov    [reg_p3+40], r13
  mov    [reg_p3+48], r14
  
  pop    r14
  pop    r13
  pop    r12
  ret

///////////////////////////////////////////////////////////////// MACRO
.macro SUB434_PX  P0
  push   r12
  push   r13

  mov    r8, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  mov    r12, [reg_p1+32]
  mov    r13, [reg_p1+40]
  mov    rcx, [reg_p1+48]
  sub    r8, [reg_p2]
  sbb    r9, [reg_p2+8]
  sbb    r10, [reg_p2+16]
  sbb    r11, [reg_p2+24]
  sbb    r12, [reg_p2+32]
  sbb    r13, [reg_p2+40]
  sbb    rcx, [reg_p2+48]

  mov    rax, [rip+\P0]
  mov    rdi, [rip+\P0+8]
  mov    rsi, [rip+\P0+24]
  add    r8, rax
  mov    rax, [rip+\P0+32]
  adc    r9, rdi
  adc    r10, rdi
  adc    r11, rsi
  mov    rdi, [rip+\P0+40]
  mov    rsi, [rip+\P0+48]
  adc    r12, rax
  adc    r13, rdi
  adc    rcx, rsi
  mov    [reg_p3], r8
  mov    [reg_p3+8], r9
  mov    [reg_p3+16], r10
  mov    [reg_p3+24], r11
  mov    [reg_p3+32], r12
  mov    [reg_p3+40], r13
  mov    [reg_p3+48], rcx

  pop    r13
  pop    r12
.endm

//***********************************************************************
//  Multiprecision subtraction with correction with 2*p434
//  Operation: c [reg_p3] = a [reg_p1] - b [reg_p2] + 2*p434
//***********************************************************************
#define mp_sub434_p2_asm S2N_SIKE_P434_R3_NAMESPACE(mp_sub434_p2_asm)
.global mp_sub434_p2_asm
mp_sub434_p2_asm:
  SUB434_PX  asm_p434x2
  ret

//***********************************************************************
//  Multiprecision subtraction with correction with 4*p434
//  Operation: c [reg_p3] = a [reg_p1] - b [reg_p2] + 4*p434
//***********************************************************************
#define mp_sub434_p4_asm S2N_SIKE_P434_R3_NAMESPACE(mp_sub434_p4_asm)
.global mp_sub434_p4_asm
mp_sub434_p4_asm:
  SUB434_PX  asm_p434x4
  ret
    
///////////////////////////////////////////////////////////////// MACRO
// Schoolbook integer multiplication
// Inputs:  memory pointers M0 and M1
// Outputs: memory pointer C and regs T1, T3, rax
// Temps:   regs T0:T6
/////////////////////////////////////////////////////////////////
#ifdef S2N_ADX

.macro MUL192_SCHOOL M0, M1, C, T0, T1, T2, T3, T4, T5, T6
  mov    rdx, \M0
  mulx   \T0, \T1, \M1     // T0:T1 = A0*B0
  mov    \C, \T1           // C0_final
  mulx   \T1, \T2, 8\M1    // T1:T2 = A0*B1
  xor    rax, rax
  adox   \T0, \T2
  mulx   \T2, \T3, 16\M1   // T2:T3 = A0*B2
  adox   \T1, \T3

  mov    rdx, 8\M0
  mulx   \T3, \T4, \M1     // T3:T4 = A1*B0
  adox   \T2, rax
  xor    rax, rax
  mulx   \T5, \T6, 8\M1    // T5:T6 = A1*B1
  adox   \T4, \T0
  mov    8\C, \T4          // C1_final
  adcx   \T3, \T6
  mulx   \T6, \T0, 16\M1   // T6:T0 = A1*B2
  adox   \T3, \T1
  adcx   \T5, \T0
  adcx   \T6, rax
  adox   \T5, \T2

  mov    rdx, 16\M0
  mulx   \T1, \T0, \M1     // T1:T0 = A2*B0
  adox   \T6, rax
  xor    rax, rax
  mulx   \T4, \T2, 8\M1    // T4:T2 = A2*B1
  adox   \T0, \T3
  mov    16\C, \T0         // C2_final
  adcx   \T1, \T5
  mulx   \T0, \T3, 16\M1   // T0:T3 = A2*B2
  adcx   \T4, \T6
  adcx   \T0, rax
  adox   \T1, \T2
  adox   \T3, \T4
  adox   rax, \T0
.endm 

///////////////////////////////////////////////////////////////// MACRO
// Schoolbook integer multiplication
// Inputs:  memory pointers M0 and M1
// Outputs: memory pointer C
// Temps:   regs T0:T9
/////////////////////////////////////////////////////////////////
.macro MUL256_SCHOOL M0, M1, C, T0, T1, T2, T3, T4, T5, T6, T7, T8, T9
  mov    rdx, \M0
  mulx   \T0, \T1, \M1     // T0:T1 = A0*B0
  mov    \C, \T1           // C0_final
  mulx   \T1, \T2, 8\M1    // T1:T2 = A0*B1
  xor    rax, rax
  adox   \T0, \T2
  mulx   \T2, \T3, 16\M1   // T2:T3 = A0*B2
  adox   \T1, \T3
  mulx   \T3, \T4, 24\M1   // T3:T4 = A0*B3
  adox   \T2, \T4

  mov    rdx, 8\M0
  mulx   \T5, \T4, \M1     // T5:T4 = A1*B0
  adox   \T3, rax
  xor    rax, rax
  mulx   \T6, \T7, 8\M1    // T6:T7 = A1*B1
  adox   \T4, \T0
  mov    8\C, \T4          // C1_final
  adcx   \T5, \T7
  mulx   \T7, \T8, 16\M1   // T7:T8 = A1*B2
  adcx   \T6, \T8
  adox   \T5, \T1
  mulx   \T8, \T9, 24\M1   // T8:T9 = A1*B3
  adcx   \T7, \T9
  adcx   \T8, rax
  adox   \T6, \T2

  mov    rdx, 16\M0
  mulx   \T1, \T0, \M1     // T1:T0 = A2*B0
  adox   \T7, \T3
  adox   \T8, rax
  xor    rax, rax
  mulx   \T2, \T3, 8\M1    // T2:T3 = A2*B1
  adox   \T0, \T5
  mov    16\C, \T0         // C2_final
  adcx   \T1, \T3
  mulx   \T3, \T4, 16\M1   // T3:T4 = A2*B2
  adcx   \T2, \T4
  adox   \T1, \T6
  mulx   \T4,\T9, 24\M1    // T3:T4 = A2*B3
  adcx   \T3, \T9
  mov    rdx, 24\M0
  adcx   \T4, rax

  adox   \T2, \T7
  adox   \T3, \T8
  adox   \T4, rax

  mulx   \T5, \T0, \M1     // T5:T0 = A3*B0
  xor    rax, rax
  mulx   \T6, \T7, 8\M1    // T6:T7 = A3*B1
  adcx   \T5, \T7
  adox   \T1, \T0
  mulx   \T7, \T8, 16\M1   // T7:T8 = A3*B2
  adcx   \T6, \T8
  adox   \T2, \T5
  mulx   \T8, \T9, 24\M1   // T8:T9 = A3*B3
  adcx   \T7, \T9
  adcx   \T8, rax

  adox   \T3, \T6
  adox   \T4, \T7
  adox   \T8, rax
  mov    24\C, \T1         // C3_final
  mov    32\C, \T2         // C4_final
  mov    40\C, \T3         // C5_final
  mov    48\C, \T4         // C6_final
  mov    56\C, \T8         // C7_final
.endm 

#else // S2N_ADX

.macro MUL192_SCHOOL M0, M1, C, T0, T1, T2, T3, T4, T5, T6
  mov    rdx, \M0
  mulx   \T0, \T1, \M1     // T0:T1 = A0*B0
  mov    \C, \T1           // C0_final
  mulx   \T1, \T2, 8\M1    // T1:T2 = A0*B1
  add    \T0, \T2
  mulx   \T2, \T3, 16\M1   // T2:T3 = A0*B2
  adc    \T1, \T3

  mov    rdx, 8\M0
  mulx   \T3, \T4, \M1     // T3:T4 = A1*B0
  adc    \T2, 0
  mulx   \T5, \T6, 8\M1    // T5:T6 = A1*B1
  add    \T4, \T0
  mov    8\C, \T4          // C1_final
  adc    \T3, \T1
  adc    \T5, \T2
  mulx   \T2, \T1, 16\M1   // T2:T1 = A1*B2
  adc    \T2, 0

  add    \T3, \T6
  adc    \T5, \T1
  adc    \T2, 0

  mov    rdx, 16\M0
  mulx   \T1, \T0, \M1     // T1:T0 = A2*B0
  add    \T0, \T3
  mov    16\C, \T0         // C2_final
  mulx   \T4, \T6, 8\M1    // T4:T6 = A2*B1
  adc    \T1, \T5
  adc    \T2, \T4
  mulx   rax, \T3, 16\M1   // rax:T3 = A2*B2
  adc    rax, 0
  add    \T1, \T6
  adc    \T3, \T2
  adc    rax, 0
.endm 

.macro MUL256_SCHOOL M0, M1, C, T0, T1, T2, T3, T4, T5, T6, T7, T8, T9
  mov    rdx, \M0
  mulx   \T0, \T1, \M1     // T0:T1 = A0*B0
  mov    \C, \T1           // C0_final
  mulx   \T1, \T2, 8\M1    // T1:T2 = A0*B1
  add    \T0, \T2
  mulx   \T2, \T3, 16\M1   // T2:T3 = A0*B2
  adc    \T1, \T3
  mulx   \T3, \T4, 24\M1   // T3:T4 = A0*B3
  adc    \T2, \T4
  mov    rdx, 8\M0
  adc    \T3, 0

  mulx   \T5, \T4, \M1     // T5:T4 = A1*B0
  mulx   \T6, \T7, 8\M1    // T6:T7 = A1*B1
  add    \T5, \T7
  mulx   \T7, \T8, 16\M1   // T7:T8 = A1*B2
  adc    \T6, \T8
  mulx   \T8, \T9, 24\M1   // T8:T9 = A1*B3
  adc    \T7, \T9
  adc    \T8, 0

  add    \T4, \T0
  mov    8\C, \T4          // C1_final
  adc    \T5, \T1
  adc    \T6, \T2
  adc    \T7, \T3
  mov    rdx, 16\M0
  adc    \T8, 0

  mulx   \T1, \T0, \M1     // T1:T0 = A2*B0
  mulx   \T2, \T3, 8\M1    // T2:T3 = A2*B1
  add    \T1, \T3
  mulx   \T3, \T4, 16\M1   // T3:T4 = A2*B2
  adc    \T2, \T4
  mulx   \T4,\T9, 24\M1    // T3:T4 = A2*B3
  adc    \T3, \T9
  mov    rdx, 24\M0
  adc    \T4, 0

  add    \T0, \T5
  mov    16\C, \T0         // C2_final
  adc    \T1, \T6
  adc    \T2, \T7
  adc    \T3, \T8
  adc    \T4, 0

  mulx   \T5, \T0, \M1     // T5:T0 = A3*B0
  mulx   \T6, \T7, 8\M1    // T6:T7 = A3*B1
  add    \T5, \T7
  mulx   \T7, \T8, 16\M1   // T7:T8 = A3*B2
  adc    \T6, \T8
  mulx   \T8, \T9, 24\M1   // T8:T9 = A3*B3
  adc    \T7, \T9
  adc    \T8, 0

  add    \T1, \T0
  mov    24\C, \T1         // C3_final
  adc    \T2, \T5
  mov    32\C, \T2         // C4_final
  adc    \T3, \T6
  mov    40\C, \T3         // C5_final
  adc    \T4, \T7
  mov    48\C, \T4         // C6_final
  adc    \T8, 0
  mov    56\C, \T8         // C7_final
.endm

#endif // S2N_ADX

//*****************************************************************************
//  434-bit multiplication using Karatsuba (one level), schoolbook (one level)
//*****************************************************************************
#define mul434_asm S2N_SIKE_P434_R3_NAMESPACE(mul434_asm)
.global mul434_asm
mul434_asm:
  push   r12
  push   r13
  push   r14
  push   r15
  mov    rcx, reg_p3

  // r8-r11 <- AH + AL, rax <- mask
  xor    rax, rax
  mov    r8, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  push   rbx
  push   rbp
  sub    rsp, 96
  add    r8, [reg_p1+32]
  adc    r9, [reg_p1+40]
  adc    r10, [reg_p1+48]
  adc    r11, 0
  sbb    rax, 0
  mov    [rsp], r8
  mov    [rsp+8], r9
  mov    [rsp+16], r10
  mov    [rsp+24], r11

  // r12-r15 <- BH + BL, rbx <- mask
  xor    rbx, rbx
  mov    r12, [reg_p2]
  mov    r13, [reg_p2+8]
  mov    r14, [reg_p2+16]
  mov    r15, [reg_p2+24]
  add    r12, [reg_p2+32]
  adc    r13, [reg_p2+40]
  adc    r14, [reg_p2+48]
  adc    r15, 0
  sbb    rbx, 0
  mov    [rsp+32], r12
  mov    [rsp+40], r13
  mov    [rsp+48], r14
  mov    [rsp+56], r15

  // r12-r15 <- masked (BH + BL)
  and    r12, rax
  and    r13, rax
  and    r14, rax
  and    r15, rax

  // r8-r11 <- masked (AH + AL)
  and    r8, rbx
  and    r9, rbx
  and    r10, rbx
  and    r11, rbx

  // r8-r11 <- masked (AH + AL) + masked (AH + AL)
  add    r8, r12
  adc    r9, r13
  adc    r10, r14
  adc    r11, r15
  mov    [rsp+64], r8
  mov    [rsp+72], r9
  mov    [rsp+80], r10
  mov    [rsp+88], r11

  // [rsp] <- (AH+AL) x (BH+BL), low part
  MUL256_SCHOOL  [rsp], [rsp+32], [rsp], r8, r9, r10, r11, r12, r13, r14, r15, rbx, rbp

  // [rcx] <- AL x BL
  MUL256_SCHOOL  [reg_p1], [reg_p2], [rcx], r8, r9, r10, r11, r12, r13, r14, r15, rbx, rbp     // Result C0-C3

  // [rcx+64], rbx, rbp, rax <- AH x BH
  MUL192_SCHOOL  [reg_p1+32], [reg_p2+32], [rcx+64], r8, rbx, r10, rbp, r12, r13, r14

  // r8-r11 <- (AH+AL) x (BH+BL), final step
  mov    r8, [rsp+64]
  mov    r9, [rsp+72]
  mov    r10, [rsp+80]
  mov    r11, [rsp+88]
  mov    rdx, [rsp+32]
  add    r8, rdx
  mov    rdx, [rsp+40]
  adc    r9, rdx
  mov    rdx, [rsp+48]
  adc    r10, rdx
  mov    rdx, [rsp+56]
  adc    r11, rdx

  // r8-r15 <- (AH+AL) x (BH+BL) - ALxBL
  mov    r12, [rsp]
  mov    r13, [rsp+8]
  mov    r14, [rsp+16]
  mov    r15, [rsp+24]
  sub    r12, [rcx]
  sbb    r13, [rcx+8]
  sbb    r14, [rcx+16]
  sbb    r15, [rcx+24]
  sbb    r8, [rcx+32]
  sbb    r9, [rcx+40]
  sbb    r10, [rcx+48]
  sbb    r11, [rcx+56]

  // r8-r15 <- (AH+AL) x (BH+BL) - ALxBL - AHxBH
  sub    r12, [rcx+64]
  sbb    r13, [rcx+72]
  sbb    r14, [rcx+80]
  sbb    r15, rbx
  sbb    r8, rbp
  sbb    r9, rax
  sbb    r10, 0
  sbb    r11, 0

  add    r12, [rcx+32]
  mov    [rcx+32], r12    // Result C4-C7
  adc    r13, [rcx+40]
  mov    [rcx+40], r13
  adc    r14, [rcx+48]
  mov    [rcx+48], r14
  adc    r15, [rcx+56]
  mov    [rcx+56], r15
  adc    r8, [rcx+64]
  mov    [rcx+64], r8    // Result C8-C15
  adc    r9, [rcx+72]
  mov    [rcx+72], r9
  adc    r10, [rcx+80]
  mov    [rcx+80], r10
  adc    r11, rbx
  mov    [rcx+88], r11
  adc    rbp, 0
  mov    [rcx+96], rbp
  adc    rax, 0
  mov    [rcx+104], rax

  add    rsp, 96
  pop    rbp
  pop    rbx
  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret

///////////////////////////////////////////////////////////////// MACRO
// Schoolbook integer multiplication
// Inputs:  reg I0 and memory pointer M1
// Outputs: regs T0:T4
// Temps:   regs T0:T5
/////////////////////////////////////////////////////////////////
.macro MUL64x256_SCHOOL I0, M1, T0, T1, T2, T3, T4, T5 
  mulx   \T2, \T4, 8\M1
  xor    rax, rax
  mulx   \T3, \T5, 16\M1
  ADD1   \T1, \T4            // T1 <- C1_final
  ADC1   \T2, \T5            // T2 <- C2_final
  mulx   \T4, \T5, 24\M1
  ADC1   \T3, \T5            // T3 <- C3_final
  ADC1   \T4, rax            // T4 <- C4_final
.endm

///////////////////////////////////////////////////////////////// MACRO
// Schoolbook integer multiplication
// Inputs:  regs I0 and I1, and memory pointer M1
// Outputs: regs T0:T5
// Temps:   regs T0:T5
/////////////////////////////////////////////////////////////////
#ifdef S2N_ADX

.macro MUL128x256_SCHOOL I0, I1, M1, T0, T1, T2, T3, T4, T5
  mulx   \T2, \T4, 8\M1
  xor    rax, rax
  mulx   \T3, \T5, 16\M1
  ADD1   \T1, \T4
  ADC1   \T2, \T5
  mulx   \T4, \T5, 24\M1
  ADC1   \T3, \T5
  ADC1   \T4, rax

  xor    rax, rax
  mov    rdx, \I1
  mulx   \I1, \T5, \M1
  ADD2   \T1, \T5            // T1 <- C1_final
  ADC2   \T2, \I1
  mulx   \T5, \I1, 8\M1
  ADC2   \T3, \T5
  ADD1   \T2, \I1
  mulx   \T5, \I1, 16\M1
  ADC2   \T4, \T5
  ADC1   \T3, \I1
  mulx   \T5, \I1, 24\M1
  ADC2   \T5, rax
  ADC1   \T4, \I1
  ADC1   \T5, rax
.endm

#else // S2N_ADX

.macro MUL128x256_SCHOOL I0, I1, M1, T0, T1, T2, T3, T4, T5 
  mulx   \T2, \T4, 8\M1
  mulx   \T3, \T5, 16\M1
  add    \T1, \T4
  adc    \T2, \T5
  mulx   \T4, \T5, 24\M1
  adc    \T3, \T5
  adc    \T4, 0

  mov    rdx, \I1
  mulx   \I1, \T5, \M1
  add    \T1, \T5            // T1 <- C1_final
  adc    \T2, \I1
  mulx   \T5, \I1, 8\M1
  adc    \T3, \T5
  mulx   \T5, rax, 16\M1
  adc    \T4, \T5
  mulx   \T5, rdx, 24\M1
  adc    \T5, 0
  add    \T2, \I1
  adc    \T3, rax
  adc    \T4, rdx
  adc    \T5, 0
.endm

#endif // S2N_ADX

//**************************************************************************************
//  Montgomery reduction
//  Based on method described in Faz-Hernandez et al. https://eprint.iacr.org/2017/1015
//  Operation: c [reg_p2] = a [reg_p1]
//**************************************************************************************
#define rdc434_asm S2N_SIKE_P434_R3_NAMESPACE(rdc434_asm)
.global rdc434_asm
rdc434_asm:
  push   r14

  // a[0-1] x p434p1_nz --> result: r8:r13
  mov    rdx, [reg_p1]
  mov    r14, [reg_p1+8]
  mulx   r9, r8, [rip+asm_p434p1+24]   // result r8
  push   r12
  push   r13
  push   r15
  push   rbp
  push   rbx
  MUL128x256_SCHOOL rdx, r14, [rip+asm_p434p1+24], r8, r9, r10, r11, r12, r13

  mov    rdx, [reg_p1+16]
  mov    rcx, [reg_p1+72]
  add    r8, [reg_p1+24]
  adc    r9, [reg_p1+32]
  adc    r10, [reg_p1+40]
  adc    r11, [reg_p1+48]
  adc    r12, [reg_p1+56]
  adc    r13, [reg_p1+64]
  adc    rcx, 0
  mulx   rbp, rbx, [rip+asm_p434p1+24]   // result rbx
  mov    [reg_p2], r9
  mov    [reg_p2+8], r10
  mov    [reg_p2+16], r11
  mov    [reg_p2+24], r12
  mov    [reg_p2+32], r13
  mov    r9, [reg_p1+80]
  mov    r10, [reg_p1+88]
  mov    r11, [reg_p1+96]
  mov    rdi, [reg_p1+104]
  adc    r9, 0
  adc    r10, 0
  adc    r11, 0
  adc    rdi, 0

  // a[2-3] x p434p1_nz --> result: rbx, rbp, r12:r15
  MUL128x256_SCHOOL rdx, r8, [rip+asm_p434p1+24], rbx, rbp, r12, r13, r14, r15

  mov    rdx, [reg_p2]
  add    rbx, [reg_p2+8]
  adc    rbp, [reg_p2+16]
  adc    r12, [reg_p2+24]
  adc    r13, [reg_p2+32]
  adc    r14, rcx
  mov    rcx, 0
  adc    r15, r9
  adc    rcx, r10
  mulx   r9, r8, [rip+asm_p434p1+24]   // result r8
  mov    [reg_p2], rbp
  mov    [reg_p2+8], r12
  mov    [reg_p2+16], r13
  adc    r11, 0
  adc    rdi, 0

  // a[4-5] x p434p1_nz --> result: r8:r13
  MUL128x256_SCHOOL rdx, rbx, [rip+asm_p434p1+24], r8, r9, r10, rbp, r12, r13

  mov    rdx, [reg_p2]
  add    r8, [reg_p2+8]
  adc    r9, [reg_p2+16]
  adc    r10, r14
  adc    rbp, r15
  adc    r12, rcx
  adc    r13, r11
  adc    rdi, 0
  mulx   r15, r14, [rip+asm_p434p1+24]  // result r14
  mov    [reg_p2], r8        // Final result c0-c1
  mov    [reg_p2+8], r9

  // a[6-7] x p434p1_nz --> result: r14:r15, r8:r9, r11
  MUL64x256_SCHOOL rdx, [rip+asm_p434p1+24], r14, r15, r8, r9, r11, rcx

  // Final result c2:c6
  add    r14, r10
  adc    r15, rbp
  pop    rbx
  pop    rbp
  adc    r8, r12
  adc    r9, r13
  adc    r11, rdi
  mov    [reg_p2+16], r14
  mov    [reg_p2+24], r15
  pop    r15
  pop    r13
  mov    [reg_p2+32], r8
  mov    [reg_p2+40], r9
  mov    [reg_p2+48], r11

  pop    r12
  pop    r14
  ret

//***********************************************************************
//  434-bit multiprecision addition
//  Operation: c [reg_p3] = a [reg_p1] + b [reg_p2]
//***********************************************************************
#define mp_add434_asm S2N_SIKE_P434_R3_NAMESPACE(mp_add434_asm)
.global mp_add434_asm
mp_add434_asm:
  mov    r8, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  add    r8, [reg_p2] 
  adc    r9, [reg_p2+8] 
  adc    r10, [reg_p2+16] 
  adc    r11, [reg_p2+24] 
  mov    [reg_p3], r8
  mov    [reg_p3+8], r9
  mov    [reg_p3+16], r10
  mov    [reg_p3+24], r11

  mov    r8, [reg_p1+32]
  mov    r9, [reg_p1+40]
  mov    r10, [reg_p1+48]
  adc    r8, [reg_p2+32] 
  adc    r9, [reg_p2+40] 
  adc    r10, [reg_p2+48] 
  mov    [reg_p3+32], r8
  mov    [reg_p3+40], r9
  mov    [reg_p3+48], r10
  ret

//***************************************************************************
//  2x434-bit multiprecision subtraction/addition
//  Operation: c [reg_p3] = a [reg_p1] - b [reg_p2]. If c < 0, add p434*2^448
//***************************************************************************
#define mp_subadd434x2_asm S2N_SIKE_P434_R3_NAMESPACE(mp_subadd434x2_asm)
.global mp_subadd434x2_asm
mp_subadd434x2_asm:
  push   r12
  push   r13 
  push   r14 
  push   r15 
  xor    rax, rax
  mov    r8, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  mov    r12, [reg_p1+32]
  sub    r8, [reg_p2] 
  sbb    r9, [reg_p2+8] 
  sbb    r10, [reg_p2+16] 
  sbb    r11, [reg_p2+24] 
  sbb    r12, [reg_p2+32] 
  mov    [reg_p3], r8
  mov    [reg_p3+8], r9
  mov    [reg_p3+16], r10
  mov    [reg_p3+24], r11
  mov    [reg_p3+32], r12

  mov    r8, [reg_p1+40]
  mov    r9, [reg_p1+48]
  mov    r10, [reg_p1+56] 
  mov    r11, [reg_p1+64]
  mov    r12, [reg_p1+72] 
  sbb    r8, [reg_p2+40] 
  sbb    r9, [reg_p2+48] 
  sbb    r10, [reg_p2+56]
  sbb    r11, [reg_p2+64] 
  sbb    r12, [reg_p2+72]
  mov    [reg_p3+40], r8
  mov    [reg_p3+48], r9
  mov    [reg_p3+56], r10

  mov    r13, [reg_p1+80]
  mov    r14, [reg_p1+88] 
  mov    r15, [reg_p1+96]
  mov    rcx, [reg_p1+104]
  sbb    r13, [reg_p2+80]
  sbb    r14, [reg_p2+88]
  sbb    r15, [reg_p2+96] 
  sbb    rcx, [reg_p2+104] 
  sbb    rax, 0

  // Add p434 anded with the mask in rax 
  mov    r8, [rip+asm_p434]
  mov    r9, [rip+asm_p434+24]
  mov    r10, [rip+asm_p434+32]
  mov    rdi, [rip+asm_p434+40]
  mov    rsi, [rip+asm_p434+48]
  and    r8, rax
  and    r9, rax
  and    r10, rax
  and    rdi, rax
  and    rsi, rax
  mov    rax, [reg_p3+56]
  add    rax, r8
  adc    r11, r8
  adc    r12, r8
  adc    r13, r9
  adc    r14, r10
  adc    r15, rdi
  adc    rcx, rsi

  mov    [reg_p3+56], rax
  mov    [reg_p3+64], r11
  mov    [reg_p3+72], r12
  mov    [reg_p3+80], r13
  mov    [reg_p3+88], r14
  mov    [reg_p3+96], r15
  mov    [reg_p3+104], rcx
  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret

//***********************************************************************
//  Double 2x434-bit multiprecision subtraction
//  Operation: c [reg_p3] = c [reg_p3] - a [reg_p1] - b [reg_p2]
//***********************************************************************
#define mp_dblsub434x2_asm S2N_SIKE_P434_R3_NAMESPACE(mp_dblsub434x2_asm)
.global mp_dblsub434x2_asm
mp_dblsub434x2_asm:
  push   r12
  push   r13
  push   r14

  mov    r8, [reg_p3]
  mov    r9, [reg_p3+8]
  mov    r10, [reg_p3+16]
  mov    r11, [reg_p3+24]
  mov    r12, [reg_p3+32]
  mov    r13, [reg_p3+40]
  mov    r14, [reg_p3+48]
  sub    r8, [reg_p1]
  sbb    r9, [reg_p1+8] 
  sbb    r10, [reg_p1+16] 
  sbb    r11, [reg_p1+24] 
  sbb    r12, [reg_p1+32] 
  sbb    r13, [reg_p1+40] 
  sbb    r14, [reg_p1+48]
  setc   al  
  sub    r8, [reg_p2]
  sbb    r9, [reg_p2+8] 
  sbb    r10, [reg_p2+16] 
  sbb    r11, [reg_p2+24] 
  sbb    r12, [reg_p2+32] 
  sbb    r13, [reg_p2+40] 
  sbb    r14, [reg_p2+48]
  setc   cl  
  mov    [reg_p3], r8
  mov    [reg_p3+8], r9
  mov    [reg_p3+16], r10
  mov    [reg_p3+24], r11
  mov    [reg_p3+32], r12
  mov    [reg_p3+40], r13
  mov    [reg_p3+48], r14

  mov    r8, [reg_p3+56]
  mov    r9, [reg_p3+64]
  mov    r10, [reg_p3+72]
  mov    r11, [reg_p3+80]
  mov    r12, [reg_p3+88]
  mov    r13, [reg_p3+96]
  mov    r14, [reg_p3+104]
  bt     rax, 0  
  sbb    r8, [reg_p1+56] 
  sbb    r9, [reg_p1+64] 
  sbb    r10, [reg_p1+72] 
  sbb    r11, [reg_p1+80] 
  sbb    r12, [reg_p1+88] 
  sbb    r13, [reg_p1+96] 
  sbb    r14, [reg_p1+104]
  bt     rcx, 0  
  sbb    r8, [reg_p2+56] 
  sbb    r9, [reg_p2+64] 
  sbb    r10, [reg_p2+72] 
  sbb    r11, [reg_p2+80] 
  sbb    r12, [reg_p2+88] 
  sbb    r13, [reg_p2+96] 
  sbb    r14, [reg_p2+104] 
  mov    [reg_p3+56], r8
  mov    [reg_p3+64], r9
  mov    [reg_p3+72], r10
  mov    [reg_p3+80], r11
  mov    [reg_p3+88], r12
  mov    [reg_p3+96], r13
  mov    [reg_p3+104], r14

  pop    r14
  pop    r13
  pop    r12
  ret
