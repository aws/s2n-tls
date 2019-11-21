//*******************************************************************************************
// SIDH: an efficient supersingular isogeny cryptography library
//
// Abstract: field arithmetic in x64 assembly for P434 on Linux
//*******************************************************************************************  

.intel_syntax noprefix 

// Registers that are used for parameter passing:
#define reg_p1  rdi
#define reg_p2  rsi
#define reg_p3  rdx

// Define addition instructions
#ifdef _MULX_
#ifdef _ADX_

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
#endif


.text
//***********************************************************************
//  Field addition
//  Operation: c [reg_p3] = a [reg_p1] + b [reg_p2]
//*********************************************************************** 
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

  mov    rbx, [rip+p434x2]
  sub    r8, rbx
  mov    rcx, [rip+p434x2+8]
  sbb    r9, rcx
  sbb    r10, rcx
  mov    rdi, [rip+p434x2+24]
  sbb    r11, rdi
  mov    rsi, [rip+p434x2+32]
  sbb    r12, rsi
  mov    rbp, [rip+p434x2+40]
  sbb    r13, rbp
  mov    r15, [rip+p434x2+48]
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
  
  mov    rcx, [rip+p434x2]
  mov    rdi, [rip+p434x2+8]
  mov    rsi, [rip+p434x2+24]
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

  mov    r8, [rip+p434x2+32]
  mov    rdi, [rip+p434x2+40]
  mov    rsi, [rip+p434x2+48]
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


#ifdef _MULX_
    
///////////////////////////////////////////////////////////////// MACRO
// Schoolbook integer multiplication, a full row at a time
// Inputs:  memory pointers M0 and M1
// Outputs: memory pointer C
// Temps:   regs T0:T9
/////////////////////////////////////////////////////////////////

#ifdef _ADX_
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
    adox   \T0, rax
    mov    24\C, \T1         // C3_final
    mov    32\C, \T3         // C4_final
    mov    40\C, \T0         // C5_final
.endm 

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

#else

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
    mulx   \T0, \T1, 16\M1   // T0:T1 = A1*B2
    adc    \T0, 0    

    add    \T3, \T6  
    adc    \T5, \T1     
    adc    \T0, 0
    
    mov    rdx, 16\M0
    mulx   \T1, \T2, \M1     // T1:T2 = A2*B0
    add    \T2, \T3   
    mov    16\C, \T2         // C2_final 
    mulx   \T4, \T6, 8\M1    // T4:T6 = A2*B1
    adc    \T1, \T5    
    adc    \T0, \T4 
    mulx   \T2, \T3, 16\M1   // T0:T3 = A2*B2 
    adc    \T2, 0
    add    \T1, \T6
    adc    \T0, \T3
    adc    \T2, 0
    mov    24\C, \T1         // C3_final
    mov    32\C, \T0         // C4_final
    mov    40\C, \T2         // C5_final
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
#endif


//*****************************************************************************
//  434-bit multiplication using Karatsuba (one level), schoolbook (one level)
//***************************************************************************** 
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

    // r8-r11 <- masked (AH + AL) + masked (BH + BL)
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

    // [rcx+64] <- AH x BH
    MUL192_SCHOOL  [reg_p1+32], [reg_p2+32], [rcx+64], r8, r9, r10, r11, r12, r13, r14
    
    // r8-r11 <- (AH+AL) x (BH+BL), final step
    mov    r8, [rsp+64]
    mov    r9, [rsp+72]
    mov    r10, [rsp+80]
    mov    r11, [rsp+88]
    mov    rax, [rsp+32]
    add    r8, rax
    mov    rax, [rsp+40]
    adc    r9, rax
    mov    rax, [rsp+48]
    adc    r10, rax
    mov    rax, [rsp+56]
    adc    r11, rax
    
    // [rsp], x3-x5 <- (AH+AL) x (BH+BL) - ALxBL
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
    sbb    r15, [rcx+88]
    sbb    r8, [rcx+96]
    sbb    r9, [rcx+104]
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
    adc    r11, [rcx+88]
    mov    [rcx+88], r11
    mov    r12, [rcx+96]
    adc    r12, 0
    mov    [rcx+96], r12 
    mov    r13, [rcx+104]
    adc    r13, 0
    mov    [rcx+104], r13
    
    add    rsp, 96    
    pop    rbp  
    pop    rbx
    pop    r15
    pop    r14
    pop    r13
    pop    r12
    ret

#else

//***********************************************************************                       
//  Integer multiplication
//  Based on Karatsuba method
//  Operation: c [reg_p3] = a [reg_p1] * b [reg_p2]
//  NOTE: a=c or b=c are not allowed
//***********************************************************************
.global mul434_asm
mul434_asm:

  ret

# error "CONFIGURATION NOT SUPPORTED. TRY USE_MULX=TRUE"

#endif


#ifdef _MULX_

///////////////////////////////////////////////////////////////// MACRO
// Schoolbook integer multiplication
// Inputs:  memory pointers M0 and M1
// Outputs: regs T0:T5
// Temps:   regs T7:T6
/////////////////////////////////////////////////////////////////
.macro MUL64x256_SCHOOL M0, M1, T0, T1, T2, T3, T4, T5 
    mov    rdx, \M0
    mulx   \T1, \T0, \M1       // T0 <- C0_final    
    mulx   \T2, \T4, 8\M1
    xor    rax, rax
    mulx   \T3, \T5, 16\M1 
    ADD1   \T1, \T4            // T1 <- C1_final   
    ADC1   \T2, \T5            // T2 <- C2_final 
    mulx   \T4, \T5, 24\M1
    ADC1   \T3, \T5            // T3 <- C3_final
    ADC1   \T4, rax            // T4 <- C4_final
.endm

#ifdef _ADX_
.macro MUL128x256_SCHOOL M0, M1, T0, T1, T2, T3, T4, T5, T6 
    mov    rdx, \M0
    mulx   \T1, \T0, \M1       // T0 <- C0_final    
    mulx   \T2, \T4, 8\M1
    xor    rax, rax
    mulx   \T3, \T5, 16\M1 
    ADD1   \T1, \T4               
    ADC1   \T2, \T5     
    mulx   \T4, \T5, 24\M1
    ADC1   \T3, \T5 
    ADC1   \T4, rax   
    
    xor    rax, rax
    mov    rdx, 8\M0 
    mulx   \T6, \T5, \M1 
    ADD2   \T1, \T5            // T1 <- C1_final 
    ADC2   \T2, \T6     
    mulx   \T5, \T6, 8\M1
    ADC2   \T3, \T5 
    ADD1   \T2, \T6        
    mulx   \T5, \T6, 16\M1
    ADC2   \T4, \T5 
    ADC1   \T3, \T6     
    mulx   \T5, \T6, 24\M1   
    ADC2   \T5, rax         
    ADC1   \T4, \T6  
    ADC1   \T5, rax 
.endm

#else

.macro MUL128x256_SCHOOL M0, M1, T0, T1, T2, T3, T4, T5, T6 
    mov    rdx, \M0
    mulx   \T1, \T0, \M1       // T0 <- C0_final    
    mulx   \T2, \T4, 8\M1
    mulx   \T3, \T5, 16\M1 
    add    \T1, \T4               
    adc    \T2, \T5     
    mulx   \T4, \T5, 24\M1
    adc    \T3, \T5 
    adc    \T4, 0   
    
    mov    rdx, 8\M0 
    mulx   \T6, \T5, \M1 
    add    \T1, \T5            // T1 <- C1_final 
    adc    \T2, \T6     
    mulx   \T5, \T6, 8\M1
    adc    \T3, \T5       
    mulx   \T5, rax, 16\M1
    adc    \T4, \T5     
    mulx   \T5, rdx, 24\M1 
    adc    \T5, 0
    add    \T2, \T6  
    adc    \T3, rax        
    adc    \T4, rdx  
    adc    \T5, 0 
.endm
#endif

  
//**************************************************************************************
//  Montgomery reduction
//  Based on method described in Faz-Hernandez et al. https://eprint.iacr.org/2017/1015
//  Operation: c [reg_p2] = a [reg_p1]
//  NOTE: a=c is not allowed
//************************************************************************************** 
.global rdc434_asm
rdc434_asm:
    push   r12
    push   r13 

    // a[0-1] x p434p1_nz --> result: r8:r13 
    MUL128x256_SCHOOL [reg_p1], [rip+p434p1+24], r8, r9, r10, r11, r12, r13, rcx     

    xor    rcx, rcx
    add    r8, [reg_p1+24]  
    adc    r9, [reg_p1+32]  
    adc    r10, [reg_p1+40]   
    adc    r11, [reg_p1+48]   
    adc    r12, [reg_p1+56]   
    adc    r13, [reg_p1+64]   
    adc    rcx, [reg_p1+72]  
    mov    [reg_p1+24], r8  
    mov    [reg_p1+32], r9  
    mov    [reg_p1+40], r10  
    mov    [reg_p1+48], r11  
    mov    [reg_p1+56], r12  
    mov    [reg_p1+64], r13  
    mov    [reg_p1+72], rcx  
    mov    r8, [reg_p1+80]  
    mov    r9, [reg_p1+88]  
    mov    r10, [reg_p1+96]
    mov    r11, [reg_p1+104]
    adc    r8, 0
    adc    r9, 0
    adc    r10, 0
    adc    r11, 0
    mov    [reg_p1+80], r8  
    mov    [reg_p1+88], r9  
    mov    [reg_p1+96], r10
    mov    [reg_p1+104], r11

    // a[2-3] x p434p1_nz --> result: r8:r13
    MUL128x256_SCHOOL [reg_p1+16], [rip+p434p1+24], r8, r9, r10, r11, r12, r13, rcx 

    xor    rcx, rcx
    add    r8, [reg_p1+40]  
    adc    r9, [reg_p1+48]  
    adc    r10, [reg_p1+56]   
    adc    r11, [reg_p1+64]  
    adc    r12, [reg_p1+72]   
    adc    r13, [reg_p1+80]   
    adc    rcx, [reg_p1+88]
    mov    [reg_p1+40], r8  
    mov    [reg_p1+48], r9  
    mov    [reg_p1+56], r10  
    mov    [reg_p1+64], r11   
    mov    [reg_p1+72], r12  
    mov    [reg_p1+80], r13  
    mov    [reg_p1+88], rcx
    mov    r8, [reg_p1+96]
    mov    r9, [reg_p1+104]
    adc    r8, 0
    adc    r9, 0 
    mov    [reg_p1+96], r8  
    mov    [reg_p1+104], r9

    // a[4-5] x p434p1_nz --> result: r8:r13
    MUL128x256_SCHOOL [reg_p1+32], [rip+p434p1+24], r8, r9, r10, r11, r12, r13, rcx  

    xor    rcx, rcx
    add    r8, [reg_p1+56]  
    adc    r9, [reg_p1+64]  
    adc    r10, [reg_p1+72]   
    adc    r11, [reg_p1+80]  
    adc    r12, [reg_p1+88]   
    adc    r13, [reg_p1+96]   
    adc    rcx, [reg_p1+104]
    mov    [reg_p2], r8        // Final result c0-c1
    mov    [reg_p2+8], r9         
    mov    [reg_p1+72], r10 
    mov    [reg_p1+80], r11   
    mov    [reg_p1+88], r12  
    mov    [reg_p1+96], r13  
    mov    [reg_p1+104], rcx

    // a[6-7] x p434p1_nz --> result: r8:r12
    MUL64x256_SCHOOL [reg_p1+48], [rip+p434p1+24], r8, r9, r10, r11, r12, r13  
    
    // Final result c2:c6
    add    r8, [reg_p1+72]  
    adc    r9, [reg_p1+80]  
    adc    r10, [reg_p1+88]   
    adc    r11, [reg_p1+96]  
    adc    r12, [reg_p1+104] 
    mov    [reg_p2+16], r8  
    mov    [reg_p2+24], r9  
    mov    [reg_p2+32], r10  
    mov    [reg_p2+40], r11   
    mov    [reg_p2+48], r12

    pop    r13
    pop    r12
    ret

  #else
  
//***********************************************************************
//  Montgomery reduction
//  Based on comba method
//  Operation: c [reg_p2] = a [reg_p1]                                                      
//  NOTE: a=c is not allowed
//*********************************************************************** 
.global rdc434_asm
rdc434_asm:

  ret

# error "CONFIGURATION NOT SUPPORTED. TRY USE_MULX=TRUE"

  #endif


//***********************************************************************
//  434-bit multiprecision addition
//  Operation: c [reg_p3] = a [reg_p1] + b [reg_p2]
//*********************************************************************** 
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


//***********************************************************************
//  2x434-bit multiprecision subtraction/addition
//  Operation: c [x2] = a [x0] - b [x1]. If c < 0, add p434*2^448
//*********************************************************************** 
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
  mov    r8, [rip+p434]
  mov    r9, [rip+p434+24]
  mov    r10, [rip+p434+32]
  mov    rdi, [rip+p434+40]
  mov    rsi, [rip+p434+48]
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
.global mp_dblsub434x2_asm
mp_dblsub434x2_asm:
  push   r12
  push   r13
  
  xor    rax, rax
  mov    r8, [reg_p3]
  mov    r9, [reg_p3+8]
  mov    r10, [reg_p3+16]
  mov    r11, [reg_p3+24]
  mov    r12, [reg_p3+32]
  mov    r13, [reg_p3+40]
  mov    rcx, [reg_p3+48]
  sub    r8, [reg_p1]
  sbb    r9, [reg_p1+8] 
  sbb    r10, [reg_p1+16] 
  sbb    r11, [reg_p1+24] 
  sbb    r12, [reg_p1+32] 
  sbb    r13, [reg_p1+40] 
  sbb    rcx, [reg_p1+48]
  adc    rax, 0
  sub    r8, [reg_p2]
  sbb    r9, [reg_p2+8] 
  sbb    r10, [reg_p2+16] 
  sbb    r11, [reg_p2+24] 
  sbb    r12, [reg_p2+32] 
  sbb    r13, [reg_p2+40] 
  sbb    rcx, [reg_p2+48]
  adc    rax, 0  
  mov    [reg_p3], r8
  mov    [reg_p3+8], r9
  mov    [reg_p3+16], r10
  mov    [reg_p3+24], r11
  mov    [reg_p3+32], r12
  mov    [reg_p3+40], r13
  mov    [reg_p3+48], rcx
    
  mov    r8, [reg_p3+56]
  mov    r9, [reg_p3+64]
  mov    r10, [reg_p3+72]
  mov    r11, [reg_p3+80]
  mov    r12, [reg_p3+88]
  mov    r13, [reg_p3+96]
  mov    rcx, [reg_p3+104]
  sub    r8, rax 
  sbb    r8, [reg_p1+56] 
  sbb    r9, [reg_p1+64] 
  sbb    r10, [reg_p1+72] 
  sbb    r11, [reg_p1+80] 
  sbb    r12, [reg_p1+88] 
  sbb    r13, [reg_p1+96] 
  sbb    rcx, [reg_p1+104]
  sub    r8, [reg_p2+56] 
  sbb    r9, [reg_p2+64] 
  sbb    r10, [reg_p2+72] 
  sbb    r11, [reg_p2+80] 
  sbb    r12, [reg_p2+88] 
  sbb    r13, [reg_p2+96] 
  sbb    rcx, [reg_p2+104] 
  mov    [reg_p3+56], r8
  mov    [reg_p3+64], r9
  mov    [reg_p3+72], r10
  mov    [reg_p3+80], r11
  mov    [reg_p3+88], r12
  mov    [reg_p3+96], r13
  mov    [reg_p3+104], rcx
  
  pop    r13
  pop    r12
  ret