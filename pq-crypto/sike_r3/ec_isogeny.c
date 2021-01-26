/********************************************************************************************
* Supersingular Isogeny Key Encapsulation Library
*
* Abstract: elliptic curve and isogeny functions
*********************************************************************************************/


void xDBL(const point_proj_t P, point_proj_t Q, const f2elm_t A24plus, const f2elm_t C24)
{ // Doubling of a Montgomery point in projective coordinates (X:Z).
  // Input: projective Montgomery x-coordinates P = (X1:Z1), where x1=X1/Z1 and Montgomery curve constants A+2C and 4C.
  // Output: projective Montgomery x-coordinates Q = 2*P = (X2:Z2).
    f2elm_t t0, t1;
    
    mp2_sub_p2(P->X, P->Z, t0);                     // t0 = X1-Z1
    mp2_add(P->X, P->Z, t1);                        // t1 = X1+Z1
    fp2sqr_mont(t0, t0);                            // t0 = (X1-Z1)^2 
    fp2sqr_mont(t1, t1);                            // t1 = (X1+Z1)^2 
    fp2mul_mont(C24, t0, Q->Z);                     // Z2 = C24*(X1-Z1)^2   
    fp2mul_mont(t1, Q->Z, Q->X);                    // X2 = C24*(X1-Z1)^2*(X1+Z1)^2
    mp2_sub_p2(t1, t0, t1);                         // t1 = (X1+Z1)^2-(X1-Z1)^2 
    fp2mul_mont(A24plus, t1, t0);                   // t0 = A24plus*[(X1+Z1)^2-(X1-Z1)^2]
    mp2_add(Q->Z, t0, Q->Z);                        // Z2 = A24plus*[(X1+Z1)^2-(X1-Z1)^2] + C24*(X1-Z1)^2
    fp2mul_mont(Q->Z, t1, Q->Z);                    // Z2 = [A24plus*[(X1+Z1)^2-(X1-Z1)^2] + C24*(X1-Z1)^2]*[(X1+Z1)^2-(X1-Z1)^2]
}


void xDBLe(const point_proj_t P, point_proj_t Q, const f2elm_t A24plus, const f2elm_t C24, const int e)
{ // Computes [2^e](X:Z) on Montgomery curve with projective constant via e repeated doublings.
  // Input: projective Montgomery x-coordinates P = (XP:ZP), such that xP=XP/ZP and Montgomery curve constants A+2C and 4C.
  // Output: projective Montgomery x-coordinates Q <- (2^e)*P.
    int i;
    
    copy_words((digit_t*)P, (digit_t*)Q, 2*2*NWORDS_FIELD);

    for (i = 0; i < e; i++) {
        xDBL(Q, Q, A24plus, C24);
    }
}

#if (OALICE_BITS % 2 == 1)

void get_2_isog(const point_proj_t P, f2elm_t A, f2elm_t C)
{ // Computes the corresponding 2-isogeny of a projective Montgomery point (X2:Z2) of order 2.
  // Input:  projective point of order two P = (X2:Z2).
  // Output: the 2-isogenous Montgomery curve with projective coefficients A/C.
    
    fp2sqr_mont(P->X, A);                           // A = X2^2
    fp2sqr_mont(P->Z, C);                           // C = Z2^2
    mp2_sub_p2(C, A, A);                            // A = Z2^2 - X2^2
}


void eval_2_isog(point_proj_t P, point_proj_t Q)
{ // Evaluates the isogeny at the point (X:Z) in the domain of the isogeny, given a 2-isogeny phi.
  // Inputs: the projective point P = (X:Z) and the 2-isogeny kernel projetive point Q = (X2:Z2).
  // Output: the projective point P = phi(P) = (X:Z) in the codomain. 
    f2elm_t t0, t1, t2, t3;
    
    mp2_add(Q->X, Q->Z, t0);                        // t0 = X2+Z2
    mp2_sub_p2(Q->X, Q->Z, t1);                     // t1 = X2-Z2
    mp2_add(P->X, P->Z, t2);                        // t2 = X+Z
    mp2_sub_p2(P->X, P->Z, t3);                     // t3 = X-Z
    fp2mul_mont(t0, t3, t0);                        // t0 = (X2+Z2)*(X-Z)
    fp2mul_mont(t1, t2, t1);                        // t1 = (X2-Z2)*(X+Z)
    mp2_add(t0, t1, t2);                            // t2 = (X2+Z2)*(X-Z) + (X2-Z2)*(X+Z)
    mp2_sub_p2(t0, t1, t3);                         // t3 = (X2+Z2)*(X-Z) - (X2-Z2)*(X+Z)
    fp2mul_mont(P->X, t2, P->X);                    // Xfinal
    fp2mul_mont(P->Z, t3, P->Z);                    // Zfinal
}

#endif

void get_4_isog(const point_proj_t P, f2elm_t A24plus, f2elm_t C24, f2elm_t* coeff)
{ // Computes the corresponding 4-isogeny of a projective Montgomery point (X4:Z4) of order 4.
  // Input:  projective point of order four P = (X4:Z4).
  // Output: the 4-isogenous Montgomery curve with projective coefficients A+2C/4C and the 3 coefficients 
  //         that are used to evaluate the isogeny at a point in eval_4_isog().
    
    mp2_sub_p2(P->X, P->Z, coeff[1]);               // coeff[1] = X4-Z4
    mp2_add(P->X, P->Z, coeff[2]);                  // coeff[2] = X4+Z4
    fp2sqr_mont(P->Z, coeff[0]);                    // coeff[0] = Z4^2
    mp2_add(coeff[0], coeff[0], coeff[0]);          // coeff[0] = 2*Z4^2
    fp2sqr_mont(coeff[0], C24);                     // C24 = 4*Z4^4
    mp2_add(coeff[0], coeff[0], coeff[0]);          // coeff[0] = 4*Z4^2
    fp2sqr_mont(P->X, A24plus);                     // A24plus = X4^2
    mp2_add(A24plus, A24plus, A24plus);             // A24plus = 2*X4^2
    fp2sqr_mont(A24plus, A24plus);                  // A24plus = 4*X4^4
}


void eval_4_isog(point_proj_t P, f2elm_t* coeff)
{ // Evaluates the isogeny at the point (X:Z) in the domain of the isogeny, given a 4-isogeny phi defined 
  // by the 3 coefficients in coeff (computed in the function get_4_isog()).
  // Inputs: the coefficients defining the isogeny, and the projective point P = (X:Z).
  // Output: the projective point P = phi(P) = (X:Z) in the codomain. 
    f2elm_t t0, t1;
    
    mp2_add(P->X, P->Z, t0);                        // t0 = X+Z
    mp2_sub_p2(P->X, P->Z, t1);                     // t1 = X-Z
    fp2mul_mont(t0, coeff[1], P->X);                // X = (X+Z)*coeff[1]
    fp2mul_mont(t1, coeff[2], P->Z);                // Z = (X-Z)*coeff[2]
    fp2mul_mont(t0, t1, t0);                        // t0 = (X+Z)*(X-Z)
    fp2mul_mont(coeff[0], t0, t0);                  // t0 = coeff[0]*(X+Z)*(X-Z)
    mp2_add(P->X, P->Z, t1);                        // t1 = (X-Z)*coeff[2] + (X+Z)*coeff[1]
    mp2_sub_p2(P->X, P->Z, P->Z);                   // Z = (X-Z)*coeff[2] - (X+Z)*coeff[1]
    fp2sqr_mont(t1, t1);                            // t1 = [(X-Z)*coeff[2] + (X+Z)*coeff[1]]^2
    fp2sqr_mont(P->Z, P->Z);                        // Z = [(X-Z)*coeff[2] - (X+Z)*coeff[1]]^2
    mp2_add(t1, t0, P->X);                          // X = coeff[0]*(X+Z)*(X-Z) + [(X-Z)*coeff[2] + (X+Z)*coeff[1]]^2
    mp2_sub_p2(P->Z, t0, t0);                       // t0 = [(X-Z)*coeff[2] - (X+Z)*coeff[1]]^2 - coeff[0]*(X+Z)*(X-Z)
    fp2mul_mont(P->X, t1, P->X);                    // Xfinal
    fp2mul_mont(P->Z, t0, P->Z);                    // Zfinal
}


void xTPL(const point_proj_t P, point_proj_t Q, const f2elm_t A24minus, const f2elm_t A24plus)              
{ // Tripling of a Montgomery point in projective coordinates (X:Z).
  // Input: projective Montgomery x-coordinates P = (X:Z), where x=X/Z and Montgomery curve constants A24plus = A+2C and A24minus = A-2C.
  // Output: projective Montgomery x-coordinates Q = 3*P = (X3:Z3).
    f2elm_t t0, t1, t2, t3, t4, t5, t6;
                                    
    mp2_sub_p2(P->X, P->Z, t0);                     // t0 = X-Z 
    fp2sqr_mont(t0, t2);                            // t2 = (X-Z)^2           
    mp2_add(P->X, P->Z, t1);                        // t1 = X+Z 
    fp2sqr_mont(t1, t3);                            // t3 = (X+Z)^2
    mp2_add(P->X, P->X, t4);                        // t4 = 2*X
    mp2_add(P->Z, P->Z, t0);                        // t0 = 2*Z 
    fp2sqr_mont(t4, t1);                            // t1 = 4*X^2
    mp2_sub_p2(t1, t3, t1);                         // t1 = 4*X^2 - (X+Z)^2 
    mp2_sub_p2(t1, t2, t1);                         // t1 = 4*X^2 - (X+Z)^2 - (X-Z)^2
    fp2mul_mont(A24plus, t3, t5);                   // t5 = A24plus*(X+Z)^2 
    fp2mul_mont(t3, t5, t3);                        // t3 = A24plus*(X+Z)^4
    fp2mul_mont(A24minus, t2, t6);                  // t6 = A24minus*(X-Z)^2
    fp2mul_mont(t2, t6, t2);                        // t2 = A24minus*(X-Z)^4
    mp2_sub_p2(t2, t3, t3);                         // t3 = A24minus*(X-Z)^4 - A24plus*(X+Z)^4
    mp2_sub_p2(t5, t6, t2);                         // t2 = A24plus*(X+Z)^2 - A24minus*(X-Z)^2
    fp2mul_mont(t1, t2, t1);                        // t1 = [4*X^2 - (X+Z)^2 - (X-Z)^2]*[A24plus*(X+Z)^2 - A24minus*(X-Z)^2]
    fp2add(t3, t1, t2);                             // t2 = [4*X^2 - (X+Z)^2 - (X-Z)^2]*[A24plus*(X+Z)^2 - A24minus*(X-Z)^2] + A24minus*(X-Z)^4 - A24plus*(X+Z)^4
    fp2sqr_mont(t2, t2);                            // t2 = t2^2
    fp2mul_mont(t4, t2, Q->X);                      // X3 = 2*X*t2
    fp2sub(t3, t1, t1);                             // t1 = A24minus*(X-Z)^4 - A24plus*(X+Z)^4 - [4*X^2 - (X+Z)^2 - (X-Z)^2]*[A24plus*(X+Z)^2 - A24minus*(X-Z)^2]
    fp2sqr_mont(t1, t1);                            // t1 = t1^2
    fp2mul_mont(t0, t1, Q->Z);                      // Z3 = 2*Z*t1
}


void xTPLe(const point_proj_t P, point_proj_t Q, const f2elm_t A24minus, const f2elm_t A24plus, const int e)
{ // Computes [3^e](X:Z) on Montgomery curve with projective constant via e repeated triplings.
  // Input: projective Montgomery x-coordinates P = (XP:ZP), such that xP=XP/ZP and Montgomery curve constants A24plus = A+2C and A24minus = A-2C.
  // Output: projective Montgomery x-coordinates Q <- (3^e)*P.
    int i;
        
    copy_words((digit_t*)P, (digit_t*)Q, 2*2*NWORDS_FIELD);

    for (i = 0; i < e; i++) {
        xTPL(Q, Q, A24minus, A24plus);
    }
}


void get_3_isog(const point_proj_t P, f2elm_t A24minus, f2elm_t A24plus, f2elm_t* coeff)
{ // Computes the corresponding 3-isogeny of a projective Montgomery point (X3:Z3) of order 3.
  // Input:  projective point of order three P = (X3:Z3).
  // Output: the 3-isogenous Montgomery curve with projective coefficient A/C. 
    f2elm_t t0, t1, t2, t3, t4;
    
    mp2_sub_p2(P->X, P->Z, coeff[0]);               // coeff0 = X-Z
    fp2sqr_mont(coeff[0], t0);                      // t0 = (X-Z)^2
    mp2_add(P->X, P->Z, coeff[1]);                  // coeff1 = X+Z
    fp2sqr_mont(coeff[1], t1);                      // t1 = (X+Z)^2
    mp2_add(P->X, P->X, t3);                        // t3 = 2*X
    fp2sqr_mont(t3, t3);                            // t3 = 4*X^2 
    fp2sub(t3, t0, t2);                             // t2 = 4*X^2 - (X-Z)^2 
    fp2sub(t3, t1, t3);                             // t3 = 4*X^2 - (X+Z)^2
    mp2_add(t0, t3, t4);                            // t4 = 4*X^2 - (X+Z)^2 + (X-Z)^2 
    mp2_add(t4, t4, t4);                            // t4 = 2(4*X^2 - (X+Z)^2 + (X-Z)^2) 
    mp2_add(t1, t4, t4);                            // t4 = 8*X^2 - (X+Z)^2 + 2*(X-Z)^2
    fp2mul_mont(t2, t4, A24minus);                  // A24minus = [4*X^2 - (X-Z)^2]*[8*X^2 - (X+Z)^2 + 2*(X-Z)^2]
    mp2_add(t1, t2, t4);                            // t4 = 4*X^2 + (X+Z)^2 - (X-Z)^2
    mp2_add(t4, t4, t4);                            // t4 = 2(4*X^2 + (X+Z)^2 - (X-Z)^2) 
    mp2_add(t0, t4, t4);                            // t4 = 8*X^2 + 2*(X+Z)^2 - (X-Z)^2
    fp2mul_mont(t3, t4, A24plus);                   // A24plus = [4*X^2 - (X+Z)^2]*[8*X^2 + 2*(X+Z)^2 - (X-Z)^2]
}


void eval_3_isog(point_proj_t Q, const f2elm_t* coeff)
{ // Computes the 3-isogeny R=phi(X:Z), given projective point (X3:Z3) of order 3 on a Montgomery curve and 
  // a point P with 2 coefficients in coeff (computed in the function get_3_isog()).
  // Inputs: projective points P = (X3:Z3) and Q = (X:Z).
  // Output: the projective point Q <- phi(Q) = (X3:Z3). 
    f2elm_t t0, t1, t2;

    mp2_add(Q->X, Q->Z, t0);                      // t0 = X+Z
    mp2_sub_p2(Q->X, Q->Z, t1);                   // t1 = X-Z
    fp2mul_mont(coeff[0], t0, t0);                // t0 = coeff0*(X+Z)
    fp2mul_mont(coeff[1], t1, t1);                // t1 = coeff1*(X-Z)
    mp2_add(t0, t1, t2);                          // t2 = coeff0*(X+Z) + coeff1*(X-Z)
    mp2_sub_p2(t1, t0, t0);                       // t0 = coeff1*(X-Z) - coeff0*(X+Z)
    fp2sqr_mont(t2, t2);                          // t2 = [coeff0*(X+Z) + coeff1*(X-Z)]^2
    fp2sqr_mont(t0, t0);                          // t0 = [coeff1*(X-Z) - coeff0*(X+Z)]^2
    fp2mul_mont(Q->X, t2, Q->X);                  // X3final = X*[coeff0*(X+Z) + coeff1*(X-Z)]^2        
    fp2mul_mont(Q->Z, t0, Q->Z);                  // Z3final = Z*[coeff1*(X-Z) - coeff0*(X+Z)]^2
}


void inv_3_way(f2elm_t z1, f2elm_t z2, f2elm_t z3)
{ // 3-way simultaneous inversion
  // Input:  z1,z2,z3
  // Output: 1/z1,1/z2,1/z3 (override inputs).
    f2elm_t t0, t1, t2, t3;

    fp2mul_mont(z1, z2, t0);                      // t0 = z1*z2
    fp2mul_mont(z3, t0, t1);                      // t1 = z1*z2*z3
    fp2inv_mont(t1);                              // t1 = 1/(z1*z2*z3)
    fp2mul_mont(z3, t1, t2);                      // t2 = 1/(z1*z2) 
    fp2mul_mont(t2, z2, t3);                      // t3 = 1/z1
    fp2mul_mont(t2, z1, z2);                      // z2 = 1/z2
    fp2mul_mont(t0, t1, z3);                      // z3 = 1/z3
    fp2copy(t3, z1);                              // z1 = 1/z1
}


void get_A(const f2elm_t xP, const f2elm_t xQ, const f2elm_t xR, f2elm_t A)
{ // Given the x-coordinates of P, Q, and R, returns the value A corresponding to the Montgomery curve E_A: y^2=x^3+A*x^2+x such that R=Q-P on E_A.
  // Input:  the x-coordinates xP, xQ, and xR of the points P, Q and R.
  // Output: the coefficient A corresponding to the curve E_A: y^2=x^3+A*x^2+x.
    f2elm_t t0, t1, one = {0};
    
    fpcopy((digit_t*)&Montgomery_one, one[0]);
    fp2add(xP, xQ, t1);                           // t1 = xP+xQ
    fp2mul_mont(xP, xQ, t0);                      // t0 = xP*xQ
    fp2mul_mont(xR, t1, A);                       // A = xR*t1
    fp2add(t0, A, A);                             // A = A+t0
    fp2mul_mont(t0, xR, t0);                      // t0 = t0*xR
    fp2sub(A, one, A);                            // A = A-1
    fp2add(t0, t0, t0);                           // t0 = t0+t0
    fp2add(t1, xR, t1);                           // t1 = t1+xR
    fp2add(t0, t0, t0);                           // t0 = t0+t0
    fp2sqr_mont(A, A);                            // A = A^2
    fp2inv_mont(t0);                              // t0 = 1/t0
    fp2mul_mont(A, t0, A);                        // A = A*t0
    fp2sub(A, t1, A);                             // Afinal = A-t1
}


void j_inv(const f2elm_t A, const f2elm_t C, f2elm_t jinv)
{ // Computes the j-invariant of a Montgomery curve with projective constant.
  // Input: A,C in GF(p^2).
  // Output: j=256*(A^2-3*C^2)^3/(C^4*(A^2-4*C^2)), which is the j-invariant of the Montgomery curve B*y^2=x^3+(A/C)*x^2+x or (equivalently) j-invariant of B'*y^2=C*x^3+A*x^2+C*x.
    f2elm_t t0, t1;
    
    fp2sqr_mont(A, jinv);                           // jinv = A^2        
    fp2sqr_mont(C, t1);                             // t1 = C^2
    fp2add(t1, t1, t0);                             // t0 = t1+t1
    fp2sub(jinv, t0, t0);                           // t0 = jinv-t0
    fp2sub(t0, t1, t0);                             // t0 = t0-t1
    fp2sub(t0, t1, jinv);                           // jinv = t0-t1
    fp2sqr_mont(t1, t1);                            // t1 = t1^2
    fp2mul_mont(jinv, t1, jinv);                    // jinv = jinv*t1
    fp2add(t0, t0, t0);                             // t0 = t0+t0
    fp2add(t0, t0, t0);                             // t0 = t0+t0
    fp2sqr_mont(t0, t1);                            // t1 = t0^2
    fp2mul_mont(t0, t1, t0);                        // t0 = t0*t1
    fp2add(t0, t0, t0);                             // t0 = t0+t0
    fp2add(t0, t0, t0);                             // t0 = t0+t0
    fp2inv_mont(jinv);                              // jinv = 1/jinv 
    fp2mul_mont(jinv, t0, jinv);                    // jinv = t0*jinv
}


void xDBLADD(point_proj_t P, point_proj_t Q, const f2elm_t xPQ, const f2elm_t A24)
{ // Simultaneous doubling and differential addition.
  // Input: projective Montgomery points P=(XP:ZP) and Q=(XQ:ZQ) such that xP=XP/ZP and xQ=XQ/ZQ, affine difference xPQ=x(P-Q) and Montgomery curve constant A24=(A+2)/4.
  // Output: projective Montgomery points P <- 2*P = (X2P:Z2P) such that x(2P)=X2P/Z2P, and Q <- P+Q = (XQP:ZQP) such that = x(Q+P)=XQP/ZQP. 
    f2elm_t t0, t1, t2;

    mp2_add(P->X, P->Z, t0);                        // t0 = XP+ZP
    mp2_sub_p2(P->X, P->Z, t1);                     // t1 = XP-ZP
    fp2sqr_mont(t0, P->X);                          // XP = (XP+ZP)^2
    mp2_sub_p2(Q->X, Q->Z, t2);                     // t2 = XQ-ZQ
    mp2_add(Q->X, Q->Z, Q->X);                      // XQ = XQ+ZQ
    fp2mul_mont(t0, t2, t0);                        // t0 = (XP+ZP)*(XQ-ZQ)
    fp2sqr_mont(t1, P->Z);                          // ZP = (XP-ZP)^2
    fp2mul_mont(t1, Q->X, t1);                      // t1 = (XP-ZP)*(XQ+ZQ)
    mp2_sub_p2(P->X, P->Z, t2);                     // t2 = (XP+ZP)^2-(XP-ZP)^2
    fp2mul_mont(P->X, P->Z, P->X);                  // XP = (XP+ZP)^2*(XP-ZP)^2
    fp2mul_mont(A24, t2, Q->X);                     // XQ = A24*[(XP+ZP)^2-(XP-ZP)^2]
    mp2_sub_p2(t0, t1, Q->Z);                       // ZQ = (XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)
    mp2_add(Q->X, P->Z, P->Z);                      // ZP = A24*[(XP+ZP)^2-(XP-ZP)^2]+(XP-ZP)^2
    mp2_add(t0, t1, Q->X);                          // XQ = (XP+ZP)*(XQ-ZQ)+(XP-ZP)*(XQ+ZQ)
    fp2mul_mont(P->Z, t2, P->Z);                    // ZP = [A24*[(XP+ZP)^2-(XP-ZP)^2]+(XP-ZP)^2]*[(XP+ZP)^2-(XP-ZP)^2]
    fp2sqr_mont(Q->Z, Q->Z);                        // ZQ = [(XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)]^2
    fp2sqr_mont(Q->X, Q->X);                        // XQ = [(XP+ZP)*(XQ-ZQ)+(XP-ZP)*(XQ+ZQ)]^2
    fp2mul_mont(Q->Z, xPQ, Q->Z);                   // ZQ = xPQ*[(XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)]^2
}


static void swap_points(point_proj_t P, point_proj_t Q, const digit_t option)
{ // Swap points.
  // If option = 0 then P <- P and Q <- Q, else if option = 0xFF...FF then P <- Q and Q <- P
    digit_t temp;
    unsigned int i;

    for (i = 0; i < NWORDS_FIELD; i++) {
        temp = option & (P->X[0][i] ^ Q->X[0][i]);
        P->X[0][i] = temp ^ P->X[0][i]; 
        Q->X[0][i] = temp ^ Q->X[0][i];  
        temp = option & (P->X[1][i] ^ Q->X[1][i]);
        P->X[1][i] = temp ^ P->X[1][i]; 
        Q->X[1][i] = temp ^ Q->X[1][i];
        temp = option & (P->Z[0][i] ^ Q->Z[0][i]);
        P->Z[0][i] = temp ^ P->Z[0][i]; 
        Q->Z[0][i] = temp ^ Q->Z[0][i];
        temp = option & (P->Z[1][i] ^ Q->Z[1][i]);
        P->Z[1][i] = temp ^ P->Z[1][i]; 
        Q->Z[1][i] = temp ^ Q->Z[1][i]; 
    }
}


static void LADDER3PT(const f2elm_t xP, const f2elm_t xQ, const f2elm_t xPQ, const digit_t* m, const unsigned int AliceOrBob, point_proj_t R, const f2elm_t A)
{
    point_proj_t R0 = {0}, R2 = {0};
    f2elm_t A24 = {0};
    digit_t mask;
    int i, nbits, bit, swap, prevbit = 0;

    if (AliceOrBob == ALICE) {
        nbits = OALICE_BITS;
    } else {
        nbits = OBOB_BITS - 1;
    }

    // Initializing constant
    fpcopy((digit_t*)&Montgomery_one, A24[0]);
    mp2_add(A24, A24, A24);
    mp2_add(A, A24, A24);
    fp2div2(A24, A24);  
    fp2div2(A24, A24);  // A24 = (A+2)/4

    // Initializing points
    fp2copy(xQ, R0->X);
    fpcopy((digit_t*)&Montgomery_one, (digit_t*)R0->Z);
    fp2copy(xPQ, R2->X);
    fpcopy((digit_t*)&Montgomery_one, (digit_t*)R2->Z);
    fp2copy(xP, R->X);
    fpcopy((digit_t*)&Montgomery_one, (digit_t*)R->Z);
    fpzero((digit_t*)(R->Z)[1]);

    // Main loop
    for (i = 0; i < nbits; i++) {
        bit = (m[i >> LOG2RADIX] >> (i & (RADIX-1))) & 1;
        swap = bit ^ prevbit;
        prevbit = bit;
        mask = 0 - (digit_t)swap;

        swap_points(R, R2, mask);
        xDBLADD(R0, R2, R->X, A24);
        fp2mul_mont(R2->X, R->Z, R2->X);
    }
    swap = 0 ^ prevbit;
    mask = 0 - (digit_t)swap;
    swap_points(R, R2, mask);
}

#ifdef COMPRESS

static void CompletePoint(const point_proj_t P, point_full_proj_t R)
{ // Complete point on A = 0 curve
    f2elm_t xz, s2, r2, yz, invz, t0, t1, one = {0};

    fpcopy((digit_t*)&Montgomery_one, one[0]);
    fp2mul_mont(P->X, P->Z, xz);
    fpsub(P->X[0], P->Z[1], t0[0]);
    fpadd(P->X[1], P->Z[0], t0[1]);
    fpadd(P->X[0], P->Z[1], t1[0]);
    fpsub(P->X[1], P->Z[0], t1[1]);
    fp2mul_mont(t0, t1, s2);
    fp2mul_mont(xz, s2, r2);
    sqrt_Fp2(r2, yz);
    fp2copy(P->Z,invz);
    fp2inv_mont_bingcd(invz);    
    fp2mul_mont(P->X, invz, R->X);
    fp2sqr_mont(invz, t0);
    fp2mul_mont(yz, t0, R->Y);
    fp2copy(one, R->Z);
}


void CompleteMPoint(const f2elm_t A, point_proj_t P, point_full_proj_t R)
{ // Given an xz-only representation on a montgomery curve, compute its affine representation
    f2elm_t zero = {0}, one = {0}, xz, yz, s2, r2, invz, temp0, temp1;

    fpcopy((digit_t*)&Montgomery_one, one[0]);    
    if (memcmp(P->Z[0], zero,NBITS_TO_NBYTES(NBITS_FIELD)) != 0 || memcmp(P->Z[1], zero, NBITS_TO_NBYTES(NBITS_FIELD)) != 0) {
        fp2mul_mont(P->X, P->Z, xz);       // xz = x*z;
        fpsub(P->X[0], P->Z[1], temp0[0]);
        fpadd(P->X[1], P->Z[0], temp0[1]);
        fpadd(P->X[0], P->Z[1], temp1[0]);
        fpsub(P->X[1], P->Z[0], temp1[1]);        
        fp2mul_mont(temp0, temp1, s2);     // s2 = (x + i*z)*(x - i*z);
        fp2mul_mont(A, xz, temp0);
        fp2add(temp0, s2, temp1);
        fp2mul_mont(xz, temp1, r2);        // r2 = xz*(A*xz + s2);
        sqrt_Fp2(r2, yz);
        fp2copy(P->Z, invz);
        fp2inv_mont_bingcd(invz);        
        fp2mul_mont(P->X, invz, R->X);
        fp2sqr_mont(invz, temp0);
        fp2mul_mont(yz, temp0, R->Y);      // R = EM![x*invz, yz*invz^2];
        fp2copy(one, R->Z);
    } else {
        fp2copy(zero, R->X);
        fp2copy(one, R->Y); 
        fp2copy(zero, R->Z);               // R = EM!0;
    }
}


void Double(point_proj_t P, point_proj_t Q, f2elm_t A24, const int k)
{ // Doubling of a Montgomery point in projective coordinates (X:Z) over affine curve coefficient A. 
  // Input: projective Montgomery x-coordinates P = (X1:Z1), where x1=X1/Z1 and Montgomery curve constants (A+2)/4.
  // Output: projective Montgomery x-coordinates Q = 2*P = (X2:Z2). 
    f2elm_t temp, a, b, c, aa, bb;    
    
    fp2copy(P->X, Q->X);
    fp2copy(P->Z, Q->Z);
    
    for (int j = 0; j < k; j++) {
        fp2add(Q->X, Q->Z, a);
        fp2sub(Q->X, Q->Z, b);
        fp2sqr_mont(a, aa);
        fp2sqr_mont(b, bb);
        fp2sub(aa, bb, c);
        fp2mul_mont(aa, bb, Q->X);
        fp2mul_mont(A24, c, temp);
        fp2add(temp, bb, temp);
        fp2mul_mont(c, temp, Q->Z);
    }
}


void xTPL_fast(const point_proj_t P, point_proj_t Q, const f2elm_t A2)
{ // Montgomery curve (E: y^2 = x^3 + A*x^2 + x) x-only tripling at a cost 5M + 6S + 9A = 27p + 61a.
  // Input : projective Montgomery x-coordinates P = (X:Z), where x=X/Z and Montgomery curve constant A/2. 
  // Output: projective Montgomery x-coordinates Q = 3*P = (X3:Z3).
       f2elm_t t1, t2, t3, t4;
       
       fp2sqr_mont(P->X, t1);        // t1 = x^2
       fp2sqr_mont(P->Z, t2);        // t2 = z^2
       fp2add(t1, t2, t3);           // t3 = t1 + t2
       fp2add(P->X, P->Z, t4);       // t4 = x + z
       fp2sqr_mont(t4, t4);          // t4 = t4^2
       fp2sub(t4, t3, t4);           // t4 = t4 - t3
       fp2mul_mont(A2, t4, t4);      // t4 = t4*A2
       fp2add(t3, t4, t4);           // t4 = t4 + t3
       fp2sub(t1, t2, t3);           // t3 = t1 - t2
       fp2sqr_mont(t3, t3);          // t3 = t3^2
       fp2mul_mont(t1, t4, t1);      // t1 = t1*t4
       fp2shl(t1, 2, t1);            // t1 = 4*t1
       fp2sub(t1, t3, t1);           // t1 = t1 - t3
       fp2sqr_mont(t1, t1);          // t1 = t1^2
       fp2mul_mont(t2, t4, t2);      // t2 = t2*t4
       fp2shl(t2, 2, t2);            // t2 = 4*t2
       fp2sub(t2, t3, t2);           // t2 = t2 - t3
       fp2sqr_mont(t2, t2);          // t2 = t2^2
       fp2mul_mont(P->X, t2, Q->X);  // x = x*t2
       fp2mul_mont(P->Z, t1, Q->Z);  // z = z*t1    
}


void xTPLe_fast(point_proj_t P, point_proj_t Q, const f2elm_t A2, int e)
{ // Computes [3^e](X:Z) on Montgomery curve with projective constant via e repeated triplings. e triplings in E costs k*(5M + 6S + 9A)
  // Input: projective Montgomery x-coordinates P = (X:Z), where x=X/Z, Montgomery curve constant A2 = A/2 and the number of triplings e.
  // Output: projective Montgomery x-coordinates Q <- [3^e]P.    
    point_proj_t T;

    copy_words((digit_t*)P, (digit_t*)T, 2*2*NWORDS_FIELD);
    for (int j = 0; j < e; j++) { 
        xTPL_fast(T, T, A2);
    }
    copy_words((digit_t*)T, (digit_t*)Q, 2*2*NWORDS_FIELD);
}


void ADD(const point_full_proj_t P, const f2elm_t QX, const f2elm_t QY, const f2elm_t QZ, const f2elm_t A, point_full_proj_t R)
{ // General addition.
  // Input: projective Montgomery points P=(XP:YP:ZP) and Q=(XQ:YQ:ZQ).
  // Output: projective Montgomery point R <- P+Q = (XQP:YQP:ZQP). 
    f2elm_t t0 = {0}, t1 = {0}, t2 = {0}, t3 = {0}, t4 = {0}, t5 = {0}, t6 = {0}, t7 = {0};

    fp2mul_mont(QX, P->Z, t0);            // t0 = x2*Z1    
    fp2mul_mont(P->X, QZ, t1);            // t1 = X1*z2    
    fp2add(t0, t1, t2);                   // t2 = t0 + t1
    fp2sub(t1, t0, t3);                   // t3 = t1 - t0
    fp2mul_mont(QX, P->X, t0);            // t0 = x2*X1    
    fp2mul_mont(P->Z, QZ, t1);            // t1 = Z1*z2
    fp2add(t0, t1, t4);                   // t4 = t0 + t1
    fp2mul_mont(t0, A, t0);               // t0 = t0*A
    fp2mul_mont(QY, P->Y, t5);            // t5 = y2*Y1
    fp2sub(t0, t5, t0);                   // t0 = t0 - t5
    fp2mul_mont(t0, t1, t0);              // t0 = t0*t1
    fp2add(t0, t0, t0);                   // t0 = t0 + t0
    fp2mul_mont(t2, t4, t5);              // t5 = t2*t4
    fp2add(t5, t0, t5);                   // t5 = t5 + t0
    fp2sqr_mont(P->X, t0);                // t0 = X1 ^ 2
    fp2sqr_mont(P->Z, t6);                // t6 = Z1 ^ 2
    fp2add(t0, t6, t0);                   // t0 = t0 + t6    
    fp2add(t1, t1, t1);                   // t1 = t1 + t1
    fp2mul_mont(QY, P->X, t7);            // t7 = y2*X1
    fp2mul_mont(QX, P->Y, t6);            // t6 = x2*Y1
    fp2sub(t7, t6, t7);                   // t7 = t7 - t6
    fp2mul_mont(t1, t7, t1);              // t1 = t1*t7
    fp2mul_mont(A, t2, t7);               // t7 = A*t2
    fp2add(t7, t4, t4);                   // t4 = t4 + t7
    fp2mul_mont(t1, t4, t4);              // t4 = t1*t4
    fp2mul_mont(QY, QZ, t1);              // t1 = y2*z2
    fp2mul_mont(t0, t1, t0);              // t0 = t0*t1
    fp2sqr_mont(QZ, t1);                  // t1 = z2 ^ 2
    fp2sqr_mont(QX, t6);                  // t6 = x2 ^ 2
    fp2add(t1, t6, t1);                   // t1 = t1 + t6
    fp2mul_mont(P->Z, P->Y, t6);          // t6 = Z1*Y1
    fp2mul_mont(t1, t6, t1);              // t1 = t1*t6
    fp2sub(t0, t1, t0);                   // t0 = t0 - t1
    fp2mul_mont(t2, t0, t0);              // t0 = t2*t0
    fp2mul_mont(t5, t3, R->X);            // X3 = t5*t3    
    fp2add(t4, t0, R->Y);                 // Y3 = t4 + t0
    fp2sqr_mont(t3, t0);                  // t0 = t3 ^ 2
    fp2mul_mont(t3, t0, R->Z);            // Z3 = t3*t0
}


void Mont_ladder(const f2elm_t x, const digit_t* m, point_proj_t P, point_proj_t Q, const f2elm_t A24, const unsigned int order_bits, const unsigned int order_fullbits)
{ // The Montgomery ladder
  // Inputs: the affine x-coordinate of a point P on E: B*y^2=x^3+A*x^2+x, 
  //         scalar m
  //         curve constant A24 = (A+2)/4
  //         order_bits = subgroup order bitlength
  //         order_fullbits = smallest multiple of 32 larger than the order bitlength
  // Output: P = m*(x:1)
    unsigned int bit = 0, owords = NBITS_TO_NWORDS(order_fullbits);
    digit_t mask, scalar[NWORDS_ORDER];
    int i;
    
    // Initializing with the points (1:0) and (x:1)
    fpcopy((digit_t*)&Montgomery_one, (digit_t*)P->X[0]);
    fpzero(P->X[1]);
    fp2zero(P->Z);
    
    fp2copy(x, Q->X);    
    fpcopy((digit_t*)&Montgomery_one, (digit_t*)Q->Z[0]);    
    fpzero(Q->Z[1]);

    for (i = NWORDS_ORDER-1; i >= 0; i--) {
        scalar[i] = m[i];
    }
    
    for (i = order_fullbits-order_bits; i > 0; i--) {
        mp_shiftl1(scalar, owords);
    }    
    
    for (i = order_bits; i > 0; i--) {
        bit = (unsigned int)(scalar[owords-1] >> (RADIX-1));
        mp_shiftl1(scalar, owords);
        mask = 0-(digit_t)bit;

        swap_points(P, Q, mask);        
        xDBLADD(P, Q, x, A24);                     // If bit=0 then P <- 2*P and Q <- P+Q, 
        swap_points(P, Q, mask);                   // else if bit=1 then Q <- 2*Q and P <- P+Q
    }
}


void mont_twodim_scalarmult(digit_t* a, const point_t R, const point_t S, const f2elm_t A, const f2elm_t A24, point_full_proj_t P, const unsigned int order_bits)
{ // Computes P = R + [a]S  
    point_proj_t P0 = {0}, P1 = {0};
    point_full_proj_t P2 = {0};
    f2elm_t one = {0};    

    fpcopy((digit_t*)&Montgomery_one, one[0]);
    Mont_ladder(S->x, a, P0, P1, A24, order_bits, MAXBITS_ORDER);    
    recover_os(P0->X, P0->Z, P1->X, P1->Z, S->x, S->y, A, P2->X, P2->Y, P2->Z);     
    ADD(P2, R->x, R->y, one, A, P);       
}


void xDBLADD_proj(point_proj_t P, point_proj_t Q, const f2elm_t XPQ, const f2elm_t ZPQ, const f2elm_t A24)
{ // Simultaneous doubling and differential addition.
  // Input: projective Montgomery points P=(XP:ZP) and Q=(XQ:ZQ) such that xP=XP/ZP and xQ=XQ/ZQ, affine difference xPQ=x(P-Q) and Montgomery curve constant A24=(A+2)/4.
  // Output: projective Montgomery points P <- 2*P = (X2P:Z2P) such that x(2P)=X2P/Z2P, and Q <- P+Q = (XQP:ZQP) such that = x(Q+P)=XQP/ZQP. 
    f2elm_t t0, t1, t2;

    fp2add(P->X, P->Z, t0);                         // t0 = XP+ZP
    fp2sub(P->X, P->Z, t1);                         // t1 = XP-ZP    
    fp2sqr_mont(t0, P->X);                          // XP = (XP+ZP)^2    
    fp2sub(Q->X, Q->Z, t2);                         // t2 = XQ-ZQ
    fp2correction(t2);    
    fp2add(Q->X, Q->Z, Q->X);                       // XQ = XQ+ZQ    
    fp2mul_mont(t0, t2, t0);                        // t0 = (XP+ZP)*(XQ-ZQ)    
    fp2sqr_mont(t1, P->Z);                          // ZP = (XP-ZP)^2    
    fp2mul_mont(t1, Q->X, t1);                      // t1 = (XP-ZP)*(XQ+ZQ)    
    fp2sub(P->X, P->Z, t2);                         // t2 = (XP+ZP)^2-(XP-ZP)^2    
    fp2mul_mont(P->X, P->Z, P->X);                  // XP = (XP+ZP)^2*(XP-ZP)^2    
    fp2mul_mont(t2, A24, Q->X);                     // XQ = A24*[(XP+ZP)^2-(XP-ZP)^2]    
    fp2sub(t0, t1, Q->Z);                           // ZQ = (XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)    
    fp2add(Q->X, P->Z, P->Z);                       // ZP = A24*[(XP+ZP)^2-(XP-ZP)^2]+(XP-ZP)^2    
    fp2add(t0, t1, Q->X);                           // XQ = (XP+ZP)*(XQ-ZQ)+(XP-ZP)*(XQ+ZQ)    
    fp2mul_mont(P->Z, t2, P->Z);                    // ZP = [A24*[(XP+ZP)^2-(XP-ZP)^2]+(XP-ZP)^2]*[(XP+ZP)^2-(XP-ZP)^2]    
    fp2sqr_mont(Q->Z, Q->Z);                        // ZQ = [(XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)]^2    
    fp2sqr_mont(Q->X, Q->X);                        // XQ = [(XP+ZP)*(XQ-ZQ)+(XP-ZP)*(XQ+ZQ)]^2    
    fp2mul_mont(Q->X, ZPQ, Q->X);                   // XQ = ZPQ*[(XP+ZP)*(XQ-ZQ)+(XP-ZP)*(XQ+ZQ)]^2    
    fp2mul_mont(Q->Z, XPQ, Q->Z);                   // ZQ = XPQ*[(XP+ZP)*(XQ-ZQ)-(XP-ZP)*(XQ+ZQ)]^2          
}


void xDBL_e(const point_proj_t P, point_proj_t Q, const f2elm_t A24, const int e)
{ // Doubling of a Montgomery point in projective coordinates (X:Z) over affine curve coefficient A. 
  // Input: projective Montgomery x-coordinates P = (X1:Z1), where x1=X1/Z1 and Montgomery curve constants (A+2)/4.
  // Output: projective Montgomery x-coordinates Q = 2*P = (X2:Z2). 
    f2elm_t temp, a, b, c, aa, bb;    
    
    fp2copy(P->X,Q->X);
    fp2copy(P->Z,Q->Z);
    
    for (int j = 0; j < e; j++) {
        fp2add(Q->X, Q->Z, a);           // a = xQ + zQ
        fp2sub(Q->X, Q->Z, b);           // b = xQ - zQ
        fp2sqr_mont(a, aa);              //aa = (xQ + zQ)^2
        fp2sqr_mont(b, bb);              //bb = (xQ - zQ)^2
        fp2sub(aa, bb, c);               // c = (xQ + zQ)^2 - (xQ - zQ)^2
        fp2mul_mont(aa, bb, Q->X);       // xQ = (xQ + zQ)^2 * (xQ - zQ)^2
        fp2mul_mont(A24, c, temp);       // temp = A24 * ((xQ + zQ)^2 - (xQ - zQ)^2)
        fp2add(temp, bb, temp);          // temp = A24 * ((xQ + zQ)^2 - (xQ - zQ)^2) + (xQ - zQ)^2
        fp2mul_mont(c, temp, Q->Z);      // temp =  (A24 * ((xQ + zQ)^2 - (xQ - zQ)^2) + (xQ - zQ)^2) * ((xQ + zQ)^2 - (xQ - zQ)^2)
    }
}


void Ladder(const point_proj_t P, const digit_t* m, const f2elm_t A, const unsigned int order_bits, point_proj_t R) 
{
    point_proj_t R0, R1;
    f2elm_t A24 = {0};
    unsigned int bit = 0;
    digit_t mask;
    int j, swap, prevbit = 0;    
        
    fpcopy((digit_t*)&Montgomery_one, A24[0]);
    fpadd(A24[0], A24[0], A24[0]);
    fp2add(A, A24, A24);
    fp2div2(A24, A24);  
    fp2div2(A24, A24);  // A24 = (A+2)/4          

    j = order_bits - 1;
    bit = (m[j >> LOG2RADIX] >> (j & (RADIX-1))) & 1;
    while (bit == 0) {
        j--;
        bit = (m[j >> LOG2RADIX] >> (j & (RADIX-1))) & 1;
    }

    // R0 <- P, R1 <- 2P
    fp2copy(P->X, R0->X);
    fp2copy(P->Z, R0->Z);
    xDBL_e(P, R1, A24, 1);    
    
    // Main loop
    for (int i = j - 1;  i >= 0; i--) {
        bit = (m[i >> LOG2RADIX] >> (i & (RADIX-1))) & 1;
        swap = bit ^ prevbit;
        prevbit = bit;
        mask = 0 - (digit_t)swap;

        swap_points(R0, R1, mask);
        xDBLADD_proj(R0, R1, P->X, P->Z, A24);
    }
    swap = 0 ^ prevbit;
    mask = 0 - (digit_t)swap;
    swap_points(R0, R1, mask);    
    
    fp2copy(R0->X, R->X);
    fp2copy(R0->Z, R->Z);
}

#endif