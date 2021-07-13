#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "kyber512r3_fips202.h"
#include "kyber512r3_fips202x4_avx2.h"
#include <immintrin.h>

/*****
 
 Implementation is taken from the Keccak Code Package
        https://github.com/XKCP/XKCP
 *****/
//#define KeccakF1600_StatePermute4x FIPS202X4_NAMESPACE(_KeccakP1600times4_PermuteAll_24rounds)
//extern void KeccakF1600_StatePermute4x(__m256i *s);


typedef __m256i V256;

static const uint64_t KeccakF1600RoundConstants[24] = {
    0x0000000000000001ULL,
    0x0000000000008082ULL,
    0x800000000000808aULL,
    0x8000000080008000ULL,
    0x000000000000808bULL,
    0x0000000080000001ULL,
    0x8000000080008081ULL,
    0x8000000000008009ULL,
    0x000000000000008aULL,
    0x0000000000000088ULL,
    0x0000000080008009ULL,
    0x000000008000000aULL,
    0x000000008000808bULL,
    0x800000000000008bULL,
    0x8000000000008089ULL,
    0x8000000000008003ULL,
    0x8000000000008002ULL,
    0x8000000000000080ULL,
    0x000000000000800aULL,
    0x800000008000000aULL,
    0x8000000080008081ULL,
    0x8000000000008080ULL,
    0x0000000080000001ULL,
    0x8000000080008008ULL};

static const uint64_t rho8[4] = {0x0605040302010007, 0x0E0D0C0B0A09080F, 0x1615141312111017, 0x1E1D1C1B1A19181F};
static const uint64_t rho56[4] = {0x0007060504030201, 0x080F0E0D0C0B0A09, 0x1017161514131211, 0x181F1E1D1C1B1A19};
#define ANDnu256(a, b)          _mm256_andnot_si256(a, b)
#define CONST256(a)             _mm256_load_si256((const void *)&(a))
#define LOAD256(a)              _mm256_load_si256((const void *)&(a))
#define STORE256(a, b)          _mm256_store_si256((V256 *)&(a), b)
#define ROL64in256(d, a, o)     d = _mm256_or_si256(_mm256_slli_epi64(a, o), _mm256_srli_epi64(a, 64-(o)))
#define ROL64in256_8(d, a)      d = _mm256_shuffle_epi8(a, CONST256(rho8))
#define ROL64in256_56(d, a)     d = _mm256_shuffle_epi8(a, CONST256(rho56))
#define XOR256(a, b)            _mm256_xor_si256(a, b)
#define XOReq256(a, b)          a = _mm256_xor_si256(a, b)
#define CONST256_64(a)          _mm256_set1_epi64x(a)

#define prepareTheta \
    Ca = XOR256(Aba, XOR256(Aga, XOR256(Aka, XOR256(Ama, Asa)))); \
    Ce = XOR256(Abe, XOR256(Age, XOR256(Ake, XOR256(Ame, Ase)))); \
    Ci = XOR256(Abi, XOR256(Agi, XOR256(Aki, XOR256(Ami, Asi)))); \
    Co = XOR256(Abo, XOR256(Ago, XOR256(Ako, XOR256(Amo, Aso)))); \
    Cu = XOR256(Abu, XOR256(Agu, XOR256(Aku, XOR256(Amu, Asu)))); \

/* --- Theta Rho Pi Chi Iota Prepare-theta */
/* --- 64-bit lanes mapped to 64-bit words */
#define thetaRhoPiChiIotaPrepareTheta(i, A, E) \
    ROL64in256(Ce1, Ce, 1); \
    Da = XOR256(Cu, Ce1); \
    ROL64in256(Ci1, Ci, 1); \
    De = XOR256(Ca, Ci1); \
    ROL64in256(Co1, Co, 1); \
    Di = XOR256(Ce, Co1); \
    ROL64in256(Cu1, Cu, 1); \
    Do = XOR256(Ci, Cu1); \
    ROL64in256(Ca1, Ca, 1); \
    Du = XOR256(Co, Ca1); \
\
    XOReq256(A##ba, Da); \
    Bba = A##ba; \
    XOReq256(A##ge, De); \
    ROL64in256(Bbe, A##ge, 44); \
    XOReq256(A##ki, Di); \
    ROL64in256(Bbi, A##ki, 43); \
    E##ba = XOR256(Bba, ANDnu256(Bbe, Bbi)); \
    XOReq256(E##ba, CONST256_64(KeccakF1600RoundConstants[i])); \
    Ca = E##ba; \
    XOReq256(A##mo, Do); \
    ROL64in256(Bbo, A##mo, 21); \
    E##be = XOR256(Bbe, ANDnu256(Bbi, Bbo)); \
    Ce = E##be; \
    XOReq256(A##su, Du); \
    ROL64in256(Bbu, A##su, 14); \
    E##bi = XOR256(Bbi, ANDnu256(Bbo, Bbu)); \
    Ci = E##bi; \
    E##bo = XOR256(Bbo, ANDnu256(Bbu, Bba)); \
    Co = E##bo; \
    E##bu = XOR256(Bbu, ANDnu256(Bba, Bbe)); \
    Cu = E##bu; \
\
    XOReq256(A##bo, Do); \
    ROL64in256(Bga, A##bo, 28); \
    XOReq256(A##gu, Du); \
    ROL64in256(Bge, A##gu, 20); \
    XOReq256(A##ka, Da); \
    ROL64in256(Bgi, A##ka, 3); \
    E##ga = XOR256(Bga, ANDnu256(Bge, Bgi)); \
    XOReq256(Ca, E##ga); \
    XOReq256(A##me, De); \
    ROL64in256(Bgo, A##me, 45); \
    E##ge = XOR256(Bge, ANDnu256(Bgi, Bgo)); \
    XOReq256(Ce, E##ge); \
    XOReq256(A##si, Di); \
    ROL64in256(Bgu, A##si, 61); \
    E##gi = XOR256(Bgi, ANDnu256(Bgo, Bgu)); \
    XOReq256(Ci, E##gi); \
    E##go = XOR256(Bgo, ANDnu256(Bgu, Bga)); \
    XOReq256(Co, E##go); \
    E##gu = XOR256(Bgu, ANDnu256(Bga, Bge)); \
    XOReq256(Cu, E##gu); \
\
    XOReq256(A##be, De); \
    ROL64in256(Bka, A##be, 1); \
    XOReq256(A##gi, Di); \
    ROL64in256(Bke, A##gi, 6); \
    XOReq256(A##ko, Do); \
    ROL64in256(Bki, A##ko, 25); \
    E##ka = XOR256(Bka, ANDnu256(Bke, Bki)); \
    XOReq256(Ca, E##ka); \
    XOReq256(A##mu, Du); \
    ROL64in256_8(Bko, A##mu); \
    E##ke = XOR256(Bke, ANDnu256(Bki, Bko)); \
    XOReq256(Ce, E##ke); \
    XOReq256(A##sa, Da); \
    ROL64in256(Bku, A##sa, 18); \
    E##ki = XOR256(Bki, ANDnu256(Bko, Bku)); \
    XOReq256(Ci, E##ki); \
    E##ko = XOR256(Bko, ANDnu256(Bku, Bka)); \
    XOReq256(Co, E##ko); \
    E##ku = XOR256(Bku, ANDnu256(Bka, Bke)); \
    XOReq256(Cu, E##ku); \
\
    XOReq256(A##bu, Du); \
    ROL64in256(Bma, A##bu, 27); \
    XOReq256(A##ga, Da); \
    ROL64in256(Bme, A##ga, 36); \
    XOReq256(A##ke, De); \
    ROL64in256(Bmi, A##ke, 10); \
    E##ma = XOR256(Bma, ANDnu256(Bme, Bmi)); \
    XOReq256(Ca, E##ma); \
    XOReq256(A##mi, Di); \
    ROL64in256(Bmo, A##mi, 15); \
    E##me = XOR256(Bme, ANDnu256(Bmi, Bmo)); \
    XOReq256(Ce, E##me); \
    XOReq256(A##so, Do); \
    ROL64in256_56(Bmu, A##so); \
    E##mi = XOR256(Bmi, ANDnu256(Bmo, Bmu)); \
    XOReq256(Ci, E##mi); \
    E##mo = XOR256(Bmo, ANDnu256(Bmu, Bma)); \
    XOReq256(Co, E##mo); \
    E##mu = XOR256(Bmu, ANDnu256(Bma, Bme)); \
    XOReq256(Cu, E##mu); \
\
    XOReq256(A##bi, Di); \
    ROL64in256(Bsa, A##bi, 62); \
    XOReq256(A##go, Do); \
    ROL64in256(Bse, A##go, 55); \
    XOReq256(A##ku, Du); \
    ROL64in256(Bsi, A##ku, 39); \
    E##sa = XOR256(Bsa, ANDnu256(Bse, Bsi)); \
    XOReq256(Ca, E##sa); \
    XOReq256(A##ma, Da); \
    ROL64in256(Bso, A##ma, 41); \
    E##se = XOR256(Bse, ANDnu256(Bsi, Bso)); \
    XOReq256(Ce, E##se); \
    XOReq256(A##se, De); \
    ROL64in256(Bsu, A##se, 2); \
    E##si = XOR256(Bsi, ANDnu256(Bso, Bsu)); \
    XOReq256(Ci, E##si); \
    E##so = XOR256(Bso, ANDnu256(Bsu, Bsa)); \
    XOReq256(Co, E##so); \
    E##su = XOR256(Bsu, ANDnu256(Bsa, Bse)); \
    XOReq256(Cu, E##su); \
\


#define rounds24 \
    prepareTheta \
    for(i=0; i<24; i+=6) { \
        thetaRhoPiChiIotaPrepareTheta(i  , A, E) \
        thetaRhoPiChiIotaPrepareTheta(i+1, E, A) \
        thetaRhoPiChiIotaPrepareTheta(i+2, A, E) \
        thetaRhoPiChiIotaPrepareTheta(i+3, E, A) \
        thetaRhoPiChiIotaPrepareTheta(i+4, A, E) \
        thetaRhoPiChiIotaPrepareTheta(i+5, E, A) \
    } \


#define declareABCDE \
    V256 Aba, Abe, Abi, Abo, Abu; \
    V256 Aga, Age, Agi, Ago, Agu; \
    V256 Aka, Ake, Aki, Ako, Aku; \
    V256 Ama, Ame, Ami, Amo, Amu; \
    V256 Asa, Ase, Asi, Aso, Asu; \
    V256 Bba, Bbe, Bbi, Bbo, Bbu; \
    V256 Bga, Bge, Bgi, Bgo, Bgu; \
    V256 Bka, Bke, Bki, Bko, Bku; \
    V256 Bma, Bme, Bmi, Bmo, Bmu; \
    V256 Bsa, Bse, Bsi, Bso, Bsu; \
    V256 Ca, Ce, Ci, Co, Cu; \
    V256 Ca1, Ce1, Ci1, Co1, Cu1; \
    V256 Da, De, Di, Do, Du; \
    V256 Eba, Ebe, Ebi, Ebo, Ebu; \
    V256 Ega, Ege, Egi, Ego, Egu; \
    V256 Eka, Eke, Eki, Eko, Eku; \
    V256 Ema, Eme, Emi, Emo, Emu; \
    V256 Esa, Ese, Esi, Eso, Esu; \
    
#define copyFromState(X, state) \
    X##ba = LOAD256(state[ 0]); \
    X##be = LOAD256(state[ 1]); \
    X##bi = LOAD256(state[ 2]); \
    X##bo = LOAD256(state[ 3]); \
    X##bu = LOAD256(state[ 4]); \
    X##ga = LOAD256(state[ 5]); \
    X##ge = LOAD256(state[ 6]); \
    X##gi = LOAD256(state[ 7]); \
    X##go = LOAD256(state[ 8]); \
    X##gu = LOAD256(state[ 9]); \
    X##ka = LOAD256(state[10]); \
    X##ke = LOAD256(state[11]); \
    X##ki = LOAD256(state[12]); \
    X##ko = LOAD256(state[13]); \
    X##ku = LOAD256(state[14]); \
    X##ma = LOAD256(state[15]); \
    X##me = LOAD256(state[16]); \
    X##mi = LOAD256(state[17]); \
    X##mo = LOAD256(state[18]); \
    X##mu = LOAD256(state[19]); \
    X##sa = LOAD256(state[20]); \
    X##se = LOAD256(state[21]); \
    X##si = LOAD256(state[22]); \
    X##so = LOAD256(state[23]); \
    X##su = LOAD256(state[24]); \

#define copyToState(state, X) \
    STORE256(state[ 0], X##ba); \
    STORE256(state[ 1], X##be); \
    STORE256(state[ 2], X##bi); \
    STORE256(state[ 3], X##bo); \
    STORE256(state[ 4], X##bu); \
    STORE256(state[ 5], X##ga); \
    STORE256(state[ 6], X##ge); \
    STORE256(state[ 7], X##gi); \
    STORE256(state[ 8], X##go); \
    STORE256(state[ 9], X##gu); \
    STORE256(state[10], X##ka); \
    STORE256(state[11], X##ke); \
    STORE256(state[12], X##ki); \
    STORE256(state[13], X##ko); \
    STORE256(state[14], X##ku); \
    STORE256(state[15], X##ma); \
    STORE256(state[16], X##me); \
    STORE256(state[17], X##mi); \
    STORE256(state[18], X##mo); \
    STORE256(state[19], X##mu); \
    STORE256(state[20], X##sa); \
    STORE256(state[21], X##se); \
    STORE256(state[22], X##si); \
    STORE256(state[23], X##so); \
    STORE256(state[24], X##su); \

void KeccakP1600times4_PermuteAll_24rounds(void *states)
{
    V256 *statesAsLanes = (V256 *)states;
    declareABCDE
        unsigned int i;
    copyFromState(A, statesAsLanes)
    rounds24
    copyToState(statesAsLanes, A)
}



static inline void store64(uint8_t x[8], uint64_t u) {
  unsigned int i;

  for(i=0;i<8;i++)
    x[i] = u >> 8*i;
}

static void keccakx4_absorb(__m256i s[25],
                            unsigned int r,
                            const uint8_t *in0,
                            const uint8_t *in1,
                            const uint8_t *in2,
                            const uint8_t *in3,
                            size_t inlen,
                            uint8_t p)
{
  size_t i, pos = 0;
  __m256i t, idx;

  for(i = 0; i < 25; ++i)
    s[i] = _mm256_setzero_si256();

  idx = _mm256_set_epi64x((long long)in3, (long long)in2, (long long)in1, (long long)in0);
  while(inlen >= r) {
    for(i = 0; i < r/8; ++i) {
      t = _mm256_i64gather_epi64((long long *)pos, idx, 1);
      s[i] = _mm256_xor_si256(s[i], t);
      pos += 8;
    }

    KeccakP1600times4_PermuteAll_24rounds(s);
    inlen -= r;
  }

  i = 0;
  while(inlen >= 8) {
    t = _mm256_i64gather_epi64((long long *)pos, idx, 1);
    s[i] = _mm256_xor_si256(s[i], t);

    i++;
    pos += 8;
    inlen -= 8;
  }

  if(inlen) {
    t = _mm256_i64gather_epi64((long long *)pos, idx, 1);
    idx = _mm256_set1_epi64x((1ULL << (8*inlen)) - 1);
    t = _mm256_and_si256(t, idx);
    s[i] = _mm256_xor_si256(s[i], t);
  }

  t = _mm256_set1_epi64x((uint64_t)p << 8*inlen);
  s[i] = _mm256_xor_si256(s[i], t);
  t = _mm256_set1_epi64x(1ULL << 63);
  s[r/8 - 1] = _mm256_xor_si256(s[r/8 - 1], t);
}

static void keccakx4_squeezeblocks(uint8_t *out0,
                                   uint8_t *out1,
                                   uint8_t *out2,
                                   uint8_t *out3,
                                   size_t nblocks,
                                   unsigned int r,
                                   __m256i s[25])
{
  unsigned int i;
  uint64_t f0,f1,f2,f3;

  while(nblocks > 0) {
    KeccakP1600times4_PermuteAll_24rounds(s);
    for(i=0; i < r/8; ++i) {
      f0 = _mm256_extract_epi64(s[i], 0);
      f1 = _mm256_extract_epi64(s[i], 1);
      f2 = _mm256_extract_epi64(s[i], 2);
      f3 = _mm256_extract_epi64(s[i], 3);
      store64(out0, f0);
      store64(out1, f1);
      store64(out2, f2);
      store64(out3, f3);

      out0 += 8;
      out1 += 8;
      out2 += 8;
      out3 += 8;
    }

    --nblocks;
  }
}

void shake128x4_absorb(keccakx4_state *state,
                       const uint8_t *in0,
                       const uint8_t *in1,
                       const uint8_t *in2,
                       const uint8_t *in3,
                       size_t inlen)
{
  keccakx4_absorb(state->s, S2N_KYBER_512_R3_SHAKE128_RATE, in0, in1, in2, in3, inlen, 0x1F);
}

void shake128x4_squeezeblocks(uint8_t *out0,
                              uint8_t *out1,
                              uint8_t *out2,
                              uint8_t *out3,
                              size_t nblocks,
                              keccakx4_state *state)
{
  keccakx4_squeezeblocks(out0, out1, out2, out3, nblocks, S2N_KYBER_512_R3_SHAKE128_RATE,
                         state->s);
}

void shake256x4_absorb(keccakx4_state *state,
                       const uint8_t *in0,
                       const uint8_t *in1,
                       const uint8_t *in2,
                       const uint8_t *in3,
                       size_t inlen)
{
  keccakx4_absorb(state->s, S2N_KYBER_512_R3_SHAKE256_RATE, in0, in1, in2, in3, inlen, 0x1F);
}

void shake256x4_squeezeblocks(uint8_t *out0,
                              uint8_t *out1,
                              uint8_t *out2,
                              uint8_t *out3,
                              size_t nblocks,
                              keccakx4_state *state)
{
  keccakx4_squeezeblocks(out0, out1, out2, out3, nblocks, S2N_KYBER_512_R3_SHAKE256_RATE,
                         state->s);
}

void shake128x4(uint8_t *out0,
                uint8_t *out1,
                uint8_t *out2,
                uint8_t *out3,
                size_t outlen,
                const uint8_t *in0,
                const uint8_t *in1,
                const uint8_t *in2,
                const uint8_t *in3,
                size_t inlen)
{
  unsigned int i;
  size_t nblocks = outlen/S2N_KYBER_512_R3_SHAKE128_RATE;
  uint8_t t[4][S2N_KYBER_512_R3_SHAKE128_RATE];
  keccakx4_state state;

  shake128x4_absorb(&state, in0, in1, in2, in3, inlen);
  shake128x4_squeezeblocks(out0, out1, out2, out3, nblocks, &state);

  out0 += nblocks*S2N_KYBER_512_R3_SHAKE128_RATE;
  out1 += nblocks*S2N_KYBER_512_R3_SHAKE128_RATE;
  out2 += nblocks*S2N_KYBER_512_R3_SHAKE128_RATE;
  out3 += nblocks*S2N_KYBER_512_R3_SHAKE128_RATE;
  outlen -= nblocks*S2N_KYBER_512_R3_SHAKE128_RATE;

  if(outlen) {
    shake128x4_squeezeblocks(t[0], t[1], t[2], t[3], 1, &state);
    for(i = 0; i < outlen; ++i) {
      out0[i] = t[0][i];
      out1[i] = t[1][i];
      out2[i] = t[2][i];
      out3[i] = t[3][i];
    }
  }
}

void shake256x4(uint8_t *out0,
                uint8_t *out1,
                uint8_t *out2,
                uint8_t *out3,
                size_t outlen,
                const uint8_t *in0,
                const uint8_t *in1,
                const uint8_t *in2,
                const uint8_t *in3,
                size_t inlen)
{
  unsigned int i;
  size_t nblocks = outlen/S2N_KYBER_512_R3_SHAKE256_RATE;
  uint8_t t[4][S2N_KYBER_512_R3_SHAKE256_RATE];
  keccakx4_state state;

  shake256x4_absorb(&state, in0, in1, in2, in3, inlen);
  shake256x4_squeezeblocks(out0, out1, out2, out3, nblocks, &state);

  out0 += nblocks*S2N_KYBER_512_R3_SHAKE256_RATE;
  out1 += nblocks*S2N_KYBER_512_R3_SHAKE256_RATE;
  out2 += nblocks*S2N_KYBER_512_R3_SHAKE256_RATE;
  out3 += nblocks*S2N_KYBER_512_R3_SHAKE256_RATE;
  outlen -= nblocks*S2N_KYBER_512_R3_SHAKE256_RATE;

  if(outlen) {
    shake256x4_squeezeblocks(t[0], t[1], t[2], t[3], 1, &state);
    for(i = 0; i < outlen; ++i) {
      out0[i] = t[0][i];
      out1[i] = t[1][i];
      out2[i] = t[2][i];
      out3[i] = t[3][i];
    }
  }
}
