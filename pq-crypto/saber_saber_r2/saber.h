// s2n requires having KEM_NAME.h name in this directory
// the saber reference code has it in api.h
// i could have made saber.h a symbolic link but i dont know how this would survice
// through various code repo systems

#include "api.h"

#define SABER_SABER_R2_SECRET_KEY_BYTES SABER_SECRETKEYBYTES
#define SABER_SABER_R2_CRYPTO_BYTES SABER_KEYBYTES
#define SABER_SABER_R2_PUBLIC_KEY_BYTES SABER_PUBLICKEYBYTES
#define SABER_SABER_R2_CIPHERTEXT_BYTES SABER_BYTES_CCA_DEC 
