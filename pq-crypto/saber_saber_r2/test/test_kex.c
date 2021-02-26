#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "../api.h"
#include "../poly.h"
#include "../rng.h"
#include "../SABER_indcpa.h"
#include "../verify.h"
#include "cpucycles.c"

// void fprintBstr(char *S, unsigned char *A, unsigned long long L)
// {
// 	unsigned long long  i;

// 	printf("%s", S);

// 	for ( i=0; i<L; i++ )
// 		printf("%02X", A[i]);

// 	if ( L == 0 )
// 		printf("00");

// 	printf("\n");
// }

uint64_t clock1,clock2;
uint64_t clock_kp_mv,clock_cl_mv, clock_kp_sm, clock_cl_sm;

static int test_kem_cca()
{


  uint8_t pk[SABER_PUBLICKEYBYTES];
  uint8_t sk[SABER_SECRETKEYBYTES];
  uint8_t c[SABER_BYTES_CCA_DEC];	
  uint8_t k_a[SABER_KEYBYTES], k_b[SABER_KEYBYTES];
	
  unsigned char entropy_input[48];
	
  uint64_t i, j, repeat;
  repeat=10000;	
  uint64_t CLOCK1,CLOCK2;
  uint64_t CLOCK_kp,CLOCK_enc,CLOCK_dec;

//  	CLOCK1 = 0;
//      CLOCK2 = 0;
	CLOCK_kp = CLOCK_enc = CLOCK_dec = 0;
	clock_kp_mv=clock_cl_mv=0;
	clock_kp_sm = clock_cl_sm = 0;


   
	time_t t;
   	// Intializes random number generator
   	srand((unsigned) time(&t));

    	for (i=0; i<48; i++){
        	//entropy_input[i] = rand()%256;
        	entropy_input[i] = i;
	}
    	randombytes_init(entropy_input, NULL, 256);


	printf("SABER_INDCPA_PUBLICKEYBYTES=%d\n", SABER_INDCPA_PUBLICKEYBYTES);
	printf("SABER_INDCPA_SECRETKEYBYTES=%d\n", SABER_INDCPA_SECRETKEYBYTES);
	printf("SABER_PUBLICKEYBYTES=%d\n", SABER_PUBLICKEYBYTES);
	printf("SABER_SECRETKEYBYTES=%d\n", SABER_SECRETKEYBYTES);
	printf("SABER_KEYBYTES=%d\n", SABER_KEYBYTES);
	printf("SABER_HASHBYTES=%d\n", SABER_HASHBYTES);
 	printf("SABER_BYTES_CCA_DEC=%d\n", SABER_BYTES_CCA_DEC);
	printf("\n");
 


  	for(i=0; i<repeat; i++)
  	{
	    //printf("i : %lu\n",i);

	    //Generation of secret key sk and public key pk pair
	    CLOCK1=cpucycles();	
	    crypto_kem_keypair(pk, sk);
	    CLOCK2=cpucycles();	
	    CLOCK_kp=CLOCK_kp+(CLOCK2-CLOCK1);	


	    //Key-Encapsulation call; input: pk; output: ciphertext c, shared-secret k_a;	
	    CLOCK1=cpucycles();
	    crypto_kem_enc(c, k_a, pk);
	    CLOCK2=cpucycles();	
	    CLOCK_enc=CLOCK_enc+(CLOCK2-CLOCK1);	

		/*
		printf("ciphertext=\n");
		for(j=0; j<SABER_BYTES_CCA_DEC; j++)
		printf("%02x", c[j]);
		printf("\n");
		*/

	    //Key-Decapsulation call; input: sk, c; output: shared-secret k_b;	
	    CLOCK1=cpucycles();
	    crypto_kem_dec(k_b, c, sk);
	    CLOCK2=cpucycles();	
	    CLOCK_dec=CLOCK_dec+(CLOCK2-CLOCK1);	
	  

		
	    // Functional verification: check if k_a == k_b?
	    for(j=0; j<SABER_KEYBYTES; j++)
	    {
		//printf("%u \t %u\n", k_a[j], k_b[j]);
		if(k_a[j] != k_b[j])
		{
			printf("----- ERR CCA KEM ------\n");
			return 0;	
			break;
		}
	    }
		//printf("\n");
  	}

	printf("Repeat is : %lld\n",repeat);
	printf("Average times key_pair: \t %llu \n",(unsigned long long) CLOCK_kp/repeat);
	printf("Average times enc: \t %llu \n",(unsigned long long) CLOCK_enc/repeat);
	printf("Average times dec: \t %llu \n",(unsigned long long) CLOCK_dec/repeat);


	printf("Average times kp mv: \t %llu \n",(unsigned long long) clock_kp_mv/repeat);
	printf("Average times cl mv: \t %llu \n",(unsigned long long) clock_cl_mv/repeat);
	printf("Average times sample_kp: \t %llu \n",(unsigned long long) clock_kp_sm/repeat);

  	return 0;
}

/*
void test_kem_cpa(){

	uint8_t pk[SABER_PUBLICKEYBYTES];
	uint8_t sk[SABER_SECRETKEYBYTES];

	indcpa_kem_keypair(unsigned char *pk, unsigned char *sk);
	indcpa_kem_enc(unsigned char *message_received, unsigned char *noiseseed, const unsigned char *pk, unsigned char *ciphertext)
	indcpa_kem_dec(const unsigned char *sk, const unsigned char *ciphertext, unsigned char message_dec[])
}
*/
int main()
{
	test_kem_cca();
	return 0;
}
