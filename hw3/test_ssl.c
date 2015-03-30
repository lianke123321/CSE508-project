#include <openssl/aes.h>
#include <openssl/rand.h> 
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

// Code example uses partail code from: http://stackoverflow.com/questions/3141860/aes-ctr-256-encryption-mode-of-operation-on-openssl
// Mostly in the ctr_ state, and init_ctr functions. 

struct ctr_state {
	unsigned char ivec[AES_BLOCK_SIZE];  
	unsigned int num; 
	unsigned char ecount[AES_BLOCK_SIZE]; 
}; 

int init_ctr(struct ctr_state *state, const unsigned char iv[8]) {
	/* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
	 * first call. */
	state->num = 0;
	memset(state->ecount, 0, AES_BLOCK_SIZE);

	/* Initialise counter in 'ivec' to 0 */
	memset(state->ivec + 8, 0, 8);

	/* Copy IV into 'ivec' */
	memcpy(state->ivec, iv, 8);
}

int main(int argc, char *argv[])
{
	struct ctr_state state;
	unsigned char iv[8] = "iek,87sa";
	AES_KEY aes_key;
	unsigned const char *key = "abcdefgh87654321";
	
	//printf("length of key: %d\n", strlen(key));
	
	char *plaintext = "I have no idea what I am doing";
	unsigned char encryption[strlen(plaintext)];
	unsigned char decryption[strlen(plaintext)];
	
	/*if(!RAND_bytes(iv, 8)) {
		printf("Error generating random bytes.\n");
		exit(1);
	}*/
	
	init_ctr(&state, iv);
	
	if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
		fprintf(stderr, "Set encryption key error!\n");
		exit(1);
	}
	
	printf("Clean text:     %s\n", plaintext);
	
	AES_ctr128_encrypt(plaintext, encryption, strlen(plaintext), &aes_key, state.ivec, state.ecount, &state.num);
	printf("Chipered text:  %.*s\n", (int)strlen(plaintext), encryption);
	
	init_ctr(&state, iv);
	AES_ctr128_encrypt(encryption, decryption, strlen(plaintext), &aes_key, state.ivec, state.ecount, &state.num);
	printf("Decrypted text: %.*s\n", (int)strlen(plaintext), decryption);
	
	return 0;
}