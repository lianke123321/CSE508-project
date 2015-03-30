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

AES_KEY key; 

//int bytes_read, bytes_written;   
unsigned char indata[AES_BLOCK_SIZE]; 
unsigned char outdata[AES_BLOCK_SIZE];
unsigned char iv[AES_BLOCK_SIZE]; //16?
struct ctr_state state;


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

char* TextEncrypt(const unsigned char* enc_key, char* text, int bytes_read) {
	//Cria vector com valores aleatórios
	if(!RAND_bytes(iv, 8)) {
		printf("Erro: Não foi possivel criar bytes aleatorios.\n");
		exit(1);
	}
	
	init_ctr(&state, iv); //Chamada do contador
	
	//Inicializa a chave de encriptação
	if (AES_set_encrypt_key(enc_key, 128, &key) < 0) {
		fprintf(stderr, "Nao foi possível definir chave de encriptacao.");
		exit(1);
	}
	
	//bytes_read = strlen(text);
	
	AES_set_encrypt_key(enc_key, 128, &key);	
	
	//Encripta em blocos de 16 bytes e guarda o texto cifrado numa string -> outdata
	AES_ctr128_encrypt(text, outdata, bytes_read, &key, state.ivec, state.ecount, &state.num);
	
	fflush(stdin);
	return outdata;
}

char* TextDecrypt(const unsigned char* enc_key, unsigned char* cypherText,\
	int bytes_read) {
	//Inicialização da Chave de encriptação 
	if (AES_set_encrypt_key(enc_key, 128, &key) < 0) {
		fprintf(stderr, "Nao foi possível definir chave de decodificacao.");
		exit(1);
	}
	
	init_ctr(&state, iv);//Chamada do contador
	
	//Encripta em blocos de 16 bytes e escreve o ficheiro output.txt cifrado
	//bytes_read = strlen(cypherText);
	
	AES_set_encrypt_key(enc_key, 128, &key);
	
	AES_ctr128_encrypt(cypherText, outdata, bytes_read, &key, state.ivec, state.ecount, &state.num);
	
	fflush(stdin);
	return outdata;
}

int main(int argc, char *argv[])
{
    char* text = "This bitch is crazy, I am gonna fuck her brain out!";

    //Receive hexadecimal 128 bits key 
    unsigned const char * key = "1234567812345678";
    //unsigned const char * key = "9EF4BCDE";   
    char * cipher, * decrypted;

    printf("Clean text: %s\n", text);

    cipher = TextEncrypt(key, text, strlen(text));
    printf("Chiper text: %s\n", cipher);

    decrypted = TextDecrypt(key, cipher, strlen(text));
    printf("Decrypted text: %s\n", decrypted);

    return 0;
}