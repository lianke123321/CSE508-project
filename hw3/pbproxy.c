#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include <openssl/aes.h>
#include <openssl/rand.h> 
#include <openssl/hmac.h>
#include <openssl/buffer.h>

#define BUF_SIZE 4096

typedef enum { false, true } boolean;

typedef struct {
	int sock;
	struct sockaddr address;
	struct sockaddr_in sshaddr;
	int addr_len;
	const char *key;
} connection_t;

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

char* read_file(const char* filename) {
	char *buffer = 0;
	long length;
	FILE *f = fopen (filename, "rb");
	
	if (f) {
		fseek (f, 0, SEEK_END);
		length = ftell (f);
		fseek (f, 0, SEEK_SET);
		buffer = malloc (length);
		if (buffer)
			fread (buffer, 1, length, f);
		fclose (f);
	} else
		return 0;
	
	return buffer;
}

void* server_process(void* ptr) {
	if (!ptr) pthread_exit(0); 
	
	//int tid;
	//tid = (int)pthread_getthreadid_np();
	
	printf("New thread started\n");
	
	connection_t *conn = (connection_t *)ptr;
	char buffer[BUF_SIZE];
	int ssh_fd, n;
	boolean ssh_done = false;
	
	ssh_fd = socket(AF_INET, SOCK_STREAM, 0);
	
	if (connect(ssh_fd, (struct sockaddr *)&conn->sshaddr, sizeof(conn->sshaddr)) == -1) {
		printf("Connection to ssh failed!\n");
		pthread_exit(0);
	} else {
		printf("Connection to ssh established!\n");
	}
	
	int flags = fcntl(conn->sock, F_GETFL);
	if (flags == -1) {
		printf("read sock 1 flag error!\n");
		pthread_exit(0);
	}
	fcntl(conn->sock, F_SETFL, flags | O_NONBLOCK);
	
	flags = fcntl(ssh_fd, F_GETFL);
	if (flags == -1) {
		printf("read ssh_fd flag error!\n");
		pthread_exit(0);
	}
	fcntl(ssh_fd, F_SETFL, flags | O_NONBLOCK);
	
	struct ctr_state state;
	unsigned char iv[8] = "iek,87sa";
	AES_KEY aes_key;
	
	if (AES_set_encrypt_key(conn->key, 128, &aes_key) < 0) {
		fprintf(stderr, "Set encryption key error!\n");
		exit(1);
	}
	
	while (1) {
		while ((n = read(conn->sock, buffer, BUF_SIZE)) > 0) {
			unsigned char decryption[n];
			init_ctr(&state, iv);
			
			AES_ctr128_encrypt(buffer, decryption, n, &aes_key, state.ivec, state.ecount, &state.num);
			
			write(ssh_fd, decryption, n);
			if (n < BUF_SIZE)
				break;
		};
		
		while ((n = read(ssh_fd, buffer, BUF_SIZE)) >= 0) {
			if (n > 0)
				write(conn->sock, buffer, n);
			
			if (ssh_done == false && n == 0)
				ssh_done = true;
			
			if (n < BUF_SIZE)
				break;
		}
		
		if (ssh_done)
			break;
	}
	
	printf("Closing connections and exit thread!\n");
	close(conn->sock);
	close(ssh_fd);
	free(conn);
	pthread_exit(0);
}

int main(int argc, char *argv[]) {
	int opt = 0;
	char *str_listen_port = NULL;
	boolean server_mode = false;
	char *key_file = NULL;
	char *str_dst = NULL;
	char *str_dst_port = NULL;
	
	while ((opt = getopt(argc, argv, "l:k:")) != -1) {
		switch(opt) {
			case 'l':
				str_listen_port = optarg;
				server_mode = true;
				break;
			case 'k':
				key_file = optarg;
				break;
			case '?':
				// when user didn't specify argument
				if (optopt == 'l') {
					fprintf(stderr, "Please specify port number to listen!\n");
					return 0;
				} else if (optopt == 'k') {
					fprintf(stderr, "Please specify key file to use!\n");
					return 0;
				} else {
					fprintf(stderr, "Unknown argument!\n");
					return 0;
				}
			default:
				fprintf(stderr, "Default case?!\n");
				return 0;
		}
	}
	
	// get destination ip and port
	if (optind == argc - 2) {
		str_dst = argv[optind];
		str_dst_port = argv[optind+1];
	} else {
		fprintf(stderr, "optind: %d, argc: %d\n", optind, argc);
		fprintf(stderr, "Incorrect destination and port arguments. Exiting...\n");
		return 0;
	}
	
	if (key_file == NULL) {
		fprintf(stderr, "Key file not specified!\n");
		return 0;
	}
	
	fprintf(stderr, "\n\tInitializing pbproxy using following parameters:\n\
		server mode: %s\n\
		listening port: %s\n\
		key file: %s\n\
		destination addr: %s\n\
		destination port: %s\n\n\n"\
		, server_mode ? "true" : "false", str_listen_port, key_file,\
		str_dst, str_dst_port);
	
	unsigned const char *key = read_file(key_file);
	if (!key) {
		fprintf(stderr, "read key file failed!\n");
		return 0;
	}
	
	int dst_port = (int)strtol(str_dst_port, NULL, 10);
	struct hostent *nlp_host;
	
	if ((nlp_host=gethostbyname(str_dst)) == 0) {
		fprintf(stderr, "Resolve Error!\n");
		return 0;
	}
	
	struct sockaddr_in servaddr, sshaddr;
	bzero(&servaddr, sizeof(servaddr));
	bzero(&servaddr, sizeof(sshaddr));
	
	// pbproxy running in server mode
	if (server_mode == true) {
		connection_t *connection;
		pthread_t thread;
		int listen_fd;
		int listen_port = (int)strtol(str_listen_port, NULL, 10);
		listen_fd = socket(AF_INET, SOCK_STREAM, 0);
		//ssh_fd = socket(AF_INET, SOCK_STREAM, 0);
		
		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr = htons(INADDR_ANY);
		servaddr.sin_port = htons(listen_port);
		
		sshaddr.sin_family = AF_INET;
		sshaddr.sin_port = htons(dst_port);
		sshaddr.sin_addr.s_addr = ((struct in_addr *)(nlp_host->h_addr))->s_addr;
		
		bind(listen_fd, (struct sockaddr *)&servaddr, sizeof(servaddr));
		
		if (listen(listen_fd, 10) < 0) {
			fprintf(stderr, "Attempting to listen failed!\n");
			return 0;
		};
		
		while (1) {
			connection = (connection_t *)malloc(sizeof(connection_t));
			connection->sock = accept(listen_fd, &connection->address, &connection->addr_len);
			if (connection->sock > 0) {
				connection->sshaddr = sshaddr;
				connection->key = key;
				pthread_create(&thread, 0, server_process, (void*)connection);
				pthread_detach(thread);
			} else {
				free(connection);
			}
		}
		
	} else {
		// pbproxy running in client mode
		int sockfd, n;
		char buffer[BUF_SIZE];
		
		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		
		servaddr.sin_family = AF_INET;
		servaddr.sin_port = htons(dst_port);
		
		servaddr.sin_addr.s_addr = ((struct in_addr *)(nlp_host->h_addr))->s_addr;
		
		if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
			fprintf(stderr, "Connection failed!\n");
			return 0;
		}
		
		fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
		fcntl(sockfd, F_SETFL, O_NONBLOCK);
		
		struct ctr_state state;
		unsigned char iv[8] = "iek,87sa";
		AES_KEY aes_key;
		
		if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
			fprintf(stderr, "Set encryption key error!\n");
			exit(1);
		}
		
		while(1) {
			while ((n = read(STDIN_FILENO, buffer, BUF_SIZE)) > 0) {
				unsigned char encryption[n];
				init_ctr(&state, iv);
				AES_ctr128_encrypt(buffer, encryption, n, &aes_key, state.ivec, state.ecount, &state.num);
				
				write(sockfd, encryption, n);
				if (n < BUF_SIZE)
					break;
			}
			
			while ((n = read(sockfd, buffer, BUF_SIZE)) > 0) {
				write(STDOUT_FILENO, buffer, n);
				if (n < BUF_SIZE)
					break;
			}
		}
	}
	
	return 1;
}
