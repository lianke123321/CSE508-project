#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
 
//以下头文件是为了使样例程序正常运行
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

typedef enum { false, true } boolean;

int main(int argc, char *argv[]) {
	int opt = 0;
	char *listen_port = NULL;
	boolean server_mode = false;
	char *key_file = NULL;
	char *dst = NULL;
	char *dst_port = NULL;
	
	while ((opt = getopt(argc, argv, "l:k:")) != -1) {
		switch(opt) {
			case 'l':
				listen_port = optarg;
				server_mode = true;
				//printf("listen_port: %s\n", listen_port);
				break;
			case 'k':
				key_file = optarg;
				//printf("key_file: %s\n", key_file);
				break;
			case '?':
				// when user didn't specify argument
				if (optopt == 'l') {
					printf("Please specify port number to listen!\n");
					return 0;
				} else if (optopt == 'k') {
					printf("Please specify key file to use!\n");
					return 0;
				} else {
					printf("Unknown argument!\n");
					return 0;
				}
			default:
				printf("Default case?!\n");
				return 0;
		}
	}
	
	// get destination ip and port
	if (optind == argc - 2) {
		dst = argv[optind];
		dst_port = argv[optind+1];
	} else {
		printf("optind: %d, argc: %d\n", optind, argc);
		printf("Incorrect destination and port arguments. Exiting...\n");
		return 0;
	}
	
	if (key_file == NULL) {
		printf("Key file not specified!\n");
		return 0;
	}
	
	printf("\nInitializing pbproxy using following parameters:\n\
		server mode: %s\n\
		listening port: %s\n\
		key file: %s\n\
		destination addr: %s\n\
		destination port: %s\n\n\n"\
		, server_mode ? "true" : "false", listen_port, key_file,\
		dst, dst_port);
}
