#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

typedef enum { false, true } boolean;

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
		str_dst = argv[optind];
		str_dst_port = argv[optind+1];
	} else {
		printf("optind: %d, argc: %d\n", optind, argc);
		printf("Incorrect destination and port arguments. Exiting...\n");
		return 0;
	}
	
	if (key_file == NULL) {
		printf("Key file not specified!\n");
		return 0;
	}
	
	/*printf("\nInitializing pbproxy using following parameters:\n\
		server mode: %s\n\
		listening port: %s\n\
		key file: %s\n\
		destination addr: %s\n\
		destination port: %s\n\n\n"\
		, server_mode ? "true" : "false", str_listen_port, key_file,\
		str_dst, str_dst_port);*/
	
	int dst_port = (int)strtol(str_dst_port, NULL, 10);
	struct hostent *nlp_host;
	
	if ((nlp_host=gethostbyname(str_dst)) == 0) {
		printf("Resolve Error!\n");
		return 0;
	}
	
	struct sockaddr_in servaddr;
	bzero(&servaddr, sizeof(servaddr));
	
	// pbproxy running in server mode
	if (server_mode == true) {
		char str[100];
		int listen_fd, comm_fd;
		int listen_port = (int)strtol(str_listen_port, NULL, 10);
		listen_fd = socket(AF_INET, SOCK_STREAM, 0);
		
		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr = htons(INADDR_ANY);
		servaddr.sin_port = htons(listen_port);
		
		bind(listen_fd, (struct sockaddr *)&servaddr, sizeof(servaddr));
		
		listen(listen_fd, 10);
		
		comm_fd = accept(listen_fd, (struct sockaddr*) NULL, NULL);
		
		while (1) {
			bzero(str, 100);
			read(comm_fd, str, 100);
			printf("Echoing back - %s",str);
			write(comm_fd, str, strlen(str)+1);
		}
	} else {
		// pbproxy running in client mode
		int sockfd,n;
		char sendline[100];
		char recvline[100];
		
		sockfd=socket(AF_INET,SOCK_STREAM,0);
		
		servaddr.sin_family=AF_INET;
		servaddr.sin_port=htons(dst_port);
		
		servaddr.sin_addr.s_addr=((struct in_addr *)(nlp_host->h_addr))->s_addr;
		
		if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
			//printf("Connection failed!\n");
			return 0;
		} else {
			//printf("Connection established!\n");
		}
		
		while(1) {
			bzero(sendline, 100);
			bzero(recvline, 100);
			fgets(sendline, 100, stdin); /*stdin = 0 , for standard input */
			
			write(sockfd, sendline, strlen(sendline)+1);
			read(sockfd, recvline, 100);
			//printf("%s",recvline);
			//fprintf(stdout, "%s", recvline);
			fputs(recvline, stdout);
		}
	}
	
	return 1;
}
