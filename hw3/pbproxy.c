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

#define BUF_SIZE 4096

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
	
	struct sockaddr_in servaddr, sshaddr;
	bzero(&servaddr, sizeof(servaddr));
	bzero(&servaddr, sizeof(sshaddr));
	
	// pbproxy running in server mode
	if (server_mode == true) {
		char buffer[BUF_SIZE];
		int listen_fd, comm_fd, ssh_fd, n;
		int listen_port = (int)strtol(str_listen_port, NULL, 10);
		listen_fd = socket(AF_INET, SOCK_STREAM, 0);
		ssh_fd = socket(AF_INET, SOCK_STREAM, 0);
		
		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr = htons(INADDR_ANY);
		servaddr.sin_port = htons(listen_port);
		
		sshaddr.sin_family = AF_INET;
		sshaddr.sin_port = htons(dst_port);
		sshaddr.sin_addr.s_addr = ((struct in_addr *)(nlp_host->h_addr))->s_addr;
		
		bind(listen_fd, (struct sockaddr *)&servaddr, sizeof(servaddr));
		
		listen(listen_fd, 10);
		
		comm_fd = accept(listen_fd, (struct sockaddr*) NULL, NULL);
		
		if (connect(ssh_fd, (struct sockaddr *)&sshaddr, sizeof(sshaddr)) == -1) {
			printf("Connection to ssh failed!\n");
			return 0;
		} else {
			printf("Connection to ssh established!\n");
		}
		
		//fputs("about to change blocking mode\n", stderr);
		int flags = fcntl(comm_fd, F_GETFL);
		if (flags == -1) {
			printf("read comm_fd flag error!\n");
			return 0;
		}
		fcntl(comm_fd, F_SETFL, flags | O_NONBLOCK);
		
		flags = fcntl(ssh_fd, F_GETFL);
		if (flags == -1) {
			printf("read ssh_fd flag error!\n");
			return 0;
		}
		fcntl(ssh_fd, F_SETFL, flags | O_NONBLOCK);
		
		while (1) {
			//bzero(buffer, BUF_SIZE);
			//fputs("about to read from comm_fd\n", stderr);
			while ((n = read(comm_fd, buffer, BUF_SIZE)) > 0) {
				//int m = n;
				//fputs("comm_fd -> ssh_fd\n", stderr);
				write(ssh_fd, buffer, n);
				//write(comm_fd, buffer, n);
				if (n < BUF_SIZE)
					break;
			};
			
			//fputs("about to read from ssh_fd\n", stderr);
			while ((n = read(ssh_fd, buffer, BUF_SIZE)) > 0) {
				//fputs("ssh_fd -> comm_fd\n", stderr);
				write(comm_fd, buffer, n);
				if (n < BUF_SIZE)
					break;
			}
			
			//fputs("finished one round!\n", stderr);
		}
	} else {
		// pbproxy running in client mode
		int sockfd, n;
		//char sendline[BUF_SIZE];
		//char recvline[BUF_SIZE];
		char buffer[BUF_SIZE];
		
		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		
		servaddr.sin_family = AF_INET;
		servaddr.sin_port = htons(dst_port);
		
		servaddr.sin_addr.s_addr = ((struct in_addr *)(nlp_host->h_addr))->s_addr;
		
		if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
			//printf("Connection failed!\n");
			return 0;
		} else {
			//printf("Connection established!\n");
		}
		
		fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
		fcntl(sockfd, F_SETFL, O_NONBLOCK);
		//fcntl(STDOUT_FILENO, F_SETFL, O_NONBLOCK);
		
		while(1) {
			//bzero(sendline, BUF_SIZE);
			//bzero(recvline, BUF_SIZE);
			//fputs("about to take input\n", stderr);
			while ((n = read(STDIN_FILENO, buffer, BUF_SIZE)) > 0) {
				//fputs("ssh -> socket\n", stderr);
				write(sockfd, buffer, n);
				if (n < BUF_SIZE)
					break;
			}
			
			//n = 0;
			//fputs("read finished\n", stderr);
			//fgets(sendline, BUF_SIZE, stdin);
			//fputs("read from ssh\n", stderr);
			//write(STDERR_FILENO, sendline, n);
			//fputs(sendline, stderr);
			
			//write(sockfd, buffer, n);
			//read(sockfd, recvline, BUF_SIZE);
			
			while ((n = read(sockfd, buffer, BUF_SIZE)) > 0) {
				//fputs("read from sock exceeds buffer size!\n", stderr);
				//fprintf(stderr, "n is %d\n", n);
				//return 0;
				//fputs("socket -> ssh\n", stderr);
				write(STDOUT_FILENO, buffer, n);
				if (n < BUF_SIZE)
					break;
			}
			
			//n = 0;
			//fputs("write finished\n", stderr);
			//fprintf(stdout, "%s", recvline);
			//fputs("write to ssh\n", stderr);
			//write(STDERR_FILENO, recvline, n);
			//fputs("write to end\n", stderr);
			//fputs(recvline, stderr);
			//fputs(recvline, stdout);
			//write(STDOUT_FILENO, buffer, n);
		}
	}
	
	return 1;
}
