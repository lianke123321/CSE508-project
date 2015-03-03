#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef enum { false, true } boolean;

int main(int argc, char *argv[]) {
	int opt = 0;
	char *interface = NULL;
	char *file = NULL;
	char *string = NULL;
	boolean http = false;
	char *expression = NULL;
	// this string is used for communication between this
	// program and pcap
	char errbuf[PCAP_ERRBUF_SIZE];
	// this is like file system
	pcap_t *handle;
	// compiled filter
	struct bpf_program filter;
	// http get and post filter before compiling
	char filter_string[] = "(tcp port http) && ((tcp[32:4] = 0x47455420) || \
		(tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354))";
	// The netmask of interface
	bpf_u_int32 mask;
	// The ip address of interface
	bpf_u_int32 net;
	// the struct to store packet header
	struct pcap_pkthdr header;
	// the actual packet
	const u_char *packet;

	while ((opt = getopt(argc, argv, "i:r:s:g")) != -1) {
		switch(opt) {
			case 'i':
				interface = optarg;
				//printf("interface: %s\n", interface);
				break;
			case 'r':
				file = optarg;
				//printf("file: %s\n", file);
				break;
			case 's':
				string = optarg;
				//printf("string: %s\n", string);
				break;
			case 'g':
				//printf("Enable Http sniffer mode...\n");
				http = true;
				break;
			case '?':
				// when user didn't specify argument
				if (optopt == 'i') {
					printf("Please specify interface!\n");
					return 0;
				} else if (optopt == 'r') {
					printf("Please specify file name!\n");
					return 0;
				} else if (optopt == 's') {
					printf("Please specify match string!\n");
					return 0;
				}
		}
		
		// get expression
		if (optind == argc)
			break;
		else if (optind == argc - 1)
			expression = argv[optind];
		else {
			printf("Redundant argument! Existing...\n");
			return 0;
		}
	}
	
	if (interface != NULL && file != NULL) {
		printf("You can only use interface OR file!\n");
		return 0;
	}
	
	if (interface == NULL && file == NULL) {
		interface = pcap_lookupdev(errbuf);
		//interface = NULL;
		if (interface == NULL) {
			printf("Error finding default device! Error message: %s\n\
			Exiting...\n", errbuf);
			return 0;
		}
	}
	
	printf("\nInitializing mydump using following parameters:\n\
		interface: %s\n\
		file: %s\n\
		match string: %s\n\
		http sniffer mode: %s\n\
		expression: %s\n\n\n", interface, file, string,\
		http ? "true" : "false", expression);
	
	// open interface or file here
	if (interface != NULL && file == NULL) {
		// Get ip and netmask of sniffing interface or file
		if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
			printf("Error getting ip and mask! Error message: %s\n", errbuf);
			net = 0;
			mask = 0;
		}
		// Start pcap session
		handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			printf("Error opening live! Error message: %s\n\
			Existing...\n", errbuf);
			return 0;
		}
	} else if (interface == NULL && file != NULL) {
		handle = pcap_open_offline(file, errbuf);
		if (handle == NULL) {
			printf("Error opening file! Error message: %s\n\
			Existing...\n", errbuf);
			return 0;
		}
	} else {
		printf("This shouldn't be printed out! Existing...\n");
		return 0;
	}
	
	// check if link-layer header is ethernet
	if (pcap_datalink(handle) != DLT_EN10MB) {
		printf("Interface %s doesn't using ethernet header! Existing\n", interface);
		return 0;
	}
	
	// set http sniffer mode
	if (http) {
		// compile filter string
		if (pcap_compile(handle, &filter, filter_string, 0, net) == -1) {
			printf("Error compiling http filter! Error message: %s\n\
			Existing...\n", pcap_geterr(handle));
			return 0;
		}
		// apply compiled filter to session
		if (pcap_setfilter(handle, &filter) == -1) {
			printf("Error applying http filer! Error message: %s\n\
			Existing...\n", pcap_geterr(handle));
			return 0;
		}
	}
	
	// compile and apply expression
	if (expression != NULL) {
		// compile filter string
		if (pcap_compile(handle, &filter, expression, 0, net) == -1) {
			printf("Error compiling expression! Error message: %s\n\
			Existing...\n", pcap_geterr(handle));
			return 0;
		}
		// apply compiled filter to session
		if (pcap_setfilter(handle, &filter) == -1) {
			printf("Error applying expression! Error message: %s\n\
			Existing...\n", pcap_geterr(handle));
			return 0;
		}
	}
	
	// now we start sniffing!
	packet = pcap_next(handle, &header);
	printf("Captured packet length: %d\n", header.len);
	
	//pcap_freecode(&filter);
	pcap_close(handle);
	printf("Reached the end of code block\n");
	return 0;
}