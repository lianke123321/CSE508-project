#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>

int main(int argc, char *argv[]) {
	int opt = 0;
	char *interface = NULL;
	char *datafile = NULL;
	char *expression = NULL;
	// this string is used for communication between this
	// program and pcap
	char errbuf[PCAP_ERRBUF_SIZE];
	// this is like file system
	pcap_t *handle;
	// compiled filter
	struct bpf_program filter;
	// The netmask of interface
	bpf_u_int32 mask;
	// The ip address of interface
	bpf_u_int32 net;
	// the struct to store packet header
	struct pcap_pkthdr header;
	// the actual packet
	const u_char *packet;
	// set counter to negative so sniffer will continue working
	int cnt = -1;

	while ((opt = getopt(argc, argv, "i:r:")) != -1) {
		switch(opt) {
			case 'i':
				interface = optarg;
				//printf("interface: %s\n", interface);
				break;
			case 'r':
				datafile = optarg;
				//printf("string: %s\n", string);
				break;
			case '?':
				// when user didn't specify argument
				if (optopt == 'i') {
					printf("Please specify interface!\n");
					return 0;
				} else if (optopt == 'r') {
					printf("Please specify regular expression!\n");
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
	
	// get expression
	if (optind == argc - 1)
		expression = argv[optind];
	else if (optind < argc -1) {
		printf("Redundant arguments. Exiting...\n");
		return 0;
	}
	
	if (interface != NULL && datafile != NULL) {
		printf("You can only use interface OR file!\n");
		return 0;
	}
	
	if (interface == NULL && datafile == NULL) {
		interface = pcap_lookupdev(errbuf);
		//interface = NULL;
		if (interface == NULL) {
			printf("Error finding default device! Error message: %s\n\
			Exiting...\n", errbuf);
			return 0;
		}
	}
	
	printf("\n\tInitializing quantum detector using following parameters:\n\
		interface: %s\n\
		data file: %s\n\
		expression: %s\n\n\n", interface, datafile, expression);
	
	// open interface here
	if (interface != NULL && datafile == NULL) {
		// Get ip and netmask of sniffing interface or file
		if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
			printf("Error getting ip and mask of the interface! Error message: %s\n", errbuf);
			net = 0;
			mask = 0;
		}
		// Start pcap session
		handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			printf("Error opening live sniffer! Error message: %s\n\
			Existing...\n", errbuf);
			return 0;
		}
	} else if (interface == NULL && datafile != NULL) {
		handle = pcap_open_offline(datafile, errbuf);
		if (handle == NULL) {
			printf("Error opening trace file! Error message: %s\n\
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
	//pcap_loop(handle, cnt, handle_packet, regexp);
	
	//pcap_freecode(&filter);
	pcap_close(handle);
	printf("\n\t... ... the end ... ...\n\n");
	return 0;
}