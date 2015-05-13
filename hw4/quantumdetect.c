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

#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14
#define ETHERTYPE_IPV4 0x0800

/* Ethernet header */
struct sniff_ethernet
{
	u_char  ether_dhost[ETHER_ADDR_LEN];	/* destination host address */
	u_char  ether_shost[ETHER_ADDR_LEN];	/* source host address */
	u_short ether_type;					 /* IP? ARP? RARP? etc */
};

// handle each packet and detecting MotS atteck
void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	/* declare pointers to packet headers */
	//printf("Got packet!\n");
	const struct sniff_ethernet *ethernet;
	const struct ip *ip;
	const struct tcphdr *tcp;
	const char *payload;
	
	int size_ip;
	int size_tcp;
	int size_payload;
	
	// extract ethernet header
	ethernet = (struct sniff_ethernet*)(packet);
	
	if (ntohs(ethernet->ether_type) == ETHERTYPE_IPV4) {
		printf("IPv4 ");
		// extract ip header
		ip = (struct ip*)(packet + SIZE_ETHERNET);
		size_ip = ip->ip_hl * 4;
		if (size_ip < 20) {
			printf("* Invalid IP header length: %u bytes\n", size_ip);
			return;
		}
		
		// for tcp packet
		if (ip->ip_p == IPPROTO_TCP) {
			printf("TCP ");
			tcp = (struct tcphdr *)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = tcp->th_off * 4;
			if (size_tcp < 20) {
				printf("* Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}
			printf("%s.%d -> ", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
			printf("%s.%d ", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
			printf("len %d ", ntohs(ip->ip_len));
			
			// extract payload
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
			
			// print payload
			if (size_payload > 0) {
				printf("Payload (%d bytes)\n", size_payload);
			} else {
				printf("No payload\n");
				return;
			}
		} else {
			printf("NON-TCP packet\n");
			return;
		}
		
	} else {
		printf("NON-IPv4 packet\n");
		return;
	}
}

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
	pcap_loop(handle, cnt, handle_packet, NULL);
	
	//pcap_freecode(&filter);
	pcap_close(handle);
	printf("\n\t... ... the end ... ...\n\n");
	return 0;
}