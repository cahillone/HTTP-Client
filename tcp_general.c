// Chad Cahill
// EECE 598, California State University - Chico
// Spring 2014

#include <pcap/pcap.h>
#include <arpa/inet.h> // inet_ntop() etc...
#include <netinet/ether.h> // ether_ntoa() etc...
#include <string.h> // for memcpy() etc...
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <sys/types.h>
#include <netpacket/packet.h>
#include <stdlib.h> /* rand, srand */
#include <time.h> /* time */

#include "tcp_general.h"

#define PACKET_SIZE 54
#define SYN_MASK 0x02
#define FIN_MASK 0x01
#define ACK_MASK 0x10

/* getMyAddresses looks up this host's MAC and IPv4 addresses.
 * These addresses are stored in the MAC and IPv4 buffers given as arguments.
 * getMyAddresses assumes the device used is eth0.
 * Returns 0 on success.
 * Returns -1 on error.
 */
int getMyAddresses(u_char *myMAC, u_char *myIPv4) {
  struct ifaddrs *ifaddr, *ifa;
  char IPv4[32];

  memset(myMAC, 0, 6);
  memset(myIPv4, 0, 4);

  if (getifaddrs(&ifaddr) == -1) {
    perror("getifaddrs");
    return -1;
  }

  for (ifa = ifaddr; ifa != NULL; ifa = ifa-> ifa_next) {
    if (ifa -> ifa_addr == NULL)
      continue;

  if (ifa->ifa_addr->sa_family == AF_PACKET 
    && !(strcmp(ifa->ifa_name, "eth0"))) {
    // store my MAC address
    memcpy(myMAC, ((struct sockaddr_ll*)ifa->ifa_addr) -> sll_addr, 6);
  }

  if (ifa -> ifa_addr ->sa_family == AF_INET
    && !(strcmp(ifa -> ifa_name, "eth0"))) {
    // store my IPv4 address
    if (getnameinfo(ifa -> ifa_addr, sizeof(struct sockaddr_in), IPv4, 32,
      NULL, 0, NI_NUMERICHOST) != 0) {
      printf("getnameinfo() failed\n");
      return -1;
    }
    inet_pton(AF_INET, IPv4, myIPv4);
    }
  }
 	return 0;
}

/* genIPv4Header takes a pointer to a header structure
 * in order to generate an IPv4 header placed in the character array: packet.
 * First 14 bytes: Ethernet frame.
 * Next 20 bytes: IPv4 header.
 * This function assumes a protocol of TCP will be used.
 * This function relies on another function (calculateChecksum) to calculate it's checksum.
 */
void genIPv4Header(u_char *packet, struct header *host){

	host->ethernet_head.type = htons(0x0800);
	
	/* Begin Ethernet Frame */	
	memcpy(packet, host->ethernet_head.destination, 6);
	memcpy(packet + 6, host->ethernet_head.source, 6);
	memcpy(packet + 12, &host->ethernet_head.type, 2);
	/* End Ethernet Frame */

	host->IP_head.version_IHL = 0x45;
	host->IP_head.ToS = 0x00;
	host->IP_head.total_length = htons(20 + 20);
	host->IP_head.identification = htons(0x0000);
	host->IP_head.flags = 0x40;
	host->IP_head.frag_offset = 0x00;
	host->IP_head.TTL = 0x40;
	host->IP_head.protocol = 0x06;
	host->IP_head.checksum = htons(0x0000);
	
	/* Begin IP Frame */
	memcpy(packet + 14, &host->IP_head.version_IHL, sizeof(host->IP_head.version_IHL));
	memcpy(packet + 15, &host->IP_head.ToS, 1);
	memcpy(packet + 16, &host->IP_head.total_length, 2);
	memcpy(packet + 18, &host->IP_head.identification, 2);
	memcpy(packet + 20, &host->IP_head.flags, 1);
	memcpy(packet + 21, &host->IP_head.frag_offset, 1);
	memcpy(packet + 22, &host->IP_head.TTL, 1);
	memcpy(packet + 23, &host->IP_head.protocol, 1);
	memcpy(packet + 24, &host->IP_head.checksum, 2);
	memcpy(packet + 26, host->IP_head.source, 4);
	memcpy(packet + 30, host->IP_head.destination, 4);

	host->IP_head.checksum = htons(calculateChecksum(packet + 14, 20));

	memcpy(packet + 24, &host->IP_head.checksum, 2);
	/* End IP Frame */
}

/* genTCPHeader takes in a pointer to a header structure.
 * genTCPHeader builds a TCP header using the structure's data and places the header on the character array: packet.
 * genTCPHeader assumes no data follows the TCP header.
 * 'packet' should already have an Ethernet frame and IPv4 header occupying the first 34 bytes
 * so the 20 byte TCP header will be placed after the IPv4 header resulting in a total header length of 54 bytes.
 */
void genTCPHeader(u_char *packet, struct header *host) {

	host->TCP_head.data_offset = 0x50;
	host->TCP_head.window = htons(1500);
	host->TCP_head.checksum = htons(0x0000);
	host->TCP_head.urgent_pointer = htons(0x0000);

	memcpy(packet + 34, &host->TCP_head.src_port, 2);
	memcpy(packet + 36, &host->TCP_head.dst_port, 2);
	memcpy(packet + 38, &host->TCP_head.seq_num, 4);
	memcpy(packet + 42, &host->TCP_head.ack_num, 4);
	memcpy(packet + 46, &host->TCP_head.data_offset, 1);
	memcpy(packet + 47, &host->TCP_head.flags, 1);
	memcpy(packet + 48, &host->TCP_head.window, 2);
	memcpy(packet + 50, &host->TCP_head.checksum, 2);
	memcpy(packet + 52, &host->TCP_head.urgent_pointer, 2);

	u_char preChecksumHeader[32];
	memcpy(preChecksumHeader, packet + 34, 20);
	memcpy(preChecksumHeader + 20, host->TCP_head.pseudoheader, 12);
	
	host->TCP_head.checksum = htons(calculateChecksum(preChecksumHeader, 32));
	
	memcpy(packet + 50, &host->TCP_head.checksum, 2);
	
	return;
}

/* generatePort will generate a 'random' number between min and max.
 * This number may be used as a source port. 
 */
uint16_t generatePort(int min, int max) {
	uint16_t port = 0;
	srand(time(NULL));
	port = rand() % max + min;
	return port;
}

/* gererateISN generates a random 32 bit number.
 * This number may be used as an Initial Sequence Number for a TCP connection
 */
uint32_t generateISN() {
	uint32_t ISN = 0;
	srand(time(NULL));
	ISN = rand() % 0xFFFFFFFF;
	/* fprintf(stdout, "%X\n", ISN); */
	return ISN;
}

/* setFlags takes 1 as an argument to set a flag, or 0 to clear a flag.
 * For example setFlags(1,1,0) would set the ACK and SYN flags, while clearing the FIN flag.
 * setFlags returns an unsigned character which may be passed into the 'flags' member variable of a TCP Header structure.
 */
u_char setFlags(int ACK, int SYN, int FIN) {
	u_char flag = 0;
	if (ACK) {
		flag = flag | 0x10;
	}
	if (SYN) {
		flag = flag | 0x02;
	}
	if (FIN) {
		flag = flag | 0x01;
	}
	return flag;
}

/* genPseudoHeader takes in a pointer to a header structure.
 * genPseudoHeader makes a Pseudo Header and places it in the character array: pseudoheader.
 * Note: the Pseudo Header is used to generate the TCP checksum.
 */
void genPseudoHeader(struct header *host) {
	memcpy(host->TCP_head.pseudoheader, host->IP_head.source, 4);
	memcpy(host->TCP_head.pseudoheader + 4, host->IP_head.destination, 4);
	host->TCP_head.pseudoheader[8] = 0x00;
	memcpy(host->TCP_head.pseudoheader + 9, &host->IP_head.protocol, 1);
	host->TCP_head.pseudoheader[10] = 0x00;
	host->TCP_head.pseudoheader[11] = 0x14;	
	return;
}

/* calculateChecksum takes in a header and its length as arguments.
 * The checksum is calculated by adding up all 16 bit segments of the header 
 * and then taking the one's compliment of the final answer. 
 * Note: if you are calculating a TCP checksum make sure the pseudoheader is included in the header.
 * The majority of this function came from www.netfor2.com/ipsum.htm */
uint16_t calculateChecksum(u_char *header, int header_length) {	
	uint16_t checksum = 0;
	uint16_t word16;
	uint32_t sum = 0;
	int i = 0;
	for (i = 0; i < header_length; i = i + 2) {
		word16 = ((header[i] << 8) & 0xFF00) + (header[i+1] & 0x00FF);
		sum = sum + (uint32_t) word16;
	}
	while (sum>>16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	sum = ~sum;
	
	checksum = (uint16_t) sum;
	return checksum;
}

/* IPpacketForMe takes in the current packet fetched by pcap, and a pointer to a header structure.
 * IPpacketForMe returns 1 if the current packet is indeed a TCP packet intended for 
 * this host with the correct port.
 * 0 is returned otherwise. 
 */
int IPpacketForMe(const u_char *packet_data, struct header *host) {
	if (
		(
		memcmp(packet_data /* dstMAC */, host->ethernet_head.source, 6) ||
		memcmp(packet_data + 12 /* type */, &host->ethernet_head.type /* IP */, 2) ||
		memcmp(packet_data + 23 /* protocol */, &host->IP_head.protocol /* TCP */, 1) ||
		memcmp(packet_data + 30 /* dstIP */, host->IP_head.source, 4) ||
		memcmp(packet_data + 36 /* dstPort */, &host->TCP_head.src_port, 2)
		) == 0
	) {
	return 1;
	}
	else
	return 0;
}

/* TCPconnect performs a 3 way handshake in order to connect this host with another host via TCP.
 * TCPconnect takes in a pointer to the character array: packet, a pointer to this host's header structure, and the current pcap_handle.
 * TCPconnect returns 0 on success, or -1 on error.
 */
int TCPconnect(u_char *packet, struct header *host, pcap_t *pcap_handle) {
	int SYN_recv_flag = 0; /* Flags to indicate SYN and ACK received */
	int ACK_recv_flag = 0; /* Flags... */
	int captured_packets = 0; /* Integer to count packets captured */
	int ret = 0; /* Used to check return values */

	struct pcap_pkthdr *packet_hdr = NULL;  /* Packet header from PCAP */
	const u_char *packet_data = NULL;       /* Packet data from PCAP */

	/* Initiate 3 - way SYN handshake */
	while((SYN_recv_flag && ACK_recv_flag) == 0) {
	/* If no SYN, ACK received within 500 captured packets, then assume outgoing SYN was dropped and retransmit */
	captured_packets = 0;

	/* Send SYN packet */
	
	/* Set SYN flag */
	host -> TCP_head.flags = setFlags(0, 1, 0);
	genTCPHeader(packet, host);	

	if (pcap_inject(pcap_handle, packet, PACKET_SIZE) == -1) {
		fprintf(stderr, "Error: pcap_inject\n");
		return -1;
	}

	/* SYN SENT state */
	
	/* Fetch next packet */	
	ret = pcap_next_ex(pcap_handle, &packet_hdr, &packet_data);
	while((captured_packets < 500) && ((SYN_recv_flag && ACK_recv_flag) == 0)) {	
		/* Continue to fetch packets until SYN, ACK is received */

		/* Check for errors in the fetched packet */

		/* An error occurred */
		if( ret == -1 ) {
			pcap_perror(pcap_handle, "Error processing packet:");
			pcap_close(pcap_handle);
			return -1;
		}
		/* Unexpected return values; other values shouldn't happen when reading trace files */
		else if( ret != 1 ) {
			fprintf(stderr, "Unexpected return value (%i) from pcap_next_ex()\n", ret);
			pcap_close(pcap_handle);
			return -1;
		}
		/* Check if packet is intended for me */
		if (IPpacketForMe(packet_data, host) == 1) {
			/* packet is for me */

			/* Check for ACK flag */
			if ((packet_data[47] & ACK_MASK) == ACK_MASK) {
				ACK_recv_flag = 1;

				/* Add one to sender's SEQ number because sender's SYN packet was acknowledged by destination */
				host -> TCP_head.seq_num = htonl(ntohl(host->TCP_head.seq_num) + 1);
			}
			/* Check for SYN flag */
			if ((packet_data[47] & SYN_MASK) == SYN_MASK) {
				SYN_recv_flag = 1;

				/* Set source ACK number equal to destination SEQ number */
				memcpy(&host->TCP_head.ack_num, packet_data + 38, 4);

				/* Add one to source ACK number to acknowledge SYN packet was received */
				host->TCP_head.ack_num = htonl(ntohl(host->TCP_head.ack_num) + 1);
				
			}
		}
		/* Fetch the next packet */
		ret = pcap_next_ex(pcap_handle, &packet_hdr, &packet_data);
		captured_packets ++;
	}
	}

	/* Send ACK packet */
	
	host->TCP_head.flags = setFlags(1, 0, 0); 
	genTCPHeader(packet, host);

	if (pcap_inject(pcap_handle, packet, PACKET_SIZE) == -1) {
		fprintf(stderr, "Error: pcap_inject\n");
		return -1;
	}
	return 0;
}


/* TCPteardown performs a 3 way handshake in order to close the current connection.
 * TCPteardown takes in a pointer to the character array: packet, a pointer to this host's header structure, and the current pcap_handle.
 * TCPteardown returns 0 on success, or -1 on error.
 */
int TCPteardown(u_char *packet, struct header *host, pcap_t *pcap_handle) {
	int FIN_recv_flag = 0;
	int ACK_recv_flag = 0;
	int captured_packets = 0;
	int ret = 0;
	uint32_t destination_ack_num = 0;

	struct pcap_pkthdr *packet_hdr = NULL;  /* Packet header from PCAP */
	const u_char *packet_data = NULL;       /* Packet data from PCAP */
	/* Initiate 3 - way FIN handshake */
	
	/* Set FIN, ACK  flags */
	host->TCP_head.flags = setFlags(1, 0, 1);
	genTCPHeader(packet, host);
	
	while((FIN_recv_flag && ACK_recv_flag) == 0) {
	/* Retransmit source FIN, ACK packet if destination's FIN, ACK is not received within 500 captured packets */
	captured_packets = 0;

	/* Send FIN,ACK packet */
	if (pcap_inject(pcap_handle, packet, PACKET_SIZE) == -1) {
		fprintf(stderr, "Error: pcap_inject\n");
		return -1;
	}

	/* FIN WAIT - 1 state */
	
	/* Fetch next packet */	
	ret = pcap_next_ex(pcap_handle, &packet_hdr, &packet_data);
	while((captured_packets < 500) && ((FIN_recv_flag && ACK_recv_flag) == 0)) {
		/* Continue to fetch packets until FIN, ACK is received */

		/* Check for errors in the fetched packet */

		/* An error occurred */
		if( ret == -1 ) {
			pcap_perror(pcap_handle, "Error processing packet:");
			pcap_close(pcap_handle);
			return -1;
		}
		/* Unexpected return values; other values shouldn't happen when reading trace files */
		else if( ret != 1 ) {
			fprintf(stderr, "Unexpected return value (%i) from pcap_next_ex()\n", ret);
			pcap_close(pcap_handle);
			return -1;
		}
		/* Check if packet is intended for me */
		if (IPpacketForMe(packet_data, host) == 1) {
			/* packet is for me */

			/* Check for FIN and ACK flags */
			
			/* Check for ACK flag */
			if ((packet_data[47] & ACK_MASK) == ACK_MASK) {
				/* rcv ACK of FIN */

				/* FIN WAIT -2 state */
				ACK_recv_flag = 1;

				/* Increment this host's SEQ num if other host's */
				/* ACK num - 1 == SEQ num */

				memcpy(&destination_ack_num, packet_data + 42, 4);

				if (ntohl(host->TCP_head.seq_num) == (ntohl(destination_ack_num) - 1)) {
		
					/* Add one to client SEQ number because server has acknowledged the client's FIN packet */
					host->TCP_head.seq_num = htonl(ntohl(host->TCP_head.seq_num) + 1);
				}
			}
			/* Check for FIN flag */
			if ((packet_data[47] & FIN_MASK) == FIN_MASK) {	
				/* rcv FIN */
				/* TIME WAIT state */
				FIN_recv_flag = 1;
	
				/* Add one to client's ACK number to acknowlege the server's FIN packet */
				host->TCP_head.ack_num = htonl(ntohl(host->TCP_head.ack_num) + 1);
			}
		}

		/* Fetch the next packet */
		ret = pcap_next_ex(pcap_handle, &packet_hdr, &packet_data);
		captured_packets ++;
	}
	}

	/* Send ACK packet */
	
	host->TCP_head.flags = setFlags(1, 0, 0);
	genTCPHeader(packet, host);
	if (pcap_inject(pcap_handle, packet, PACKET_SIZE) == -1) {
		fprintf(stderr, "Error: pcap_inject\n");
		return -1;
	}
	return 0;
}
