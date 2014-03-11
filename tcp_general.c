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
#include <string.h>

#include "tcp_general.h"

/* getMyAddresses looks up this host's MAC and IPv4 addresses.
 * These addresses are stored in the MAC and IPv4 buffers given as arguments.
 * getMyAddresses assumes the device used is eth0.
 * Returns 0 on success.
 * Returns -1 on error.
 */
int getMyAddresses(u_char *myMAC, u_char *myIPv4) {
  struct ifaddrs *ifaddr, *ifa;
  char IPv4[NI_MAXSERV];

  memset(myMAC, 0, ETH_ALEN);
  memset(myIPv4, 0, IP_ALEN);

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
    memcpy(myMAC, ((struct sockaddr_ll*)ifa->ifa_addr) -> sll_addr, ETH_ALEN);
  }

  if (ifa -> ifa_addr ->sa_family == AF_INET
    && !(strcmp(ifa -> ifa_name, "eth0"))) {
    // store my IPv4 address
    if (getnameinfo(ifa -> ifa_addr, sizeof(struct sockaddr_in), IPv4, NI_MAXSERV,
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

	host->ethernet_head.type = htons(ETHERTYPE_IP);
	
	/* Begin Ethernet Frame */	
	memcpy(packet, host->ethernet_head.destination, ETH_ALEN);
	memcpy(packet + ETH_ALEN, host->ethernet_head.source, ETH_ALEN);
	memcpy(packet + ETH_TYPE_OFFSET, &host->ethernet_head.type, ETHERTYPE_SIZE);
	/* End Ethernet Frame */

	/* set, total_length, flags, source, destination before calling this function */
	host -> IP_head.version_IHL = (((u_char) IP_VERSION) << 4) | IP_MIN_IHL;
	host->IP_head.ToS = IP_TOS_ROUTINE;
	host->IP_head.identification = htons(IP_ID);
	// host->IP_head.flags = 0x40;
	host->IP_head.frag_offset = IP_FRAGMENT_OFFSET;
	host->IP_head.TTL = IP_TTL_DEFAULT;
	host->IP_head.protocol = IP_PROTOCOL_TCP;
	host->IP_head.checksum = htons(IP_ZERO_CHECKSUM);
	
	/* Begin IP Frame */
	memcpy(packet + ETH_HDR_SIZE,		 &host->IP_head.version_IHL, 		sizeof(host->IP_head.version_IHL));
	memcpy(packet + IP_TOS_OFFSET,		 &host->IP_head.ToS, 			sizeof(host->IP_head.ToS));
	memcpy(packet + IP_TOTAL_LEN_OFFSET,	 &host->IP_head.total_length, 		sizeof(host->IP_head.total_length));
	memcpy(packet + IP_ID_OFFSET,		 &host->IP_head.identification, 	sizeof(host->IP_head.identification));
	memcpy(packet + IP_FLAGS_OFFSET,	 &host->IP_head.flags, 			sizeof(host->IP_head.flags));
	memcpy(packet + IP_FRAGOFF_OFFSET,	 &host->IP_head.frag_offset, 		sizeof(host->IP_head.frag_offset));
	memcpy(packet + IP_TTL_OFFSET,		 &host->IP_head.TTL, 			sizeof(host->IP_head.TTL));
	memcpy(packet + IP_PROTOCOL_OFFSET,	 &host->IP_head.protocol, 		sizeof(host->IP_head.protocol));
	memcpy(packet + IP_CHECKSUM_OFFSET,	 &host->IP_head.checksum, 		sizeof(host->IP_head.checksum));
	memcpy(packet + IP_SOURCE_OFFSET,	 host->IP_head.source, 			sizeof(host->IP_head.source));
	memcpy(packet + IP_DESTINATION_OFFSET,	 host->IP_head.destination, 		sizeof(host->IP_head.destination));

	host->IP_head.checksum = htons(calculateChecksum(packet + ETH_HDR_SIZE, IP_HDR_SIZE));

	memcpy(packet + IP_CHECKSUM_OFFSET,	 &host->IP_head.checksum, 		sizeof(host->IP_head.checksum));
	/* End IP Frame */
}

/* genTCPHeader takes in a pointer to a header structure.
 * genTCPHeader builds a TCP header using the structure's data and places the header on the character array: packet.
 * genTCPHeader assumes no data follows the TCP header.
 * 'packet' should already have an Ethernet frame and IPv4 header occupying the first 34 bytes
 * so the 20 byte TCP header will be placed after the IPv4 header resulting in a total header length of 54 bytes.
 */
void genTCPHeader(u_char *packet, struct header *host) {
	/* Set TCP length(for pseudoheader), source port, destination port, sequence number, ack number, and flags before calling this function */

	genIPv4Header(packet, host);
	genPseudoHeader(host);

	host->TCP_head.data_offset = TCP_DATA_OFFSET;
	host->TCP_head.window = htons(TCP_WINDOW);
	host->TCP_head.checksum = htons(TCP_ZERO_CHECKSUM);
	host->TCP_head.urgent_pointer = htons(TCP_URGENT_POINTER);

	memcpy(packet + TCP_SRC_PORT_OFFSET,	 &host->TCP_head.src_port,		sizeof(host->TCP_head.src_port));
	memcpy(packet + TCP_DST_PORT_OFFSET,	 &host->TCP_head.dst_port,		sizeof(host->TCP_head.dst_port));
	memcpy(packet + TCP_SEQ_OFFSET,		 &host->TCP_head.seq_num,		sizeof(host->TCP_head.seq_num));
	memcpy(packet + TCP_ACK_OFFSET,		 &host->TCP_head.ack_num,		sizeof(host->TCP_head.ack_num));
	memcpy(packet + TCP_DATA_OFFSET_OFFSET,	 &host->TCP_head.data_offset,		sizeof(host->TCP_head.data_offset));
	memcpy(packet + TCP_FLAGS_OFFSET,	 &host->TCP_head.flags,			sizeof(host->TCP_head.flags));
	memcpy(packet + TCP_WINDOW_OFFSET,	 &host->TCP_head.window,		sizeof(host->TCP_head.window));
	memcpy(packet + TCP_CHECKSUM_OFFSET,	 &host->TCP_head.checksum,		sizeof(host->TCP_head.checksum));
	memcpy(packet + TCP_URGENT_P_OFFSET,	 &host->TCP_head.urgent_pointer,	sizeof(host->TCP_head.urgent_pointer));

	int odd_octets = 0;	/* flag to be set if number of octets in TCP header and text is odd */
	if (host->TCP_head.TCP_length % 2 == 1) { /* Odd number of octets in TCP header and text */
		odd_octets = 1;
		host->TCP_head.TCP_length += 1;
	}

	u_char preChecksumHeader[TCP_PSEUDOHEADER_SIZE + host->TCP_head.TCP_length];
	if (odd_octets == 1) { /* add zero padding to the last octet for proper checksum calculation in the case of odd octets */
		printf("odd octets");
		preChecksumHeader[TCP_PSEUDOHEADER_SIZE + host->TCP_head.TCP_length - 1] = 0x00;
	}

	memcpy(preChecksumHeader, 				&host->TCP_head.pseudoheader, 		TCP_PSEUDOHEADER_SIZE);

	memcpy(preChecksumHeader + TCP_PSEUDOHEADER_SIZE, 	packet + TCP_HDR_OFFSET, 		host->TCP_head.TCP_length);

	host->TCP_head.checksum = htons(calculateChecksum(preChecksumHeader, TCP_PSEUDOHEADER_SIZE + host->TCP_head.TCP_length));

	memcpy(packet + TCP_CHECKSUM_OFFSET,	 &host->TCP_head.checksum, 		sizeof(host->TCP_head.checksum));
	
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
		flag = flag | ACK_MASK;
	}
	if (SYN) {
		flag = flag | SYN_MASK;
	}
	if (FIN) {
		flag = flag | FIN_MASK;
	}
	return flag;
}

/* genPseudoHeader takes in a pointer to a header structure.
 * genPseudoHeader makes a Pseudo Header and places it in the character array: pseudoheader.
 * Note: the Pseudo Header is used to generate the TCP checksum.
 */
void genPseudoHeader(struct header *host) {

	host -> TCP_head.TCP_length = htons(host->TCP_head.TCP_length);

	memcpy(host->TCP_head.pseudoheader,				 host->IP_head.source,		 IP_ALEN);
	memcpy(host->TCP_head.pseudoheader + PSEUDO_IP_DST_OFFSET,	 host->IP_head.destination,	 IP_ALEN);
	host->TCP_head.pseudoheader[PSEUDO_ZERO_OFFSET] = 0x00;
	memcpy(host->TCP_head.pseudoheader + PSEUDO_PTCL_OFFSET,	 &host->IP_head.protocol,	 sizeof(host->IP_head.protocol));
	memcpy(host->TCP_head.pseudoheader + PSEUDO_TCP_LEN_OFFSET,	 &host->TCP_head.TCP_length,	 sizeof(host->TCP_head.TCP_length));

	host -> TCP_head.TCP_length = ntohs(host->TCP_head.TCP_length);

	//printf("TCP length: %x\n", host->TCP_head.TCP_length);

	/* OK for now */
/*
	host->TCP_head.pseudoheader[PSEUDO_TCP_LEN_OFFSET] = 0x00;
	host->TCP_head.pseudoheader[11] = 0x14;
*/
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
		memcmp(packet_data /* dstMAC */, 			host->ethernet_head.source, 		ETH_ALEN) 				||
		memcmp(packet_data + ETH_TYPE_OFFSET /* type */, 	&host->ethernet_head.type /* IP */, 	sizeof(host->ethernet_head.type)) 	||
		memcmp(packet_data + IP_PROTOCOL_OFFSET /* protocol */, &host->IP_head.protocol /* TCP */, 	sizeof(host->IP_head.protocol)) 	||
		memcmp(packet_data + IP_DESTINATION_OFFSET /* dstIP */, host->IP_head.source, 			IP_ALEN) 				||
		memcmp(packet_data + TCP_DST_PORT_OFFSET /* dstPort */, &host->TCP_head.src_port, 		sizeof(host->TCP_head.src_port))
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
	uint32_t destination_ack_num = 0;
	uint32_t destination_seq_num = 0;

	struct pcap_pkthdr *packet_hdr = NULL;  /* Packet header from PCAP */
	const u_char *packet_data = NULL;       /* Packet data from PCAP */

	host -> IP_head.total_length = htons(IP_HDR_SIZE + TCP_HDR_SIZE);
	host -> TCP_head.TCP_length = TCP_HDR_SIZE;

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
			memcpy(&destination_seq_num, packet_data + TCP_SEQ_OFFSET, LONG_SIZE);
			memcpy(&destination_ack_num, packet_data + TCP_ACK_OFFSET, LONG_SIZE);

			/* Check for ACK flag */
			if ((packet_data[TCP_FLAGS_OFFSET] & ACK_MASK) == ACK_MASK) {
				ACK_recv_flag = 1;

				/* Add one to sender's SEQ number because sender's SYN packet was acknowledged by destination */
				host -> TCP_head.seq_num = htonl(ntohl(host->TCP_head.seq_num) + 1);
			}

			/* Check for SYN flag */
			if ((packet_data[47] & SYN_MASK) == SYN_MASK
				&& ntohl(host->TCP_head.seq_num) == (ntohl(destination_ack_num))
				) {
				SYN_recv_flag = 1;

				/* Set source ACK number equal to destination SEQ number */
				memcpy(&host->TCP_head.ack_num, packet_data + TCP_SEQ_OFFSET, 4);

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
	uint32_t destination_seq_num = 0;

	struct pcap_pkthdr *packet_hdr = NULL;  /* Packet header from PCAP */
	const u_char *packet_data = NULL;       /* Packet data from PCAP */

/* Move this code to after HTTP GET request */
/*
	host -> IP_head.total_length = htons(IP_HDR_SIZE + TCP_HDR_SIZE);
	host -> TCP_head.TCP_length = TCP_HDR_SIZE;
	
	// Initiate 3 - way FIN handshake 
	
	// Set FIN, ACK  flags 
	host->TCP_head.flags = setFlags(1, 0, 1);
	genTCPHeader(packet, host);
*/
	
	while((FIN_recv_flag && ACK_recv_flag) == 0) {
	/* Retransmit source FIN, ACK packet if destination's FIN, ACK is not received within 500 captured packets */
	captured_packets = 0;

	/* Send FIN,ACK packet */
	/* move this code to after HTTP GET request */
/*
	if (pcap_inject(pcap_handle, packet, PACKET_SIZE) == -1) {
		fprintf(stderr, "Error: pcap_inject\n");
		return -1;
	}
*/
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
			memcpy(&destination_seq_num, packet_data + TCP_SEQ_OFFSET, LONG_SIZE);

			/* Check for FIN and ACK flags */
			
			/* Check for ACK flag */
			/* Ensure this host's ACK num is equal to other host's SEQ num (prevent duplicates) */
			if ((packet_data[TCP_FLAGS_OFFSET] & ACK_MASK) == ACK_MASK
				&& ntohl(host->TCP_head.ack_num) == (ntohl(destination_seq_num))
			) {
				/* rcv ACK of FIN */

				/* FIN WAIT -2 state */
				ACK_recv_flag = 1;

				/* Increment this host's SEQ num if other host's */
				/* ACK num - 1 == SEQ num */

				memcpy(&destination_ack_num, packet_data + TCP_ACK_OFFSET, LONG_SIZE);

				if (ntohl(host->TCP_head.seq_num) == (ntohl(destination_ack_num) - 1)) {
		
					/* Add one to client SEQ number because server has acknowledged the client's FIN packet */
					host->TCP_head.seq_num = htonl(ntohl(host->TCP_head.seq_num) + 1);
				}
			}
			/* Check for FIN flag */
			if ((packet_data[TCP_FLAGS_OFFSET] & FIN_MASK) == FIN_MASK) {	
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

int HTTPgetRequest(struct header *host, pcap_t *pcap_handle, char *hostname) {

	host -> IP_head.total_length = htons(IP_HDR_SIZE + TCP_HDR_SIZE + strlen(hostname) + strlen("GET / HTTP/1.1\r\nHost: \r\n\r\n"));
	host -> TCP_head.TCP_length = ntohs(host->IP_head.total_length) - IP_HDR_SIZE;

	u_char packet[ETH_HDR_SIZE + IP_HDR_SIZE + host -> TCP_head.TCP_length];
	u_char HTTP_data[host->TCP_head.TCP_length - TCP_HDR_SIZE];

	strcpy((char *) HTTP_data, "GET / HTTP/1.1\r\nHost: ");
	strcpy((char *) HTTP_data + HTTP_HOST_OFFSET, hostname);
	strcpy((char *) HTTP_data + HTTP_HOST_OFFSET + strlen(hostname), "\r\n\r\n");

	memcpy(packet + ETH_HDR_SIZE + IP_HDR_SIZE + TCP_HDR_SIZE, HTTP_data, host->TCP_head.TCP_length - TCP_HDR_SIZE);

	host->TCP_head.flags = setFlags(1, 0, 0);
	genTCPHeader(packet, host);

	if (pcap_inject(pcap_handle, packet, ETH_HDR_SIZE + IP_HDR_SIZE + host -> TCP_head.TCP_length) == -1) {
		fprintf(stderr, "Error: pcap_inject\n");
		return -1;
	}

	host -> IP_head.total_length = htons(IP_HDR_SIZE + TCP_HDR_SIZE);
	host -> TCP_head.TCP_length = TCP_HDR_SIZE;
	
	/* Initiate 3 - way FIN handshake */
	
	/* Set FIN, ACK  flags */
	host->TCP_head.flags = setFlags(1, 0, 1);
	genTCPHeader(packet, host);

	/* Send FIN,ACK packet */
	if (pcap_inject(pcap_handle, packet, PACKET_SIZE) == -1) {
		fprintf(stderr, "Error: pcap_inject\n");
		return -1;
	}

	return 0;
}

int processHTTP(struct header *host, pcap_t *pcap_handle) {
	int FIN_recv_flag = 0;
	int recv_next_pkt_flag = 0;
	uint32_t destination_ack_num = 0;
	uint32_t destination_seq_num = 0;
	int ret = 0;

	struct pcap_pkthdr *packet_hdr = NULL;  /* Packet header from PCAP */
	const u_char *packet_data = NULL;       /* Packet data from PCAP */

	while (FIN_recv_flag == 0) {
	
		/* Re-transmit last packet or send next packet */	
		if (pcap_inject(pcap_handle, packet, PACKET_SIZE) == -1) {
			fprintf(stderr, "Error: pcap_inject\n");
			return -1;
		}
		

		/* Fetch next packet */	
		ret = pcap_next_ex(pcap_handle, &packet_hdr, &packet_data);
		
		while (captured_packets < 500 && recv_next_pkt_flag == 0) {

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

				memcpy(&destination_seq_num, packet_data + TCP_SEQ_OFFSET, LONG_SIZE);

				if (host->TCP_head.ack_num == destination_seq_num) {

					recv_next_pkt_flag = 1;

					//host->TCP_head.ack_num += /* their data length */
					/* packet is for me and my ACK num is equal to their SEQ num */
					/* process the packet */
					/* print data to file */
					/* print info to terminal */
					/* increment my ACK num by their bytes of data */
				}
			}
		
		/* Fetch next packet */	
		ret = pcap_next_ex(pcap_handle, &packet_hdr, &packet_data);
		}
	}

	return 0;
}
