// Chad Cahill
// EECE 598, California State University - Chico
// Spring 2014

#ifndef _TCP_GENERAL_H_INCLUDED
#define _TCP_GENERAL_H_INCLUDED

struct ethernet_header {
	u_char destination[6];
	u_char source[6];
	uint16_t type;
};
	
struct IP_header {
	u_char version_IHL;
	u_char ToS;		
	uint16_t total_length;
	uint16_t identification;
	u_char flags;
	u_char frag_offset;
	u_char TTL;
	u_char protocol;
	uint16_t checksum;
	u_char source[4];
	u_char destination[4];
	};

struct TCP_header {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
	u_char data_offset;
	u_char flags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent_pointer;
	u_char pseudoheader[12];
};

struct header {
	struct ethernet_header ethernet_head;
	struct IP_header IP_head;
	struct TCP_header TCP_head;
};

int getMyAddresses(u_char *myMAC, u_char *myIPv4);

void genIPv4Header(u_char *packet, struct header *host);

void genTCPHeader(u_char *packet, struct header *host);

uint16_t generatePort(int min, int max);

uint32_t generateISN();

u_char setFlags(int ACK, int SYN, int FIN);

void genPseudoHeader(struct header *host);

uint16_t calculateChecksum(u_char *header, int header_length);

int IPpacketForMe(const u_char *packet_data, struct header *host);

int TCPconnect(u_char *packet, struct header *host, pcap_t *pcap_handle);

int TCPteardown(u_char *packet, struct header *host, pcap_t *pcap_handle);

#endif
