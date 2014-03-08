// Chad Cahill
// EECE 598, California State University - Chico
// Spring 2014

#ifndef _TCP_GENERAL_H_INCLUDED
#define _TCP_GENERAL_H_INCLUDED

#define PACKET_SIZE 54

#define	ETHERTYPE_IP		0x0800		/* IP */

#define ETH_ALEN		6		/* Octets in one ethernet addr	 */
#define ETHERTYPE_SIZE		2		/* Octets in ethernet type field */
#define ETH_HDR_SIZE		14		/* Octets in ethernet header */

#define IP_VERSION		4		/* IP version 4 */
#define IP_MIN_IHL		5		/* Minimum Internet Header Length */
#define IP_TOS_ROUTINE		0x00		/* Routine Type of Service */
#define IP_ID			0x0000		/* No Identification necessary */
#define IP_FRAGMENT_OFFSET	0x00
#define IP_TTL_DEFAULT		0x40		/* Default Time To Live */
#define IP_PROTOCOL_TCP		0x06		/* Protocol over IP is TCP */
#define IP_ZERO_CHECKSUM	0x0000		/* Checksum is zero before calculation */

#define IP_HDR_SIZE		20		/* Octets in IP header */

#define IP_TOS_OFFSET		15		/* Octets before IP TOS field */
#define IP_TOTAL_LEN_OFFSET	16		/* Octets before IP Total Length field */
#define IP_ID_OFFSET		18		/* Octets before IP Identification field */
#define IP_FLAGS_OFFSET		20		/* Octets before IP Flags field */
#define IP_FRAGOFF_OFFSET	21	/* Octets before IP Fragment offset field */
#define IP_TTL_OFFSET		22		/* Octets before IP TTL field */
#define IP_PROTOCOL_OFFSET	23		/* Octets before IP Protocol field */
#define IP_CHECKSUM_OFFSET	24		/* Octets before IP Checksum field */
#define IP_SOURCE_OFFSET	26		/* Octets before IP Source field */
#define IP_DESTINATION_OFFSET	30		/* Octets before IP Destination field */

#define TCP_PORT_HTTP		80		/* Port 80 for HTTP */
#define TCP_DATA_OFFSET		5		/* TCP Data Offset with no options */
#define TCP_RESERVED		0		/* Must be zero */
#define SYN_MASK 		0x02 		/* SYN mask for TCP */
#define FIN_MASK 		0x01 		/* FIN mask for TCP */
#define ACK_MASK 		0x10 		/* ACK mask for TCP */
#define TCP_WINDOW		1500		/* TCP Window size */
#define TCP_ZERO_CHECKSUM	0x0000		/* Checksum zero before calculation */
#define TCP_URGENT_POINTER	0x0000		/* No urgent data */

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

int HTTPgetRequest(u_char *packet, struct header *host, pcap_t *pcap_handle, char *hostname);

#endif
