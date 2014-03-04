// Chad Cahill
// EECE 598, California State University - Chico
// Spring 2014

#include <pcap/pcap.h> // pcap_inject() etc...
#include <arpa/inet.h> // inet_ntop() etc...
#include <netinet/ether.h> // ether_ntoa() etc...
#include <string.h> // for memcpy() etc...

#include "tcp_general.h"

#define PACKET_SIZE 54 /* Ethernet frame (14B) + IP Header (20B) + TCP Header (20B) = 54B */

int main(int argc, char *argv[]) {
	struct header client; /* Declare structure to store client header */
	char pcap_buff[PCAP_ERRBUF_SIZE]; /* Error buffer used by pcap functions */
	pcap_t *pcap_handle = NULL; /* Handle for PCAP library */
	char *dev_name = NULL; /* Device name for live capture */
	struct ether_addr *ea;
	u_char packet[PACKET_SIZE]; /* buffer to store packet to be sent onto network */

	/* Check command line arguments */
	/* Set command line arguments as destination IP and MAC addresses. */
	if(argc == 3) {
		if ((inet_pton(AF_INET, argv[1], client.IP_head.destination)) != 1) {
			fprintf(stderr, "Error: check server IP address\n");
			return -1;
		}
		if ((ea = ether_aton(argv[2])) == NULL) {
			fprintf(stderr, "Error: check server MAC address\n");
			return -1;
		}
		memcpy(client.ethernet_head.destination, ea, 6);
	}
	else if(argc != 3){
		fprintf(stderr, "Error: check command line arguments\n");
	}

	/* Lookup this hosts's MAC and IP addresses */
	/* Set them appropriately in the client's header */	
	if (getMyAddresses(client.ethernet_head.source, client.IP_head.source) == -1) {
		fprintf(stderr, "Error: getMyAddresses\n");
	}
	
	/* Generate the IP header and place it in the character array packet for later use */
	genIPv4Header(packet, &client);

	/* Generate the PseudoHeader (for use with TCP checksum calculation later) */
	genPseudoHeader(&client);

	/* Lookup and open the default device */
	dev_name = pcap_lookupdev(pcap_buff);
	if( dev_name == NULL ){
		fprintf(stderr, "Error finding default capture device: %s\n", pcap_buff);
		return -1;
	}
	pcap_handle = pcap_open_live(dev_name, BUFSIZ, 1, 0, pcap_buff);
	if( pcap_handle == NULL ){
		fprintf(stderr, "Error opening capture device %s: %s\n", dev_name, pcap_buff);
		return -1;
	}

	/* LISTEN state */

	/* Generate (semi - random) client port number */
	client.TCP_head.src_port = htons(generatePort(1024, 4999));

	/* Set destination port */	
	client.TCP_head.dst_port = htons(80); // use port 80 for web applications

	/* Generate (random) initial client SEQ number */
	client.TCP_head.seq_num = htonl(generateISN());

	/* Establish a TCP connection with 3 way handshake */
	if (TCPconnect(packet, &client, pcap_handle) == -1) {
		fprintf(stderr, "Error: TCPconnect()\n");
		return -1;
	}
		
	/* ESTABLISHED state */
	
	/* Close the TCP connection with 3 way handshake */
	if (TCPteardown(packet, &client, pcap_handle) == -1) {
		fprintf(stderr, "Error: TCPconnect()\n");
		return -1;
	}
	
	/* Close the device */
	pcap_close(pcap_handle);

	/* Exit Program */
	return 0;
}
