/*	
*	Comp4320: Lab 3
*
*	File: Client.c	
*	Author: Andrew K. Marshall (akm0012)
*	Group ID: 15
*	Date: 12/2/14
*	Version: 0.0
*	Version Notes: Testing 
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define GROUP_PORT "10025"    // Port should be 10010 + Group ID (15)
#define MAX_MESSAGE_LEN 1024
#define MAX_PACKET_LEN 1029	// 1Kb for message, and 5 bytes for header
#define GROUP_ID 15 

#define DEBUG 1	// Used for debugging 1 = ON, 0 = OFF


// Struct that will be used to send data to the Server
struct packet_to_send
{
	unsigned short short_1;
	unsigned char char_1;
	unsigned short short_2;
//	unsigned short error;
} __attribute__((__packed__));

typedef struct packet_to_send tx_packet;



int main(int argc, char *argv[])
{
    
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	int numbytes_tx;
	int numbytes_rx;
	struct sockaddr_storage their_addr;
	socklen_t addr_len;
	
	char *my_server;	// The host server name
	char *my_port;	// The port we will be using
	unsigned char request_ID;	// Request ID in range of 0 - 127
	int num_of_hostnames;
	char *hostname_list;
	int hostnames_total_len;
	char delimiter = '~';
	unsigned char checksum;
	int attempts = 0;
	
	// The packet we will send
	tx_packet packet_out;
	
	

	// Get the Packet Ready to Send
    packet_out.short_1 = htons(0x1234);
    packet_out.char_1 = 15;
    packet_out.short_2 = htons(10086);

	
	if (DEBUG) {
		printf("\n----- Packet Out -----\n");
		printf("packet_out.short_1: %X\n", ntohs(packet_out.short_1));
		printf("packet_out.char_1: %d\n", packet_out.char_1);
		printf("packet_out.short_2: %d\n", ntohs(packet_out.short_2));

	}
	
	memset(&hints, 0, sizeof hints);	// put 0's in all the mem space for hints (clearing hints)
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

    if ((rv = getaddrinfo(argv[1], argv[2], &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and make a socket
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
			p->ai_protocol)) == -1) 
		{
			perror("Error: socket");
			continue;
		}
		
		break;
	}

	if (p == NULL) {
		fprintf(stderr, "Error: failed to bind socket\n");
		return 2;
	}


	if ((numbytes_tx = sendto(sockfd, (char *)&packet_out, sizeof(packet_out), 0,
		p->ai_addr, p->ai_addrlen)) == -1) 
	{    
		perror("Error: sendto");
		exit(1);
    }

	if (DEBUG) {
		printf("Sent %d bytes to %s\n", numbytes_tx, argv[1]);
	}    

	if (DEBUG) {
		printf("Waiting for responce...\n\n");
	}

    
	addr_len = sizeof their_addr;

	// Create the struct used to check if the packet is valid	
	tx_packet rx_verify;
	
	if ((numbytes_rx = recvfrom(sockfd,(char *) &rx_verify, MAX_PACKET_LEN, 0, 
		(struct sockaddr *)&their_addr, &addr_len)) == -1)
	{
		perror("recvfrom");
		exit(1);
	}

	// DEBUG: Print the contents of the packet
	if (DEBUG) {
		printf("----- Received Packet -----\n");
		printf("Packet is %d bytes long.\n", numbytes_rx);
		printf("rx_verify.short_1: \t%d \t(%X)\n", ntohs(rx_verify.short_1), ntohs(rx_verify.short_1));
		printf("rx_verify.char_1: \t%d \t(%X)\n", rx_verify.char_1, rx_verify.char_1);
		printf("rx_verify.short_2: \t%d \t(%X)\n", ntohs(rx_verify.short_2), ntohs(rx_verify.short_2));
	}
/*
	// Check if we got an error packet from Server
	
	if (numbytes_rx == 5)
	{
		// Check the checksum of the packet
		if (calculate_checksum((unsigned char *)&rx_verify, numbytes_rx) != 0x00)
		{
			// Checksum Error
			printf("ERROR: Checksum: '0x%X' did not equal '0x00'\n", 
				calculate_checksum((unsigned char *)&rx_verify, numbytes_rx));
		}

		// Checking for Length Error
		else if (rx_verify.b2 == 127 && rx_verify.b3 == 127
			&& rx_verify.b4 == 0x00 && rx_verify.b5 == 0x00)
		{
			// Server sent error b/c of LENGTH
			printf("ERROR: Server is reporting a length mismatch.\n");
		}

		// WARNING: This assumes no group has an ID of 127
		// Checking for Checksum Error 
		else if (rx_verify.b2 != 127 && rx_verify.b4 == 0x00
			&& rx_verify.b5 == 0x00)
		{
			// Server sent error b/c of CHECKSUM
			printf("ERROR: Server is reporting a checksum error. \tGroup ID: %d \tRequest ID: %d\n",
				rx_verify.b2, rx_verify.b3);
		}

		attempts++;
		printf("Resending. Attempts: \t%d\n", attempts);
	}
	
	else if (numbytes_rx > 5)
	{
		// This is not an error packet, but still needs to be verified 
		
		// Check the checksum of the packet
		if (calculate_checksum((unsigned char *)&rx_verify, numbytes_rx) != 0x00)
		{
			// Checksum Error
			printf("ERROR: Checksum: '0x%X' did not equal '0x00'\n", 
				calculate_checksum((unsigned char *)&rx_verify, numbytes_rx));
		
			attempts++;
			printf("Resending. Attempts: \t%d\n", attempts);
		}

		// Check to make sure the length of the packet matches the num of bytes received 
		else if (numbytes_rx != make_short(rx_verify.b1, rx_verify.b2))
		{
			// Length Mismatch Error
			printf("ERROR: Length mismatch: Packet.TML: %d did not match bytes received: %d\n", 
				make_short(rx_verify.b1, rx_verify.b2), numbytes_rx);
		
			attempts++;
			printf("Resending. Attempts: \t%d\n", attempts);
		}

		else 
		{
			// Make attempts 10 so we don't try again.
			attempts = 10;
			
			// We have a valid packet
			rx_confirmed.length = make_short(rx_verify.b1, rx_verify.b2);
			rx_confirmed.checksum = rx_verify.b3;
			rx_confirmed.GID = rx_verify.b4;
			rx_confirmed.RID = rx_verify.b5;
			
			// Determine how many IP Address we have
			int IP_addresses_in;
			IP_addresses_in = (rx_confirmed.length - 5) / 4;

			// Get the 4 byte IP addresses
			int y;
			for (y = 0; y < IP_addresses_in ; y++)
			{
				rx_confirmed.payload[y] = rx_verify.extra[y];
			}

			if (DEBUG) {
				printf("rx_confirmed.length: \t%d \t(%X)\n", rx_confirmed.length, rx_confirmed.length);
				printf("rx_confirmed.checksum: \t%d \t(%X)\n", rx_confirmed.checksum, rx_confirmed.checksum);
				printf("rx_confirmed.GID: \t%d \t(%X)\n", rx_confirmed.GID, rx_confirmed.GID);
				printf("rx_confirmed.RID: \t%d \t(%X)\n", rx_confirmed.RID, rx_confirmed.RID);
				printf("rx_confirmed contains %d IP Addresses.\n", (rx_confirmed.length - 5) / 4);
			}
			
			// Get the 4 byte IP addresses
			for (y = 0; y < IP_addresses_in ; y++)
			{
				uint32_t ip = rx_confirmed.payload[y];
				struct in_addr ip_addr;
				ip_addr.s_addr = ip;
				// inet_ntoa takes care of the network byte order
				printf("%s: %s\n", host_storage[y],  inet_ntoa(ip_addr)); 
				
			}
			
		}

	} 

	else 
	{
		// This packet is too short for any valid respose
		printf("ERROR: Packet too short.\n"); 
		
		attempts++;
		printf("Resending. Attempts: \t%d\n", attempts);
	}

*/
	freeaddrinfo(servinfo);
	close(sockfd);

	return 0;
}
