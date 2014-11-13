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

#define DEBUG 0	// Used for debugging 1 = ON, 0 = OFF

// Prototypes
unsigned char calculate_checksum(unsigned char *, int); 
unsigned short make_short(unsigned char, unsigned char); 

// Struct that will be used to send data to the Server
struct dns_packet_to_send
{
	unsigned short TML;
	unsigned char checksum;
	unsigned char group_ID;
	unsigned char request_ID;
	char payload[MAX_MESSAGE_LEN];
} __attribute__((__packed__));

typedef struct dns_packet_to_send dns_packet;

// Struct that will be used to recieve unverified incoming packets.
struct incoming_unverified_packet
{
	unsigned char b1;
	unsigned char b2;
	unsigned char b3;
	unsigned char b4;
	unsigned char b5;
	unsigned int extra[MAX_MESSAGE_LEN];
} __attribute__((__packed__));

typedef struct incoming_unverified_packet rx_check;

// Struct that wil be used after the incoming packet has been verified.
struct incoming_verified_packet
{
	unsigned short length;
	unsigned char checksum;
	unsigned char GID;
	unsigned char RID;
	unsigned int payload[MAX_MESSAGE_LEN];
} __attribute__((__packed__));

typedef struct incoming_verified_packet rx_packet;

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
	dns_packet packet_out;
	
	if (argc < 5) {
		fprintf(stderr,"Too few arguments given. Refer to the README.\n");
		exit(1);
	}

	// Get the params from the command line
	my_server = argv[1];
	my_port = argv[2];
	request_ID = (unsigned char) atoi(argv[3]);

	// Check to make sure the Request ID is in the correct range
	if (request_ID < 0 || request_ID > 127) 
	{
		fprintf(stderr, "Request ID must be in range of: 0 - 127.\n");
		exit(1);
	}

	if (DEBUG) {
		printf("----- Parameters -----\n");
		printf("Server: %s\n", my_server);
		printf("Port: %s\n", my_port);
		printf("Request ID: %i\n", request_ID);
	}

	// Get the size of all the hostnames including space for '~'
	hostnames_total_len = 0;
	
	int y = 4;	// Start at the first index of arg[v] that has a host name
	for (y; y < argc; y++) 
	{
		hostnames_total_len++;	// Add 1 for the '~'
		hostnames_total_len = hostnames_total_len + strlen(argv[y]);
		
	}

	if (DEBUG) {
		printf("Total Length %i\n", hostnames_total_len);
	}

	// Create space for all the host names 
	hostname_list = (char *) malloc(hostnames_total_len);

	num_of_hostnames = argc - 4;

	// Here we create the array used to hold the Host names.
	char *host_storage[num_of_hostnames];
	

	if (DEBUG) {
		printf("Number of hostnames entered: %d\n", num_of_hostnames);
	}

	int i = 4;	// Start at the first index of arg[v] that has a host name
	for (i; i < argc; i++) 
	{
	
		if (DEBUG) {
			printf("Hostname %i: %s\n", i - 3, argv[i]);
		}
	
		// Add the host names to a list so we can reference them later
		host_storage[i - 4] = argv[i];

		if (DEBUG) {
			printf("host_storage[%d]: %s\n", i-4, argv[i]);
		}
	
		// Add the delimeter
		int p = strlen(hostname_list) - strlen(argv[i] - 1);
		hostname_list[p] = delimiter;
		
		// Add the host name
		strcat(hostname_list, argv[i]);

		if (DEBUG) {
			printf("Hostnames (combined): %s\n", hostname_list);
		}
	}

	if (DEBUG) {
		printf("sizeof Hostnames (combined): %i\n",(int) sizeof hostname_list);
		printf("strlen Hostnames (combined): %i\n", (int) strlen(hostname_list));
		printf("Total Number of host names: %i\n", num_of_hostnames);
	}

	// Get the Packet Ready to Send
	packet_out.group_ID = GROUP_ID;
	packet_out.request_ID = request_ID;
	strcpy(packet_out.payload, hostname_list);

	packet_out.TML = htons((sizeof packet_out.TML)
		+ (sizeof packet_out.checksum)
		+ (sizeof packet_out.group_ID)
		+ (sizeof packet_out.request_ID)
		+ (strlen(packet_out.payload)));
	
	// Clear the checksum
	packet_out.checksum = 0;	

	// Calculate the checksum
	checksum = calculate_checksum((unsigned char *)&packet_out, ntohs(packet_out.TML));
	
	// Set the checksum
	packet_out.checksum = checksum;	

	if (DEBUG) {
		printf("Checksum: %X\n", checksum);
	}

	if (DEBUG) {
		printf("\n----- Packet Out -----\n");
		printf("packet_out.TML: %d\n", ntohs(packet_out.TML));
		printf("packet_out.checksum: %X\n", packet_out.checksum);
		printf("packet_out.group_ID: %d\n", packet_out.group_ID);
		printf("packet_out.request_ID: %d\n", packet_out.request_ID);
		printf("packet_out.payload: %s\n", packet_out.payload);
		printf("strlen(packet_out.payload): %d\n\n", (int)strlen(packet_out.payload));

	}
	
	memset(&hints, 0, sizeof hints);	// put 0's in all the mem space for hints (clearing hints)
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	if ((rv = getaddrinfo(my_server, my_port, &hints, &servinfo)) != 0) {
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

// Attempt to send a packet, if we recieve an error we try again. Max Attempts = 7
do
{
	if ((numbytes_tx = sendto(sockfd, (char *)&packet_out, ntohs(packet_out.TML), 0, 
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
	rx_check rx_verify;
	
	// Create the struct used to store the valid packet
	rx_packet rx_confirmed;

	if ((numbytes_rx = recvfrom(sockfd,(char *) &rx_verify, MAX_PACKET_LEN, 0, 
		(struct sockaddr *)&their_addr, &addr_len)) == -1)
	{
		perror("recvfrom");
		exit(1);
	}

	// Add the null terminator
	rx_verify.extra[numbytes_rx - 5] = '\0'; // -5 to account for header

	// DEBUG: Print the contents of the packet
	if (DEBUG) {
		printf("----- Received Packet -----\n");
		printf("Packet is %d bytes long.\n", numbytes_rx);
		printf("rx_verify.b1: \t%d \t(%X)\n", rx_verify.b1, rx_verify.b1);
		printf("rx_verify.b2: \t%d \t(%X)\n", rx_verify.b2, rx_verify.b2);
		printf("rx_verify.b3: \t%d \t(%X)\n", rx_verify.b3, rx_verify.b3);
		printf("rx_verify.b4: \t%d \t(%X)\n", rx_verify.b4, rx_verify.b4);
		printf("rx_verify.b5: \t%d \t(%X)\n", rx_verify.b5, rx_verify.b5);
		printf("rx_verify.extra: \t%o\n\n", rx_verify.extra[0]);
	}

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

	
// End do-while loop
} while (attempts < 7);

	freeaddrinfo(servinfo);
	close(sockfd);

	return 0;
}

// Support Functions 
/*
* This function calculates the 1-complement checksum
*
*/
unsigned char calculate_checksum(unsigned char *data_in, int data_in_length) 
{

	int checksum = 0;
	int carry = 0;
	int i;

	for (i = 0; i < data_in_length; i++) 
	{
		if (0) {
			printf("Data[%d]: \t%X\n", i, (int)data_in[i]);
		}	
	
		checksum += (int) data_in[i];
		carry = checksum >> 8;
		checksum = checksum & 0xFF;
	
		if (0) {
			printf("Before - i:%i \tcarry: %X\t checksum: %X\n", i, carry, checksum);
		}		

		checksum = checksum + carry;
		
		if (0) {
			printf("After - i:%i \tcarry: %X\t checksum: %X\n", i, carry, checksum);
		}
	}

	if (0) {
		printf("Real Sum: %X\n", checksum);
	}

	checksum = ~checksum;

	if (0) {
		printf("Checksum: %X\n", checksum);
	}

	return (unsigned char) checksum;
}

/*
* This function combines two bytes to get a short. 
*
*/
unsigned short make_short(unsigned char a, unsigned char b) 
{
	unsigned short val = 0;
	val = a;
	val <<= 8;
	val |= b;
	return val;
}
