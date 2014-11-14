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
#include <sys/wait.h>
#include <signal.h>

#define BACKLOG 10	 // how many pending connections queue will hold


#define MAX_MESSAGE_LEN 1024
#define MAX_PACKET_LEN 1029	// 1Kb for message, and 5 bytes for header
#define GROUP_ID 15 

#define DEBUG 1	// Used for debugging 1 = ON, 0 = OFF


// Struct that will be used to send data to the Server
struct transmitted_packet
{
	unsigned short magic_num;
	unsigned char GID_client;
	unsigned short port_num;
} __attribute__((__packed__));

typedef struct transmitted_packet tx_packet;

// Struct that will be used to recieve unverified incoming packets.
struct incoming_unverified_packet
{
	unsigned short short_1;
	unsigned char char_2;
	unsigned char extra_char[6];
} __attribute__((__packed__));

typedef struct incoming_unverified_packet rx_verify;

// Struct that wil be used after the incoming packet has been verified.
// Indicates we need to wait for another client
struct incoming_verified_packet_wait
{
	unsigned short magic_num;
	unsigned char GID_server;
	unsigned short port_num;
} __attribute__((__packed__));

typedef struct incoming_verified_packet_wait rx_wait;

// Struct that wil be used after the incoming packet has been verified.
// Indicates we can pair with another client
struct incoming_verified_packet_pair
{
	unsigned short magic_num;
	unsigned char GID_server;
	unsigned int IP_addr;
	unsigned short port_num;
} __attribute__((__packed__));

typedef struct incoming_verified_packet_pair rx_pair;

// Struct that wil be used if we recieve an error
struct incoming_error_packet
{
	unsigned short magic_num;
	unsigned char GID_server;
	unsigned short error_code;
} __attribute__((__packed__));

typedef struct incoming_error_packet rx_error;

// Prototypes
unsigned short make_short(unsigned char, unsigned char);
unsigned int make_int(unsigned char, unsigned char, 
	unsigned char, unsigned char);
int create_and_run_TCP_server(tx_packet);

void sigchld_handler(int s)
{
	while(waitpid(-1, NULL, WNOHANG) > 0);
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


int main(int argc, char *argv[])
{
    
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	int numbytes_tx;
	int numbytes_rx;
	struct sockaddr_in their_addr;
	socklen_t addr_len;
	
	char *my_server;	// The host server name
	char *server_port;	// The port we will be using
	char *my_port;      // The port we are willing to play on
	
	// The packet we will send
	tx_packet packet_out;
	
	if (argc != 4) {
		fprintf(stderr,"Incorrect arguments. Refer to the README.\n");
		exit(1);
	}

	// Get the params from the command line
	my_server = argv[1];
	server_port = argv[2];
	my_port = argv[3];

	// Check to make sure the Port Number is in the correct range
	// atoi() - used to convert strings to int
   if (atoi(my_port) < (10010 + (GROUP_ID * 5))
         || atoi(my_port) > (10010 + (GROUP_ID * 5) + 4))
	{
        printf("Error: Port number was '%s' this is not in range of [",
               my_port);
        printf("%d, %d]\n", 10010 + GROUP_ID * 5,
               10010 + GROUP_ID * 5 + 4);
		exit(1);
	}

	if (DEBUG) {
		printf("----- Parameters -----\n");
		printf("Server: %s\n", my_server);
		printf("Server Port: %s\n", server_port);
		printf("My Port: %s\n", my_port);
	}

	// Get the Packet Ready to Send
	packet_out.magic_num = htons(0x1234);
	packet_out.GID_client = GROUP_ID;
	packet_out.port_num = htons((unsigned short) strtoul(my_port, NULL, 0));
	
	if (DEBUG) {
		printf("\n----- Packet Out -----\n");
		printf("packet_out.magic_num: %X\n", ntohs(packet_out.magic_num));
		printf("packet_out.GID_client: %d\n", packet_out.GID_client);
		printf("packet_out.port_num: %d\n", ntohs(packet_out.port_num));

	}
	
	memset(&hints, 0, sizeof hints);	// put 0's in all the mem space for hints (clearing hints)
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	if ((rv = getaddrinfo(my_server, server_port, &hints, &servinfo)) != 0) {
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

	// Send the data to the server
	if ((numbytes_tx = sendto(sockfd, (char *)&packet_out, sizeof(packet_out), 0, 
		p->ai_addr, p->ai_addrlen)) == -1) 
	{    
		perror("Error: sendto");
		exit(1);
    }

	if (DEBUG) {
		printf("Sent %d bytes to %s\n", numbytes_tx, argv[1]);
		printf("Waiting for responce...\n\n");
	}

	addr_len = sizeof their_addr;

	// Create the structs needed for receiving a packet	
	rx_verify rx_check;
	rx_pair rx_pair_info;
	
	if ((numbytes_rx = recvfrom(sockfd, (char *)&rx_check, MAX_PACKET_LEN, 0, 
		(struct sockaddr *)&their_addr, &addr_len)) == -1)
	{
		perror("recvfrom");
		exit(1);
	}

	if (DEBUG) {
		printf("Incoming Packet Size: %d\n", numbytes_rx);
	}

	// Check and see if the packet was an error.
	if (numbytes_rx == 5 && rx_check.extra_char[0] == 0x00)
	{
		// Check so see what error is was.
		char error_code = 0x00;
		error_code = rx_check.extra_char[1];

		// Incorrect Magic Number
		if (error_code == 0x01) 
		{
			printf("Error: The magic number in the sent request was incorrect.\n");
			printf("Error code: %X\n", error_code);
			exit(1);
		}

		// Incorrect Length 
		else if (error_code == 0x02) 
		{
			printf("Error: The packet length in the sent request was incorrect.\n");
			printf("Error code: %X\n", error_code);
			exit(1);
		}

		// Port not in correct range 
		else if (error_code == 0x04)
		{
			printf("Error: The port in the sent request was not in the correct range.\n");
			printf("Error code: %X\n", error_code);
			exit(1);
		}

		// Unknown error occured.
		else
		{
			printf("Error: An unknown error occured.\n");
			printf("Error code: %X\n", error_code);
			exit(1);
		}
	}

	// This is a wait packet
	else if (numbytes_rx == 5)
	{
		printf("Need to wait until another client wants to play. Creating TCP Server.\n");

		//TODO: Create a TCP Server with the sent port address. 
		create_and_run_TCP_server(packet_out);

	}

	// This is a pair packet
	else if (numbytes_rx == 9)
	{
		printf("The server has sent match making information.\n");

		rx_pair_info.magic_num = ntohs(rx_check.short_1);
		rx_pair_info.GID_server = rx_check.char_2;	

		int IP_in = make_int(rx_check.extra_char[0],
			rx_check.extra_char[1],
			rx_check.extra_char[2],
			rx_check.extra_char[3]);

		rx_pair_info.IP_addr = IP_in;
		rx_pair_info.port_num = make_short(rx_check.extra_char[4], rx_check.extra_char[5]);

		if (DEBUG) {
			printf("rx_pair_info.magic_num = %X\n", rx_pair_info.magic_num);
			printf("rx_pair_info.GID_server = %d\n", rx_pair_info.GID_server);
			printf("rx_pair_info.IP_addr = %X (", rx_pair_info.IP_addr);
         printf("%d.%d.%d.%d)\n",
				(int)(their_addr.sin_addr.s_addr & 0xFF),
				(int)((their_addr.sin_addr.s_addr & 0xFF00)>>8),
				(int)((their_addr.sin_addr.s_addr & 0xFF0000)>>16),
				(int)((their_addr.sin_addr.s_addr & 0xFF000000)>>24));
			printf("rx_pair_info.port_num = %d\n", rx_pair_info.port_num);
		}

		//TODO: Connect to a TCP server with the above information.
		connect_to_TCP_server(rx_pair_info);
	}

	else
	{
		//TODO: This should never happen
	}



/*

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

*/	
	freeaddrinfo(servinfo);
	close(sockfd);

	return 0;
}

// Support Functions

/*
* This function combines four bytes to get an int. 
*
*/
unsigned int make_int(unsigned char a, unsigned char b, 
	unsigned char c, unsigned char d) 
{
	unsigned int val = 0;
	val = a;
	val <<= 8;
	val |= b;
	
	val <<= 8;
	val |= c;

	val <<= 8;
	val |= d;	

	return val;
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


int create_and_run_TCP_server(tx_packet server_info)
{
	if (DEBUG){
		printf("Creating TCP Server...\n");
	}

	int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr; // connector's address information
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int rv;

	char my_port[5] = {0};      // The port we are willing to play on

	// Converts the short back to a char*
	sprintf(my_port, "%d", ntohs(server_info.port_num));

	if (DEBUG) {
		printf("my_port* = %s\n", my_port);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; // use my IP
	
	if ((rv = getaddrinfo(NULL, my_port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
							 p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}
		
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
					   sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}
		
		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}
		
		break;
	}
	
	if (p == NULL)  {
		fprintf(stderr, "server: failed to bind\n");
		return 2;
	}
	
	freeaddrinfo(servinfo); // all done with this structure
	
	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}

	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}
	
	printf("server: waiting for connections...\n");
	
	int run = 1;
	
	while(run == 1) {  // main accept() loop
		sin_size = sizeof their_addr;
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1) {
			perror("accept");
			continue;
		}
		
		inet_ntop(their_addr.ss_family,
				  get_in_addr((struct sockaddr *)&their_addr),
				  s, sizeof s);
		printf("server: got connection from %s\n", s);
		
		int numbytes;
		//char newBuf[1000];

		rx_pair newBuf;	
	
		if((numbytes = recv(new_fd, (char*)&newBuf, 1000 - 1, 0)) == -1)
		{
			perror("recv_error");
			exit(1);
		}
		
		printf("Message Recieved: %X\n", newBuf.magic_num);
		
		if (!fork()) { // this is the child process
			close(sockfd); // child doesn't need the listener
			if (send(new_fd, (char*)&newBuf, sizeof(newBuf), 0) == -1)
				perror("send");
			close(new_fd);
			exit(0);
		}
		
		close(new_fd);  // parent doesn't need this
		
		printf("Continue? 0=No, 1=Yes\n");
		scanf("%d", &run);
	}
	
	return 0;
    
    
}

int connect_to_TCP_server(rx_pair server_info_in)
{
	int sockfd, numbytes;
	char buf[MAX_PACKET_LEN];
	struct addrinfo hints, *servinfo, *p;
	int status;
	char s[INET6_ADDRSTRLEN];
	
	// Command Line arguments will fill these out
	char* hostname;
	char port[5] = {0};      // The port we are willing to play on
	
	// Converts the short back to a char*
	sprintf(port, "%d", server_info_in.port_num);

	// Converts the hex IP address into a char* using dotted notation
	struct in_addr addr;
	addr.s_addr = htonl(server_info_in.IP_addr); 
	hostname = inet_ntoa(addr);
	
	if (DEBUG) {
		printf("hostname: %s\n", hostname);
		printf("port: %s\n", port);
	}
	
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	
	if ((status = getaddrinfo(hostname, port, &hints, &servinfo)) != 0)
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		return 1;
	}
	
	// Loop through all the results and connect to the first we can
	for (p = servinfo; p != NULL; p = p->ai_next)
	{
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
		{
			perror("Socket error");
			continue;
		}
		
		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("Connect error");
			continue;
		}
		
		break;
	}
	
	if (p == NULL)
	{
		fprintf(stderr, "Failed to connect!\n");
		return 2;
	}
	
	if (DEBUG) {
		inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);
		
		printf("Connected to: %s\n", s);
	}

	freeaddrinfo(servinfo); 	// All done with this structure

	if (send(sockfd, (char *)&server_info_in, sizeof(server_info_in), 0) == -1)
	{
		perror("Send Error");
	}
	
	int numbytes_rec;
	rx_pair test;	
	
	if ((numbytes_rec = recv(sockfd,
		(char *)&test, MAX_PACKET_LEN, 0)) == -1)
	{
		perror("recv error");
		exit(1);
	}
		
	printf("test.magic_num: %X\n", test.magic_num);
	
	close(sockfd);
	
	return 0;

}

































