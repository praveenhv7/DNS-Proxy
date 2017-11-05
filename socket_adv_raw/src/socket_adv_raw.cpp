//============================================================================
// Name        : socket_adv_raw.cpp
// Author      : praveen
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <netinet/ip.h>
#include<netinet/if_ether.h>
#include<unistd.h>
#include<net/ethernet.h>
using namespace std;

char* convertToDNSFormat(char *name);
void createIPPacket(struct ip_packet *packet, unsigned int, char *dnsIpAddress);
void createUDPPacket(struct udp_packet *udpPacket, int hostnameLen);
void createDNSPacket(void *dnsPacket, char *);
void sendAndRecvTCPPackets();
void sendAndRecvDNSPackets(int identificationNum, int queryLen, char *,char *);
void parseUDPPacket(void *packet, int totalLength, int identificationNum, int,
		char *);
void parseDNSResponse(void *packet, int, char *, int);
void convertIpDecimalToString(unsigned short *ipAddress, char *ipAddressString);
void sendDNSPacketAndGetResponse(char *hostName, char *dnsIpAddress,
		char *hostAddress);
int stringLength(char *str);
char *convertHostToDotNotation(char *hostName);

struct ip_packet {
	unsigned char version_ihl; //8bits
	unsigned char dscp_ecn;	//8 bits
	unsigned short int totalLen; //16

	unsigned short int identification;
	unsigned short int flags_fragment_offset;

	unsigned char ttl;
	unsigned char protocol;
	unsigned short int headerChecksum;

	unsigned int sourceAddress;
	unsigned int destinationAddress;
};

struct udp_packet {
	unsigned short int source_port; //16
	unsigned short int destination_port;
	unsigned short int length;
	unsigned short int checksum;

};

struct dns_packet {
	unsigned short int identification;
	unsigned short int codes;
	unsigned short int tot_questions;
	unsigned short int tot_answers;
	unsigned short int tot_aut_res_records;
	unsigned short int tot_add_res_records;

};

struct dns_response {
	unsigned short int nameLocation; //2bytes
	unsigned short int type;  //2bytes
	unsigned short int classDNS; //2bytes
	unsigned short int timeToLive_1; //2bytes
	unsigned short int timeToLive_2;
	unsigned short int dataLength; //2bytes.

};

struct tcp_packet {
	unsigned short int source_port;
	unsigned short int destination_port;
	unsigned int sequence_num;
	unsigned int ack_num;
	unsigned char data_offset_reser_NS;
	unsigned char flags;
	unsigned short int window_size;
	unsigned short int checksum;
	unsigned short int urgent_pointer;
};

/**
 * Open socket and accept a UDP packet containing the hostname resolve the hostname
 * and send the IP address mapped to that hostname
 */
int main(){
	unsigned portNumber=5265;
	int sockUDP=0;
	 struct sockaddr_in myaddr;  // address of the server
	 struct sockaddr_in claddr;
	 char buffer[4096];
	 long recvlen;
	 socklen_t clientlen=sizeof(claddr);
	 int length;


	 myaddr.sin_addr.s_addr=htonl(INADDR_ANY);
	 myaddr.sin_family=AF_INET;
	 myaddr.sin_port=htons(portNumber);

	sockUDP=socket(AF_INET,SOCK_DGRAM,0);
	if(sockUDP>0)
	{
		/* setsockopt: Handy debugging trick that lets
		   * us rerun the server immediately after we kill it;
		   * otherwise we have to wait about 20 secs.
		   * Eliminates "ERROR on binding: Address already in use" error.
		   */
		 int optval = 1;
		  setsockopt(sockUDP, SOL_SOCKET, SO_REUSEADDR,
			     (const void *)&optval , sizeof(int));

		//int bind(int, const sockaddr *, unsigned int)
		if(bind(sockUDP, (struct sockaddr *)&myaddr,sizeof(myaddr)) < 0 )
		{
			printf("\n Bind Failed");
			fflush(stdout);
		}
		else
		{
			printf("\n Bind success waiting for data");
			fflush(stdout);
			//recvfrom(int sockfd, void *buf, size_t len, int flags,struct sockaddr *src_addr, socklen_t *addrlen);
			while(1)
			{
				length=recvfrom(sockUDP,buffer,4096,0,(struct sockaddr *)&claddr,&clientlen);
				printf( "\n %d bytes: '%s'\n", length, buffer );
				printf("\n %d ",ntohs(claddr.sin_port));


				char *dnsIpAddress = "208.67.222.123";
				char hostAddress[20];
				sendDNSPacketAndGetResponse(buffer, dnsIpAddress, hostAddress);
				printf("\n Final IP address obtained %s", hostAddress);
				
				

				int lenAddr=stringLength(hostAddress);

				int status=sendto(sockUDP, hostAddress, lenAddr, 0, (struct sockaddr*) &claddr, clientlen);
				fflush(stdout);
				if(status==-1)
				{
					printf("\n Error Sending");
					fflush(stdout);

				}
				else
					printf("\nData Sent");
					fflush(stdout);
			}

		}
	}
	else {
		printf("\nSocket Creation failed");
	}
}


/**
 * Objective: Initialize host name string and DNS server address
 * Returns: NA
 * Print the final Result
 * Calls function to create a IP packet
 */

int testDNSReqAndRes() {

	char *hostName = "www.northeastern.edu";
	char *dnsIpAddress = "208.67.222.123";
	char hostAddress[20];
	sendDNSPacketAndGetResponse(hostName, dnsIpAddress, hostAddress);
	printf("\n Final IP address obtained %s", hostAddress);
}

/**
 * Objective: Find the length of the String
 * Input: Pointer to a string / char-array
 * Returns : int -> length of the passed String
 */
int stringLength(char *str) {

	if (str != NULL) {
		int len = 0;
		while (*(str + len) != '\0') {
			len++;
		}

		return len;
	} else
		return 0;
}

/**
 * Objective:
 * Input:
 * Returns:
 * Example:
 * Explanation:
 */
void sendDNSPacketAndGetResponse(char *hostName, char *dnsIpAddress,
		char *hostAddress) {

	struct ip_packet *packet, packetStruct;
	struct udp_packet *udpPacket;
	struct dns_packet *dnsPacketPtr;

	int ipPacketSize = sizeof(*packet);
	int udpPacketSize = sizeof(*udpPacket);
	int dnsPacketSize = sizeof(*dnsPacketPtr);

	int queryLen = stringLength(hostName) + 2;

	cout << "IP  Packet Header Size " << ipPacketSize << endl;
	cout << "UDP Packet Header Size " << udpPacketSize << endl;
	cout << "DNS packet Header Size " << dnsPacketSize << endl;

	struct sockaddr_in sin;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(80);
	sin.sin_addr.s_addr = inet_addr(dnsIpAddress);
	int sockFd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	unsigned int totalPacketSize = ipPacketSize + udpPacketSize
			+ sizeof(struct dns_packet) + (queryLen * sizeof(char)) + 4;
	void *totPacket = malloc(totalPacketSize);

	packet = (struct ip_packet*) totPacket;
	createIPPacket(packet, totalPacketSize, dnsIpAddress);

	udpPacket = (struct udp_packet*) (totPacket + sizeof(packetStruct));
	createUDPPacket(udpPacket, queryLen);

	//char *dataWritten=(char *)(totPacket+ipPacketSize+udpPacketSize);
	void *dnsPacket = totPacket + ipPacketSize + udpPacketSize;
	createDNSPacket(dnsPacket, hostName);

	int dnsRequestID = ((struct dns_packet*) dnsPacket)->identification;

	printf("\n Sent a DNS request with ID %d", dnsRequestID);

	if (sendto(sockFd, totPacket, ntohs(packet->totalLen), 0,
			(struct sockaddr *) &sin, sizeof(sin)) < 0) {
		perror("\nsendto failed");
	}
	//Data send successfully
	else {
		printf("\nPacket Send. Length : %d \n", packet->totalLen);
	}

	free(totPacket);
	sendAndRecvDNSPackets(dnsRequestID, queryLen, hostAddress,dnsIpAddress);

}

/**
 * Objective:
 * Input:
 * Returns:
 * Example:
 * Explanation:
 */
void createIPPacket(struct ip_packet *packet, unsigned totalPacketSize,
		char *dnsIpAddress) {

	unsigned char version = 4;
	unsigned char headerLen = 5;

	cout << "left shift 4 bits " << (version << 4) << endl;

	unsigned char ver_len = version << 4 | headerLen;
	unsigned short int version_header = ver_len | headerLen;
	packet->version_ihl = version_header;
	packet->dscp_ecn = 0;
	cout << "\n total packet size is :" << totalPacketSize;
	packet->totalLen = htons(totalPacketSize);
	packet->identification = htons(12345);

	unsigned short int fragmentation = 0;
	unsigned char ipFlags = 64;
	cout << "\n IP Flags :" << ipFlags;
	cout << "\n flags_fragment_offset : " << ((ipFlags | fragmentation) << 8);
	unsigned short int flags_fragment_offset_temp = (ipFlags | fragmentation)
			<< 8;

	cout << "\nhtons of the result is :" << htons(flags_fragment_offset_temp);

	packet->flags_fragment_offset = htons((ipFlags | fragmentation) << 8);
	packet->ttl = 64;
	packet->protocol = 17;
	packet->headerChecksum = htons(0);

	packet->sourceAddress = inet_addr("192.168.133.133");
	packet->destinationAddress = inet_addr(dnsIpAddress);

}

/**
 * Objective:
 * Input:
 * Returns:
 * Example:
 * Explanation:
 */
void createUDPPacket(struct udp_packet *udpPacket, int hostnameLen) {

	int udpPacketSize = sizeof(*udpPacket);

	udpPacket->source_port = htons(5555);
	udpPacket->destination_port = htons(53);
	udpPacket->length = htons(
			udpPacketSize + sizeof(struct dns_packet)
					+ (hostnameLen * sizeof(char)) + 4);
	udpPacket->checksum = htons(0);
}
/**
 * Objective:
 * Input:
 * Returns:
 * Example:
 * Explanation:
 */
void createDNSPacket(void *dnsQueryPacket, char *hostName) {

	//char *name = "www.google.com";

	int nameLen = 0;
	char *query = convertToDNSFormat(hostName);
	int len = 0;

	while (*(query + len) != '\0') {
		len++;

	}
	len++;

	struct dns_packet *dnsPacket = (struct dns_packet*) dnsQueryPacket;
	dnsPacket->identification = 26602;

	unsigned short int qrCode = 0;
	unsigned short int opcode = 0;
	unsigned short int AA = 0;
	unsigned short int TC = 0;
	unsigned short int RD = 1;
	unsigned short int RA = 0;
	unsigned short int Z = 0;
	unsigned short int rcode = 0;
	char type = 'A';

	dnsPacket->codes = htons(
			((qrCode << 15) | (opcode << 14) | (AA << 10) | (TC << 9)
					| (RD << 8) | (RA << 7) | (Z << 6) | rcode));
	dnsPacket->tot_questions = htons(1);
	dnsPacket->tot_answers = htons(0);
	dnsPacket->tot_aut_res_records = htons(0);
	dnsPacket->tot_add_res_records = htons(0);
	void *queryPacket = dnsQueryPacket + sizeof(struct dns_packet);
	memcpy(queryPacket, query, len * sizeof(char));

	cout << "\n query name : " << (char *) queryPacket << endl;

	unsigned short int *typePtr = (unsigned short int *) (dnsQueryPacket
			+ sizeof(struct dns_packet) + (len * sizeof(char)));
	*typePtr = htons(1);
	unsigned short int *classDns = (unsigned short int *) (dnsQueryPacket
			+ sizeof(struct dns_packet) + (len * sizeof(char))
			+ sizeof(unsigned short int));
	*classDns = htons(1);

	free(query);

}
/**
 * Objective:
 * Input:
 * Returns:
 * Example:
 * Explanation:
 */
char* convertToDNSFormat(char *names) {

	cout << "\n*******************************************" << endl;
	cout << "In function convertToDNSFormat(char *names)" << endl;

	char *name = convertHostToDotNotation(names); //3www6google3com0

	int len = 0;

	while (*(name + len) != '\0') {
		len++;
	}
	printf("\n actual string with the appended '.' %s", name);
	printf("\n Length of the string is %d:\n", len);

	char *query = (char *) malloc(len + 2); //query has the address of first assigned byte
	char *temp = query; //making a copy of the first assigned byte

	char stack[len];
	stack[0] = '\0';

	int iQuery = 0;
	int iName = 0;
	int pos = 0;
	int prevDot = 0;
	int elems = 0;
	while (*(name + iName) != '\0') {
		if (*(name + iName) == '.') {
			if (prevDot == 0) {
				prevDot = iName;
				elems = iName;
				printf("Number of Elements for DOT = %d\n", elems);

				*(query + pos) = elems;
				pos++;

			} else {

				elems = iName - prevDot - 1;
				printf("Number of Elements for DOT = %d\n", elems);
				prevDot = iName;
				*(query + pos) = elems;
				pos++;

			}

			int counter = elems;
			while (counter > 0) {
				*(query + pos) = *(name + iQuery);
				iQuery++;
				pos++;
				counter--;
			}
			iQuery++; //skipping the "."

			iName++;
		}

		else {
			iName++;

		}

	}
	printf("Position now pointing at %d: \n", pos);
	*(query + pos) = 0;
	pos++;
	*(query + pos) = '\0';

	len = 0;
	while (*(temp + len) != '\0') {
		printf("%d", *(temp + len));
		len++;

	}
	printf("\n");
	len = 0;
	while (*(temp + len) != '\0') {
		printf("%c", *(temp + len));
		len++;
	}

	free(name);

	return temp;

	cout << "*******************************************" << endl;
}
/**
 * Objective:
 * Input:
 * Returns:
 * Example:
 * Explanation:
 */
void createTCPPacket(void *tcpPacketMem, int srcPortNum, int dstPortNum,
		int seqNum, int ackNum) {
	struct tcp_packet *tcpPacket;
	tcpPacket = (struct tcp_packet*) tcpPacketMem;

	tcpPacket->source_port = htons(12345);
	tcpPacket->destination_port = htons(8080);
	tcpPacket->sequence_num = 1;
	tcpPacket->ack_num = 0;
	unsigned short int dataOffset = 5;
	unsigned short int reserved = 0;
	unsigned short int ns = 0;

	unsigned short int data_offset_reser_NS = ((dataOffset << 4)
			| (reserved << 1) | (ns));
	tcpPacket->data_offset_reser_NS = data_offset_reser_NS;

	unsigned short int CWR = 0;
	unsigned short int ECE = 0;
	unsigned short int URG = 0;
	unsigned short int ACK = 0;
	unsigned short int PSH = 0;
	unsigned short int RST = 0;
	unsigned short int SYN = 0;
	unsigned short int FIN = 0;

	tcpPacket->window_size = htons(512);
	tcpPacket->checksum = htons(0);
	tcpPacket->urgent_pointer = 0;

}
/**
 * Objective:
 * Input:
 * Returns:
 * Example:
 * Explanation:
 */
void sendAndRecvDNSPackets(int identificationNum, int queryLen,
		char *hostAddress,char *dnsIpAddress) {
	struct ip_packet *ipPacket;

	struct dns_packet *dnsPacket;

	int sockfd;
	int count = 0;
	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sockfd < 0) {
		printf("error in socket\n");
		return;
	}
	bool recvNext = true;

	while (recvNext) {
		void *buffer = (unsigned char *) malloc(65536); //to receive data
		memset(buffer, 0, 65536);
		struct sockaddr saddr;
		int saddr_len = sizeof(saddr);
		int buflen = 0;

		//Receive a network packet and copy in to buffer
		buflen = recvfrom(sockfd, buffer, 65536, 0, &saddr,
				(socklen_t *) &saddr_len);
		if (buflen < 0) {
			printf("error in reading recvfrom function\n");
			return;
		}

		struct sockaddr_in *addr_in = (struct sockaddr_in *) &saddr;
		char *s = inet_ntoa(addr_in->sin_addr);
		printf("\n IP address: %s\n", s);

		ipPacket = (struct ip_packet*) (buffer + sizeof(struct ethhdr));

		struct sockaddr_in sin, sdest;

		sin.sin_addr.s_addr = ipPacket->sourceAddress;
		sdest.sin_addr.s_addr = ipPacket->destinationAddress;

		if (ipPacket->sourceAddress == inet_addr(dnsIpAddress)) {
			printf("\nFrom address -> %s ", inet_ntoa(sin.sin_addr));
			printf("\nTo address -> %s", inet_ntoa(sdest.sin_addr));
			recvNext = false;
		} else if (count > 10) {
			break;
		}

		printf("\ncount \n %d", count);
		printf("\nIP protocol used = %d", ipPacket->protocol);

		if (ipPacket->protocol == 17) {
			printf("/n UDP packet, may be a DNS Response.");

			int totalLength = ntohs(ipPacket->totalLen);
			parseUDPPacket(buffer, totalLength, identificationNum, queryLen,
					hostAddress);
		} else if (ipPacket->protocol == 6) {
			printf("\n TCP packet");
		}

		printf("\n checking next packet");
		count++;

		free(buffer);

	}

}
/**
 * Objective:
 * Input:
 * Returns:
 * Example:
 * Explanation:
 */
void parseUDPPacket(void *packet, int totalLength, int identificationNum,
		int queryLen, char *hostAddress) {

	printf("\n Entering parseUDPPacket");
	struct udp_packet *udpPacket;
	struct dns_packet *dnsPacket;

	udpPacket = (struct udp_packet*) (packet + sizeof(struct ethhdr)
			+ sizeof(struct ip_packet));
	int udpTotalLength = ntohs(udpPacket->length);

	if (udpTotalLength > sizeof(struct udp_packet)) {
		printf("\n checking for DNS packet");

		dnsPacket = (struct dns_packet*) (packet + sizeof(struct ethhdr)
				+ sizeof(struct ip_packet) + sizeof(struct udp_packet));
		if (identificationNum == dnsPacket->identification) {
			int lengthOfResponse = udpTotalLength - sizeof(struct dns_packet);
			int queryCount = ntohs(dnsPacket->tot_questions);
			int replyCount = ntohs(dnsPacket->tot_answers);
			int authCount = ntohs(dnsPacket->tot_aut_res_records);

			printf("\n*******STATS*********\n");
			printf("UDP packet size =%d\n", udpTotalLength);
			printf("size of dns header =%d\n", sizeof(struct dns_packet));
			printf("Length of response =%d\n", lengthOfResponse);
			printf("query count = %d\n", queryCount);
			printf("reply count =%d\n", replyCount);
			printf("auth count =%d\n", authCount);
			printf("\n*******END STATS*********\n");
			parseDNSResponse(packet, queryLen, hostAddress, replyCount);
		}

	} else {
		printf("\n Unknown Format");
	}

}
/**
 * Objective: Parse the DNS response packet and identify the type. if its CNAME print it if its IP store it in input variable
 * Input: IP packet, length of the actual query(www.google.com), variable to store the IP address, number of replies obtained.
 * Returns: NA
 * Example:
 * Explanation: packet pointer is advanced after parsing each response. for loop is used to go through each query.
 */
void parseDNSResponse(void *packet, int queryLen, char *hostAddress,
		int replyCount) {
	printf("\n inside parseDNSResponse \n");
	printf("\n query length =%d", queryLen);
	void *dnsResponse = (packet + sizeof(struct ethhdr)
			+ sizeof(struct ip_packet) + sizeof(struct udp_packet)
			+ sizeof(struct dns_packet) + queryLen + 4);

	for (int i = 0; i < replyCount; i++) {

			unsigned short int *nameLocation = (unsigned short int*) (dnsResponse);
			unsigned short int *type = (unsigned short int*) (dnsResponse + 2);
			unsigned short int *classDNS = (unsigned short int*) (dnsResponse + 4);
			unsigned int *timeToLive = (unsigned int*) (dnsResponse + 6);
			unsigned short int *dataLen = (unsigned short int*) (dnsResponse + 10);

			printf("\n*********** DNS Response Stats************\n");
			printf("\n name location from start of DNS = %x", ntohs(*nameLocation));
			printf("\n type of DNS response =%d", ntohs(*type));
			printf("\n class of dns response =%d", ntohs(*classDNS));
			printf("\n time to live =%d", ntohl(*timeToLive));
			printf("\n data length =%d", ntohs(*dataLen));
			int typeDNSResponse = ntohs(*type);

		if (typeDNSResponse == 5) {

			int upperLimit = ntohs(*dataLen);
			printf("\nUpper for data is %d \n", upperLimit);
			char *cName=(char *)(dnsResponse+12);
			printf("\nCNAME obtained:");
			for(int i=0;i<upperLimit;i++)
			{
				printf("%c",*(cName+i));
			}
			printf("\n ");
			dnsResponse=(dnsResponse+12)+upperLimit;

		}

		else if (typeDNSResponse == 1) {

			int upperLimit = ntohs(*dataLen);
			//to get to the actual response.
			char *address = (char *) (dnsResponse + 12);
			unsigned short ipAddress[4];
			printf("\n address value \n");
			printf("\n 0 value is %d\n", address[0]);
			for (int i = 0; i < upperLimit; i++) {

				unsigned int val = address[i];
				unsigned int convertDec = val & 255;
				printf("values obtained =%d", convertDec);
				ipAddress[i] = convertDec;

			}
			//char  ipAddressString[16];
			convertIpDecimalToString(ipAddress, hostAddress);
			dnsResponse=(dnsResponse+12)+upperLimit;
		}

	}

	printf("\n the string obtained is %s ", hostAddress);

}
/**
 * Objective: Extract single digit from the IP address obtained and reversing it.
 * Input: pointer to ipAddress array which contains 4 number in dotted notation.
 * 			pointer to char array which contains the output.
 * Returns: NA
 * Example: 271 -> 172
 * Explanation: converting from network byte order to host order and making a IP string.
 */
void convertIpDecimalToString(unsigned short *ipAddress,
		char *ipAddressString) {

	int ipIndex = 0;

	for (int i = 0; i < 4; i++) {
		int addressSingleDigit[3] = { 0, 0, 0 };
		int ipPart = ipAddress[i];
		int j = 0;
		/**
		 * extracting single digit.
		 */
		while (ipPart != 0) {

			int temp = ipPart % 10;
			ipPart = ipPart / 10;
			addressSingleDigit[j] = temp;

			j++;
		}
		/**
		 * reversing the digits obtained.
		 * adding 48 to get the char representation of the number.
		 */
		for (int k = 2; k >= 0; k--) {

			ipAddressString[ipIndex] = 48 + addressSingleDigit[k];
			ipIndex++;
		}
		/**
		 * adding '.' after 3 digits.
		 */
		ipAddressString[ipIndex] = '.';
		ipIndex++;
	}
	ipAddressString[15] = '\0';

}
/**
 * Objective: Convert DNS host name to dot notation
 * Input: char pointer which contains the hostname in normal form
 * Returns: pointer to char which contains the hostname with an appended '.'
 * Example: input :www.google.com -> output: www.google.com.
 * Explanation: Dot notation is used to calculate the number of letter before a dot.
 */
char *convertHostToDotNotation(char *hostName) {

	int len = 0;
	while (*(hostName + len) != '\0') {
		len++;
	}

	printf(" \n Length of the hostname is %d ", len);

	char *hostNameDNSForm = (char *) malloc(len + 1);

	for (int i = 0; i < len; i++) {

		*(hostNameDNSForm + i) = *(hostName + i);
	}

	hostNameDNSForm[len] = '.';
	hostNameDNSForm[len + 1] = '\0';
	printf("\n converted string is %s", hostNameDNSForm);

	return hostNameDNSForm;

}

void printLogs(char *functionName) {


}
