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

char* convertToDNSFormat(char *names);
void createIPPacket(struct ip_packet *packet, unsigned int);
void createUDPPacket(struct udp_packet *udpPacket);
void createDNSPacket(void *dnsPacket);
void sendAndRecvTCPPackets();
void sendAndRecvDNSPackets(int identificationNum, int queryLen);
void parseUDPPacket(void *packet, int totalLength, int identificationNum, int);
void parseDNSResponse(void *packet, int);
void convertIpDecimalToString(unsigned short *ipAddress,char *ipAddressString);



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

int main() {

	struct ip_packet *packet, packetStruct;
	struct udp_packet *udpPacket;
	struct dns_packet *dnsPacketPtr;

	int ipPacketSize = sizeof(*packet);
	int udpPacketSize = sizeof(*udpPacket);
	int dnsPacketSize = sizeof(*dnsPacketPtr);

	int queryLen = 16;

	cout << "IP  Packet Header Size " << ipPacketSize << endl;
	cout << "UDP Packet Header Size " << udpPacketSize << endl;
	cout << "DNS packet Header Size " << dnsPacketSize << endl;

	struct sockaddr_in sin;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(80);
	sin.sin_addr.s_addr = inet_addr("208.67.222.123");
	int sockFd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	unsigned int totalPacketSize = ipPacketSize + udpPacketSize
			+ sizeof(struct dns_packet) + (16 * sizeof(char)) + 4;
	void *totPacket = malloc(totalPacketSize);

	packet = (struct ip_packet*) totPacket;
	createIPPacket(packet, totalPacketSize);

	udpPacket = (struct udp_packet*) (totPacket + sizeof(packetStruct));
	createUDPPacket(udpPacket);

	//char *dataWritten=(char *)(totPacket+ipPacketSize+udpPacketSize);
	void *dnsPacket = totPacket + ipPacketSize + udpPacketSize;
	createDNSPacket(dnsPacket);

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
	sendAndRecvDNSPackets(dnsRequestID, queryLen);

	return 0;
}

void createIPPacket(struct ip_packet *packet, unsigned totalPacketSize) {

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
	packet->destinationAddress = inet_addr("208.67.222.123");

}

void createUDPPacket(struct udp_packet *udpPacket) {

	int udpPacketSize = sizeof(*udpPacket);

	udpPacket->source_port = htons(5555);
	udpPacket->destination_port = htons(53);
	udpPacket->length = htons(
			udpPacketSize + sizeof(struct dns_packet) + (16 * sizeof(char))
					+ 4);
	udpPacket->checksum = htons(0);
}

void createDNSPacket(void *dnsQueryPacket) {

	char *name = "www.google.com";

	int nameLen = 0;
	char *query = convertToDNSFormat(name);
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

}

char* convertToDNSFormat(char *names) {
	//cout << "!!!Hello World!!!" << endl; // prints !!!Hello World!!!

	char *name = "www.google.com."; //3www6google3com0

	int len = 0;

	while (*(name + len) != '\0') {
		len++;
	}

	printf("Length of the string is %d:\n", len);

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

	return temp;

}

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

void sendAndRecvDNSPackets(int identificationNum, int queryLen) {
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

		if (ipPacket->sourceAddress == inet_addr("208.67.222.123")) {
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
			parseUDPPacket(buffer, totalLength, identificationNum, queryLen);
		} else if (ipPacket->protocol == 6) {
			printf("\n TCP packet");
		}

		printf("\n checking next packet");
		count++;

		free(buffer);

	}

}

void parseUDPPacket(void *packet, int totalLength, int identificationNum,
		int queryLen) {

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
			parseDNSResponse(packet, queryLen);
		}

	} else {
		printf("\n Unknown Format");
	}

}

void parseDNSResponse(void *packet, int queryLen) {
	printf("\n inside parseDNSResponse \n");
	printf("\n query length =%d", queryLen);
	void *dnsResponse = (packet + sizeof(struct ethhdr)
			+ sizeof(struct ip_packet) + sizeof(struct udp_packet)
			+ sizeof(struct dns_packet) + queryLen + 4);

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

	int upperLimit = ntohs(*dataLen);

	printf("\nUpper for data is %d \n", upperLimit);

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
	char  ipAddressString[16];
	convertIpDecimalToString(ipAddress,ipAddressString);

	printf("\n the string obtained is %s ", ipAddressString);

}

void convertIpDecimalToString(unsigned short *ipAddress,char *ipAddressString) {

	int ipIndex = 0;

		for (int i = 0; i < 4; i++) {
			int addressSingleDigit[3] = { 0, 0, 0 };
			int ipPart = ipAddress[i];
			int j = 0;
			while (ipPart != 0) {

				int temp = ipPart % 10;
				ipPart = ipPart / 10;
				addressSingleDigit[j] = temp;

				j++;
			}


			for (int k = 2; k >= 0; k--) {

				ipAddressString[ipIndex] = 48 + addressSingleDigit[k];
				ipIndex++;
			}

			ipAddressString[ipIndex] = '.';
			ipIndex++;
		}
		ipAddressString[15] = '\0';

}
