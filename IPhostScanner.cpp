#define ICMP_ECHO_REQUEST_TYPE 8
#define ICMP_ECHO_RREQUEST_CODE 0
#define ICMP_ECHO_REPLY_TYPE 0
#define ICMP_ECHO_REPLY_CODE 0
#define ICMP_MINIMUM_HEADER 8
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <stdio.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <WinSock2.h>

#pragma comment(lib,"ws2_32.lib")

struct hostent* host;
struct sockaddr_in dest;
struct sockaddr_in from;

using namespace std;

typedef struct ip_hdr {
	unsigned char ipherLen;
	unsigned char ipTOS;
	unsigned short ipLength;
	unsigned short ipID;
	unsigned short ipFlags;
	unsigned char ipTTL;
	unsigned char ipProtocol;
	unsigned short ipChecksum;
	unsigned long ipSource;
	unsigned long ipDestination;
}IPHDR,*IP_HDR;

typedef struct icmp_hdr {
	unsigned char icmp_type;
	unsigned char icmp_code;
	unsigned short icmp_checksum;
	unsigned icmp_id;
	unsigned short icmp_sequence;
	unsigned long icmp_timestamp;
}ICMP_HDR,*PICMP_HDR;

int timeout = 1000;

void InitializeWinsock() {
	int status;
	WSADATA wsa;
	if (status = WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		cout << "failed to WSAStartup()" << WSAGetLastError();
		exit(EXIT_FAILURE);
	}
}

void InitIcmpHeader(ICMP_HDR* icmp_hdr) {
	char buff[sizeof(ICMP_HDR) + 32];
	icmp_hdr->icmp_type = ICMP_ECHO_REQUEST_TYPE;
	icmp_hdr->icmp_code = ICMP_ECHO_REPLY_CODE;
	icmp_hdr->icmp_id = (USHORT)GetCurrentProcessId();
	icmp_hdr->icmp_checksum = 0;
	icmp_hdr->icmp_sequence = 0;
	icmp_hdr->icmp_timestamp = GetTickCount();

	memset(&buff[sizeof(ICMP_HDR)], 'E', 32);
}

void Resolove(char hostname[]) {
	if (isdigit(hostname[0])) {
		dest.sin_addr.s_addr = inet_addr(hostname);
	}
	else if ((host = gethostbyname(hostname)) != 0) {
		strncpy((char*)&dest.sin_addr, (char*)host->h_addr_list[0], sizeof(dest.sin_addr));
	}
	else {
		exit(EXIT_FAILURE);
	}
}

void ResoloveIPAddr(char starthost[], char endhost[], int* start, int* end) {
	int cd1 = 0;
	int cd2 = 0;
	int ci1 = 0;
	int ci2 = 0;
	char c1[4], c2[4];
	while (*starthost != '\0' && *endhost != '\0') {
		if (*starthost != '\0') {
			if (cd1 < 3) {
				if (*starthost == '.') {
					++cd1;
				}
			}
			else {
				c1[ci1] = *starthost;
				++ci1;
			}
			++starthost;
			if (*endhost != '\0') {
				if (cd2 < 3) {
					if (*endhost == '.') {
						++cd2;
					}
				}
				else {
					c2[ci2] = *endhost;
					++ci2;
				}
				++endhost;
			}
			c1[3] = c2[3] = '\0';
			*start = atoi(c1);
			*end = atoi(c2);
		}
	}
}

char* Assemble(char starthost[], int cur) {
	int i = 0;
	int cd = 0;
	char appendix[4], * tmp = starthost;
	_itoa(cur, appendix, 10);
	while (cd < 3) {
		if (*tmp == '.') {
			++cd;
		}
		++tmp;
	}
	*tmp = '\0';
	strcat(starthost, appendix);
	return starthost;
}

unsigned short checksum(unsigned short* buffer, int size) {
	unsigned long cksum = 0;
	while (size > 1) {
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size) {
		cksum += *(UCHAR*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (USHORT)(~cksum);
}

void SegmentScan(char starthost[], char endhost[]) {
	int status, tick, start, end, i;
	WSADATA wsa;
	SOCKET sock = INVALID_SOCKET;
	
	ICMP_HDR* icmp_hdr, * recv_icmp;
	unsigned short nSeq = 0;
	int nLen = sizeof(from);

	InitializeWinsock();

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	if (sock == INVALID_SOCKET) {
		if (WSAGetLastError() == 10013) {
			printf("Socket Failed: Permission denied.\n");
			exit(EXIT_FAILURE);
		}
	}
	dest.sin_family = AF_INET;

	ResoloveIPAddr(starthost, endhost, &start, &end);

	timeval tv = { timeout, 0 };
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(timeval));

	printf("Start scanning...\n");
	cout << "---------------------------------------------------------" << endl;
	printf("|Hostname\tstate\tDelay\t\OS\t\t\t|\n");

	for (i = start; i <= end; i++) {
		cout << '|';
		char recvBuf[1024 * 5];
		char buff[sizeof(ICMP_HDR) + 32];
		icmp_hdr = (ICMP_HDR*)buff;

		Resolove(Assemble(starthost, i));
		InitIcmpHeader(icmp_hdr);
		icmp_hdr->icmp_sequence = i;
		icmp_hdr->icmp_checksum = checksum((unsigned short*)buff, sizeof(ICMP_HDR) + 32);

		//cout << "send IP" << inet_ntoa(dest.sin_addr) << endl;
		status = sendto(sock, buff, sizeof(ICMP_HDR) + 32, 0, (SOCKADDR*)&dest, sizeof(dest));

		/*是否发送成功*/
		if (status == SOCKET_ERROR) {
			printf("sent() error:%d\n", WSAGetLastError());
			exit(EXIT_FAILURE);
		}
		else {
			//cout << "send successed!" << endl;
		}
		
		status = recvfrom(sock, recvBuf, 1024 * 5, 0, (SOCKADDR*)&from, &nLen);
		recv_icmp = (ICMP_HDR*)(recvBuf + 20);
		IPHDR *recv_ip = (IPHDR*)(recvBuf);
		tick = GetTickCount();

		if (status == SOCKET_ERROR) {
			if (WSAGetLastError() == WSAETIMEDOUT) {
				printf("%s\tunknow.\t\t\t\t\t|\n",inet_ntoa(dest.sin_addr));
				continue;
			}
		}

		if (status < sizeof(IP_HDR) + sizeof(ICMP_HDR)) {
			printf("too few bytes from %s\n", inet_ntoa(from.sin_addr));

			continue;
		}
		if (recv_icmp->icmp_type != 0) {
			printf("%s\tunknow.\t\t\t\t\t|\n", starthost);

			continue;
		}

		else {
			printf("%s\talive\t%dms\t", inet_ntoa(from.sin_addr), tick - recv_icmp->icmp_timestamp, recv_ip->ipTTL);
			if (recv_ip->ipTTL == 32) {
				printf("windows 95\t|\n");
			}
			else if (recv_ip->ipTTL == 64) {
				printf("widnows/linux/macos\t|\n");
			}
			else if ((int)recv_ip->ipTTL == 128) {
				printf("windowsNT/2K\t|\n");
			}
			else if ((int)recv_ip->ipTTL == 255) {
				printf("UNIX\t|\n");
			}
			else {
				printf("unknow\t\t\t\t|\n");
			}
		}
	}
	cout << "---------------------------------------------------------" << endl;
	closesocket(sock);
}

void IPTest(char starthost[]) {
	int status, tick, i;
	WSADATA wsa;
	SOCKET sock = INVALID_SOCKET;

	ICMP_HDR* icmp_hdr, * recv_icmp;
	unsigned short nSeq = 0;
	int nLen = sizeof(from);


	InitializeWinsock();

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	if (sock == INVALID_SOCKET) {
		if (WSAGetLastError() == 10013) {
			printf("Socket Failed: Permission denied.\n");
			exit(EXIT_FAILURE);
		}
	}
	dest.sin_family = AF_INET;

	timeval tv = { timeout, 0 };
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(timeval));

	printf("Start scanning...\n");
	cout << "---------------------------------------------------------" << endl;
	printf("|Hostname\tstate\tDelay\t\OS\t\t\t|\n");

	char recvBuf[1024 * 5];
	char buff[sizeof(ICMP_HDR) + 32];
	icmp_hdr = (ICMP_HDR*)buff;

	Resolove(starthost);
	InitIcmpHeader(icmp_hdr);
	icmp_hdr->icmp_sequence = 1;
	icmp_hdr->icmp_checksum = checksum((unsigned short*)buff, sizeof(ICMP_HDR) + 32);

	cout << "|";
	status = sendto(sock, buff, sizeof(ICMP_HDR) + 32, 0, (SOCKADDR*)&dest, sizeof(dest));

	/*是否发送成功*/
	if (status == SOCKET_ERROR) {
		printf("sent() error:%d\n", WSAGetLastError());
		exit(EXIT_FAILURE);
	}

	status = recvfrom(sock, recvBuf, 1024 * 5, 0, (SOCKADDR*)&from, &nLen);
	recv_icmp = (ICMP_HDR*)(recvBuf + 20);
	IPHDR* recv_ip = (IPHDR*)(recvBuf);
	tick = GetTickCount();

	if (status == SOCKET_ERROR) {
		if (WSAGetLastError() == WSAETIMEDOUT) {
			printf("%s\tunknow.\t\t\t\t\t|\n", inet_ntoa(dest.sin_addr));
		}
		
	}
	else {
		
		if (status < sizeof(IP_HDR) + sizeof(ICMP_HDR)) {
			printf("too few bytes from %s\n", inet_ntoa(from.sin_addr));
		}
		if (recv_icmp->icmp_type != 0) {
			printf("%s\tunknow\t\t\t\t\t|\n", inet_ntoa(dest.sin_addr));
		}
		else {
			printf("%s\talive\t%dms\t", inet_ntoa(from.sin_addr), tick - recv_icmp->icmp_timestamp, recv_ip->ipTTL);
			if (recv_ip->ipTTL == 32) {
				printf("windows 95\t|\n");
			}
			else if (recv_ip->ipTTL == 64) {
				printf("widnows/linux/macos\t|\n");
			}
			else if ((int)recv_ip->ipTTL == 128) {
				printf("windowsNT/2K\t|\n");
			}
			else if ((int)recv_ip->ipTTL == 255) {
				printf("UNIX\t|\n");
			}
			else {
				printf("unknow\t\t\t\t|\n");
			}
		}
	}
	cout << "---------------------------------------------------------" << endl;
	closesocket(sock);
}

int main() {
	cout << "---------------------------------------------------------" << endl;
	cout << "|\t\t\t主机存活性探测\t\t\t|" << endl;
	cout << "---------------------------------------------------------" << endl;
	cout << "|\t\t\t1.对单IP地址进行探测\t\t|" << endl;
	cout << "|\t\t\t2.对IP段进行探测\t\t|" << endl;
	cout << "|\t\t\t请输入序号选择：\t\t|" << endl;
	cout << "---------------------------------------------------------" << endl;
	int mode;
	cin >> mode;
	switch (mode) {
		char starthost[100];
		case 1:
			cin.ignore();
			cout << "输入ip地址：" << endl;
			cin.getline(starthost, 100);
			IPTest(starthost);
			cout << "finished." << endl;
			break;
		case 2:
			char endhost[100];
			cout << "输入地址段：" << endl;
			cin.ignore();
			cin.getline(starthost, 100);
			cin.getline(endhost, 100);
			SegmentScan(starthost, endhost);
			cout << "finished." << endl;
			break;
		default:break;
	}
	
	return 0;
}