#pragma once
#include <unordered_map>
#include <windows.h>
#include <iostream>
#include <time.h>
#include <vector>
#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"


using namespace std;

#define PARSE_ATTACKER

#define MAC_ADDRESS_SIZE	6
#define DATA_BLOCK_SIZE		0x2000

#define MAX_BLOCK_SIZE		0x1000000
#define MAX_PACKET_CNT		0x10000
#define STREAM_TIMEOUT		6

#define PROCESS_WAITTIME	1000

#pragma pack(1)

typedef struct  __DATABLOCKLIST
{
	struct  
	{
		int					size;
		__DATABLOCKLIST *	next;
		__DATABLOCKLIST *	previous;
	}hdr;

	char				data[DATA_BLOCK_SIZE];
}DATABLOCKLIST,*LPDATABLOCKLIST;

typedef struct
{
	unsigned char	srcmac[MAC_ADDRESS_SIZE];
	unsigned char	dstmac[MAC_ADDRESS_SIZE];
	unsigned int	srcip;
	unsigned short	srcport;
	unsigned int	dstip;
	unsigned short	dstport;
	unsigned int	protocol;
#ifdef PARSE_ATTACKER
	pcap_t		*	pcapt;
#endif
}SESSIONSOCKET, *LPSESSIONSOCKET;

typedef struct __PACKETSIZE{
	int				size;
	__PACKETSIZE *	next;
	__PACKETSIZE *	previous;
#ifdef PARSE_ATTACKER
	pcap_pkthdr		hdr;
#endif
}PACKSIZELIST,*LPPACKSIZELIST;

typedef struct {
	SESSIONSOCKET		sock;

	time_t				starttime;
	int					ready;
	int					totalsize;
	int					packcnt;
	LPDATABLOCKLIST		datalist;
	LPDATABLOCKLIST		lastdata;
	LPPACKSIZELIST		sizelist;
	LPPACKSIZELIST		lastsize;

	time_t				starttime2;
	int					ready2;
	int					totalsize2;
	int					packcnt2;
	LPDATABLOCKLIST		datalist2;
	LPDATABLOCKLIST		lastdata2;
	LPPACKSIZELIST		sizelist2;
	LPPACKSIZELIST		lastsize2;
}DATALISTHEADER,*LPDATALISTHEADER;

#pragma pack()


class DataBlockList {

public:
	static int push(pcap_pkthdr *pcaphdr, SESSIONSOCKET *sock, const char * data, int datalen);

	static int push(pcap_pkthdr *pcaphdr, SESSIONSOCKET *sock, const char * data, int datalen, int fin,int syn);

	static int remove(DATALISTHEADER hdr);

	static int __stdcall process();

	static void enterlock();
	static void leavelock();

	static void init();

	static int getBlock(LPDATABLOCKLIST &first, int & offset, int size, char **data);
	static int getNextPacket(LPDATABLOCKLIST &first, int &offset, LPPACKSIZELIST &sizelist, char *data);
	static int writeBlocks(LPDATABLOCKLIST list, string filename);

	static int find(char * flag, int flaglen, LPDATABLOCKLIST &first, int & offset);
};