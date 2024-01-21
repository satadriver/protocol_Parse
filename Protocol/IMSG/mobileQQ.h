#pragma once
#include <iostream>
#include "../DataList.h"

using namespace std;

#pragma pack(1)

typedef struct  
{
	unsigned int len;
	unsigned int version;
	unsigned char cryption;
	unsigned int offset;
}MOBILEQQ_PACK_HDR,*LPMOBILEQQ_PACK_HDR;

#pragma pack()

//#define MIN_MOBILEQQ_PACKET_SIZE (sizeof(MOBILEQQ_PACK_PARSE_HDR) + 4 + 1 + 5);


class MobileQQ {
public:
	static int isMobileQQPack(DATALISTHEADER hdr);
	static int parsePacket(const char * data, int & len,int dport,int sport,DATALISTHEADER hdr);
};